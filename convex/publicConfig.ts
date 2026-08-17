/**
 * Public bootstrap config (P7): the anonymous SPA reads this to render the
 * captcha widget, the tier-comparison table, and the backend chooser. Ported
 * from the old PublicConfig contract. Public + safe: the Cap SITE key is
 * public, tier limits are public, and only the backend enabled/label subset of
 * settings is exposed (never squad/backend secrets). A plain query so it can be
 * served reactively or via the GET /api/v1/config HTTP route.
 */
import { query } from './_generated/server';
import { resolveBillingConfig } from './lib/billingConfig';
import {
  readDonationState,
  readDonationHistory,
  bonusGbFromCents,
  effectiveBonusGb,
  currentMonthKey,
  currentMonthDailyGb,
} from './lib/donationBonus';
import { readUserCounts } from './lib/statusCounters';
import { resolveTheme } from './lib/themeConfig';
import { resolveVerification } from './lib/verificationConfig';
import { resolveSiteConfig } from './lib/siteConfig';
import { publicAnalytics, resolveAnalyticsConfig } from './lib/analyticsConfig';
import { publicFamilyProjection } from './lib/connectionModes';
import { resolvePublicModes } from './lib/placement';
import { BACKEND_IDS } from './lib/backendIds';
import { CAPABILITIES } from './lib/backends/capabilities';
import { resolveClients, publicClients } from './lib/clientCatalog';
import { resolveLocations } from './lib/locations';
import { resolveReferralConfig } from './lib/referralConfig';
import type { BackendId } from './lib/backendIds';

export const get = query({
  args: {},
  handler: async (ctx) => {
    const rows = await ctx.db.query('appSettings').collect();
    const settings: Record<string, unknown> = {
      'outline.enabled': false,
      'remnawave.enabled': true,
      'subscription.default_backend': 'remnawave',
      'subscription.user_choice_enabled': false,
      'subscription.backend_labels': { remnawave: 'Xray', outline: 'Outline' },
      // Free-account lifetime (days). Public so the signup flow can state the
      // real validity (DB-driven) instead of a hardcoded number that drifts.
      'freetier.expiryDays': 90,
      // Whether per-tier device (HWID) limits are enforced — drives the connect
      // UI's app-compatibility gating. Non-secret boolean.
      'devices.enforcementEnabled': false,
    };
    for (const row of rows) {
      if (!(row.key in settings)) continue;
      try {
        settings[row.key] = JSON.parse(row.value);
      } catch {
        /* keep default */
      }
    }

    const active = await ctx.db
      .query('tiers')
      .withIndex('by_active', (q) => q.eq('isActive', true))
      .collect();
    const seen = new Set<string>();
    const tiers = active
      .slice()
      .sort((a, b) => a.priority - b.priority)
      .filter((t) => (seen.has(t.slug) ? false : (seen.add(t.slug), true)))
      .map((t) => ({
        slug: t.slug,
        name: t.name,
        description: t.description ?? null,
        monthlyTrafficGb: t.monthlyTrafficGb,
        deviceLimit: t.deviceLimit,
      }));

    const labels = settings['subscription.backend_labels'] as {
      remnawave: string;
      outline: string;
    };
    const environment = (process.env.ENVIRONMENT ?? 'production') as
      | 'production'
      | 'development'
      | 'test';

    // All the independent sub-resolvers fan out in ONE Promise.all: this
    // function became the single heaviest public query (each resolver is
    // itself many indexed point reads), and awaiting them sequentially marched
    // a slow datastore straight into the 1s UDF timeout (seen live on beta
    // 2026-07-31: "Restarting Isolate user_timeout ... publicConfig.js:get").
    const [
      billing,
      donationState,
      storedDonationHistory,
      userCounts,
      firstMirror,
      publicModes,
      referralCfg,
      theme,
      verification,
      site,
      analyticsCfg,
      locations,
      clientsCatalog,
    ] = await Promise.all([
      // Public-safe billing catalog: prices, durations, which rails are live, and
      // the tier slug the membership maps to. No secrets (API keys/IPN secrets are
      // env-only). The SPA gates the upgrade UI on `billing.enabled` + `rails.*`.
      resolveBillingConfig(ctx.db),
      // Live shared donation bonus (GB) on every free user's monthly cap this month.
      readDonationState(ctx.db),
      readDonationHistory(ctx.db),
      readUserCounts(ctx.db),
      // Is the opt-in "trouble connecting? try a mirror" affordance available? Only
      // a boolean (≥1 active mirror provider) — no provider details/secrets. Lets the
      // SPA hide the affordance entirely on a dormant deployment.
      ctx.db
        .query('mirrorProviders')
        .withIndex('by_active', (q) => q.eq('isActive', true))
        .first(),
      // Resolved once: the family list is derived from it (a family with no visible
      // child is itself hidden), so the two must be computed from the same snapshot.
      resolvePublicModes(ctx.db),
      resolveReferralConfig(ctx.db),
      resolveTheme(ctx.db),
      resolveVerification(ctx.db),
      resolveSiteConfig(ctx.db),
      resolveAnalyticsConfig(ctx.db),
      resolveLocations(ctx.db),
      resolveClients(ctx.db),
    ]);
    const mirrorsEnabled = firstMirror !== null;
    const { modes: modeProjection, catalog: modeCatalog } = publicModes;

    const currentBonusGb = billing.donation.enabled
      ? effectiveBonusGb(donationState, billing.donation, Date.now())
      : 0;
    // Public impact projection: monthly GB-added ledger + the free-user count —
    // GB and user counts ONLY, never dollar amounts (revenue stays private).
    // The current month is synthesized from the live accumulator so the graph is
    // fresh even before the next donation upserts the stored ledger entry.
    let donationHistory: { month: string; bonusGb: number }[] = [];
    if (billing.donation.enabled) {
      const mk = currentMonthKey(Date.now());
      const stored = storedDonationHistory
        .filter((h) => h.monthKey !== mk)
        .map((h) => ({ month: h.monthKey, bonusGb: h.bonusGb }));
      // This month's own raise, matching what the ledger will freeze for it — NOT
      // the live pool, which can still hold last month's money now that a
      // donation's window runs 30 days rather than to the month's end.
      const thisMonthCents = donationState.monthKey === mk ? donationState.donatedCents : 0;
      const thisMonthGb = bonusGbFromCents(thisMonthCents, billing.donation);
      // Skip the synthesized entry on a deployment with no impact yet (empty
      // ledger + nothing this month) so the SPA's non-empty gate stays honest.
      const hasCurrent = currentBonusGb > 0 || thisMonthCents > 0;
      donationHistory =
        stored.length > 0 || hasCurrent
          ? [...stored, { month: mk, bonusGb: thisMonthGb }].slice(-12)
          : [];
    }

    return {
      membersJoinUrl: process.env.MEMBERS_JOIN_URL || undefined,
      membersAccountUrl: process.env.MEMBERS_ACCOUNT_URL || undefined,
      donateUrl: process.env.DONATE_URL || undefined,
      contactUrl: process.env.CONTACT_URL || undefined,
      // W1: self-hosted Cap. `apiEndpoint` is the SAME-ORIGIN path the browser
      // widget hits (Caddy proxies /cap → the Cap service), so challenge traffic
      // stays inside `connect-src 'self'`. `siteKey` is public.
      captcha: {
        apiEndpoint: process.env.CAP_PUBLIC_ENDPOINT || '/cap',
        siteKey: process.env.CAP_SITE_KEY ?? '',
      },
      // The deployment environment string is masked to 'production' outside
      // development (nothing in the SPA consumes it at runtime, and the raw
      // value is minor deployment-tier fingerprinting). Kept required in the
      // contract for older clients; genuinely 'development' only when set.
      environment: environment === 'development' ? environment : 'production',
      tiers,
      freeTierDays: settings['freetier.expiryDays'] as number,
      backends: {
        // Legacy per-id flags kept one release for cached SPAs; `list` is the
        // N-backend projection new clients consume.
        remnawaveEnabled: settings['remnawave.enabled'] as boolean,
        outlineEnabled: settings['outline.enabled'] as boolean,
        defaultBackend: settings['subscription.default_backend'] as BackendId,
        userChoiceEnabled: settings['subscription.user_choice_enabled'] as boolean,
        labels,
        list: BACKEND_IDS.map((id) => ({
          id,
          label: labels[id] ?? id,
          enabled: settings[`${id}.enabled`] === true,
          // Member-safe capability subset: drives device-limit UI gating and
          // the access-key-vs-subscription delivery chrome. Never the full
          // server-side record.
          capabilities: {
            devices: CAPABILITIES[id].deviceManagement,
            accessKeyOnly: CAPABILITIES[id].accessKeyDelivery,
            // Can a member be moved to a different server at all? Needs at least
            // one lever — a placement to re-point, or a node pin to rotate. A
            // backend with neither (Outline) would show a control that could
            // only ever fail, so the SPA hides it.
            switchServer: CAPABILITIES[id].placement || CAPABILITIES[id].nodePinning,
          },
        })),
      },
      billing: {
        enabled: billing.enabled,
        rails: billing.rails,
        currency: billing.currency,
        tierSlug: billing.tierSlug,
        durations: billing.durations,
        cryptoMinMonths: billing.cryptoMinMonths,
        btcpayMinMonths: billing.btcpayMinMonths,
        donation: {
          enabled: billing.donation.enabled,
          suggestedAmountsCents: billing.donation.suggestedAmountsCents,
          // NO per-amount GB map: bonusGb = cents × bonusGbPerUsd, so shipping it
          // disclosed the raw rate — and with currentBonusGb + history also
          // public, the month's donation REVENUE became exactly derivable
          // (defeating the GB-only posture). Amounts only; the rate stays
          // server-side. (Review B-F3.)
          minAmountCents: billing.donation.minAmountCents,
          monthlyBonusCapGb: billing.donation.monthlyBonusCapGb,
          // How long a gift keeps funding the pool — non-secret, and the donate
          // copy needs it to say what a donation actually buys.
          bonusWindowDays: billing.donation.bonusWindowDays,
          currentBonusGb,
          // Active free users the shared bonus reaches (daily-reconciled
          // counter) — rounded DOWN to the nearest 10 so the public bootstrap
          // doesn't carry an exact live fleet-size signal (the /status page
          // bands load for the same reason).
          freeUsersHelped: Math.floor(userCounts.freeActive / 10) * 10,
          // Per-month bonus-GB ledger (last 12; GB only — no dollar amounts).
          history: donationHistory,
          // Month-to-date cumulative bonus-GB series (one value per UTC day,
          // 1st → today) for the impact graph. Same GB-only posture: the
          // conversion rate stays server-side, so per-day dollars remain
          // underivable, exactly like `currentBonusGb`.
          currentMonthDaily: billing.donation.enabled
            ? currentMonthDailyGb(donationState, billing.donation, Date.now())
            : [],
        },
      },
      mirrorsEnabled,
      // Referral-program knobs (enabled + the bonus-days numbers for the
      // signup/account copy). Non-secret; drives the referral surfaces.
      referrals: {
        enabled: referralCfg.enabled,
        refereeBonusDays: referralCfg.refereeBonusDays,
        referrerBonusDays: referralCfg.referrerBonusDays,
        vestingDays: referralCfg.vestingDays,
      },
      // Device-limit enforcement master switch (non-secret). When false the SPA
      // hides device-limit UI + app-compatibility gating (unlimited-by-default).
      devices: {
        enforcementEnabled: settings['devices.enforcementEnabled'] as boolean,
      },
      // Admin-selected brand theme (preset + optional hue), applied client-side
      // over the baked default. Non-secret; always present (fail-safe default).
      theme,
      // Admin-configured E2EE verification channels (non-secret): which off-CDN
      // channels the "Verify connection" panel shows, and whether to surface the
      // whole E2EE badge/panel at all. The panel renders only the set channels.
      verification,
      // Admin-configured site chrome (non-secret): the announcement banner (toggle
      // + text) and the footer "View source" repo link (toggle + https URL). Both
      // resolve to safe defaults (off/empty) until the operator sets them.
      site,
      // Analytics relay: ONLY the effective on/off bit (toggle AND configured).
      // The Umami host + website id are server-side-only — publicAnalytics's
      // narrow return type is the structural guarantee they can't leak here.
      analytics: publicAnalytics(analyticsCfg),
      // Member-facing connection-mode catalog: the PARENT families a member picks
      // first, plus their transport sub-choices (id + family + label + description
      // + deliveryStyle + isDefault + available = enabled AND placement pool
      // bound). Admin-disabled entries are omitted entirely. NEVER a squad UUID.
      connectionModes: modeProjection,
      connectionModeFamilies: publicFamilyProjection(modeCatalog.families, modeProjection),
      // Member-facing node-location catalog (active Remnawave instances with a
      // location set): code + display label + a coarse online bit. Never a URL
      // or credential. Drives the location picker at issuance; the SPA hides
      // the picker when fewer than two locations exist.
      locations,
      // Member-facing recommended-client catalog (CMS-managed `clients` table, or
      // the compiled defaults when unseeded). Public-safe: names, platforms, install
      // links, hwid flag, and the import scheme id (the SPA maps it to a deep-link
      // builder). No secrets. Drives the single "set up your app" section.
      clients: publicClients(clientsCatalog),
    };
  },
});
