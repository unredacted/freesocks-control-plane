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
import { resolveTheme } from './lib/themeConfig';
import { resolveVerification } from './lib/verificationConfig';
import { resolveSiteConfig } from './lib/siteConfig';
import { resolveConnectionModes, publicProjection } from './lib/connectionModes';
import { resolveBoundModeIds } from './lib/remnawavePlacement';
import { resolveClients, publicClients } from './lib/clientCatalog';

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

    // Public-safe billing catalog: prices, durations, which rails are live, and
    // the tier slug the membership maps to. No secrets (API keys/IPN secrets are
    // env-only). The SPA gates the upgrade UI on `billing.enabled` + `rails.*`.
    const billing = await resolveBillingConfig(ctx.db);

    // Is the opt-in "trouble connecting? try a mirror" affordance available? Only
    // a boolean (≥1 active mirror provider) — no provider details/secrets. Lets the
    // SPA hide the affordance entirely on a dormant deployment.
    const mirrorsEnabled =
      (await ctx.db
        .query('mirrorProviders')
        .withIndex('by_active', (q) => q.eq('isActive', true))
        .first()) !== null;

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
      environment,
      tiers,
      freeTierDays: settings['freetier.expiryDays'] as number,
      backends: {
        remnawaveEnabled: settings['remnawave.enabled'] as boolean,
        outlineEnabled: settings['outline.enabled'] as boolean,
        defaultBackend: settings['subscription.default_backend'] as 'remnawave' | 'outline',
        userChoiceEnabled: settings['subscription.user_choice_enabled'] as boolean,
        labels,
      },
      billing: {
        enabled: billing.enabled,
        rails: billing.rails,
        currency: billing.currency,
        tierSlug: billing.tierSlug,
        durations: billing.durations,
        cryptoMinMonths: billing.cryptoMinMonths,
      },
      mirrorsEnabled,
      // Device-limit enforcement master switch (non-secret). When false the SPA
      // hides device-limit UI + app-compatibility gating (unlimited-by-default).
      devices: {
        enforcementEnabled: settings['devices.enforcementEnabled'] as boolean,
      },
      // Admin-selected brand theme (preset + optional hue), applied client-side
      // over the baked default. Non-secret; always present (fail-safe default).
      theme: await resolveTheme(ctx.db),
      // Admin-configured E2EE verification channels (non-secret): which off-CDN
      // channels the "Verify connection" panel shows, and whether to surface the
      // whole E2EE badge/panel at all. The panel renders only the set channels.
      verification: await resolveVerification(ctx.db),
      // Admin-configured site chrome (non-secret): the announcement banner (toggle
      // + text) and the footer "View source" repo link (toggle + https URL). Both
      // resolve to safe defaults (off/empty) until the operator sets them.
      site: await resolveSiteConfig(ctx.db),
      // Member-facing connection-mode catalog (id + label + description +
      // deliveryStyle + isDefault + available = placement pool bound). NEVER a
      // squad UUID. Drives the transport chooser + its delivery behavior.
      connectionModes: publicProjection(
        await resolveConnectionModes(ctx.db),
        await resolveBoundModeIds(ctx.db),
      ),
      // Member-facing recommended-client catalog (CMS-managed `clients` table, or
      // the compiled defaults when unseeded). Public-safe: names, platforms, install
      // links, hwid flag, and the import scheme id (the SPA maps it to a deep-link
      // builder). No secrets. Drives the single "set up your app" section.
      clients: publicClients(await resolveClients(ctx.db)),
    };
  },
});
