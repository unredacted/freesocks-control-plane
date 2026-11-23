/**
 * The declared shape of `publicConfig.get`, the ONLY public Convex function
 * (anyone who reaches the deploy port can call it, and `/api/v1/config` serves
 * it to every visitor).
 *
 * Convex checks the return value against this validator on every call and
 * rejects any field not listed here, so a value added to the projection (or a
 * nested resolver that starts returning a new field) fails loudly instead of
 * shipping to the public bootstrap unreviewed. Adding a public field therefore
 * means adding it here AND to `PublicConfig` in src/shared/contracts/auth.ts;
 * `publicConfigReturns.test.ts` keeps the two key sets identical.
 */
import { v } from 'convex/values';
import { MIRROR_FORMATS } from '../../src/shared/mirrorFormats';
import { backendIdValidator } from './backendIds';
import { THEME_PRESET_IDS } from './themeConfig';

const literals = <T extends string>(values: readonly T[]) =>
  v.union(...values.map((x) => v.literal(x)));

const tierFeature = v.object({
  // As loose as the schema (tiers.features): a stored preset the current list
  // no longer names must not take the public bootstrap down.
  preset: v.union(v.string(), v.null()),
  iconId: v.string(),
  label: v.union(v.string(), v.null()),
});

const siteImageRef = v.object({ version: v.string(), width: v.number(), height: v.number() });

export const publicConfigReturns = v.object({
  membersJoinUrl: v.optional(v.string()),
  membersAccountUrl: v.optional(v.string()),
  donateUrl: v.optional(v.string()),
  contactUrl: v.optional(v.string()),
  captcha: v.object({ apiEndpoint: v.string(), siteKey: v.string() }),
  environment: v.union(v.literal('production'), v.literal('development')),
  tiers: v.array(
    v.object({
      slug: v.string(),
      name: v.string(),
      description: v.union(v.string(), v.null()),
      monthlyTrafficGb: v.number(),
      deviceLimit: v.number(),
      features: v.array(tierFeature),
    }),
  ),
  freeTierDays: v.number(),
  backends: v.object({
    remnawaveEnabled: v.boolean(),
    outlineEnabled: v.boolean(),
    defaultBackend: backendIdValidator,
    userChoiceEnabled: v.boolean(),
    labels: v.object({ remnawave: v.string(), outline: v.string() }),
    list: v.array(
      v.object({
        id: backendIdValidator,
        label: v.string(),
        enabled: v.boolean(),
        capabilities: v.object({
          devices: v.boolean(),
          accessKeyOnly: v.boolean(),
          switchServer: v.boolean(),
        }),
      }),
    ),
  }),
  billing: v.object({
    enabled: v.boolean(),
    rails: v.object({
      nowpayments: v.boolean(),
      btcpay: v.boolean(),
      stripe: v.boolean(),
      paypal: v.boolean(),
    }),
    currency: v.string(),
    tierSlug: v.string(),
    durations: v.array(v.object({ months: v.number(), amountCents: v.number() })),
    cryptoMinMonths: v.number(),
    btcpayMinMonths: v.number(),
    direct: v.object({
      nowpayments: v.object({ enabled: v.boolean() }),
      btcpay: v.object({ enabled: v.boolean() }),
    }),
    donation: v.object({
      enabled: v.boolean(),
      suggestedAmountsCents: v.array(v.number()),
      minAmountCents: v.number(),
      monthlyBonusCapGb: v.number(),
      bonusWindowDays: v.number(),
      currentBonusGb: v.number(),
      freeUsersHelped: v.number(),
      history: v.array(v.object({ month: v.string(), bonusGb: v.number() })),
      currentMonthDaily: v.array(v.number()),
      recentGifts: v.array(v.object({ day: v.string(), gb: v.number(), expiresAt: v.number() })),
    }),
  }),
  mirrorsEnabled: v.boolean(),
  countryQuestion: v.boolean(),
  referrals: v.object({
    enabled: v.boolean(),
    refereeBonusDays: v.number(),
    referrerBonusDays: v.number(),
    vestingDays: v.number(),
  }),
  devices: v.object({ enforcementEnabled: v.boolean() }),
  theme: v.object({ preset: literals(THEME_PRESET_IDS), hue: v.union(v.number(), v.null()) }),
  verification: v.object({
    showPanel: v.boolean(),
    releaseUrl: v.string(),
    onionAddress: v.string(),
    sourceUrl: v.string(),
    extensionUrl: v.string(),
  }),
  site: v.object({
    bannerEnabled: v.boolean(),
    bannerText: v.string(),
    bannerLinkUrl: v.string(),
    bannerLinkLabel: v.string(),
    repoEnabled: v.boolean(),
    repoUrl: v.string(),
    tosUrl: v.string(),
    privacyUrl: v.string(),
    transparencyUrl: v.string(),
    socialXUrl: v.string(),
    socialMastodonUrl: v.string(),
    socialBlueskyUrl: v.string(),
    supportEmail: v.string(),
    heroTitle: v.string(),
    heroSubtitle: v.string(),
    heroTitles: v.array(v.string()),
    homeImage: v.union(siteImageRef, v.null()),
  }),
  analytics: v.object({ enabled: v.boolean() }),
  telegram: v.union(v.object({ botUsername: v.string() }), v.null()),
  connectionModes: v.array(
    v.object({
      id: v.string(),
      family: v.string(),
      deliveryStyle: v.union(v.literal('url'), v.literal('rawConfig')),
      label: v.union(v.string(), v.null()),
      description: v.union(v.string(), v.null()),
      isDefault: v.boolean(),
      isFamilyDefault: v.boolean(),
      availableBackends: v.array(backendIdValidator),
      available: v.boolean(),
    }),
  ),
  connectionModeFamilies: v.array(
    v.object({
      id: v.string(),
      label: v.union(v.string(), v.null()),
      description: v.union(v.string(), v.null()),
      audience: v.union(v.string(), v.null()),
      iconId: v.string(),
    }),
  ),
  locations: v.array(
    v.object({
      code: v.string(),
      label: v.string(),
      online: v.boolean(),
      load: v.union(
        v.literal('quiet'),
        v.literal('busy'),
        v.literal('crowded'),
        v.literal('unknown'),
      ),
      coords: v.union(v.object({ lat: v.number(), lng: v.number() }), v.null()),
    }),
  ),
  clients: v.array(
    v.object({
      name: v.string(),
      platforms: v.array(v.string()),
      backends: v.array(backendIdValidator),
      homepageUrl: v.string(),
      schemeId: v.union(v.string(), v.null()),
      hwid: v.boolean(),
      openSource: v.boolean(),
      license: v.optional(v.string()),
      sourceUrl: v.optional(v.string()),
      easeOfUse: v.optional(
        v.union(v.literal('easy'), v.literal('moderate'), v.literal('advanced')),
      ),
      ipv6: v.optional(v.boolean()),
      xhttp: v.optional(v.boolean()),
      hysteria2: v.optional(v.boolean()),
      description: v.optional(v.string()),
      format: literals(MIRROR_FORMATS),
    }),
  ),
});
