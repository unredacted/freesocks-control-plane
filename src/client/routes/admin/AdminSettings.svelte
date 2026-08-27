<script lang="ts">
  import { z } from 'zod';
  import AdminLayout from './AdminLayout.svelte';
  import {
    Card,
    CardHeader,
    CardTitle,
    CardDescription,
    CardContent,
  } from '@client/components/ui/card';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Checkbox } from '@client/components/ui/checkbox';
  import * as Select from '@client/components/ui/select';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import { ADMIN_BACKEND_LABELS } from '../../lib/backendLabels';
  import AdminListState from './AdminListState.svelte';
  import { adminAnalyticsQuery, appSettingsQuery, configQuery, queryKeys } from '../../lib/queries';
  import Link from '../../components/Link.svelte';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { AdminAnalyticsConfig, AppSettingsRecord } from '../../../shared/contracts/admin';
  import { toast } from 'svelte-sonner';

  /**
   * Settings page. Renders one form for every known setting with a
   * type-appropriate control (toggle, select, text, number). On save, sends
   * the full edited bag in one PATCH so the admin can change multiple
   * settings atomically.
   *
   * Adding a new setting:
   *   1. Add it to `SETTINGS_DEFAULTS` in `convex/appSettings.ts` (the keyset
   *      allowlist the admin PATCH route validates against).
   *   2. Add a row below in `FIELDS` describing how to render it.
   * The PATCH handler rejects any key not in `SETTINGS_DEFAULTS`, so a UI bug
   * can't persist an unknown setting.
   */

  const settings = appSettingsQuery();
  const qc = useQueryClient();

  // Local working copy of the settings bag: we don't want to drop the user's
  // edits if the underlying query refetches in the background.
  let draft = $state<Record<string, unknown>>({});
  let initialized = $state(false);
  // Free-text mirror of the privacyCountries array so typing (incl. spaces) isn't
  // reflowed by re-joining; parsed back into `draft` as a normalized array on input.
  let privacyCountriesText = $state('');

  $effect(() => {
    if (settings.data && !initialized) {
      draft = { ...settings.data };
      privacyCountriesText = (
        (settings.data['delivery.privacyCountries'] as string[] | undefined) ?? []
      ).join(' ');
      initialized = true;
    }
  });

  const save = createMutation(() => ({
    mutationFn: async () => {
      const SaveResponse = z.object({ settings: AppSettingsRecord });
      const result = await apiClient.patch('/api/v1/admin/settings', draft, SaveResponse);
      return result.settings;
    },
    onSuccess: (updated) => {
      draft = { ...updated };
      void qc.invalidateQueries({ queryKey: queryKeys.adminSettings });
      // Settings feed the public /api/v1/config (backend toggles, default, labels)
      // - refresh it too so member tabs in this browser don't serve stale config.
      void qc.invalidateQueries({ queryKey: queryKeys.config });
      toast.success('Settings saved');
    },
    onError: (err) => {
      toast.error('Could not save settings', { description: apiErrorMessage(err) });
    },
  }));

  // E2EE verification config lives in its own namespace (publicConfig.verification),
  // not the settings bag, so it has its own draft + save (mirrors the theme page).
  // Server sanitizes each URL (https-only / .onion) and returns the cleaned values.
  const cfg = configQuery();
  let vDraft = $state<{
    showPanel: boolean;
    releaseUrl: string;
    onionAddress: string;
    sourceUrl: string;
    extensionUrl: string;
  }>({ showPanel: true, releaseUrl: '', onionAddress: '', sourceUrl: '', extensionUrl: '' });
  let vInit = $state(false);
  $effect(() => {
    const v = cfg.data?.verification;
    if (v && !vInit) {
      vDraft = {
        showPanel: v.showPanel,
        releaseUrl: v.releaseUrl,
        onionAddress: v.onionAddress,
        sourceUrl: v.sourceUrl,
        extensionUrl: v.extensionUrl,
      };
      vInit = true;
    }
  });
  const saveVerification = createMutation(() => ({
    mutationFn: async () => {
      const Resp = z.object({
        showPanel: z.boolean(),
        releaseUrl: z.string(),
        onionAddress: z.string(),
        sourceUrl: z.string(),
        extensionUrl: z.string(),
      });
      return apiClient.patch('/api/v1/admin/verification', vDraft, Resp);
    },
    onSuccess: (updated) => {
      vDraft = { ...updated };
      void qc.invalidateQueries({ queryKey: queryKeys.config });
      toast.success('Verification settings saved');
    },
    onError: (err) => {
      toast.error('Could not save verification settings', { description: apiErrorMessage(err) });
    },
  }));

  // Site chrome (announcement banner + footer repo link) lives in its own namespace
  // (publicConfig.site), like verification - own draft + save. The server sanitizes
  // the banner text (trim/cap) and the repo URL (https-only) and echoes the cleaned
  // values back.
  let sDraft = $state<{
    bannerEnabled: boolean;
    bannerText: string;
    bannerLinkUrl: string;
    bannerLinkLabel: string;
    repoEnabled: boolean;
    repoUrl: string;
    tosUrl: string;
    privacyUrl: string;
    transparencyUrl: string;
    socialXUrl: string;
    socialMastodonUrl: string;
    socialBlueskyUrl: string;
    supportEmail: string;
    heroTitle: string;
    heroSubtitle: string;
    heroTitles: string;
  }>({
    bannerEnabled: false,
    bannerText: '',
    bannerLinkUrl: '',
    bannerLinkLabel: '',
    repoEnabled: false,
    repoUrl: '',
    tosUrl: '',
    privacyUrl: '',
    transparencyUrl: '',
    socialXUrl: '',
    socialMastodonUrl: '',
    socialBlueskyUrl: '',
    supportEmail: '',
    heroTitle: '',
    heroSubtitle: '',
    heroTitles: '',
  });
  // Placeholders = the ACTUAL built-in (English) defaults the SPA falls back to
  // when these overrides are blank, so the operator sees what "blank" means.
  // Keep in sync with messages/en.json `home.hero.*` (the admin CMS is
  // deliberately English-only). A JS string, not an &#10; entity, so the
  // textarea placeholder really renders one title per line.
  const HERO_TITLE_DEFAULT = 'A VPN for Freedom';
  const HERO_TITLES_DEFAULT = [
    'A VPN for Freedom',
    'A VPN for dissidents',
    'A VPN for privacy',
    'A VPN for the world',
  ].join('\n');
  const HERO_SUBTITLE_DEFAULT =
    'FreeSocks is built to defeat Internet censorship. No email or password is required to sign up, just an account ID. Your subscription URL works in most VPN clients, and memberships come with {limits}.';
  let sInit = $state(false);
  $effect(() => {
    const s = cfg.data?.site;
    if (s && !sInit) {
      sDraft = {
        bannerEnabled: s.bannerEnabled,
        bannerText: s.bannerText,
        bannerLinkUrl: s.bannerLinkUrl,
        bannerLinkLabel: s.bannerLinkLabel,
        repoEnabled: s.repoEnabled,
        repoUrl: s.repoUrl,
        tosUrl: s.tosUrl,
        privacyUrl: s.privacyUrl,
        transparencyUrl: s.transparencyUrl,
        socialXUrl: s.socialXUrl,
        socialMastodonUrl: s.socialMastodonUrl,
        socialBlueskyUrl: s.socialBlueskyUrl,
        supportEmail: s.supportEmail,
        heroTitle: s.heroTitle,
        heroSubtitle: s.heroSubtitle,
        heroTitles: (s.heroTitles ?? []).join('\n'),
      };
      sInit = true;
    }
  });
  const saveSite = createMutation(() => ({
    mutationFn: async () => {
      const Resp = z.object({
        bannerEnabled: z.boolean(),
        bannerText: z.string(),
        bannerLinkUrl: z.string(),
        bannerLinkLabel: z.string(),
        repoEnabled: z.boolean(),
        repoUrl: z.string(),
        tosUrl: z.string(),
        privacyUrl: z.string(),
        transparencyUrl: z.string(),
        socialXUrl: z.string(),
        socialMastodonUrl: z.string(),
        socialBlueskyUrl: z.string(),
        supportEmail: z.string(),
        heroTitle: z.string(),
        heroSubtitle: z.string(),
        heroTitles: z.array(z.string()),
      });
      return apiClient.patch(
        '/api/v1/admin/site',
        { ...sDraft, heroTitles: sDraft.heroTitles.split('\n') },
        Resp,
      );
    },
    onSuccess: (updated) => {
      sDraft = { ...updated, heroTitles: updated.heroTitles.join('\n') };
      void qc.invalidateQueries({ queryKey: queryKeys.config });
      toast.success('Site settings saved');
    },
    onError: (err) => {
      toast.error('Could not save site settings', { description: apiErrorMessage(err) });
    },
  }));

  // Analytics relay (self-hosted Umami): its own namespace + own admin GET —
  // the Umami URL/website id are deliberately NOT in the public /api/v1/config
  // (only the enabled bit is), so current values come from adminAnalyticsQuery,
  // not configQuery. The server sanitizes (https-only URL, UUID id) and echoes
  // the cleaned values back.
  const analytics = adminAnalyticsQuery();
  let aDraft = $state<{
    enabled: boolean;
    umamiUrl: string;
    websiteId: string;
    forwardIp: boolean;
    ipHeader: string;
    geoMode: 'full' | 'coarse';
  }>({
    enabled: false,
    umamiUrl: '',
    websiteId: '',
    forwardIp: false,
    ipHeader: '',
    geoMode: 'full',
  });
  let aInit = $state(false);
  $effect(() => {
    if (analytics.data && !aInit) {
      aDraft = { ...analytics.data };
      aInit = true;
    }
  });

  // The IP-source select maps well-known CDN headers to friendly labels;
  // anything else stored in ipHeader renders as the "Custom header" choice.
  const IP_SOURCES = [
    { value: '', label: 'Resolved client IP (default)' },
    { value: 'cf-connecting-ip', label: 'Cloudflare (cf-connecting-ip)' },
    { value: 'fastly-client-ip', label: 'Fastly (fastly-client-ip)' },
    { value: 'custom', label: 'Custom header…' },
  ];
  let ipSourceChoice = $derived(
    IP_SOURCES.some((s) => s.value === aDraft.ipHeader && s.value !== 'custom')
      ? aDraft.ipHeader
      : 'custom',
  );
  // Keeps the custom text box populated while switching between choices.
  let customIpHeader = $state('');
  $effect(() => {
    if (aInit && ipSourceChoice === 'custom' && customIpHeader === '' && aDraft.ipHeader !== '') {
      customIpHeader = aDraft.ipHeader;
    }
  });
  function pickIpSource(v: string) {
    if (v === 'custom') {
      aDraft = { ...aDraft, ipHeader: customIpHeader || 'x-real-ip' };
      customIpHeader = aDraft.ipHeader;
    } else {
      aDraft = { ...aDraft, ipHeader: v };
    }
  }
  const saveAnalytics = createMutation(() => ({
    mutationFn: async () => {
      return apiClient.patch('/api/v1/admin/analytics', aDraft, AdminAnalyticsConfig);
    },
    onSuccess: (updated) => {
      aDraft = { ...updated };
      void qc.invalidateQueries({ queryKey: queryKeys.adminAnalytics });
      // The enabled bit feeds the public /api/v1/config (the SPA's beacon gate).
      void qc.invalidateQueries({ queryKey: queryKeys.config });
      toast.success('Analytics settings saved');
    },
    onError: (err) => {
      toast.error('Could not save analytics settings', { description: apiErrorMessage(err) });
    },
  }));
</script>

<AdminLayout>
  <h1 class="text-2xl font-bold mb-2">Settings</h1>
  <p class="text-sm text-muted-foreground mb-6">
    Runtime configuration. Changes apply immediately; cache invalidates within seconds.
  </p>

  {#if settings.isPending}
    <div class="space-y-4">
      {#each Array(4) as _, i (i)}
        <Card><CardHeader><Skeleton class="h-5 w-64" /></CardHeader></Card>
      {/each}
    </div>
  {:else if settings.isError}
    <AdminListState error={settings.error} />
  {:else}
    <div class="space-y-4 max-w-2xl">
      <!-- Backend availability toggles -->
      <Card>
        <CardHeader>
          <CardTitle class="text-base">Backend availability</CardTitle>
          <CardDescription>
            Master switches for each proxy backend. Disabling a backend hides it from the
            /get-account chooser and rejects new issuance against it.
          </CardDescription>
        </CardHeader>
        <CardContent class="space-y-3 text-sm">
          <label class="flex items-center gap-3">
            <Checkbox
              checked={draft['remnawave.enabled'] === true}
              onCheckedChange={(v) => (draft = { ...draft, 'remnawave.enabled': v === true })}
            />
            <span>Remnawave enabled</span>
          </label>
          <label class="flex items-center gap-3">
            <Checkbox
              checked={draft['outline.enabled'] === true}
              onCheckedChange={(v) => (draft = { ...draft, 'outline.enabled': v === true })}
            />
            <span>Outline enabled</span>
          </label>
        </CardContent>
      </Card>

      <!-- Device (HWID) limits -->
      <Card>
        <CardHeader>
          <CardTitle class="text-base">Device limits</CardTitle>
          <CardDescription>
            Master switch for per-tier device (HWID) limits. When OFF (the default), every user is
            effectively unlimited and the device UI is hidden. When ON, each tier's device limit
            applies and the connect screen steers members to HWID-capable apps.
            <strong class="text-foreground">
              Enforcement also requires HWID_DEVICE_LIMIT_ENABLED=true on the Remnawave panel</strong
            >
            - FCP can't read or set that panel setting. Set the per-tier limit under Tiers.
          </CardDescription>
        </CardHeader>
        <CardContent class="text-sm">
          <label class="flex items-center gap-3">
            <Checkbox
              checked={draft['devices.enforcementEnabled'] === true}
              onCheckedChange={(v) =>
                (draft = { ...draft, 'devices.enforcementEnabled': v === true })}
            />
            <span>Enforce per-tier device limits</span>
          </label>
        </CardContent>
      </Card>

      <!-- End-user backend choice -->
      <Card>
        <CardHeader>
          <CardTitle class="text-base">End-user backend choice</CardTitle>
          <CardDescription>
            Controls whether anonymous + member users can choose between backends, and which backend
            they get if they don't choose.
          </CardDescription>
        </CardHeader>
        <CardContent class="space-y-3 text-sm">
          <label class="flex items-center gap-3">
            <Checkbox
              checked={draft['subscription.user_choice_enabled'] === true}
              onCheckedChange={(v) =>
                (draft = { ...draft, 'subscription.user_choice_enabled': v === true })}
            />
            <span>Show backend chooser on /get-account and /account</span>
          </label>
          <div class="space-y-1.5">
            <label
              class="text-xs uppercase tracking-wider text-muted-foreground font-semibold block"
              for="default-backend"
            >
              Default backend
            </label>
            <Select.Root
              type="single"
              value={String(draft['subscription.default_backend'] ?? 'remnawave')}
              onValueChange={(v) => (draft = { ...draft, 'subscription.default_backend': v })}
            >
              <Select.Trigger class="w-48">
                {draft['subscription.default_backend'] === 'outline'
                  ? ADMIN_BACKEND_LABELS.outline
                  : ADMIN_BACKEND_LABELS.remnawave}
              </Select.Trigger>
              <Select.Content>
                <Select.Item value="remnawave">{ADMIN_BACKEND_LABELS.remnawave}</Select.Item>
                <Select.Item value="outline">{ADMIN_BACKEND_LABELS.outline}</Select.Item>
              </Select.Content>
            </Select.Root>
          </div>
        </CardContent>
      </Card>

      <!-- Backend labels (admin-editable display names) -->
      <Card>
        <CardHeader>
          <CardTitle class="text-base">Backend labels</CardTitle>
          <CardDescription>
            Display names shown to end users in the chooser. Defaults are the bare provider names;
            admins can rename to whatever fits the deployment.
          </CardDescription>
        </CardHeader>
        <CardContent class="space-y-3 text-sm">
          {@const labels =
            (draft['subscription.backend_labels'] as { remnawave?: string; outline?: string }) ??
            {}}
          <div>
            <label class="text-xs text-muted-foreground mb-1 block" for="lbl-remnawave">
              Remnawave label
            </label>
            <Input
              value={labels.remnawave ?? ''}
              oninput={(e) => {
                const v = (e.target as HTMLInputElement).value;
                draft = {
                  ...draft,
                  'subscription.backend_labels': {
                    remnawave: v,
                    outline: labels.outline ?? 'Outline',
                  },
                };
              }}
            />
          </div>
          <div>
            <label class="text-xs text-muted-foreground mb-1 block" for="lbl-outline">
              Outline label
            </label>
            <Input
              value={labels.outline ?? ''}
              oninput={(e) => {
                const v = (e.target as HTMLInputElement).value;
                draft = {
                  ...draft,
                  'subscription.backend_labels': {
                    remnawave: labels.remnawave ?? 'Remnawave',
                    outline: v,
                  },
                };
              }}
            />
          </div>
        </CardContent>
      </Card>

      <!-- Free accounts -->
      <Card>
        <CardHeader>
          <CardTitle class="text-base">Free accounts</CardTitle>
          <CardDescription>
            The idle window: a free account with no VPN activity for this many days is deactivated
            by the daily sweep (key reclaimed; the account reactivates on sign-in). Actively-used
            keys are refreshed automatically and never expire.
          </CardDescription>
        </CardHeader>
        <CardContent class="space-y-3 text-sm">
          <div>
            <label class="text-xs text-muted-foreground mb-1 block" for="free-expiry-days">
              Idle window (days)
            </label>
            <Input
              id="free-expiry-days"
              type="number"
              min={1}
              class="w-32"
              value={Number(draft['freetier.expiryDays'] ?? 90)}
              oninput={(e) =>
                (draft = {
                  ...draft,
                  'freetier.expiryDays': Math.max(
                    1,
                    Math.round(Number((e.target as HTMLInputElement).value) || 90),
                  ),
                })}
            />
          </div>
        </CardContent>
      </Card>

      <!-- Subscription mirrors -->
      <Card>
        <CardHeader>
          <CardTitle class="text-base">Subscription mirrors</CardTitle>
          <CardDescription>
            Max S3 mirrors a member can add via the opt-in "trouble connecting?" flow. Mirror
            providers themselves are managed under Storage mirrors.
          </CardDescription>
        </CardHeader>
        <CardContent class="space-y-3 text-sm">
          <div>
            <label class="text-xs text-muted-foreground mb-1 block" for="mirror-max-per-user">
              Max mirrors per member
            </label>
            <Input
              id="mirror-max-per-user"
              type="number"
              min={0}
              class="w-32"
              value={Number(draft['mirror.maxPerUser'] ?? 3)}
              oninput={(e) =>
                (draft = {
                  ...draft,
                  'mirror.maxPerUser': Math.max(
                    0,
                    Math.round(Number((e.target as HTMLInputElement).value) || 0),
                  ),
                })}
            />
          </div>
        </CardContent>
      </Card>

      <!-- Delivery preference suggestion (country-based) -->
      <Card>
        <CardHeader>
          <CardTitle class="text-base">Delivery preference</CardTitle>
          <CardDescription>
            Countries (ISO 2-letter) where the picker suggests the censorship-recommended mode (see
            the Connection modes page) instead of the catalog default. Empty = always suggest the
            default. The member's actual choice is stored only on their device, never here.
          </CardDescription>
        </CardHeader>
        <CardContent class="space-y-3 text-sm">
          <div>
            <label class="text-xs text-muted-foreground mb-1 block" for="privacy-countries">
              Suggest privacy for these countries
            </label>
            <Input
              id="privacy-countries"
              placeholder="(none - always suggest stay-connected)"
              value={privacyCountriesText}
              oninput={(e) => {
                privacyCountriesText = (e.target as HTMLInputElement).value;
                draft = {
                  ...draft,
                  'delivery.privacyCountries': privacyCountriesText
                    .split(/[\s,]+/)
                    .map((c) => c.trim().toUpperCase())
                    .filter((c) => /^[A-Z]{2}$/.test(c)),
                };
              }}
            />
          </div>
        </CardContent>
      </Card>

      <div class="flex justify-end">
        <Button onclick={() => save.mutate()} disabled={save.isPending}>
          {save.isPending ? 'Saving…' : 'Save settings'}
        </Button>
      </div>

      <!-- HPKE verification (own namespace + own save) -->
      <Card>
        <CardHeader>
          <CardTitle class="text-base">HPKE encryption verification</CardTitle>
          <CardDescription>
            Controls the "HPKE" badge and its Verify panel. The links below are shown to users as
            out-of-band ways to confirm the app hasn't been tampered with; leave one blank to hide
            it. Turning the panel off hides the badge entirely (encryption still runs).
          </CardDescription>
        </CardHeader>
        <CardContent class="space-y-3 text-sm">
          <label class="flex items-center gap-3">
            <Checkbox
              checked={vDraft.showPanel}
              onCheckedChange={(v) => (vDraft = { ...vDraft, showPanel: v === true })}
            />
            <span>Show the HPKE badge and verify panel</span>
          </label>
          <div>
            <label class="text-xs text-muted-foreground mb-1 block" for="verify-release">
              Release / verification URL (https)
            </label>
            <Input
              id="verify-release"
              placeholder="https://github.com/org/repo/releases/latest"
              value={vDraft.releaseUrl}
              oninput={(e) =>
                (vDraft = { ...vDraft, releaseUrl: (e.target as HTMLInputElement).value })}
            />
          </div>
          <div>
            <label class="text-xs text-muted-foreground mb-1 block" for="verify-source">
              Source code URL (https)
            </label>
            <Input
              id="verify-source"
              placeholder="https://github.com/org/repo"
              value={vDraft.sourceUrl}
              oninput={(e) =>
                (vDraft = { ...vDraft, sourceUrl: (e.target as HTMLInputElement).value })}
            />
          </div>
          <div>
            <label class="text-xs text-muted-foreground mb-1 block" for="verify-onion">
              Tor .onion mirror (optional)
            </label>
            <Input
              id="verify-onion"
              placeholder="abcd…xyz.onion"
              value={vDraft.onionAddress}
              oninput={(e) =>
                (vDraft = { ...vDraft, onionAddress: (e.target as HTMLInputElement).value })}
            />
          </div>
          <div>
            <label class="text-xs text-muted-foreground mb-1 block" for="verify-extension">
              Verifier extension URL (https, optional)
            </label>
            <Input
              id="verify-extension"
              placeholder="https://chromewebstore.google.com/detail/…"
              value={vDraft.extensionUrl}
              oninput={(e) =>
                (vDraft = { ...vDraft, extensionUrl: (e.target as HTMLInputElement).value })}
            />
          </div>
          <div class="flex justify-end">
            {#if !vInit}
              <span class="me-3 self-center text-xs text-muted-foreground"
                >Loading current values…</span
              >
            {/if}
            <Button
              onclick={() => saveVerification.mutate()}
              disabled={saveVerification.isPending || !vInit}
            >
              {saveVerification.isPending ? 'Saving…' : 'Save verification'}
            </Button>
          </div>
        </CardContent>
      </Card>

      <!-- Site chrome: announcement banner + footer repo link (own namespace + own save) -->
      <Card>
        <CardHeader>
          <CardTitle class="text-base">Site banner & footer links</CardTitle>
          <CardDescription>
            A site-wide announcement banner shown to members (e.g. planned maintenance), and footer
            links: a "View source" repo link plus optional Terms of Service, Privacy Policy,
            Transparency Report, and social profile (X / Mastodon / Bluesky) links. All are optional
            and off/empty by default. Banner text is shown as-is in every language (not translated).
          </CardDescription>
        </CardHeader>
        <CardContent class="space-y-3 text-sm">
          <label class="flex items-center gap-3">
            <Checkbox
              checked={sDraft.bannerEnabled}
              onCheckedChange={(v) => (sDraft = { ...sDraft, bannerEnabled: v === true })}
            />
            <span>Show the announcement banner</span>
          </label>
          <div>
            <label class="text-xs text-muted-foreground mb-1 block" for="site-banner-text">
              Banner text
            </label>
            <Input
              id="site-banner-text"
              placeholder="e.g. Scheduled maintenance tonight 03:00–04:00 UTC"
              value={sDraft.bannerText}
              oninput={(e) =>
                (sDraft = { ...sDraft, bannerText: (e.target as HTMLInputElement).value })}
            />
          </div>
          <div class="grid gap-3 sm:grid-cols-2">
            <div>
              <label class="text-xs text-muted-foreground mb-1 block" for="site-banner-link-url">
                Banner link URL (https, optional)
              </label>
              <Input
                id="site-banner-link-url"
                placeholder="https://example.org/blog/announcement"
                value={sDraft.bannerLinkUrl}
                oninput={(e) =>
                  (sDraft = { ...sDraft, bannerLinkUrl: (e.target as HTMLInputElement).value })}
              />
            </div>
            <div>
              <label class="text-xs text-muted-foreground mb-1 block" for="site-banner-link-label">
                Banner link label
              </label>
              <Input
                id="site-banner-link-label"
                placeholder="e.g. Read the launch post"
                value={sDraft.bannerLinkLabel}
                oninput={(e) =>
                  (sDraft = { ...sDraft, bannerLinkLabel: (e.target as HTMLInputElement).value })}
              />
            </div>
          </div>
          <label class="flex items-center gap-3">
            <Checkbox
              checked={sDraft.repoEnabled}
              onCheckedChange={(v) => (sDraft = { ...sDraft, repoEnabled: v === true })}
            />
            <span>Show a "View source" link in the footer</span>
          </label>
          <div>
            <label class="text-xs text-muted-foreground mb-1 block" for="site-repo-url">
              Repository URL (https)
            </label>
            <Input
              id="site-repo-url"
              placeholder="https://github.com/org/repo"
              value={sDraft.repoUrl}
              oninput={(e) =>
                (sDraft = { ...sDraft, repoUrl: (e.target as HTMLInputElement).value })}
            />
          </div>
          <div>
            <label class="text-xs text-muted-foreground mb-1 block" for="site-tos-url">
              Terms of Service URL (https)
            </label>
            <Input
              id="site-tos-url"
              placeholder="https://example.org/terms"
              value={sDraft.tosUrl}
              oninput={(e) =>
                (sDraft = { ...sDraft, tosUrl: (e.target as HTMLInputElement).value })}
            />
          </div>
          <div>
            <label class="text-xs text-muted-foreground mb-1 block" for="site-privacy-url">
              Privacy Policy URL (https)
            </label>
            <Input
              id="site-privacy-url"
              placeholder="https://example.org/privacy"
              value={sDraft.privacyUrl}
              oninput={(e) =>
                (sDraft = { ...sDraft, privacyUrl: (e.target as HTMLInputElement).value })}
            />
          </div>
          <div>
            <label class="text-xs text-muted-foreground mb-1 block" for="site-transparency-url">
              Transparency Report URL (https)
            </label>
            <Input
              id="site-transparency-url"
              placeholder="https://example.org/transparency"
              value={sDraft.transparencyUrl}
              oninput={(e) =>
                (sDraft = { ...sDraft, transparencyUrl: (e.target as HTMLInputElement).value })}
            />
          </div>
          <div>
            <label class="text-xs text-muted-foreground mb-1 block" for="site-social-x-url">
              X profile URL (https)
            </label>
            <Input
              id="site-social-x-url"
              placeholder="https://x.com/yourorg"
              value={sDraft.socialXUrl}
              oninput={(e) =>
                (sDraft = { ...sDraft, socialXUrl: (e.target as HTMLInputElement).value })}
            />
          </div>
          <div>
            <label class="text-xs text-muted-foreground mb-1 block" for="site-social-mastodon-url">
              Mastodon profile URL (https)
            </label>
            <Input
              id="site-social-mastodon-url"
              placeholder="https://mastodon.social/@yourorg"
              value={sDraft.socialMastodonUrl}
              oninput={(e) =>
                (sDraft = { ...sDraft, socialMastodonUrl: (e.target as HTMLInputElement).value })}
            />
          </div>
          <div>
            <label class="text-xs text-muted-foreground mb-1 block" for="site-social-bluesky-url">
              Bluesky profile URL (https)
            </label>
            <Input
              id="site-social-bluesky-url"
              placeholder="https://bsky.app/profile/yourorg.example"
              value={sDraft.socialBlueskyUrl}
              oninput={(e) =>
                (sDraft = { ...sDraft, socialBlueskyUrl: (e.target as HTMLInputElement).value })}
            />
            <p class="text-xs text-muted-foreground mt-1">
              Leave a URL blank to hide that footer link. All URLs must be https.
            </p>
          </div>
          <div>
            <label class="text-xs text-muted-foreground mb-1 block" for="site-support-email">
              Support email
            </label>
            <Input
              id="site-support-email"
              type="email"
              placeholder="help@example.org"
              value={sDraft.supportEmail}
              oninput={(e) =>
                (sDraft = { ...sDraft, supportEmail: (e.target as HTMLInputElement).value })}
            />
            <p class="text-xs text-muted-foreground mt-1">
              Shown as a mailto support link in the footer, the home-page FAQ, and the account
              pages. Blank hides all support links.
            </p>
          </div>
          <div>
            <label class="text-xs text-muted-foreground mb-1 block" for="site-hero-title">
              Home hero title override
            </label>
            <Input
              id="site-hero-title"
              placeholder={HERO_TITLE_DEFAULT}
              value={sDraft.heroTitle}
              oninput={(e) =>
                (sDraft = { ...sDraft, heroTitle: (e.target as HTMLInputElement).value })}
            />
          </div>
          <div>
            <label class="text-xs text-muted-foreground mb-1 block" for="site-hero-subtitle">
              Home hero subtitle override
            </label>
            <Input
              id="site-hero-subtitle"
              placeholder={HERO_SUBTITLE_DEFAULT}
              value={sDraft.heroSubtitle}
              oninput={(e) =>
                (sDraft = { ...sDraft, heroSubtitle: (e.target as HTMLInputElement).value })}
            />
            <p class="text-xs text-muted-foreground mt-1">
              Both show as-is in every language (not translated), and blank falls back to the
              built-in translated copy. The built-in subtitle also interpolates the membership
              limits — a custom subtitle does not.
            </p>
          </div>
          <div>
            <label class="text-xs text-muted-foreground mb-1 block" for="site-hero-titles">
              Rotating hero titles (one per line)
            </label>
            <textarea
              id="site-hero-titles"
              class="flex min-h-24 w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm shadow-xs placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
              placeholder={HERO_TITLES_DEFAULT}
              value={sDraft.heroTitles}
              oninput={(e) =>
                (sDraft = { ...sDraft, heroTitles: (e.target as HTMLTextAreaElement).value })}
            ></textarea>
            <p class="text-xs text-muted-foreground mt-1">
              With 2+ lines, the home hero animates through them (every 4s); one line shows it
              statically. Empty falls back to hero title override, then the built-in translated
              rotation. Shown as-is in every language (not translated); max 8 lines.
            </p>
          </div>
          <div class="flex justify-end">
            {#if !sInit}
              <span class="me-3 self-center text-xs text-muted-foreground"
                >Loading current values…</span
              >
            {/if}
            <Button onclick={() => saveSite.mutate()} disabled={saveSite.isPending || !sInit}>
              {saveSite.isPending ? 'Saving…' : 'Save site settings'}
            </Button>
          </div>
        </CardContent>
      </Card>

      <!-- Analytics relay (self-hosted Umami): own namespace + own save -->
      <Card>
        <CardHeader>
          <CardTitle class="text-base">Analytics (self-hosted Umami)</CardTitle>
          <CardDescription>
            Anonymous pageview counts relayed server-side to your own Umami instance. No third-party
            script is loaded, browsers never learn the Umami address, and pageviews report a fixed
            set of routes only: no query strings, no titles, and referrers reduced to their origin
            (so Umami's referrer-path report stays empty by design). Off by default.
          </CardDescription>
        </CardHeader>
        <CardContent class="space-y-3 text-sm">
          <label class="flex items-center gap-3">
            <Checkbox
              checked={aDraft.enabled}
              onCheckedChange={(v) => (aDraft = { ...aDraft, enabled: v === true })}
            />
            <span>Send pageviews to a self-hosted Umami instance</span>
          </label>
          <div class="grid gap-3 sm:grid-cols-2">
            <div>
              <label class="text-xs text-muted-foreground mb-1 block" for="analytics-umami-url">
                Umami base URL (https)
              </label>
              <Input
                id="analytics-umami-url"
                placeholder="https://analytics.example.org"
                value={aDraft.umamiUrl}
                oninput={(e) =>
                  (aDraft = { ...aDraft, umamiUrl: (e.target as HTMLInputElement).value })}
              />
            </div>
            <div>
              <label class="text-xs text-muted-foreground mb-1 block" for="analytics-website-id">
                Website ID (UUID)
              </label>
              <Input
                id="analytics-website-id"
                placeholder="b1f0a2c4-…"
                value={aDraft.websiteId}
                oninput={(e) =>
                  (aDraft = { ...aDraft, websiteId: (e.target as HTMLInputElement).value })}
              />
            </div>
          </div>
          <label class="flex items-center gap-3">
            <Checkbox
              checked={aDraft.forwardIp}
              onCheckedChange={(v) => (aDraft = { ...aDraft, forwardIp: v === true })}
            />
            <span>Send visitor location to Umami (geo stats)</span>
          </label>
          <p class="text-xs text-muted-foreground">
            Off (default): Umami sees only this server's IP, so no geo data and maximum privacy. On:
            location is reported per request with no Umami-side configuration, so other sites on a
            shared instance are unaffected. See docs/privacy.md.
          </p>
          {#if aDraft.forwardIp}
            <div>
              <label
                class="text-xs text-muted-foreground mb-1 block"
                for="analytics-geo-mode-trigger"
              >
                Location detail
              </label>
              <Select.Root
                type="single"
                value={aDraft.geoMode}
                onValueChange={(v) =>
                  (aDraft = { ...aDraft, geoMode: v === 'coarse' ? 'coarse' : 'full' })}
              >
                <Select.Trigger id="analytics-geo-mode-trigger" class="w-96">
                  {aDraft.geoMode === 'coarse'
                    ? 'Country and region only (IP never sent, no city)'
                    : 'Full (IP-based: city + real unique-visitor counts)'}
                </Select.Trigger>
                <Select.Content>
                  <Select.Item value="full">
                    Full (IP-based: city + real unique-visitor counts)
                  </Select.Item>
                  <Select.Item value="coarse">
                    Country and region only (IP never sent, no city)
                  </Select.Item>
                </Select.Content>
              </Select.Root>
              <p class="text-xs text-muted-foreground mt-1">
                Full: the visitor IP is embedded in the event (requires Umami v2.17 or newer); Umami
                hashes it with a daily-rotating salt and stores derived country/region/city, never
                the raw IP. Country and region only: the relay copies the Cloudflare edge's geo
                headers instead and the IP never leaves this server; city is never sent, and
                unique-visitor counts fall back to per-device approximations. Like the Cloudflare IP
                source, this needs CADDY_TRUST_CF_HEADER=true on the web service (the Caddyfile
                strips client-suppliable Cloudflare headers otherwise). Region needs the free "Add
                visitor location headers" Managed Transform enabled on your Cloudflare zone (country
                works out of the box). If your Umami instance is itself behind Cloudflare, disable
                IP geolocation on that zone or the relayed location gets overwritten.
              </p>
            </div>
          {/if}
          {#if aDraft.forwardIp && aDraft.geoMode === 'full'}
            <div>
              <label
                class="text-xs text-muted-foreground mb-1 block"
                for="analytics-ip-source-trigger"
              >
                Visitor IP source
              </label>
              <div class="flex flex-wrap gap-3">
                <Select.Root type="single" value={ipSourceChoice} onValueChange={pickIpSource}>
                  <Select.Trigger id="analytics-ip-source-trigger" class="w-64">
                    {IP_SOURCES.find((s) => s.value === ipSourceChoice)?.label ?? 'Custom header…'}
                  </Select.Trigger>
                  <Select.Content>
                    {#each IP_SOURCES as src (src.value)}
                      <Select.Item value={src.value}>{src.label}</Select.Item>
                    {/each}
                  </Select.Content>
                </Select.Root>
                {#if ipSourceChoice === 'custom'}
                  <Input
                    class="w-56"
                    placeholder="x-real-ip"
                    aria-label="Custom IP header name"
                    value={customIpHeader}
                    oninput={(e) => {
                      customIpHeader = (e.target as HTMLInputElement).value;
                      aDraft = { ...aDraft, ipHeader: customIpHeader };
                    }}
                  />
                {/if}
              </div>
              <p class="text-xs text-muted-foreground mt-1">
                Where the relay reads the visitor IP. Default: the platform's trusted-proxy
                resolution (TRUSTED_PROXY_HOPS / CF_FRONTED). Pick your fronting CDN's header when
                the proxy chain doesn't preserve the forwarded chain (for example Cloudflare in
                front of a tunnel). This choice affects analytics only, never rate limiting.
                Cloudflare additionally needs CADDY_TRUST_CF_HEADER=true on the web service (the
                stock Caddyfile strips cf-connecting-ip). A header your chain doesn't actually set
                can be spoofed by clients; worst case is wrong geo data in your own Umami.
              </p>
            </div>
          {/if}
          <div class="flex justify-end">
            {#if !aInit}
              <span class="me-3 self-center text-xs text-muted-foreground"
                >Loading current values…</span
              >
            {/if}
            <Button
              onclick={() => saveAnalytics.mutate()}
              disabled={saveAnalytics.isPending || !aInit}
            >
              {saveAnalytics.isPending ? 'Saving…' : 'Save analytics settings'}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle class="text-base">Connection modes</CardTitle>
          <CardDescription>
            The member transport catalog (families, modes, copy, defaults, per-backend
            applicability) moved to its own manager with full create/edit/delete:
            <Link href="/admin/connection-modes" class="underline">Connection modes</Link>.
            Placement pools stay on the <Link href="/admin/remnawave" class="underline"
              >Remnawave</Link
            > page.
          </CardDescription>
        </CardHeader>
      </Card>
    </div>
  {/if}
</AdminLayout>
