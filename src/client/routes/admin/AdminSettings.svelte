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
  import { appSettingsQuery, configQuery, queryKeys } from '../../lib/queries';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { AppSettingsRecord } from '../../../shared/contracts/admin';
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
    repoEnabled: boolean;
    repoUrl: string;
    tosUrl: string;
    privacyUrl: string;
  }>({
    bannerEnabled: false,
    bannerText: '',
    repoEnabled: false,
    repoUrl: '',
    tosUrl: '',
    privacyUrl: '',
  });
  let sInit = $state(false);
  $effect(() => {
    const s = cfg.data?.site;
    if (s && !sInit) {
      sDraft = {
        bannerEnabled: s.bannerEnabled,
        bannerText: s.bannerText,
        repoEnabled: s.repoEnabled,
        repoUrl: s.repoUrl,
        tosUrl: s.tosUrl,
        privacyUrl: s.privacyUrl,
      };
      sInit = true;
    }
  });
  const saveSite = createMutation(() => ({
    mutationFn: async () => {
      const Resp = z.object({
        bannerEnabled: z.boolean(),
        bannerText: z.string(),
        repoEnabled: z.boolean(),
        repoUrl: z.string(),
        tosUrl: z.string(),
        privacyUrl: z.string(),
      });
      return apiClient.patch('/api/v1/admin/site', sDraft, Resp);
    },
    onSuccess: (updated) => {
      sDraft = { ...updated };
      void qc.invalidateQueries({ queryKey: queryKeys.config });
      toast.success('Site settings saved');
    },
    onError: (err) => {
      toast.error('Could not save site settings', { description: apiErrorMessage(err) });
    },
  }));

  // Connection modes (transport) - the GENERIC catalog (label/description/default).
  // The Remnawave placement pool (which nodes each mode issues into) is managed on
  // the Remnawave admin page, not here.
  let cpDraft = $state<{
    default: string;
    evadeLabel: string;
    privacyLabel: string;
    evadeDescription: string;
    privacyDescription: string;
  }>({
    default: 'evade',
    evadeLabel: '',
    privacyLabel: '',
    evadeDescription: '',
    privacyDescription: '',
  });
  let cpInit = $state(false);
  $effect(() => {
    const modes = cfg.data?.connectionModes;
    if (modes && modes.length > 0 && !cpInit) {
      // label/description arrive null unless the admin set them (blank input =
      // members see the app's own translated copy).
      cpDraft = {
        default: modes.find((m) => m.isDefault)?.id ?? 'evade',
        evadeLabel: modes.find((m) => m.id === 'evade')?.label ?? '',
        privacyLabel: modes.find((m) => m.id === 'privacy')?.label ?? '',
        evadeDescription: modes.find((m) => m.id === 'evade')?.description ?? '',
        privacyDescription: modes.find((m) => m.id === 'privacy')?.description ?? '',
      };
      cpInit = true;
    }
  });
  const saveConnectionModes = createMutation(() => ({
    mutationFn: async () => {
      const CpResp = z.object({
        modes: z.array(
          z.object({
            id: z.string(),
            label: z.string().nullable(),
            description: z.string().nullable(),
            deliveryStyle: z.enum(['url', 'rawConfig']),
            isDefault: z.boolean(),
            bound: z.boolean(),
          }),
        ),
      });
      const modes = {
        evade: { label: cpDraft.evadeLabel, description: cpDraft.evadeDescription },
        privacy: { label: cpDraft.privacyLabel, description: cpDraft.privacyDescription },
      };
      return apiClient.patch(
        '/api/v1/admin/connection-modes',
        { default: cpDraft.default, modes },
        CpResp,
      );
    },
    onSuccess: (updated) => {
      // label/description come back null when cleared - reflect that as blank inputs.
      cpDraft = {
        default: updated.modes.find((m) => m.isDefault)?.id ?? cpDraft.default,
        evadeLabel: updated.modes.find((m) => m.id === 'evade')?.label ?? '',
        privacyLabel: updated.modes.find((m) => m.id === 'privacy')?.label ?? '',
        evadeDescription: updated.modes.find((m) => m.id === 'evade')?.description ?? '',
        privacyDescription: updated.modes.find((m) => m.id === 'privacy')?.description ?? '',
      };
      void qc.invalidateQueries({ queryKey: queryKeys.config });
      toast.success('Connection modes saved');
    },
    onError: (err) => {
      toast.error('Could not save connection modes', { description: apiErrorMessage(err) });
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
            How long a free account (and its proxy key) lasts before the daily cleanup removes it.
            Also stamped as the key's expiry on the backend.
          </CardDescription>
        </CardHeader>
        <CardContent class="space-y-3 text-sm">
          <div>
            <label class="text-xs text-muted-foreground mb-1 block" for="free-expiry-days">
              Free account lifetime (days)
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
            Countries (ISO 2-letter) where the signup picker suggests "hardened privacy" instead of
            the default "stay connected". Empty = always suggest stay-connected. The member's actual
            choice is stored only on their device, never here.
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
          <CardTitle class="text-base">Site banner & footer link</CardTitle>
          <CardDescription>
            A site-wide announcement banner shown to members (e.g. planned maintenance), and footer
            links: a "View source" repo link plus optional Terms of Service and Privacy Policy
            links. All are optional and off/empty by default. Banner text is shown as-is in every
            language (not translated).
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
            <p class="text-xs text-muted-foreground mt-1">
              Leave a URL blank to hide that footer link. Both must be https.
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

      <Card>
        <CardHeader>
          <CardTitle class="text-base">Connection modes</CardTitle>
          <CardDescription>
            The member-facing transport choice: "Beat censorship" (evade) and "Maximum privacy"
            (privacy). Set the default and, optionally, a custom label/description that replaces the
            member picker's translated copy verbatim in EVERY language (leave blank to keep the
            app's own translations). Which Remnawave nodes each mode issues into - the placement
            pool + live node load - is managed on the <strong>Remnawave</strong> page.
          </CardDescription>
        </CardHeader>
        <CardContent class="space-y-5 text-sm">
          <!-- evade -->
          <div class="space-y-2">
            <label class="flex items-center gap-2 font-medium">
              <input
                type="radio"
                name="cp-default"
                checked={cpDraft.default === 'evade'}
                onchange={() => (cpDraft = { ...cpDraft, default: 'evade' })}
              />
              Beat censorship (evade)
              {#if cpDraft.default === 'evade'}
                <span
                  class="rounded-full bg-primary/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-primary"
                  >default</span
                >
              {/if}
            </label>
            <div>
              <label class="text-xs text-muted-foreground mb-1 block" for="cp-evade-label"
                >Label <span class="opacity-70">(blank = translated default)</span></label
              >
              <Input
                id="cp-evade-label"
                placeholder="Beat censorship"
                value={cpDraft.evadeLabel}
                oninput={(e) =>
                  (cpDraft = { ...cpDraft, evadeLabel: (e.target as HTMLInputElement).value })}
              />
            </div>
            <div>
              <label class="text-xs text-muted-foreground mb-1 block" for="cp-evade-description"
                >Description <span class="opacity-70">(blank = translated default)</span></label
              >
              <textarea
                id="cp-evade-description"
                rows="2"
                class="border-input focus-visible:border-ring focus-visible:ring-ring/50 w-full min-w-0 rounded-lg border bg-transparent px-2.5 py-1 text-base outline-none transition-colors focus-visible:ring-3 md:text-sm placeholder:text-muted-foreground"
                placeholder="Shown on the member's picker card"
                value={cpDraft.evadeDescription}
                oninput={(e) =>
                  (cpDraft = {
                    ...cpDraft,
                    evadeDescription: (e.target as HTMLTextAreaElement).value,
                  })}
              ></textarea>
            </div>
          </div>

          <!-- privacy -->
          <div class="space-y-2 border-t border-border pt-4">
            <label class="flex items-center gap-2 font-medium">
              <input
                type="radio"
                name="cp-default"
                checked={cpDraft.default === 'privacy'}
                onchange={() => (cpDraft = { ...cpDraft, default: 'privacy' })}
              />
              Maximum privacy (privacy)
              {#if cpDraft.default === 'privacy'}
                <span
                  class="rounded-full bg-primary/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-primary"
                  >default</span
                >
              {/if}
            </label>
            <div>
              <label class="text-xs text-muted-foreground mb-1 block" for="cp-privacy-label"
                >Label <span class="opacity-70">(blank = translated default)</span></label
              >
              <Input
                id="cp-privacy-label"
                placeholder="Maximum privacy"
                value={cpDraft.privacyLabel}
                oninput={(e) =>
                  (cpDraft = { ...cpDraft, privacyLabel: (e.target as HTMLInputElement).value })}
              />
            </div>
            <div>
              <label class="text-xs text-muted-foreground mb-1 block" for="cp-privacy-description"
                >Description <span class="opacity-70">(blank = translated default)</span></label
              >
              <textarea
                id="cp-privacy-description"
                rows="2"
                class="border-input focus-visible:border-ring focus-visible:ring-ring/50 w-full min-w-0 rounded-lg border bg-transparent px-2.5 py-1 text-base outline-none transition-colors focus-visible:ring-3 md:text-sm placeholder:text-muted-foreground"
                placeholder="Shown on the member's picker card"
                value={cpDraft.privacyDescription}
                oninput={(e) =>
                  (cpDraft = {
                    ...cpDraft,
                    privacyDescription: (e.target as HTMLTextAreaElement).value,
                  })}
              ></textarea>
            </div>
          </div>

          <div class="flex justify-end">
            {#if !cpInit}
              <span class="me-3 self-center text-xs text-muted-foreground"
                >Loading current values…</span
              >
            {/if}
            <Button
              onclick={() => saveConnectionModes.mutate()}
              disabled={saveConnectionModes.isPending || !cpInit}
            >
              {saveConnectionModes.isPending ? 'Saving…' : 'Save connection modes'}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  {/if}
</AdminLayout>
