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
  import {
    adminSquadStatsQuery,
    appSettingsQuery,
    configQuery,
    queryKeys,
  } from '../../lib/queries';
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
      // — refresh it too so member tabs in this browser don't serve stale config.
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

  // Connection profiles (transport → Remnawave squad), own namespace like theme /
  // verification. Squad UUIDs are WRITE-ONLY: publicConfig exposes only `available`
  // (bound?), never the value, so the squad inputs start blank and a blank leaves
  // the current binding untouched (keep-secret-on-blank, like backend credentials).
  let cpDraft = $state<{
    default: 'evade' | 'privacy';
    evadeLabel: string;
    privacyLabel: string;
    evadeDescription: string;
    privacyDescription: string;
    evadeSquad: string;
    privacySquad: string;
  }>({
    default: 'evade',
    evadeLabel: '',
    privacyLabel: '',
    evadeDescription: '',
    privacyDescription: '',
    evadeSquad: '',
    privacySquad: '',
  });
  let cpInit = $state(false);
  $effect(() => {
    const profiles = cfg.data?.connectionProfiles;
    if (profiles && profiles.length > 0 && !cpInit) {
      // label/description arrive null unless the admin set them (blank input =
      // members see the app's own translated copy).
      cpDraft = {
        default: profiles.find((p) => p.isDefault)?.id ?? 'evade',
        evadeLabel: profiles.find((p) => p.id === 'evade')?.label ?? '',
        privacyLabel: profiles.find((p) => p.id === 'privacy')?.label ?? '',
        evadeDescription: profiles.find((p) => p.id === 'evade')?.description ?? '',
        privacyDescription: profiles.find((p) => p.id === 'privacy')?.description ?? '',
        evadeSquad: '',
        privacySquad: '',
      };
      cpInit = true;
    }
  });
  // Live "is this profile's squad bound?" straight from config (never the uuid).
  let cpAvailable = $derived({
    evade: cfg.data?.connectionProfiles?.find((p) => p.id === 'evade')?.available ?? false,
    privacy: cfg.data?.connectionProfiles?.find((p) => p.id === 'privacy')?.available ?? false,
  });
  // Per-squad load (panel-authoritative member counts, stamped by the
  // healthcheck cron) — the read-only window into whether a pool is balancing.
  const squadStats = adminSquadStatsQuery();
  // One squad UUID per line (commas also accepted); trims + dedupes.
  function parseSquadList(text: string): string[] {
    const out: string[] = [];
    for (const raw of text.split(/[\n,]/)) {
      const s = raw.trim();
      if (s && !out.includes(s)) out.push(s);
    }
    return out;
  }
  const saveConnectionProfiles = createMutation(() => ({
    mutationFn: async () => {
      const CpResp = z.object({
        profiles: z.array(
          z.object({
            id: z.enum(['evade', 'privacy']),
            label: z.string().nullable(),
            description: z.string().nullable(),
            isDefault: z.boolean(),
            squadBound: z.boolean(),
          }),
        ),
      });
      const profiles: {
        evade: { label: string; description: string; squadUuids?: string[] };
        privacy: { label: string; description: string; squadUuids?: string[] };
      } = {
        evade: { label: cpDraft.evadeLabel, description: cpDraft.evadeDescription },
        privacy: { label: cpDraft.privacyLabel, description: cpDraft.privacyDescription },
      };
      // Only send squads when the admin typed any — blank keeps the current
      // binding. One UUID per line; 2+ = a load-balanced pool.
      const evadeSquads = parseSquadList(cpDraft.evadeSquad);
      const privacySquads = parseSquadList(cpDraft.privacySquad);
      if (evadeSquads.length > 0) profiles.evade.squadUuids = evadeSquads;
      if (privacySquads.length > 0) profiles.privacy.squadUuids = privacySquads;
      return apiClient.patch(
        '/api/v1/admin/connection-profiles',
        { default: cpDraft.default, profiles },
        CpResp,
      );
    },
    onSuccess: (updated) => {
      // Reset the write-only squad inputs; refresh config so `available` + labels update.
      // label/description come back null when cleared — reflect that as blank inputs.
      cpDraft = {
        default: updated.profiles.find((p) => p.isDefault)?.id ?? cpDraft.default,
        evadeLabel: updated.profiles.find((p) => p.id === 'evade')?.label ?? '',
        privacyLabel: updated.profiles.find((p) => p.id === 'privacy')?.label ?? '',
        evadeDescription: updated.profiles.find((p) => p.id === 'evade')?.description ?? '',
        privacyDescription: updated.profiles.find((p) => p.id === 'privacy')?.description ?? '',
        evadeSquad: '',
        privacySquad: '',
      };
      void qc.invalidateQueries({ queryKey: queryKeys.config });
      toast.success('Connection profiles saved');
    },
    onError: (err) => {
      toast.error('Could not save connection profiles', { description: apiErrorMessage(err) });
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
            — FCP can't read or set that panel setting. Set the per-tier limit under Tiers.
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
              placeholder="(none — always suggest stay-connected)"
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
            <Button onclick={() => saveVerification.mutate()} disabled={saveVerification.isPending}>
              {saveVerification.isPending ? 'Saving…' : 'Save verification'}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle class="text-base">Connection profiles</CardTitle>
          <CardDescription>
            The member-facing transport choice: "Stay connected" (a CDN-fronted squad) and "Maximize
            privacy" (a direct VLESS-Reality squad). Bind each to the Remnawave internal-squad UUID
            it should issue keys into. Squad UUIDs are write-only; leave a field blank to keep the
            current binding. The Ansible panel-bootstrap sets these automatically. Until a squad is
            bound the member picker stays a local presentation preference (issuance falls back to
            the tier's own squad). A custom label/description replaces the member picker's
            translated copy verbatim in EVERY language — leave blank to keep the app's own
            translations.
          </CardDescription>
        </CardHeader>
        <CardContent class="space-y-5 text-sm">
          <!-- Stay connected (evade) -->
          <div class="space-y-2">
            <div class="flex items-center justify-between gap-2">
              <label class="flex items-center gap-2 font-medium">
                <input
                  type="radio"
                  name="cp-default"
                  checked={cpDraft.default === 'evade'}
                  onchange={() => (cpDraft = { ...cpDraft, default: 'evade' })}
                />
                Stay connected <span class="text-xs text-muted-foreground">(default?)</span>
              </label>
              <span
                class="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide {cpAvailable.evade
                  ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                  : 'bg-muted text-muted-foreground'}"
              >
                {cpAvailable.evade ? 'Squad bound' : 'Not set'}
              </span>
            </div>
            <div>
              <label class="text-xs text-muted-foreground mb-1 block" for="cp-evade-label"
                >Label <span class="opacity-70">(blank = translated default)</span></label
              >
              <Input
                id="cp-evade-label"
                placeholder="Stay connected"
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
            <div>
              <label class="text-xs text-muted-foreground mb-1 block" for="cp-evade-squad"
                >Remnawave squad UUIDs (write-only, one per line — 2+ = load-balanced pool)</label
              >
              <textarea
                id="cp-evade-squad"
                rows="2"
                class="border-input focus-visible:border-ring focus-visible:ring-ring/50 w-full min-w-0 rounded-lg border bg-transparent px-2.5 py-1 font-mono text-base outline-none transition-colors focus-visible:ring-3 md:text-sm placeholder:text-muted-foreground"
                placeholder={cpAvailable.evade ? 'Bound — leave blank to keep' : 'Not set'}
                value={cpDraft.evadeSquad}
                oninput={(e) =>
                  (cpDraft = { ...cpDraft, evadeSquad: (e.target as HTMLTextAreaElement).value })}
              ></textarea>
            </div>
          </div>

          <!-- Maximize privacy (privacy) -->
          <div class="space-y-2 border-t border-border pt-4">
            <div class="flex items-center justify-between gap-2">
              <label class="flex items-center gap-2 font-medium">
                <input
                  type="radio"
                  name="cp-default"
                  checked={cpDraft.default === 'privacy'}
                  onchange={() => (cpDraft = { ...cpDraft, default: 'privacy' })}
                />
                Maximize privacy <span class="text-xs text-muted-foreground">(default?)</span>
              </label>
              <span
                class="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide {cpAvailable.privacy
                  ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                  : 'bg-muted text-muted-foreground'}"
              >
                {cpAvailable.privacy ? 'Squad bound' : 'Not set'}
              </span>
            </div>
            <div>
              <label class="text-xs text-muted-foreground mb-1 block" for="cp-privacy-label"
                >Label <span class="opacity-70">(blank = translated default)</span></label
              >
              <Input
                id="cp-privacy-label"
                placeholder="Maximize privacy"
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
            <div>
              <label class="text-xs text-muted-foreground mb-1 block" for="cp-privacy-squad"
                >Remnawave squad UUIDs (write-only, one per line — 2+ = load-balanced pool)</label
              >
              <textarea
                id="cp-privacy-squad"
                rows="2"
                class="border-input focus-visible:border-ring focus-visible:ring-ring/50 w-full min-w-0 rounded-lg border bg-transparent px-2.5 py-1 font-mono text-base outline-none transition-colors focus-visible:ring-3 md:text-sm placeholder:text-muted-foreground"
                placeholder={cpAvailable.privacy ? 'Bound — leave blank to keep' : 'Not set'}
                value={cpDraft.privacySquad}
                oninput={(e) =>
                  (cpDraft = { ...cpDraft, privacySquad: (e.target as HTMLTextAreaElement).value })}
              ></textarea>
            </div>
          </div>

          {#if squadStats.data && squadStats.data.length > 0}
            <div class="border-t border-border pt-4">
              <p class="mb-2 text-xs font-medium text-muted-foreground">
                Squad load (panel member counts, refreshed by the healthcheck cron — issuance picks
                the least-loaded squad of a profile's pool)
              </p>
              <div class="space-y-1">
                {#each squadStats.data as sq (sq.squadUuid)}
                  <div class="flex items-center justify-between gap-2 text-xs">
                    <span class="truncate">
                      <span class="font-medium">{sq.name ?? 'unnamed'}</span>
                      <span class="ml-1 font-mono text-muted-foreground">{sq.squadUuid}</span>
                    </span>
                    <span class="shrink-0 tabular-nums text-muted-foreground">
                      {sq.membersCount}
                      {sq.membersCount === 1 ? 'member' : 'members'}
                    </span>
                  </div>
                {/each}
              </div>
            </div>
          {/if}

          <div class="flex justify-end">
            <Button
              onclick={() => saveConnectionProfiles.mutate()}
              disabled={saveConnectionProfiles.isPending}
            >
              {saveConnectionProfiles.isPending ? 'Saving…' : 'Save connection profiles'}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  {/if}
</AdminLayout>
