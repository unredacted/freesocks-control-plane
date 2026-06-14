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
  import { appSettingsQuery, queryKeys } from '../../lib/queries';
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
   *   1. Add it to `SETTINGS_SCHEMA` in `src/server/services/app-settings.ts`.
   *   2. Add a row below in `FIELDS` describing how to render it.
   * The PATCH handler validates each value server-side against the
   * server-side Zod schema, so a UI bug can't persist a bad value.
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
    </div>
  {/if}
</AdminLayout>
