<script lang="ts">
  import { Card, CardHeader, CardTitle, CardContent } from '@client/components/ui/card';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import ChevronUp from '@lucide/svelte/icons/chevron-up';
  import ChevronDown from '@lucide/svelte/icons/chevron-down';
  import X from '@lucide/svelte/icons/x';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { z } from 'zod';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import {
    adminCensoredCountriesQuery,
    appSettingsQuery,
    configQuery,
    queryKeys,
  } from '../../lib/queries';
  import { AppSettingsRecord } from '../../../shared/contracts/admin';
  import type { AdminConnectionMode } from '../../../shared/contracts/connectionModes';
  import { COUNTRY_CODES, countryName } from '../../lib/countries';
  import { adminModeName } from '../../lib/connectionModeCopy';
  import {
    LOCATION_SLOTS,
    MAX_PREFERENCE_COUNTRIES,
    MODE_SLOTS,
    moved,
    preferencePatch,
    preferenceRows,
    withRow,
    type CountryPreferenceRow,
  } from '../../lib/countryPreferences';

  /**
   * Country preferences: per country, the modes the member picker suggests (in
   * order; the first the member's backend serves wins) and the locations
   * Automatic tries first. Stored as two settings (`delivery.country.modes`,
   * `delivery.country.exits`, the latter shared with Settings → exit location
   * by country) and saved together in one PATCH. The country is the member's
   * sign-up answer, else the one their request comes from.
   */
  let { modes }: { modes: AdminConnectionMode[] } = $props();

  const settings = appSettingsQuery();
  const censored = adminCensoredCountriesQuery();
  const cfg = configQuery();
  const qc = useQueryClient();

  let rows = $derived(
    preferenceRows(
      settings.data?.['delivery.country.modes'],
      settings.data?.['delivery.country.exits'],
    ),
  );
  let steer = $derived(settings.data?.['delivery.country.steer'] === true);
  let listed = $derived((censored.data?.countries ?? []).map((c) => c.code));
  let locations = $derived(cfg.data?.locations ?? []);
  const locationLabel = (code: string) => locations.find((l) => l.code === code)?.label ?? code;
  const modeName = (slug: string) => {
    const m = modes.find((x) => x.id === slug);
    return m ? adminModeName(m) : `${slug} (gone)`;
  };
  const name = (code: string) => countryName(code, 'en');

  // The row being edited (a copy), and whether it is new.
  let editing = $state<(CountryPreferenceRow & { isNew: boolean }) | null>(null);
  let addMode = $state('');
  let addLocation = $state('');

  function startNew() {
    const first = COUNTRY_CODES.find((c) => !rows.some((r) => r.country === c)) ?? 'IR';
    editing = { country: first, modes: [], locations: [], isNew: true };
  }
  function startEdit(r: CountryPreferenceRow) {
    editing = { ...r, modes: [...r.modes], locations: [...r.locations], isNew: false };
  }

  const save = createMutation(() => ({
    mutationFn: async (next: CountryPreferenceRow[]) =>
      apiClient.patch(
        '/api/v1/admin/settings',
        preferencePatch(next),
        z.object({ settings: AppSettingsRecord }),
      ),
    onSuccess: () => {
      editing = null;
      void qc.invalidateQueries({ queryKey: queryKeys.adminSettings });
      toast.success('Country preferences saved');
    },
    onError: (err) => toast.error('Could not save', { description: apiErrorMessage(err) }),
  }));

  function commit() {
    if (!editing) return;
    const { isNew: _n, ...row } = editing;
    if (row.modes.length === 0 && row.locations.length === 0) {
      save.mutate(withRow(rows, row.country, null));
      return;
    }
    save.mutate(withRow(rows, row.country, row));
  }

  let countryTaken = $derived(!!editing?.isNew && rows.some((r) => r.country === editing!.country));
  let modeChoices = $derived(modes.filter((m) => !editing?.modes.includes(m.id)));
  let locationChoices = $derived(locations.filter((l) => !editing?.locations.includes(l.code)));
</script>

<Card>
  <CardHeader>
    <CardTitle class="text-lg flex flex-wrap items-center justify-between gap-2">
      <span>Country preferences</span>
      {#if !editing}
        <Button
          size="sm"
          onclick={startNew}
          disabled={!settings.data || rows.length >= MAX_PREFERENCE_COUNTRIES}
        >
          Add country
        </Button>
      {/if}
    </CardTitle>
  </CardHeader>
  <CardContent class="space-y-4 text-sm">
    <p class="text-muted-foreground leading-snug">
      When a member's country is known (their answer at sign-up, else the country their request
      comes from), the mode picker suggests the first mode below that their backend serves, and a
      new key on Automatic tries these locations first. Countries without a row keep the status
      page's availability matrix, then the default mode.
    </p>
    {#if !steer}
      <p
        class="rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-400"
      >
        Ordering by country is off (Settings), so locations are not used yet. Mode suggestions work
        either way.
      </p>
    {/if}

    {#if settings.isPending}
      <Skeleton class="h-16 w-full" />
    {:else if rows.length === 0 && !editing}
      <p class="text-muted-foreground">No country has preferences yet.</p>
    {:else if rows.length > 0}
      <div class="overflow-x-auto">
        <table class="w-full text-left">
          <thead class="text-xs text-muted-foreground">
            <tr class="border-b border-border">
              <th class="py-2 pe-3 font-normal">Country</th>
              <th class="py-2 pe-3 font-normal">Suggested modes, in order</th>
              <th class="py-2 pe-3 font-normal">Preferred locations, in order</th>
              <th class="py-2"></th>
            </tr>
          </thead>
          <tbody>
            {#each rows as r (r.country)}
              <tr class="border-b border-border/60 align-top last:border-0">
                <td class="py-2.5 pe-3">
                  <span class="font-medium">{r.country}</span>
                  {name(r.country)}
                </td>
                <td class="py-2.5 pe-3">
                  {#if r.modes.length === 0}
                    <span class="text-muted-foreground">Matrix, then default</span>
                  {:else}
                    <ol class="list-inside list-decimal">
                      {#each r.modes as m (m)}<li>{modeName(m)}</li>{/each}
                    </ol>
                  {/if}
                </td>
                <td class="py-2.5 pe-3">
                  {#if r.locations.length === 0}
                    <span class="text-muted-foreground">Least loaded</span>
                  {:else}
                    <ol class="list-inside list-decimal">
                      {#each r.locations as l (l)}<li>{locationLabel(l)}</li>{/each}
                    </ol>
                    {#if !listed.includes(r.country)}
                      <p class="text-xs text-muted-foreground">
                        Not on the censored-country list: locations apply once it is.
                      </p>
                    {/if}
                  {/if}
                </td>
                <td class="py-2.5 text-end">
                  <Button size="sm" variant="outline" onclick={() => startEdit(r)}>Edit</Button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}

    {#if editing}
      <div class="space-y-4 rounded-md border border-primary/60 p-4">
        <div class="flex flex-wrap items-end gap-3">
          <div>
            <label class="mb-1 block text-xs text-muted-foreground" for="cp-country">Country</label>
            {#if editing.isNew}
              <select
                id="cp-country"
                bind:value={editing.country}
                class="h-9 min-w-56 rounded-md border border-input bg-background px-2 text-sm"
              >
                {#each COUNTRY_CODES as c (c)}
                  <option value={c} disabled={rows.some((r) => r.country === c)}>
                    {c}, {name(c)}
                  </option>
                {/each}
              </select>
            {:else}
              <p id="cp-country" class="font-medium">{editing.country}, {name(editing.country)}</p>
            {/if}
          </div>
        </div>

        <div class="grid gap-6 md:grid-cols-2">
          <div class="space-y-2">
            <p class="font-medium">Suggested modes</p>
            <ol class="space-y-1.5">
              {#each editing.modes as m, i (m)}
                <li class="flex items-center gap-2 rounded-md border border-border px-2 py-1">
                  <span class="w-4 text-xs text-muted-foreground tabular-nums">{i + 1}</span>
                  <span class="flex-1">{modeName(m)}</span>
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    aria-label="Move {modeName(m)} up"
                    disabled={i === 0}
                    onclick={() => editing && (editing.modes = moved(editing.modes, i, -1))}
                    ><ChevronUp class="size-4" /></Button
                  >
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    aria-label="Move {modeName(m)} down"
                    disabled={i === editing.modes.length - 1}
                    onclick={() => editing && (editing.modes = moved(editing.modes, i, 1))}
                    ><ChevronDown class="size-4" /></Button
                  >
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    aria-label="Remove {modeName(m)}"
                    onclick={() =>
                      editing && (editing.modes = editing.modes.filter((x) => x !== m))}
                    ><X class="size-4" /></Button
                  >
                </li>
              {/each}
            </ol>
            {#if editing.modes.length < MODE_SLOTS && modeChoices.length > 0}
              <select
                aria-label="Add a mode"
                bind:value={addMode}
                onchange={() => {
                  if (editing && addMode) editing.modes = [...editing.modes, addMode];
                  addMode = '';
                }}
                class="h-9 w-full rounded-md border border-dashed border-input bg-background px-2 text-sm"
              >
                <option value="">Add a mode…</option>
                {#each modeChoices as m (m.id)}
                  <option value={m.id}>{adminModeName(m)}{m.enabled ? '' : ' (disabled)'}</option>
                {/each}
              </select>
            {/if}
            <p class="text-xs text-muted-foreground">
              A disabled mode, or one with no node for the member's backend, is skipped.
            </p>
          </div>

          <div class="space-y-2">
            <p class="font-medium">Preferred locations (up to {LOCATION_SLOTS})</p>
            <ol class="space-y-1.5">
              {#each editing.locations as l, i (l)}
                <li class="flex items-center gap-2 rounded-md border border-border px-2 py-1">
                  <span class="w-4 text-xs text-muted-foreground tabular-nums">{i + 1}</span>
                  <span class="flex-1">{locationLabel(l)}</span>
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    aria-label="Move {locationLabel(l)} up"
                    disabled={i === 0}
                    onclick={() => editing && (editing.locations = moved(editing.locations, i, -1))}
                    ><ChevronUp class="size-4" /></Button
                  >
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    aria-label="Move {locationLabel(l)} down"
                    disabled={i === editing.locations.length - 1}
                    onclick={() => editing && (editing.locations = moved(editing.locations, i, 1))}
                    ><ChevronDown class="size-4" /></Button
                  >
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    aria-label="Remove {locationLabel(l)}"
                    onclick={() =>
                      editing && (editing.locations = editing.locations.filter((x) => x !== l))}
                    ><X class="size-4" /></Button
                  >
                </li>
              {/each}
            </ol>
            {#if editing.locations.length < LOCATION_SLOTS && locationChoices.length > 0}
              <select
                aria-label="Add a location"
                bind:value={addLocation}
                onchange={() => {
                  if (editing && addLocation)
                    editing.locations = [...editing.locations, addLocation];
                  addLocation = '';
                }}
                class="h-9 w-full rounded-md border border-dashed border-input bg-background px-2 text-sm"
              >
                <option value="">Add a location…</option>
                {#each locationChoices as l (l.code)}<option value={l.code}>{l.label}</option
                  >{/each}
              </select>
            {/if}
            <p class="text-xs text-muted-foreground">
              The same list as Settings → exit location by country. Applies to Beat censorship keys
              of members on Automatic, for countries on the censored-country list; the sign-up
              location picker marks these as recommended.
            </p>
          </div>
        </div>

        <div class="flex flex-wrap justify-between gap-2">
          <div>
            {#if !editing.isNew}
              <Button
                variant="ghost"
                class="text-destructive hover:text-destructive"
                disabled={save.isPending}
                onclick={() => editing && save.mutate(withRow(rows, editing.country, null))}
              >
                Remove country
              </Button>
            {/if}
          </div>
          <div class="flex gap-2">
            <Button variant="outline" onclick={() => (editing = null)} disabled={save.isPending}>
              Cancel
            </Button>
            <Button onclick={commit} disabled={save.isPending || countryTaken}>
              {save.isPending ? 'Saving…' : 'Save'}
            </Button>
          </div>
        </div>
      </div>
    {/if}
  </CardContent>
</Card>
