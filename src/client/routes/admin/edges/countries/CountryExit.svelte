<script lang="ts">
  /**
   * The country page's "Exit": where new keys on Automatic of members who
   * chose this country themselves go (`delivery.country.exits`, docs/edges.md
   * "Exit location by country"), and this country's row of it. Save sends the
   * whole setting with only this row changed, in one `PATCH
   * /api/v1/admin/settings`. The Countries tab's Delivery card edits every
   * country's row, plus the switch that makes the rows count.
   *
   * Props:
   *   code: string                 the country (ISO 3166-1 alpha-2)
   *   view: CountryViewResponse
   */
  import { z } from 'zod';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
  } from '@client/components/ui/card';
  import { Skeleton } from '@client/components/ui/skeleton';
  import Link from '@client/components/Link.svelte';
  import { apiClient } from '@client/lib/api';
  import { apiErrorMessage } from '@client/lib/errors';
  import { appSettingsQuery, configQuery, queryKeys } from '@client/lib/queries';
  import { edgeKeys } from '@client/lib/edgesApi';
  import { EXIT_SLOTS, exitRows, exitSentence, slotsOf, withSlot } from '@client/lib/countryExits';
  import { AppSettingsRecord } from '@shared/contracts/admin';
  import type { CountryViewResponse } from '@shared/contracts/edges';
  import { edgesPaths } from '../lib/routes';
  import { withExitRow } from './delivery';
  import { countryLabel } from './words';

  interface Props {
    code: string;
    view: CountryViewResponse;
  }
  let { code, view: v }: Props = $props();
  const uid = $props.id();
  const qc = useQueryClient();
  const settings = appSettingsQuery();
  const cfg = configQuery();
  const name = $derived(countryLabel(code));

  const stored = $derived(exitRows(settings.data?.['delivery.country.exits']));
  // This country's slots while edited (null: as stored).
  let draft = $state<string[] | null>(null);
  const slots = $derived(draft ?? slotsOf(stored, code));
  const dirty = $derived(
    draft !== null && JSON.stringify(draft) !== JSON.stringify(slotsOf(stored, code)),
  );

  function pick(i: number, value: string) {
    // Close the slots up the way the stored setting will (no gaps, no repeats).
    const row = withSlot([{ country: code, locations: slots.filter(Boolean) }], code, i, value);
    draft = slotsOf(row, code);
  }

  const save = createMutation(() => ({
    // This country's row on top of the rows on record (the others untouched).
    mutationFn: (next: string[]) =>
      apiClient.patch(
        '/api/v1/admin/settings',
        { 'delivery.country.exits': withExitRow(stored, code, next) },
        z.object({ settings: AppSettingsRecord }),
      ),
    onSuccess: () => {
      draft = null;
      void qc.invalidateQueries({ queryKey: queryKeys.adminSettings });
      void qc.invalidateQueries({ queryKey: edgeKeys.countries });
      toast.success(`Exit for ${name} saved`);
    },
    onError: (err) => toast.error('Could not save the exit', { description: apiErrorMessage(err) }),
  }));
</script>

<Card>
  <CardHeader>
    <CardTitle class="text-base">Exit for {name}</CardTitle>
    <CardDescription>
      {exitSentence(
        v.exits.map((e) => e.label),
        v.switches.steering,
      )}
    </CardDescription>
  </CardHeader>
  <CardContent class="space-y-3 text-sm">
    {#if settings.isPending}
      <Skeleton class="h-10 w-full" />
    {:else if settings.isError}
      <p class="text-destructive">Could not load the settings: {apiErrorMessage(settings.error)}</p>
    {:else}
      {#if !v.listed}
        <p class="text-muted-foreground">
          {name} is not on the censored-country list, so a row here is not used until it is.
        </p>
      {/if}
      <div class="flex flex-wrap items-center gap-2">
        {#each Array.from({ length: EXIT_SLOTS }, (_, i) => i) as i (i)}
          <select
            id={`${uid}-slot-${i}`}
            aria-label={`${name}: location ${i + 1}`}
            class="border-input bg-background h-9 rounded-md border px-2 text-sm"
            value={slots[i]}
            disabled={save.isPending || (i > 0 && !slots[i - 1])}
            onchange={(e) => pick(i, e.currentTarget.value)}
          >
            <option value="">{i === 0 ? 'Least loaded' : 'None'}</option>
            {#each cfg.data?.locations ?? [] as l (l.code)}
              <option value={l.code}>{l.label}</option>
            {/each}
          </select>
        {/each}
      </div>
      <p class="text-muted-foreground text-xs">
        In order: the first that can take a new key wins. Never for a guessed country, and keys
        already issued never move by themselves.
        <Link href={edgesPaths.countries()} class="underline underline-offset-2">
          Delivery, on the Countries tab
        </Link>
        holds ordering by country and every country's row.
      </p>
      <div class="flex justify-end gap-2">
        {#if dirty}
          <Button variant="ghost" onclick={() => (draft = null)} disabled={save.isPending}>
            Undo changes
          </Button>
        {/if}
        <Button onclick={() => save.mutate(slots)} disabled={!dirty || save.isPending}>
          {save.isPending ? 'Saving…' : 'Save exit'}
        </Button>
      </div>
    {/if}
  </CardContent>
</Card>
