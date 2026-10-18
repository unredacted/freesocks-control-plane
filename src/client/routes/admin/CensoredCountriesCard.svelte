<script lang="ts">
  /**
   * Censored countries (Settings): the one list the service uses wherever a
   * country matters. Being on it makes a country one where server names are
   * judged, a choice under "Where are you connecting from?", a row the status
   * page's availability matrix can show, and a country the mode suggestion
   * treats as censored. Two switches per country: probe edges from there, and
   * check server names from inside it (opt-in, with the risk said beside it).
   * The whole list is saved at once (PUT /api/v1/admin/censored-countries).
   */
  import ArrowDown from '@lucide/svelte/icons/arrow-down';
  import ArrowUp from '@lucide/svelte/icons/arrow-up';
  import X from '@lucide/svelte/icons/x';
  import {
    Card,
    CardHeader,
    CardTitle,
    CardDescription,
    CardContent,
  } from '@client/components/ui/card';
  import { Button } from '@client/components/ui/button';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import { countryName } from '../../lib/countries';
  import { adminCensoredCountriesQuery, queryKeys } from '../../lib/queries';
  import { AdminCensoredCountries, type CensoredCountry } from '../../../shared/contracts/admin';
  import CountryPicker from './edges/components/CountryPicker.svelte';

  const uid = $props.id();
  const qc = useQueryClient();
  const list = adminCensoredCountriesQuery();

  let draft = $state<CensoredCountry[] | null>(null);
  let picked = $state<string[]>([]);
  const rows = $derived(draft ?? list.data?.countries ?? []);
  const max = $derived(list.data?.max ?? 40);
  const dirty = $derived(draft !== null);

  function edit(next: CensoredCountry[]) {
    draft = next;
  }
  function add(code: string | undefined) {
    picked = [];
    if (!code || rows.some((r) => r.code === code) || rows.length >= max) return;
    edit([...rows, { code, checkEdges: true, checkNamesInside: false }]);
  }
  function remove(code: string) {
    edit(rows.filter((r) => r.code !== code));
  }
  function move(i: number, by: -1 | 1) {
    const j = i + by;
    if (j < 0 || j >= rows.length) return;
    const next = [...rows];
    [next[i], next[j]] = [next[j]!, next[i]!];
    edit(next);
  }
  function flag(code: string, key: 'checkEdges' | 'checkNamesInside', on: boolean) {
    edit(rows.map((r) => (r.code === code ? { ...r, [key]: on } : r)));
  }

  const save = createMutation(() => ({
    mutationFn: () =>
      apiClient.put(
        '/api/v1/admin/censored-countries',
        { countries: rows },
        AdminCensoredCountries,
      ),
    onSuccess: () => {
      draft = null;
      void qc.invalidateQueries({ queryKey: queryKeys.adminCensoredCountries });
      toast.success('Censored countries saved');
    },
    onError: (err) => {
      toast.error('Could not save the censored countries', { description: apiErrorMessage(err) });
    },
  }));
</script>

<Card>
  <CardHeader>
    <CardTitle class="text-base">Censored countries</CardTitle>
    <CardDescription>
      The one list used wherever a country matters. A country on it is one where server names are
      judged country by country, a choice members get under "Where are you connecting from?", a row
      the status page's availability matrix can show, and a place where the connection mode
      suggestion follows that matrix.
    </CardDescription>
  </CardHeader>
  <CardContent class="space-y-4 text-sm">
    {#if list.isPending}
      <Skeleton class="h-24 w-full" />
    {:else if list.isError}
      <p class="text-destructive">Could not load the list: {apiErrorMessage(list.error)}</p>
    {:else}
      {#if list.data && !list.data.stored}
        <p class="text-muted-foreground">
          Read from the settings this list replaced. Saving stores it as it is shown here.
        </p>
      {/if}
      <p class="text-muted-foreground">
        "Check names from inside" runs checks on other people's machines in that country, often home
        connections. Whoever runs one sees the address and the server name. Turn it on only where
        that is acceptable (Edges, Server names, describes the checks).
      </p>
      {#if rows.length === 0}
        <p class="text-muted-foreground">No country is on the list.</p>
      {:else}
        <ul class="divide-y rounded-md border" aria-label="Censored countries">
          {#each rows as r, i (r.code)}
            <li class="space-y-1 px-3 py-2">
              <div class="flex items-center justify-between gap-2">
                <span>
                  <span class="font-mono text-xs text-muted-foreground">{r.code}</span>
                  {countryName(r.code, 'en')}
                </span>
                <span class="flex items-center gap-1">
                  <Button
                    size="icon"
                    variant="ghost"
                    class="touch-44"
                    aria-label={`Move ${countryName(r.code, 'en')} up`}
                    disabled={i === 0}
                    onclick={() => move(i, -1)}
                  >
                    <ArrowUp class="size-4" aria-hidden="true" />
                  </Button>
                  <Button
                    size="icon"
                    variant="ghost"
                    class="touch-44"
                    aria-label={`Move ${countryName(r.code, 'en')} down`}
                    disabled={i === rows.length - 1}
                    onclick={() => move(i, 1)}
                  >
                    <ArrowDown class="size-4" aria-hidden="true" />
                  </Button>
                  <Button
                    size="icon"
                    variant="ghost"
                    class="touch-44"
                    aria-label={`Remove ${countryName(r.code, 'en')}`}
                    onclick={() => remove(r.code)}
                  >
                    <X class="size-4" aria-hidden="true" />
                  </Button>
                </span>
              </div>
              <div class="flex flex-wrap gap-x-6 gap-y-1">
                <label class="flex items-center gap-2">
                  <Checkbox
                    id={`${uid}-edges-${r.code}`}
                    checked={r.checkEdges}
                    onCheckedChange={(v) => flag(r.code, 'checkEdges', v === true)}
                  />
                  <span>Check edges from here</span>
                </label>
                <label class="flex items-center gap-2">
                  <Checkbox
                    id={`${uid}-names-${r.code}`}
                    checked={r.checkNamesInside}
                    onCheckedChange={(v) => flag(r.code, 'checkNamesInside', v === true)}
                  />
                  <span>Check names from inside</span>
                </label>
              </div>
            </li>
          {/each}
        </ul>
      {/if}
      <CountryPicker
        class="max-w-sm"
        label="Add a country"
        max={1}
        disabled={rows.length >= max}
        helper={rows.length >= max ? `The list holds at most ${max} countries.` : undefined}
        bind:value={picked}
        onchange={(next) => add(next[0])}
      />
      <div class="flex justify-end gap-2">
        {#if dirty}
          <Button variant="ghost" onclick={() => (draft = null)} disabled={save.isPending}>
            Undo changes
          </Button>
        {/if}
        <Button onclick={() => save.mutate()} disabled={!dirty || save.isPending}>
          {save.isPending ? 'Saving…' : 'Save countries'}
        </Button>
      </div>
    {/if}
  </CardContent>
</Card>
