<script lang="ts">
  /**
   * The country page's "Checks from here": this country's two switches on the
   * censored-country list (check edges from here; check SNIs from inside,
   * with the risk said beside it), the same ones the list editor on the
   * Countries tab shows. A switch saves at once: the whole list goes back
   * with only this switch changed (censoredSave). A country not on the list
   * can be added from here.
   *
   * Props:
   *   code: string                 the country (ISO 3166-1 alpha-2)
   *   view: CountryViewResponse
   */
  import { Button } from '@client/components/ui/button';
  import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
  } from '@client/components/ui/card';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { Switch } from '@client/components/ui/switch';
  import Link from '@client/components/Link.svelte';
  import { apiErrorMessage } from '@client/lib/errors';
  import { adminCensoredCountriesQuery } from '@client/lib/queries';
  import type { CountryViewResponse } from '@shared/contracts/edges';
  import { edgesPaths } from '../lib/routes';
  import {
    CENSORED_LIST_USES,
    CHECK_SWITCHES,
    withCheck,
    withCountry,
    type CheckKey,
  } from './censored';
  import { censoredSave } from './censoredSave.svelte';
  import { countryLabel } from './words';

  interface Props {
    code: string;
    view: CountryViewResponse;
  }
  let { code, view: v }: Props = $props();
  const uid = $props.id();

  const list = adminCensoredCountriesQuery();
  const rows = $derived(list.data?.countries ?? []);
  const row = $derived(rows.find((r) => r.code === code) ?? null);
  const max = $derived(list.data?.max ?? 40);
  const name = $derived(countryLabel(code));

  const save = censoredSave({
    success: (next) =>
      next.some((r) => r.code === code)
        ? `Checks from ${name} saved`
        : `${name} is no longer on the list`,
  });

  function flip(key: CheckKey, on: boolean) {
    if (!row || save.isPending) return;
    save.mutate(withCheck(rows, code, key, on));
  }
  function addToList() {
    if (row || save.isPending) return;
    save.mutate(withCountry(rows, code, max));
  }
</script>

<Card>
  <CardHeader>
    <CardTitle class="text-base">Checks from {name}</CardTitle>
    <CardDescription>
      What FCP checks from this country. Each switch saves at once. The same switches for every
      country are on the
      <Link href={edgesPaths.countries()} class="underline underline-offset-2">Countries</Link>
      tab, with the list.
    </CardDescription>
  </CardHeader>
  <CardContent class="space-y-4 text-sm">
    {#if list.isPending}
      <Skeleton class="h-16 w-full" />
    {:else if list.isError}
      <p class="text-destructive">Could not load the list: {apiErrorMessage(list.error)}</p>
    {:else if !row}
      <p class="text-muted-foreground">
        {name} is not on the censored-country list, so nothing is checked from here. {CENSORED_LIST_USES}
      </p>
      <Button size="sm" disabled={save.isPending || rows.length >= max} onclick={addToList}>
        {save.isPending ? 'Adding…' : 'Add it to the list'}
      </Button>
      {#if rows.length >= max}
        <p class="text-muted-foreground">The list holds at most {max} countries.</p>
      {/if}
    {:else}
      <ul class="space-y-4">
        {#each CHECK_SWITCHES as sw (sw.key)}
          <li class="flex items-start gap-3">
            <Switch
              id={`${uid}-${sw.key}`}
              class="mt-0.5"
              checked={row[sw.key]}
              disabled={save.isPending}
              onCheckedChange={(on) => flip(sw.key, on)}
              aria-describedby={`${uid}-${sw.key}-help`}
            />
            <div class="min-w-0">
              <label for={`${uid}-${sw.key}`} class="font-medium">{sw.label}</label>
              <p id={`${uid}-${sw.key}-help`} class="text-muted-foreground">{sw.help}</p>
            </div>
          </li>
        {/each}
      </ul>
      {#if row.checkNamesInside && v.listed && !v.listed.nameChecksRun}
        <p class="text-amber-700 dark:text-amber-300">
          SNI checks from inside are on for {name}, but none runs now: SNI checks are off, or no
          source can check from here.
          <Link href={edgesPaths.findNames()} class="underline underline-offset-2"
            >SNIs, Find more</Link
          >
        </p>
      {/if}
      {#if row.checkEdges && !v.switches.probes}
        <p class="text-amber-700 dark:text-amber-300">
          Probes are off, so edges are not checked from anywhere.
          <Link
            href={edgesPaths.settings({ section: 'probes' })}
            class="underline underline-offset-2"
          >
            Probe settings
          </Link>
        </p>
      {/if}
    {/if}
  </CardContent>
</Card>
