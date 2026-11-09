<script lang="ts">
  /**
   * The censored-country list, edited on Servers -> Countries: the one list
   * the service uses wherever a country matters. Being on it makes a country
   * one where SNIs are judged, a choice under "Where are you connecting
   * from?", a row the status page's availability matrix can show, and a
   * country the mode suggestion treats as censored. Two switches per country:
   * check edges from there, and check SNIs from inside it (opt-in, with the
   * risk said beside it); each country page has the same two switches under
   * "Checks from here". The whole list is saved at once (censoredSave).
   *
   * Props: id?: string   the card's element id (the page's "Add a country" scrolls to it)
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
  import Link from '@client/components/Link.svelte';
  import { apiErrorMessage } from '@client/lib/errors';
  import { countryName } from '@client/lib/countries';
  import { adminCensoredCountriesQuery } from '@client/lib/queries';
  import type { CensoredCountry } from '@shared/contracts/admin';
  import CountryPicker from '../components/CountryPicker.svelte';
  import { edgesPaths } from '../lib/routes';
  import {
    CHECK_SWITCHES,
    movedCountry,
    withCheck,
    withCountry,
    withoutCountry,
    type CheckKey,
  } from './censored';
  import { censoredSave } from './censoredSave.svelte';

  let { id }: { id?: string } = $props();
  const uid = $props.id();
  const list = adminCensoredCountriesQuery();

  let draft = $state<CensoredCountry[] | null>(null);
  let picked = $state<string[]>([]);
  const rows = $derived(draft ?? list.data?.countries ?? []);
  const max = $derived(list.data?.max ?? 40);
  const dirty = $derived(draft !== null);
  // The old settings can together hold more than the list's cap: the seed then
  // leaves them in place, and the operator trims the list here before saving.
  const overCap = $derived(rows.length > max);

  const save = censoredSave({
    success: 'Censored countries saved',
    onSaved: () => (draft = null),
  });

  function edit(next: CensoredCountry[]) {
    // An edit made while the PUT is in flight would be dropped when it lands.
    if (save.isPending) return;
    draft = next;
  }
  function add(code: string | undefined) {
    picked = [];
    if (code) edit(withCountry(rows, code, max));
  }
  const remove = (code: string) => edit(withoutCountry(rows, code));
  const move = (i: number, by: -1 | 1) => edit(movedCountry(rows, i, by));
  const flag = (code: string, key: CheckKey, on: boolean) => edit(withCheck(rows, code, key, on));
</script>

<Card {id}>
  <CardHeader>
    <CardTitle class="text-base">Censored countries</CardTitle>
    <CardDescription>
      The countries this tab shows, in order. Each one is checked and judged on its own.
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
      {#if (list.data?.legacyChanged ?? []).length > 0}
        <p class="text-destructive">
          Settings this list replaced were changed while an older version ran ({list.data?.legacyChanged.join(
            ', ',
          )}). This version reads only the list below, so those changes do not apply. Check the list
          and save it: saving retires them.
        </p>
      {/if}
      {#if overCap}
        <p class="text-destructive">
          These are {rows.length} countries; the list holds at most {max}. Remove {rows.length -
            max} before saving.
        </p>
      {/if}
      <p class="text-muted-foreground">
        "Check SNIs from inside" runs checks on other people's machines in that country, often home
        connections. Whoever runs one sees the address and the SNI. Turn it on only where that is
        acceptable (<Link href={edgesPaths.names()} class="underline underline-offset-2">SNIs</Link>
        describes the checks).
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
                    disabled={save.isPending || i === 0}
                    onclick={() => move(i, -1)}
                  >
                    <ArrowUp class="size-4" aria-hidden="true" />
                  </Button>
                  <Button
                    size="icon"
                    variant="ghost"
                    class="touch-44"
                    aria-label={`Move ${countryName(r.code, 'en')} down`}
                    disabled={save.isPending || i === rows.length - 1}
                    onclick={() => move(i, 1)}
                  >
                    <ArrowDown class="size-4" aria-hidden="true" />
                  </Button>
                  <Button
                    size="icon"
                    variant="ghost"
                    class="touch-44"
                    aria-label={`Remove ${countryName(r.code, 'en')}`}
                    disabled={save.isPending}
                    onclick={() => remove(r.code)}
                  >
                    <X class="size-4" aria-hidden="true" />
                  </Button>
                </span>
              </div>
              <div class="flex flex-wrap gap-x-6 gap-y-1">
                {#each CHECK_SWITCHES as sw (sw.key)}
                  <label class="flex items-center gap-2">
                    <Checkbox
                      id={`${uid}-${sw.key}-${r.code}`}
                      checked={r[sw.key]}
                      disabled={save.isPending}
                      onCheckedChange={(v) => flag(r.code, sw.key, v === true)}
                    />
                    <span>{sw.label}</span>
                  </label>
                {/each}
              </div>
            </li>
          {/each}
        </ul>
      {/if}
      <CountryPicker
        class="max-w-sm"
        label="Add a country"
        max={1}
        disabled={save.isPending || rows.length >= max}
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
        <Button onclick={() => save.mutate(rows)} disabled={!dirty || overCap || save.isPending}>
          {save.isPending ? 'Saving…' : 'Save countries'}
        </Button>
      </div>
    {/if}
  </CardContent>
</Card>
