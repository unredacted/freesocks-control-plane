<script lang="ts">
  /**
   * The lookup box: which country lists hold some names or addresses. Reads
   * every list with a version in use, and says when one is off or stale
   * (those are not read as evidence).
   *
   * All wording lives in ./listWords.ts (pure, unit-tested).
   */
  import { Button } from '@client/components/ui/button';
  import { Card, CardContent } from '@client/components/ui/card';
  import { Label } from '@client/components/ui/label';
  import { ApiCallError } from '@client/lib/api';
  import { lookupCountryLists } from '@client/lib/countryListsApi';
  import type { CountryListLookup } from '@shared/contracts/countryLists';
  import { countryLabel } from './words';
  import { HOW_WORDS, listErrorWords, parseLookup, REGIME_WORDS } from './listWords';

  const uid = $props.id();
  let text = $state('');
  let busy = $state(false);
  let error = $state<string | null>(null);
  let results = $state<CountryListLookup['results'] | null>(null);
  let entries = $derived(parseLookup(text));

  async function look() {
    if (entries.length === 0 || busy) return;
    busy = true;
    error = null;
    try {
      results = (await lookupCountryLists(entries)).results;
    } catch (e) {
      error = listErrorWords(e instanceof ApiCallError ? e.payload.error.code : null);
    } finally {
      busy = false;
    }
  }
</script>

<Card class="mt-6">
  <CardContent class="space-y-3 py-5 text-sm">
    <div>
      <h2 class="text-base font-medium">Look something up</h2>
      <p class="text-muted-foreground mt-1">
        Hostnames or addresses, one per line. A wildcard covers the hostnames below it, not the
        hostname itself.
      </p>
    </div>
    <form
      class="space-y-2"
      onsubmit={(e) => {
        e.preventDefault();
        void look();
      }}
    >
      <Label for={`${uid}-q`} class="sr-only">Hostnames or addresses</Label>
      <textarea
        id={`${uid}-q`}
        bind:value={text}
        rows="3"
        class="border-input bg-background w-full rounded-md border px-3 py-2 font-mono text-xs"
        placeholder="example.com&#10;192.0.2.1"
        autocapitalize="off"
        spellcheck={false}></textarea>
      <Button type="submit" size="sm" disabled={entries.length === 0 || busy}>
        {busy ? 'Looking…' : 'Look up'}
      </Button>
    </form>
    {#if error}
      <p class="text-destructive">{error}</p>
    {/if}
    {#if results}
      <ul class="divide-y rounded-md border" aria-label="Lookup results">
        {#each results as r (r.entry)}
          <li class="space-y-1 p-3">
            <p class="font-mono text-xs break-all">{r.entry}</p>
            {#if r.kind === 'invalid'}
              <p class="text-muted-foreground">Not a hostname or an address.</p>
            {:else if r.lists.length === 0}
              <p class="text-muted-foreground">On no list.</p>
            {:else}
              {#each r.lists as l (l.id)}
                <p>
                  {l.label}, {countryLabel(l.country)}: {REGIME_WORDS[
                    l.regime
                  ].label.toLowerCase()},
                  {HOW_WORDS[l.how]}.
                  {#if !l.enabled}
                    <span class="text-muted-foreground">The list is off.</span>
                  {:else if !l.fresh}
                    <span class="text-muted-foreground">The list is stale.</span>
                  {/if}
                </p>
              {/each}
            {/if}
          </li>
        {/each}
      </ul>
    {/if}
  </CardContent>
</Card>
