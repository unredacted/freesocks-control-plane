<script lang="ts">
  /**
   * "Mark an address for this country", on the country page: pick one of the
   * addresses the page shows (./sections.ts `markableAddresses`), then the
   * existing mark dialog (../components/CountryMarkDialog.svelte, `POST
   * countries/marks`) opens for it, preset to this country. A mark needs the
   * country on the censored-country list (the server refuses it otherwise), so
   * the button is off, and says why, for a country that is not.
   *
   * Props:
   *   code: string                     the country (ISO 3166-1 alpha-2)
   *   origins: CountryViewOrigin[]     the country view's origins
   *   listed: boolean                  the country is on the censored-country list
   */
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';
  import { countryName } from '@client/lib/countries';
  import { edgeCountriesQuery } from '@client/lib/edgesApi';
  import type { CountryViewOrigin } from '@shared/contracts/edges';
  import CountryMarkDialog from '../components/CountryMarkDialog.svelte';
  import { DIALOG_FIT, STICKY_FOOTER } from '../lib/dialogLayout';
  import { MARK_WORDS } from '../lib/statusWords';
  import { markableAddresses } from './sections';

  interface Props {
    code: string;
    origins: CountryViewOrigin[];
    listed: boolean;
  }
  let { code, origins, listed }: Props = $props();
  const uid = $props.id();

  // The marks on record (any country), for the dialog's "(now)".
  const checks = edgeCountriesQuery();
  const marks = $derived(checks.data?.marks ?? []);
  const choices = $derived(markableAddresses(origins, marks, code));

  let picking = $state(false);
  let picked = $state<string | null>(null);
  let marking = $state(false);
  const chosen = $derived(choices.find((c) => c.edgeId === picked) ?? null);

  function start() {
    picked = choices[0]?.edgeId ?? null;
    picking = true;
  }
  function next() {
    if (!chosen) return;
    picking = false;
    marking = true;
  }
</script>

<Button
  size="sm"
  variant="outline"
  disabled={!listed || choices.length === 0}
  title={!listed
    ? 'Add this country to the censored-country list first.'
    : choices.length === 0
      ? 'No address to mark yet.'
      : undefined}
  onclick={start}
>
  Mark an address for this country
</Button>

<Dialog.Root bind:open={picking}>
  <Dialog.Content class={DIALOG_FIT}>
    <Dialog.Header>
      <Dialog.Title>Mark an address for {countryName(code, 'en')}</Dialog.Title>
      <Dialog.Description>
        Pick the address. Next, say whether it works there, is blocked there, or the checks decide.
      </Dialog.Description>
    </Dialog.Header>
    <fieldset class="space-y-2">
      <legend class="sr-only">Address</legend>
      {#each choices as c (c.edgeId)}
        <label
          class="has-[:checked]:border-primary has-[:checked]:bg-primary/5 flex cursor-pointer items-start gap-2 rounded-md border px-3 py-2"
        >
          <input
            type="radio"
            class="accent-primary mt-1"
            name={`${uid}-address`}
            value={c.edgeId}
            checked={picked === c.edgeId}
            onchange={() => (picked = c.edgeId)}
          />
          <span class="min-w-0">
            <span class="block font-mono text-sm break-all">{c.address}</span>
            <span class="text-muted-foreground block text-xs">
              {c.where}{c.mark ? `. Marked: ${MARK_WORDS[c.mark].toLowerCase()}` : ''}
            </span>
          </span>
        </label>
      {/each}
    </fieldset>
    <Dialog.Footer class={STICKY_FOOTER}>
      <Button type="button" variant="outline" onclick={() => (picking = false)}>Cancel</Button>
      <Button type="button" disabled={!chosen} onclick={next}>Next</Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>

{#if chosen}
  <CountryMarkDialog
    bind:open={marking}
    scope="edge"
    ref={chosen.edgeId}
    name={chosen.address}
    countries={[code]}
    marks={marks.filter((m) => m.scope === 'edge' && m.edgeId === chosen.edgeId)}
    country={code}
  />
{/if}
