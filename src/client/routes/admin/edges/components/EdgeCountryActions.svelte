<script lang="ts">
  /**
   * The checks from each country for one address: its line per checked country
   * (CountryLines) and a "Countries" menu with "Mark for a country" (the
   * operator's word, CountryMarkDialog) and "Check from every country now" (one
   * round, `POST countries/check`, throttled like a probe request). Renders
   * nothing while the checks are off and the address has no evidence.
   *
   * Props:
   *   edgeId: string
   *   name: string                          the address, for the dialog title
   *   data: EdgeCountriesResponse | null    from `edgeCountriesQuery` (the caller's one read)
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import Globe from '@lucide/svelte/icons/globe';
  import { Button } from '@client/components/ui/button';
  import * as DropdownMenu from '@client/components/ui/dropdown-menu';
  import { invalidateCountries, requestCountryCheck } from '@client/lib/edgesApi';
  import type { EdgeCountriesResponse } from '@shared/contracts/edges';
  import { countryCheckPending, noteCountryCheck } from '../lib/countryCheckRequests';
  import { edgeCountryLines } from '../lib/countryChecks';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import CountryLines from './CountryLines.svelte';
  import CountryMarkDialog from './CountryMarkDialog.svelte';

  interface Props {
    edgeId: string;
    name: string;
    data: EdgeCountriesResponse | null;
  }
  let { edgeId, name, data }: Props = $props();
  const qc = useQueryClient();

  const lines = $derived(edgeCountryLines(data, edgeId));
  const hasEvidence = $derived(!!data?.edges.some((e) => e.edgeId === edgeId));
  const shown = $derived(!!data && data.countries.length > 0 && (data.enabled || hasEvidence));
  let now = $state(Date.now());
  $effect(() => {
    const t = setInterval(() => (now = Date.now()), 30_000);
    return () => clearInterval(t);
  });
  const checking = $derived(countryCheckPending(data, edgeId, now));
  const marks = $derived(
    (data?.marks ?? []).filter((m) => m.scope === 'edge' && m.edgeId === edgeId),
  );

  let markOpen = $state(false);
  let asking = $state(false);
  async function checkNow() {
    asking = true;
    try {
      await requestCountryCheck(edgeId);
      noteCountryCheck(edgeId);
      invalidateCountries(qc);
      toast.success('Checking from every country. Results show as they come back.');
    } catch (e) {
      toast.error(edgeErrorMessage(e));
    } finally {
      asking = false;
    }
  }
</script>

{#if shown && data}
  <div class="mt-1.5 flex items-start gap-2 ps-1">
    <div class="min-w-0 flex-1">
      <CountryLines {lines} {checking} label={`${name} from each country`} />
    </div>
    <DropdownMenu.Root>
      <DropdownMenu.Trigger>
        {#snippet child({ props })}
          <Button
            {...props}
            variant="ghost"
            size="sm"
            class="h-11 shrink-0 px-2 text-xs sm:h-7"
            aria-label={`Countries for ${name}`}
          >
            <Globe aria-hidden="true" /> Countries
          </Button>
        {/snippet}
      </DropdownMenu.Trigger>
      <DropdownMenu.Content align="end" class="w-60">
        <DropdownMenu.Item onSelect={() => (markOpen = true)}>Mark for a country</DropdownMenu.Item>
        <DropdownMenu.Item disabled={asking || checking || !data.enabled} onSelect={checkNow}>
          Check from every country now
        </DropdownMenu.Item>
      </DropdownMenu.Content>
    </DropdownMenu.Root>
  </div>
  <CountryMarkDialog
    bind:open={markOpen}
    scope="edge"
    ref={edgeId}
    {name}
    countries={data.countries}
    {marks}
  />
{/if}
