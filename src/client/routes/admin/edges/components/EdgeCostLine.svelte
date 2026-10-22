<script lang="ts">
  /**
   * What one new address at a location costs a month, before it is created
   * (docs/edges.md § "Plans and prices"): the location's plan priced, with the
   * account's own choice laid over it ("plus traffic" for a per-GB plan).
   * Renders nothing for a location it does not know.
   *
   * Props:
   *   accountId: string | null
   *   locationId: string | null
   *   each?: boolean        several addresses may be created there ("Each address")
   */
  import { providersQuery } from '@client/lib/edgesApi';
  import { costWords, sourceWords } from '../lib/planWords';

  interface Props {
    accountId: string | null;
    locationId: string | null;
    each?: boolean;
  }
  let { accountId, locationId, each = false }: Props = $props();

  const providers = providersQuery();
  const pricing = $derived(
    accountId && locationId
      ? (providers.data?.accounts
          .find((a) => a.id === accountId)
          ?.locations.find((l) => l.id === locationId)?.pricing ?? null)
      : null,
  );
</script>

{#if pricing}
  <p class="text-muted-foreground text-xs">
    {each ? 'Each address' : 'This address'}: {costWords(pricing.cost)}{pricing.plan &&
    pricing.cost.basis === 'list'
      ? ` (${sourceWords(pricing.plan).toLowerCase()})`
      : ''}.
  </p>
{/if}
