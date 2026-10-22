<script lang="ts">
  /**
   * What one new address at a location costs a month, before it is created
   * (docs/edges.md § "Plans and prices"): the plan of the size it is built
   * with, priced, with the account's own choice laid over it ("plus traffic"
   * for a per-GB plan). The size is the one `options` choose (a node's options
   * at the pick, a one-off choice), else the location's own. Renders nothing
   * for a location it does not know.
   *
   * Props:
   *   accountId: string | null
   *   locationId: string | null
   *   options?: unknown     the provider options the address is built with (only what differs)
   *   each?: boolean        several addresses may be created there ("Each address")
   */
  import { providersQuery } from '@client/lib/edgesApi';
  import { costWords, sourceWords } from '../lib/planWords';

  interface Props {
    accountId: string | null;
    locationId: string | null;
    options?: unknown;
    each?: boolean;
  }
  let { accountId, locationId, options = null, each = false }: Props = $props();

  const providers = providersQuery();
  const account = $derived(
    accountId ? (providers.data?.accounts.find((a) => a.id === accountId) ?? null) : null,
  );
  const pricing = $derived(
    account && locationId
      ? (account.locations.find((l) => l.id === locationId)?.pricing ?? null)
      : null,
  );
  /** The size the options choose (the provider's size field), when they choose one. */
  const chosenSize = $derived.by(() => {
    if (!account || !options || typeof options !== 'object') return null;
    const key = providers.data?.optionSchemas[account.provider]?.fields.find(
      (f) => f.from === 'flavors',
    )?.key;
    const v = key ? (options as Record<string, unknown>)[key] : undefined;
    return typeof v === 'string' && v.trim() !== '' ? v.trim().toLowerCase() : null;
  });
  const chosenPlan = $derived(
    chosenSize ? (pricing?.plans.find((p) => p.size.toLowerCase() === chosenSize) ?? null) : null,
  );
  const plan = $derived(chosenPlan ?? pricing?.plan ?? null);
  const cost = $derived(chosenPlan?.cost ?? pricing?.cost ?? null);
</script>

{#if pricing && cost}
  <p class="text-muted-foreground text-xs">
    {each ? 'Each address' : 'This address'}{plan ? ` (${plan.label})` : ''}: {costWords(
      cost,
    )}{plan && cost.basis === 'list' ? ` (${sourceWords(plan).toLowerCase()})` : ''}.
  </p>
{/if}
