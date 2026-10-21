<script lang="ts">
  /**
   * The provider options one node gets at one location (a pick of its set):
   * a line saying what differs from what the location builds with anyway,
   * and an Options fold with the main choices first and every other option
   * under "All options". Used on each pick of the protect sheet and the set card.
   *
   * Props:
   *   accountId, locationId                the pick
   *   fields: EdgeTemplateField[]          the provider's options (`optionSchemas`)
   *   base: Params                         what the location builds with without choices
   *   values: Params                       what this node chose (only what differs)
   *   readonly?: boolean                   show the line only (a live node changes by re-protecting)
   *   onchange?(values: Params)
   */
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import * as Collapsible from '@client/components/ui/collapsible';
  import { providerInventoryQuery } from '@client/lib/edgesApi';
  import type { EdgeTemplateField } from '@shared/contracts/edges';
  import OptionFields from '../templates/OptionFields.svelte';
  import { optionSummary } from '../lib/options';
  import type { Params } from '../templates/params';

  interface Props {
    accountId: string;
    locationId: string;
    fields: readonly EdgeTemplateField[];
    base: Params;
    values: Params;
    readonly?: boolean;
    onchange?: (values: Params) => void;
  }
  let { accountId, locationId, fields, base, values, readonly = false, onchange }: Props = $props();

  let open = $state(false);
  const words = $derived(optionSummary(fields, values));
  // The location's sizes, read when the fold opens (a size field offers them).
  const wantsSizes = $derived(open && fields.some((f) => f.from === 'flavors'));
  const inventory = providerInventoryQuery(
    () => (wantsSizes ? accountId : null),
    () => locationId,
  );
  const offered = $derived(inventory.data?.inventory?.flavors ?? []);
</script>

{#if readonly}
  <span class="text-muted-foreground block text-xs">
    {words.length > 0 ? `Options: ${words.join(', ')}.` : "Built with the location's defaults."}
  </span>
{:else}
  <Collapsible.Root bind:open>
    <Collapsible.Trigger
      class="group text-muted-foreground hover:text-foreground flex min-h-11 items-center gap-1 text-left text-xs sm:min-h-0"
    >
      <ChevronRight class="size-3.5 shrink-0 transition-transform group-data-[state=open]:rotate-90" />
      <span
        >Options{words.length > 0 ? `: ${words.join(', ')}` : ": the location's defaults"}</span
      >
    </Collapsible.Trigger>
    <Collapsible.Content class="pt-2">
      <OptionFields
        {fields}
        {values}
        {base}
        baseWord="the location's defaults"
        {offered}
        prominentFirst
        onchange={(next) => onchange?.(next)}
      />
    </Collapsible.Content>
  </Collapsible.Root>
{/if}
