<script lang="ts">
  /**
   * Start test block evidence on one PUBLISHED edge (a test deployment only:
   * the menu offers it while the origin's simulations view says `available`).
   * The block detector then reads the address as blocked in the chosen country
   * and, with automatic protection on, replaces it for real (docs/edges.md
   * "Simulating a block on a test deployment"). Mount it while wanted with
   * `open={true}`; typed confirmation of the address.
   *
   * Props: relay; edge; onClose()
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import type { EdgeAdmin, OriginAdmin } from '@shared/contracts/edges';
  import { Label } from '@client/components/ui/label';
  import * as Select from '@client/components/ui/select';
  import {
    edgeConfigQuery,
    edgeKeys,
    invalidateOverview,
    simulateBlock,
  } from '@client/lib/edgesApi';
  import NumberField from '../components/NumberField.svelte';
  import ActionConfirm from './ActionConfirm.svelte';
  import { edgeAddress } from './relayLogic';

  interface Props {
    relay: OriginAdmin;
    edge: EdgeAdmin;
    onClose: () => void;
  }
  let { relay, edge, onClose }: Props = $props();

  const qc = useQueryClient();
  const config = edgeConfigQuery();
  const countries = $derived(config.data?.config.probe.countries ?? []);
  const minReporters = $derived(
    Number((config.data?.config.detect as Record<string, unknown> | undefined)?.minReporters) || 4,
  );
  const name = $derived(edgeAddress(edge) || edge.name);

  let open = $state(true);
  let country = $state('');
  let reporters = $state(8);
  let minutes = $state(60);
  let reportersInvalid = $state(false);
  let minutesInvalid = $state(false);
  let seeded = false;
  $effect(() => {
    // Defaults once the settings are known: the first checked country, twice the detector's minimum.
    if (seeded || !config.data) return;
    seeded = true;
    country = countries[0] ?? '';
    reporters = Math.min(50, Math.max(1, 2 * minReporters));
  });

  async function start(): Promise<void> {
    await simulateBlock(edge.id, { country, reporters, minutes });
    toast.success('Test block started. The detector looks again within five minutes.');
    void qc.invalidateQueries({ queryKey: edgeKeys.relaySimulations(relay.slug) });
    invalidateOverview(qc);
  }
</script>

<ActionConfirm
  bind:open
  title={`Simulate a block of ${name}?`}
  body={`FCP will act as if this address is blocked in ${country || 'the chosen country'}. With automatic protection on, it replaces the address for real: members move to a spare and this address is removed after its drain. Use it on a test deployment only.`}
  typed={name}
  confirmLabel="Start test block"
  danger
  disabled={!country || reportersInvalid || minutesInvalid}
  {onClose}
  run={start}
>
  <div class="mt-3 space-y-4">
    <div class="space-y-1.5">
      <Label for="simulate-country">Country</Label>
      {#if countries.length === 0}
        <p class="text-muted-foreground text-sm">
          No country has address checks on. Turn them on for one under Settings first.
        </p>
      {:else}
        <Select.Root type="single" value={country} onValueChange={(v) => (country = v)}>
          <Select.Trigger id="simulate-country" class="w-full">{country || 'Choose'}</Select.Trigger
          >
          <Select.Content>
            {#each countries as c (c)}
              <Select.Item value={c}>{c}</Select.Item>
            {/each}
          </Select.Content>
        </Select.Root>
        <p class="text-muted-foreground text-xs">
          Only countries addresses are checked from count. Pick one where the checks have vantages,
          or an automatic replacement of a CDN front cannot be proven.
        </p>
      {/if}
    </div>
    <NumberField
      bind:value={reporters}
      bind:invalid={reportersInvalid}
      label="Members who report it"
      unit="members"
      min={1}
      max={50}
      helper="Counted as distinct members reporting this address, on top of real reports."
    />
    <NumberField
      bind:value={minutes}
      bind:invalid={minutesInvalid}
      label="Ends after"
      unit="min"
      min={15}
      max={360}
      helper="It also ends when the detector replaces the address, or when you end it."
    />
  </div>
</ActionConfirm>
