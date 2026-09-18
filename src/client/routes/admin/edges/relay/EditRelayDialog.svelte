<script lang="ts">
  /**
   * Edit one relay: label, location, pool size, standbys and its own rotation
   * limits. Number knobs use the server bounds (`edgeConfigQuery().bounds`); only
   * changed fields are sent.
   *
   * Props: open (bindable); relay
   */
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import type { RelayAdmin } from '@shared/contracts/edges';
  import * as Dialog from '@client/components/ui/dialog';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import { Switch } from '@client/components/ui/switch';
  import InlineError from '@client/components/InlineError.svelte';
  import {
    edgeConfigQuery,
    invalidateRelay,
    updateRelay,
    type RelayPatch,
  } from '@client/lib/edgesApi';
  import NumberField from '../components/NumberField.svelte';
  import { assertEdgeOk, edgeErrorMessage } from '../lib/edgeErrors';

  interface Props {
    open: boolean;
    relay: RelayAdmin;
  }
  let { open = $bindable(false), relay }: Props = $props();

  const qc = useQueryClient();
  const config = edgeConfigQuery();
  const bounds = $derived(config.data?.bounds ?? {});
  const defaults = $derived(config.data?.defaults ?? {});
  const num = (v: unknown): number | undefined => (typeof v === 'number' ? v : undefined);

  let label = $state('');
  let locationCode = $state('');
  let desiredPublished = $state(1);
  let standbyPerRelay = $state(0);
  let cooldownMinutes = $state(60);
  let maxRotationsPerDay = $state(4);
  let drainMinutes = $state(60);
  let probeNode = $state(false);
  let invalid = $state({
    desired: false,
    standby: false,
    cooldown: false,
    cap: false,
    drain: false,
  });

  // A fresh form every time the dialog opens (not while it is open: a background
  // refetch must not wipe what the operator is typing).
  let seeded = false;
  $effect(() => {
    if (open && !seeded) {
      seeded = true;
      label = relay.label ?? '';
      locationCode = relay.locationCode ?? '';
      desiredPublished = relay.desiredPublished;
      standbyPerRelay = relay.standbyPerRelay;
      cooldownMinutes = relay.cooldownMinutes;
      maxRotationsPerDay = relay.maxRotationsPerDay;
      drainMinutes = relay.drainMinutes;
      probeNode = relay.probeNode;
      save.reset();
    } else if (!open) {
      seeded = false;
    }
  });

  const patch = $derived.by((): RelayPatch => {
    const p: RelayPatch = {};
    const l = label.trim();
    if (l !== (relay.label ?? '')) p.label = l === '' ? null : l;
    const loc = locationCode.trim().toUpperCase();
    if (loc !== (relay.locationCode ?? '')) p.locationCode = loc === '' ? null : loc;
    if (desiredPublished !== relay.desiredPublished) p.desiredPublished = desiredPublished;
    if (standbyPerRelay !== relay.standbyPerRelay) p.standbyPerRelay = standbyPerRelay;
    if (cooldownMinutes !== relay.cooldownMinutes) p.cooldownMinutes = cooldownMinutes;
    if (maxRotationsPerDay !== relay.maxRotationsPerDay) p.maxRotationsPerDay = maxRotationsPerDay;
    if (drainMinutes !== relay.drainMinutes) p.drainMinutes = drainMinutes;
    if (probeNode !== relay.probeNode) p.probeNode = probeNode;
    return p;
  });
  const dirty = $derived(Object.keys(patch).length > 0);
  const anyInvalid = $derived(Object.values(invalid).some(Boolean));

  const save = createMutation(() => ({
    mutationFn: async (p: RelayPatch) => assertEdgeOk(await updateRelay(relay.id, p)),
    onSuccess: () => {
      toast.success('Relay saved.');
      invalidateRelay(qc, relay.slug);
      open = false;
    },
  }));
</script>

<Dialog.Root bind:open>
  <Dialog.Content class="max-h-[90vh] overflow-y-auto sm:max-w-xl">
    <Dialog.Header>
      <Dialog.Title>Edit relay {relay.slug}</Dialog.Title>
      <Dialog.Description>
        The slug, the origin and its address are fixed once edges dial them. Everything here applies
        to this relay only and overrides the fleet defaults in Settings.
      </Dialog.Description>
    </Dialog.Header>
    <form
      class="space-y-4"
      onsubmit={(e) => {
        e.preventDefault();
        if (dirty && !anyInvalid) save.mutate(patch);
      }}
    >
      <div class="grid gap-4 sm:grid-cols-2">
        <div class="space-y-1.5">
          <Label for="relay-label">Label</Label>
          <Input id="relay-label" bind:value={label} maxlength={80} placeholder="Node one" />
          <p class="text-xs text-muted-foreground">
            Shown in the admin only. Leave empty for none.
          </p>
        </div>
        <div class="space-y-1.5">
          <Label for="relay-location">Location code</Label>
          <Input
            id="relay-location"
            bind:value={locationCode}
            maxlength={12}
            class="font-mono uppercase"
            placeholder="ABC"
          />
          <p class="text-xs text-muted-foreground">
            The member-facing location this origin belongs to. Leave empty for none.
          </p>
        </div>
      </div>
      <div class="grid gap-4 sm:grid-cols-2">
        <NumberField
          bind:value={desiredPublished}
          bind:invalid={invalid.desired}
          label="Published edges wanted"
          unit="edges"
          bounds={bounds['desiredPublishedDefault']}
          min={1}
          max={4}
          defaultValue={num(defaults['desiredPublishedDefault'])}
          helper="How many edges members are spread over. More edges cost more and survive a block better."
        />
        <NumberField
          bind:value={standbyPerRelay}
          bind:invalid={invalid.standby}
          label="Standbys to keep"
          unit="edges"
          bounds={bounds['standbyPerRelay']}
          min={0}
          max={2}
          defaultValue={num(defaults['standbyPerRelay'])}
          helper="Provisioned but unpublished edges. A rotation that finds one skips the slow provisioning."
        />
        <NumberField
          bind:value={cooldownMinutes}
          bind:invalid={invalid.cooldown}
          label="Cooldown between rotations"
          unit="min"
          bounds={bounds['cooldownMinutes']}
          min={10}
          max={1440}
          defaultValue={num(defaults['cooldownMinutes'])}
          helper="After a rotation, automatic ones wait this long."
        />
        <NumberField
          bind:value={maxRotationsPerDay}
          bind:invalid={invalid.cap}
          label="Rotations per day, at most"
          bounds={bounds['maxRotationsPerRelayPerDay']}
          min={1}
          max={12}
          defaultValue={num(defaults['maxRotationsPerRelayPerDay'])}
          helper="The daily cap that keeps a confused detector from burning through budget."
        />
        <NumberField
          bind:value={drainMinutes}
          bind:invalid={invalid.drain}
          label="Drain time of a replaced edge"
          unit="min"
          bounds={bounds['drainMinutes']}
          min={1}
          max={10080}
          defaultValue={num(defaults['drainMinutes'])}
          helper="How long a replaced edge keeps forwarding before it is destroyed, so members who have not refreshed stay connected."
        />
      </div>
      {#if relay.origin.kind !== 'manual' || relay.probeNode}
        <div class="flex items-start justify-between gap-4 rounded-md border p-3">
          <div>
            <Label for="relay-probe-node">Probe the origin itself</Label>
            <p class="text-xs text-muted-foreground">
              Also measures the origin address from outside, as operator evidence. It costs probe
              budget and tells probe networks the origin address. The detector never reads it.
            </p>
          </div>
          <Switch id="relay-probe-node" bind:checked={probeNode} />
        </div>
      {/if}
      {#if save.error}
        <InlineError message={edgeErrorMessage(save.error)} />
      {/if}
      <Dialog.Footer>
        <Button type="button" variant="outline" onclick={() => (open = false)}>Cancel</Button>
        <Button type="submit" disabled={!dirty || anyInvalid || save.isPending}>
          {save.isPending ? 'Saving…' : dirty ? 'Save changes' : 'Nothing changed'}
        </Button>
      </Dialog.Footer>
    </form>
  </Dialog.Content>
</Dialog.Root>
