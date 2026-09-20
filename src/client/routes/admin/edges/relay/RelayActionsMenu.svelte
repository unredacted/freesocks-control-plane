<script lang="ts">
  /**
   * The header "Actions" menu of the origin page, with its dialogs.
   *
   * Props: origin; listeners; edgeCount; onRotationStarted(rotationId)
   */
  import ChevronDown from '@lucide/svelte/icons/chevron-down';
  import type { RelayAdmin, RelayListenerAdmin } from '@shared/contracts/edges';
  import { Button } from '@client/components/ui/button';
  import * as DropdownMenu from '@client/components/ui/dropdown-menu';
  import { invalidateProbes, probeRelay, updateRelay } from '@client/lib/edgesApi';
  import { router } from '@client/stores/router.svelte';
  import TestProvisionDialog from '../forms/TestProvisionDialog.svelte';
  import { edgesPaths } from '../lib/routes';
  import ActionConfirm from './ActionConfirm.svelte';
  import DeleteRelayDialog from './DeleteRelayDialog.svelte';
  import EditRelayDialog from './EditRelayDialog.svelte';
  import HostModeDialog from './HostModeDialog.svelte';
  import ProvisionDialog from './ProvisionDialog.svelte';
  import { relayAction } from './actions.svelte';

  interface Props {
    relay: RelayAdmin;
    listeners: RelayListenerAdmin[];
    /** Non-destroyed edges (the delete dialog says how many are torn down). */
    edgeCount: number;
    onRotationStarted: (rotationId: string) => void;
  }
  let { relay, listeners, edgeCount, onRotationStarted }: Props = $props();

  const act = relayAction(() => relay.slug);

  let editOpen = $state(false);
  let deleteOpen = $state(false);
  let hostModeOpen = $state(false);
  let provisionOpen = $state(false);
  let testProvisionOpen = $state(false);
  let disableOpen = $state(false);
  let autoRotateOpen = $state(false);

  const busy = $derived(relay.deleting);

  function probeNow(): void {
    act.mutate({
      run: () => probeRelay(relay.id),
      success: (res: { runIds: string[]; skipped: string[] }) =>
        res.runIds.length > 0
          ? `${res.runIds.length} probe run(s) requested${res.skipped.length > 0 ? `, ${res.skipped.length} target(s) skipped` : ''}. Results arrive within a minute or two.`
          : 'No probe was started. Check that probes are on, a source is enabled and the hourly budget is not used up.',
      also: invalidateProbes,
    });
  }
  function enable(): void {
    act.mutate({
      run: () => updateRelay(relay.id, { enabled: true }),
      success: 'Origin enabled. Subscriptions on this origin are rendered again.',
    });
  }
</script>

<DropdownMenu.Root>
  <DropdownMenu.Trigger>
    {#snippet child({ props })}
      <Button {...props} variant="outline">Actions <ChevronDown /></Button>
    {/snippet}
  </DropdownMenu.Trigger>
  <DropdownMenu.Content align="end" class="w-60">
    <DropdownMenu.Item onSelect={() => router.navigate(edgesPaths.setup({ relay: relay.slug }))}>
      Open setup
    </DropdownMenu.Item>
    <DropdownMenu.Separator />
    <DropdownMenu.Item disabled={busy} onSelect={() => (provisionOpen = true)}>
      Provision an edge
    </DropdownMenu.Item>
    <DropdownMenu.Item disabled={busy} onSelect={() => (testProvisionOpen = true)}>
      Test provision (new account)
    </DropdownMenu.Item>
    <DropdownMenu.Item disabled={act.isPending} onSelect={probeNow}>Probe now</DropdownMenu.Item>
    <DropdownMenu.Separator />
    {#if relay.enabled}
      <DropdownMenu.Item disabled={busy} onSelect={() => (disableOpen = true)}>
        Disable origin
      </DropdownMenu.Item>
    {:else}
      <DropdownMenu.Item disabled={busy || act.isPending} onSelect={enable}>
        Enable origin
      </DropdownMenu.Item>
    {/if}
    <DropdownMenu.Item disabled={busy} onSelect={() => (autoRotateOpen = true)}>
      Turn auto rotate {relay.autoRotate ? 'off' : 'on'}
    </DropdownMenu.Item>
    {#if relay.hostMode !== 'none'}
      <DropdownMenu.Item disabled={busy} onSelect={() => (hostModeOpen = true)}>
        {relay.hostMode === 'fcp'
          ? 'Write the panel Hosts myself'
          : 'Let FCP write the panel Hosts'}
      </DropdownMenu.Item>
    {/if}
    <DropdownMenu.Item disabled={busy} onSelect={() => (editOpen = true)}>Edit</DropdownMenu.Item>
    <DropdownMenu.Separator />
    <DropdownMenu.Item variant="destructive" disabled={busy} onSelect={() => (deleteOpen = true)}>
      Delete origin
    </DropdownMenu.Item>
  </DropdownMenu.Content>
</DropdownMenu.Root>

<EditRelayDialog bind:open={editOpen} {relay} />
<DeleteRelayDialog bind:open={deleteOpen} {relay} {edgeCount} />
<HostModeDialog bind:open={hostModeOpen} {relay} {listeners} />
<ProvisionDialog bind:open={provisionOpen} {relay} {listeners} onStarted={onRotationStarted} />
{#if testProvisionOpen}
  <TestProvisionDialog
    bind:open={testProvisionOpen}
    relayId={relay.id}
    relaySlug={relay.slug}
    onStarted={onRotationStarted}
  />
{/if}

<ActionConfirm
  bind:open={disableOpen}
  title={`Disable origin ${relay.slug}?`}
  body={relay.origin.kind === 'manual'
    ? 'Rotations and automatic provisioning stop for this relay. Its edges stay where they are.'
    : 'Rendering stops for this origin. Because delivery is edge-required, members on it go dark: their subscription is answered "temporarily unavailable" until the relay is enabled again. Edges stay provisioned and keep billing.'}
  confirmLabel="Disable relay"
  danger
  run={() =>
    act.mutateAsync({
      run: () => updateRelay(relay.id, { enabled: false }),
      success: 'Relay disabled.',
      quiet: true,
    })}
/>

<ActionConfirm
  bind:open={autoRotateOpen}
  title={relay.autoRotate ? 'Turn auto rotate off?' : 'Turn auto rotate on?'}
  body={relay.autoRotate
    ? 'The block detector keeps watching this relay but never replaces an edge on its own. A suspected block then waits for you on the overview.'
    : 'When the block detector suspects a block on this relay, it replaces the affected edge by itself, within the cooldown and the daily cap. Each replacement can spend provider budget. The fleet-wide switch in Settings must be on as well.'}
  confirmLabel={relay.autoRotate ? 'Turn off' : 'Turn on'}
  run={() =>
    act.mutateAsync({
      run: () => updateRelay(relay.id, { autoRotate: !relay.autoRotate }),
      success: relay.autoRotate
        ? 'Auto rotate is off for this relay.'
        : 'Auto rotate is on for this relay.',
      quiet: true,
    })}
/>
