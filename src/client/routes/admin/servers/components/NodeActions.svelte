<script lang="ts">
  /**
   * What can be done to one node's panel row: restart, turn off or on, edit the
   * row, remove. Removing is two different things and both are named: "stop and
   * remove" needs the node to be off already; "remove from the panel only" says
   * that the node process may keep running.
   *
   * Props: slug, node
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import { deleteNode, nodeAction, updateNode } from '@client/lib/serversApi';
  import type { PanelNodeView } from '../../../../../shared/contracts/servers';
  import ConfirmDialog from '../../edges/components/ConfirmDialog.svelte';
  import { runWrite } from '../lib/run';

  let { slug, node }: { slug: string; node: PanelNodeView } = $props();
  const qc = useQueryClient();
  const uid = $props.id();

  let busy = $state(false);
  let restartOpen = $state(false);
  let offOpen = $state(false);
  let removeOpen = $state(false);
  let removeOnlyOpen = $state(false);
  let editOpen = $state(false);
  let name = $state('');
  let address = $state('');
  let port = $state('');
  let country = $state('');

  async function act(write: Parameters<typeof runWrite>[1]) {
    busy = true;
    try {
      await runWrite(qc, write);
    } finally {
      busy = false;
    }
  }

  function startEdit() {
    name = node.name;
    address = node.address ?? '';
    port = node.port === null ? '' : String(node.port);
    country = node.countryCode ?? '';
    editOpen = true;
  }

  /** Only what changed is sent: an untouched field cannot restart the node. */
  async function saveEdit() {
    const fields: Parameters<typeof updateNode>[2] = {};
    if (name.trim() !== node.name) fields.name = name.trim();
    if (address.trim() !== (node.address ?? '')) fields.address = address.trim();
    if (port.trim() !== '' && Number(port) !== node.port) fields.port = Number(port);
    if (country.trim().toUpperCase() !== (node.countryCode ?? ''))
      fields.countryCode = country.trim().toUpperCase();
    editOpen = false;
    if (Object.keys(fields).length === 0) return;
    await act(() => updateNode(slug, node.nodeUuid, fields));
  }

  let restarts = $derived(
    address.trim() !== (node.address ?? '') || (port.trim() !== '' && Number(port) !== node.port),
  );
</script>

<div class="flex flex-wrap gap-2">
  <Button variant="outline" size="sm" disabled={busy} onclick={startEdit}>Edit</Button>
  {#if node.isDisabled}
    <Button
      variant="outline"
      size="sm"
      disabled={busy}
      onclick={() => act(() => nodeAction(slug, node.nodeUuid, 'enable'))}
    >
      Turn on
    </Button>
    <Button variant="outline" size="sm" disabled={busy} onclick={() => (removeOpen = true)}>
      Stop and remove
    </Button>
  {:else}
    <Button variant="outline" size="sm" disabled={busy} onclick={() => (restartOpen = true)}>
      Restart
    </Button>
    <Button variant="outline" size="sm" disabled={busy} onclick={() => (offOpen = true)}>
      Turn off
    </Button>
  {/if}
  <Button variant="ghost" size="sm" disabled={busy} onclick={() => (removeOnlyOpen = true)}>
    Remove from the panel only
  </Button>
</div>

<ConfirmDialog
  bind:open={restartOpen}
  title={`Restart ${node.name}?`}
  body="Everyone connected through this node is cut off for a few seconds and reconnects by themselves."
  confirmLabel="Restart"
  onConfirm={() => {
    restartOpen = false;
    void act(() => nodeAction(slug, node.nodeUuid, 'restart'));
  }}
/>
<ConfirmDialog
  bind:open={offOpen}
  title={`Turn ${node.name} off?`}
  body="Nobody can connect through this node while it is off. Their other servers keep working."
  confirmLabel="Turn off"
  danger
  onConfirm={() => {
    offOpen = false;
    void act(() => nodeAction(slug, node.nodeUuid, 'disable'));
  }}
/>
<ConfirmDialog
  bind:open={removeOpen}
  title={`Remove ${node.name}?`}
  body="The node is already off. This takes it off the panel. It is not created again by the node role unless you bring it back."
  typed={node.name}
  confirmLabel="Remove"
  danger
  onConfirm={() => {
    removeOpen = false;
    void act(() => deleteNode(slug, node.nodeUuid, false));
  }}
/>
<ConfirmDialog
  bind:open={removeOnlyOpen}
  title={`Remove ${node.name} from the panel only?`}
  body="This removes the panel's record of the node and nothing else. The node itself may keep running and serving people until someone stops it on the machine. To stop it first, turn it off and then choose Stop and remove."
  typed={node.name}
  confirmLabel="Remove from the panel"
  danger
  onConfirm={() => {
    removeOnlyOpen = false;
    void act(() => deleteNode(slug, node.nodeUuid, true));
  }}
/>

<Dialog.Root bind:open={editOpen}>
  <Dialog.Content class="sm:max-w-md">
    <Dialog.Header>
      <Dialog.Title>Edit {node.name}</Dialog.Title>
      <Dialog.Description>
        This is the panel's record of the node: where the panel reaches it, not where members
        connect.
      </Dialog.Description>
    </Dialog.Header>
    <form
      class="space-y-3"
      onsubmit={(e) => {
        e.preventDefault();
        void saveEdit();
      }}
    >
      <div class="space-y-1.5">
        <Label for={`${uid}-name`}>Name</Label>
        <Input id={`${uid}-name`} bind:value={name} autocomplete="off" spellcheck={false} />
      </div>
      <div class="grid grid-cols-3 gap-3">
        <div class="col-span-2 space-y-1.5">
          <Label for={`${uid}-address`}>Address</Label>
          <Input id={`${uid}-address`} bind:value={address} autocomplete="off" spellcheck={false} />
        </div>
        <div class="space-y-1.5">
          <Label for={`${uid}-port`}>Port</Label>
          <Input id={`${uid}-port`} bind:value={port} inputmode="numeric" autocomplete="off" />
        </div>
      </div>
      <div class="space-y-1.5">
        <Label for={`${uid}-country`}>Country code</Label>
        <Input
          id={`${uid}-country`}
          bind:value={country}
          maxlength={2}
          class="w-24 uppercase"
          autocomplete="off"
        />
      </div>
      {#if restarts}
        <p class="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm">
          Changing the address or the port makes the panel restart this node.
        </p>
      {/if}
      <Dialog.Footer>
        <Button type="button" variant="outline" onclick={() => (editOpen = false)}>Cancel</Button>
        <Button type="submit">Save</Button>
      </Dialog.Footer>
    </form>
  </Dialog.Content>
</Dialog.Root>
