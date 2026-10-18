<script lang="ts">
  /**
   * The header actions of a node page: Edit, Restart (or Turn on), and a More
   * menu with Turn off and the two removes. Removing is two different things
   * and both are named: "Stop and remove" needs the node to be off already;
   * "Remove from the backend only" says that the node process may keep running.
   *
   * An enrolled node adds "Retire node…" after a separator (typed-name confirm
   * that says members lose it at once); the retirement's steps then show in
   * its activation section. Retiring is offered even when backend changes are
   * off (`canWrite` false): the menu then holds only that.
   *
   * Props: slug, node, canWrite, intent (the enrolled node behind it, if any)
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import ChevronDown from '@lucide/svelte/icons/chevron-down';
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';
  import * as DropdownMenu from '@client/components/ui/dropdown-menu';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import { toast } from 'svelte-sonner';
  import {
    deleteNode,
    invalidateServers,
    nodeAction,
    renameNode,
    retireNode,
    updateNode,
  } from '@client/lib/serversApi';
  import type { NodeIntentView, NodeView } from '../../../../../shared/contracts/servers';
  import ConfirmDialog from '../../edges/components/ConfirmDialog.svelte';
  import { codeOf, runWrite } from '../lib/run';
  import { retireConfirmWords, serverErrorWords } from '../lib/words';

  let {
    slug,
    node,
    canWrite = true,
    intent = null,
  }: {
    slug: string;
    node: NodeView;
    canWrite?: boolean;
    intent?: NodeIntentView | null;
  } = $props();
  const qc = useQueryClient();
  const uid = $props.id();

  let busy = $state(false);
  let restartOpen = $state(false);
  let offOpen = $state(false);
  let removeOpen = $state(false);
  let removeOnlyOpen = $state(false);
  let retireOpen = $state(false);
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

  /**
   * Only what changed is sent: an untouched field cannot restart the node. A
   * new name is a rename of its own (it moves every reference to the name).
   */
  async function saveEdit() {
    const fields: Parameters<typeof updateNode>[2] = {};
    const newName = name.trim();
    if (address.trim() !== (node.address ?? '')) fields.address = address.trim();
    if (port.trim() !== '' && Number(port) !== node.port) fields.port = Number(port);
    if (country.trim().toUpperCase() !== (node.countryCode ?? ''))
      fields.countryCode = country.trim().toUpperCase();
    editOpen = false;
    // One Save: a rename starts only when the rest of the edit went through
    // (or there was none), never after a refused one.
    if (Object.keys(fields).length > 0) {
      busy = true;
      let op: Awaited<ReturnType<typeof runWrite>> = null;
      try {
        op = await runWrite(qc, () => updateNode(slug, node.nodeUuid, fields));
      } finally {
        busy = false;
      }
      if (!op || op.state === 'refused' || op.state === 'outcome_unknown') return;
    }
    if (newName !== node.name) await rename(newName);
  }

  async function rename(to: string) {
    busy = true;
    try {
      await renameNode(slug, node.nodeUuid, to);
      toast.success(`Renaming ${node.name} to ${to}. Members keep connecting.`);
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
    } finally {
      busy = false;
      invalidateServers(qc);
    }
  }

  // A role-requested retirement is decided in the activation section instead.
  let retirable = $derived(!!intent && !intent.retirement);
  async function retire() {
    if (!intent) return;
    retireOpen = false;
    busy = true;
    try {
      await retireNode(slug, intent.id);
      toast.success(`Retiring ${intent.name}. Members no longer get it.`);
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
    } finally {
      busy = false;
      invalidateServers(qc);
    }
  }

  let restarts = $derived(
    address.trim() !== (node.address ?? '') || (port.trim() !== '' && Number(port) !== node.port),
  );
</script>

{#if canWrite}
  <Button variant="outline" disabled={busy} onclick={startEdit}>Edit</Button>
  {#if node.isDisabled}
    <Button disabled={busy} onclick={() => act(() => nodeAction(slug, node.nodeUuid, 'enable'))}>
      Turn on
    </Button>
  {:else}
    <Button disabled={busy} onclick={() => (restartOpen = true)}>Restart</Button>
  {/if}
{/if}
{#if canWrite || retirable}
  <DropdownMenu.Root>
    <DropdownMenu.Trigger>
      {#snippet child({ props })}
        <Button {...props} variant="outline" disabled={busy}>
          More <ChevronDown aria-hidden="true" />
        </Button>
      {/snippet}
    </DropdownMenu.Trigger>
    <DropdownMenu.Content align="end" class="w-64">
      {#if canWrite}
        {#if !node.isDisabled}
          <DropdownMenu.Item onSelect={() => (offOpen = true)}>Turn off</DropdownMenu.Item>
        {/if}
        <DropdownMenu.Separator />
        {#if node.isDisabled}
          <DropdownMenu.Item variant="destructive" onSelect={() => (removeOpen = true)}>
            Stop and remove
          </DropdownMenu.Item>
        {/if}
        <DropdownMenu.Item variant="destructive" onSelect={() => (removeOnlyOpen = true)}>
          Remove from the backend only
        </DropdownMenu.Item>
      {/if}
      {#if retirable}
        {#if canWrite}<DropdownMenu.Separator />{/if}
        <DropdownMenu.Item variant="destructive" onSelect={() => (retireOpen = true)}>
          Retire node…
        </DropdownMenu.Item>
      {/if}
    </DropdownMenu.Content>
  </DropdownMenu.Root>
{/if}

<ConfirmDialog
  bind:open={restartOpen}
  title={`Restart ${node.name}?`}
  body="People connected through it are cut off for a few seconds and reconnect on their own."
  confirmLabel="Restart"
  onConfirm={() => {
    restartOpen = false;
    void act(() => nodeAction(slug, node.nodeUuid, 'restart'));
  }}
/>
<ConfirmDialog
  bind:open={offOpen}
  title={`Turn ${node.name} off?`}
  body="Nobody can connect through it until it is turned on again."
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
  body="It is off, so nobody is on it. The panel forgets it, and the node role will not add it back unless you say so."
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
  title={`Remove ${node.name} from the backend only?`}
  body="The panel forgets it, but the node keeps running and serving people until someone stops it on the machine. To stop it first, turn it off and choose Stop and remove."
  typed={node.name}
  confirmLabel="Remove from the panel"
  danger
  onConfirm={() => {
    removeOnlyOpen = false;
    void act(() => deleteNode(slug, node.nodeUuid, true));
  }}
/>

{#if intent}
  <ConfirmDialog
    bind:open={retireOpen}
    title={`Retire ${intent.name}?`}
    body={retireConfirmWords(intent)}
    typed={intent.name}
    confirmLabel="Retire node"
    danger
    onConfirm={retire}
  />
{/if}

<Dialog.Root bind:open={editOpen}>
  <Dialog.Content class="sm:max-w-md">
    <Dialog.Header>
      <Dialog.Title>Edit {node.name}</Dialog.Title>
      <Dialog.Description
        >Where the backend reaches the node, not where members connect.</Dialog.Description
      >
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
        <p class="text-muted-foreground text-sm">A new address or port restarts the node.</p>
      {/if}
      {#if name.trim() !== node.name}
        <p class="text-muted-foreground text-sm">
          A new name is carried over to everything that refers to the node, its addresses included.
          Members keep connecting, and the old name keeps working for the node role.
        </p>
      {/if}
      <Dialog.Footer>
        <Button type="button" variant="outline" onclick={() => (editOpen = false)}>Cancel</Button>
        <Button type="submit">Save</Button>
      </Dialog.Footer>
    </form>
  </Dialog.Content>
</Dialog.Root>
