<script lang="ts">
  /**
   * The mode groups of one backend: which transports each one grants. Changing a
   * group's transports makes the backend push to the nodes that serve them, so
   * that change stays open until those nodes have picked it up.
   *
   * Props: slug, tree, canWrite (false = list only)
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { Button } from '@client/components/ui/button';
  import { Checkbox } from '@client/components/ui/checkbox';
  import * as Dialog from '@client/components/ui/dialog';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import { createModeGroup, deleteModeGroup, updateModeGroup } from '@client/lib/serversApi';
  import type { ServerTree } from '../../../../../shared/contracts/servers';
  import ConfirmDialog from '../../edges/components/ConfirmDialog.svelte';
  import { runWrite } from '../lib/run';

  let { slug, tree, canWrite }: { slug: string; tree: ServerTree; canWrite: boolean } = $props();
  type ModeGroup = ServerTree['modeGroups'][number];
  const qc = useQueryClient();
  const uid = $props.id();

  let transports = $derived(
    tree.profiles.flatMap((p) => p.transports.map((i) => ({ ...i, profile: p.name }))),
  );

  let open = $state(false);
  let editing = $state<ModeGroup | null>(null);
  let name = $state('');
  let picked = $state<string[]>([]);
  let restore = $state(false);
  let busy = $state(false);
  let removeOpen = $state(false);

  function start(group: ModeGroup | null) {
    editing = group;
    name = group?.name ?? '';
    picked = [...(group?.transportUuids ?? [])];
    restore = false;
    open = true;
  }

  const toggle = (uuid: string, on: boolean) =>
    (picked = on ? [...picked, uuid] : picked.filter((u) => u !== uuid));

  let sameTransports = $derived(
    !!editing && [...picked].sort().join() === [...editing.transportUuids].sort().join(),
  );
  let valid = $derived(/^[A-Za-z0-9_-]{2,20}$/.test(name.trim()));

  async function save() {
    if (!valid || busy) return;
    busy = true;
    try {
      const group = editing;
      const op = await runWrite(qc, () => {
        if (!group)
          return createModeGroup(slug, { name: name.trim(), transportUuids: picked, restore });
        // Only what changed is sent: a rename alone queues no work on any node.
        const fields: { name?: string; transportUuids?: string[] } = {};
        if (name.trim() !== group.name) fields.name = name.trim();
        if (!sameTransports) fields.transportUuids = picked;
        return updateModeGroup(slug, group.groupUuid, fields);
      });
      if (op) open = false;
    } finally {
      busy = false;
    }
  }

  async function remove() {
    const group = editing;
    if (!group) return;
    removeOpen = false;
    open = false;
    await runWrite(qc, () => deleteModeGroup(slug, group.groupUuid));
  }
</script>

<section aria-labelledby="mode-groups">
  <div class="mb-3 flex items-center justify-between gap-3">
    <h2 id="mode-groups" class="text-base font-semibold">Mode groups</h2>
    {#if canWrite}
      <Button variant="outline" size="sm" onclick={() => start(null)}>Add a group</Button>
    {/if}
  </div>
  {#if tree.modeGroups.length === 0}
    <p class="text-muted-foreground text-sm">No mode groups yet.</p>
  {:else}
    <ul class="divide-y rounded-lg border text-sm">
      {#each tree.modeGroups as group (group.groupUuid)}
        <li class="flex flex-wrap items-center gap-3 px-3 py-2.5">
          <span class="min-w-0 flex-1">
            <span class="block font-medium break-all">{group.name}</span>
            <span class="text-muted-foreground block break-all">
              {group.transportTags.filter(Boolean).join(', ') || 'No transports'}
              {#if group.membersCount !== null}
                · {group.membersCount} {group.membersCount === 1 ? 'member' : 'members'}
              {/if}
            </span>
          </span>
          {#if canWrite}
            <Button variant="ghost" size="sm" onclick={() => start(group)}>Change</Button>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
</section>

<Dialog.Root bind:open>
  <Dialog.Content class="sm:max-w-md">
    <Dialog.Header>
      <Dialog.Title>{editing ? `Change ${editing.name}` : 'Add a mode group'}</Dialog.Title>
      <Dialog.Description>Keys in a group can use the transports ticked here.</Dialog.Description>
    </Dialog.Header>
    <form
      class="space-y-3"
      onsubmit={(e) => {
        e.preventDefault();
        void save();
      }}
    >
      <div class="space-y-1.5">
        <Label for={`${uid}-name`}>Name</Label>
        <Input
          id={`${uid}-name`}
          bind:value={name}
          autocomplete="off"
          spellcheck={false}
          aria-describedby={`${uid}-name-help`}
        />
        <p id={`${uid}-name-help`} class="text-muted-foreground text-sm">
          2 to 20 letters, digits, dashes or underscores.
        </p>
      </div>
      <fieldset class="space-y-2">
        <legend class="text-sm font-medium">Transports</legend>
        {#each transports as i (i.transportUuid)}
          <div class="flex items-center gap-2">
            <Checkbox
              id={`${uid}-${i.transportUuid}`}
              checked={picked.includes(i.transportUuid)}
              onCheckedChange={(v) => toggle(i.transportUuid, v === true)}
            />
            <Label for={`${uid}-${i.transportUuid}`} class="font-normal break-all">
              {i.tag} <span class="text-muted-foreground">({i.profile})</span>
            </Label>
          </div>
        {/each}
      </fieldset>
      {#if editing && !sameTransports}
        <p class="text-muted-foreground text-sm">
          New transports are pushed to the nodes that serve them.
        </p>
      {/if}
      {#if !editing}
        <div class="flex items-start gap-2">
          <Checkbox id={`${uid}-restore`} bind:checked={restore} />
          <Label for={`${uid}-restore`} class="leading-snug font-normal">
            Bring back a group of this name that was removed on purpose
          </Label>
        </div>
      {/if}
      <Dialog.Footer class="gap-2 sm:justify-between">
        {#if editing}
          <Button type="button" variant="ghost" onclick={() => (removeOpen = true)}>Remove</Button>
        {:else}
          <span></span>
        {/if}
        <span class="flex gap-2">
          <Button type="button" variant="outline" onclick={() => (open = false)}>Cancel</Button>
          <Button type="submit" disabled={!valid || busy}>{busy ? 'Working…' : 'Save'}</Button>
        </span>
      </Dialog.Footer>
    </form>
  </Dialog.Content>
</Dialog.Root>

<ConfirmDialog
  bind:open={removeOpen}
  title={`Remove ${editing?.name ?? ''}?`}
  body="Only an empty group that no connection mode issues into can be removed."
  typed={editing?.name}
  confirmLabel="Remove"
  danger
  onConfirm={remove}
/>
