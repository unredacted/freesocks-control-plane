<script lang="ts">
  /**
   * The squads of one panel: which inbounds each one grants. Changing a squad's
   * inbounds makes the panel push to the nodes that serve them, so that change
   * stays open until those nodes have picked it up.
   *
   * Props: slug, tree, canWrite (false = list only)
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { Button } from '@client/components/ui/button';
  import { Checkbox } from '@client/components/ui/checkbox';
  import * as Dialog from '@client/components/ui/dialog';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import { createSquad, deleteSquad, updateSquad } from '@client/lib/serversApi';
  import type { ServerTree } from '../../../../../shared/contracts/servers';
  import ConfirmDialog from '../../edges/components/ConfirmDialog.svelte';
  import { runWrite } from '../lib/run';

  let { slug, tree, canWrite }: { slug: string; tree: ServerTree; canWrite: boolean } = $props();
  type Squad = ServerTree['squads'][number];
  const qc = useQueryClient();
  const uid = $props.id();

  let inbounds = $derived(
    tree.profiles.flatMap((p) => p.inbounds.map((i) => ({ ...i, profile: p.name }))),
  );

  let open = $state(false);
  let editing = $state<Squad | null>(null);
  let name = $state('');
  let picked = $state<string[]>([]);
  let restore = $state(false);
  let busy = $state(false);
  let removeOpen = $state(false);

  function start(squad: Squad | null) {
    editing = squad;
    name = squad?.name ?? '';
    picked = [...(squad?.inboundUuids ?? [])];
    restore = false;
    open = true;
  }

  const toggle = (uuid: string, on: boolean) =>
    (picked = on ? [...picked, uuid] : picked.filter((u) => u !== uuid));

  let sameInbounds = $derived(
    !!editing && [...picked].sort().join() === [...editing.inboundUuids].sort().join(),
  );
  let valid = $derived(/^[A-Za-z0-9_-]{2,20}$/.test(name.trim()));

  async function save() {
    if (!valid || busy) return;
    busy = true;
    try {
      const squad = editing;
      const op = await runWrite(qc, () => {
        if (!squad) return createSquad(slug, { name: name.trim(), inboundUuids: picked, restore });
        // Only what changed is sent: a rename alone queues no work on any node.
        const fields: { name?: string; inboundUuids?: string[] } = {};
        if (name.trim() !== squad.name) fields.name = name.trim();
        if (!sameInbounds) fields.inboundUuids = picked;
        return updateSquad(slug, squad.squadUuid, fields);
      });
      if (op) open = false;
    } finally {
      busy = false;
    }
  }

  async function remove() {
    const squad = editing;
    if (!squad) return;
    removeOpen = false;
    open = false;
    await runWrite(qc, () => deleteSquad(slug, squad.squadUuid));
  }
</script>

<section aria-labelledby="squads">
  <div class="mb-3 flex items-center justify-between gap-3">
    <h2 id="squads" class="text-base font-semibold">Squads</h2>
    {#if canWrite}
      <Button variant="outline" size="sm" onclick={() => start(null)}>Add a squad</Button>
    {/if}
  </div>
  {#if tree.squads.length === 0}
    <p class="text-muted-foreground text-sm">No squads yet.</p>
  {:else}
    <ul class="divide-y rounded-lg border text-sm">
      {#each tree.squads as squad (squad.squadUuid)}
        <li class="flex flex-wrap items-center gap-3 px-3 py-2.5">
          <span class="min-w-0 flex-1">
            <span class="block font-medium break-all">{squad.name}</span>
            <span class="text-muted-foreground block break-all">
              {squad.inboundTags.filter(Boolean).join(', ') || 'No inbounds'}
              {#if squad.membersCount !== null}
                · {squad.membersCount} {squad.membersCount === 1 ? 'member' : 'members'}
              {/if}
            </span>
          </span>
          {#if canWrite}
            <Button variant="ghost" size="sm" onclick={() => start(squad)}>Change</Button>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
</section>

<Dialog.Root bind:open>
  <Dialog.Content class="sm:max-w-md">
    <Dialog.Header>
      <Dialog.Title>{editing ? `Change ${editing.name}` : 'Add a squad'}</Dialog.Title>
      <Dialog.Description>Keys in a squad can use the inbounds ticked here.</Dialog.Description>
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
        <legend class="text-sm font-medium">Inbounds</legend>
        {#each inbounds as i (i.inboundUuid)}
          <div class="flex items-center gap-2">
            <Checkbox
              id={`${uid}-${i.inboundUuid}`}
              checked={picked.includes(i.inboundUuid)}
              onCheckedChange={(v) => toggle(i.inboundUuid, v === true)}
            />
            <Label for={`${uid}-${i.inboundUuid}`} class="font-normal break-all">
              {i.tag} <span class="text-muted-foreground">({i.profile})</span>
            </Label>
          </div>
        {/each}
      </fieldset>
      {#if editing && !sameInbounds}
        <p class="text-muted-foreground text-sm">
          New inbounds are pushed to the nodes that serve them.
        </p>
      {/if}
      {#if !editing}
        <div class="flex items-start gap-2">
          <Checkbox id={`${uid}-restore`} bind:checked={restore} />
          <Label for={`${uid}-restore`} class="leading-snug font-normal">
            Bring back a squad of this name that was removed on purpose
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
  body="Only an empty squad that no connection mode issues into can be removed."
  typed={editing?.name}
  confirmLabel="Remove"
  danger
  onConfirm={remove}
/>
