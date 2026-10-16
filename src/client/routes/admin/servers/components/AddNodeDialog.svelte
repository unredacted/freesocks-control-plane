<script lang="ts">
  /**
   * "Add a node" by hand on the Nodes tab: one node row on the backend (name,
   * where the backend reaches it, the profile it runs and the transports it
   * serves), sent once through the operations ledger. The node role is the
   * normal way a node arrives (it enrolls the machine, and FCP writes the row,
   * the addresses and the approval); this dialog says so first and is for a
   * machine the role does not run.
   *
   * Before anything is sent it shows the placement check: which mode groups
   * list each chosen transport, and what the backend says about every mode's
   * pool (`POST placements/validate`, counts and names only). Pure logic:
   * ../lib/addNode.ts.
   *
   * Props: open (bindable), slug, tree
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import CircleCheck from '@lucide/svelte/icons/circle-check';
  import TriangleAlert from '@lucide/svelte/icons/triangle-alert';
  import { Button } from '@client/components/ui/button';
  import { Checkbox } from '@client/components/ui/checkbox';
  import * as Dialog from '@client/components/ui/dialog';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { createNode, placementCheckQuery } from '@client/lib/serversApi';
  import type { ServerTree } from '../../../../../shared/contracts/servers';
  import { nodeFormProblems, placementCheck, placementLines } from '../lib/addNode';
  import { runWrite } from '../lib/run';

  interface Props {
    open: boolean;
    slug: string;
    tree: ServerTree;
  }
  let { open = $bindable(false), slug, tree }: Props = $props();
  const qc = useQueryClient();
  const uid = $props.id();

  let name = $state('');
  let address = $state('');
  let port = $state('');
  let countryCode = $state('');
  let profileUuid = $state('');
  let transportUuids = $state<string[]>([]);
  let tried = $state(false);
  let busy = $state(false);

  const pools = placementCheckQuery(
    () => slug,
    () => open,
  );
  const profile = $derived(tree.profiles.find((p) => p.profileUuid === profileUuid) ?? null);
  // A new profile pick selects every one of its transports (the usual case).
  let pickedFor = '';
  $effect(() => {
    if (profileUuid === pickedFor) return;
    pickedFor = profileUuid;
    transportUuids = profile ? profile.transports.map((t) => t.transportUuid) : [];
  });
  // A fresh form each time it opens.
  let wasOpen = false;
  $effect(() => {
    if (open && !wasOpen) {
      name = '';
      address = '';
      port = '';
      countryCode = '';
      profileUuid = tree.profiles.length === 1 ? tree.profiles[0]!.profileUuid : '';
      tried = false;
    }
    wasOpen = open;
  });

  const form = $derived({ name, address, port, countryCode, profileUuid, transportUuids });
  const problems = $derived(
    nodeFormProblems(
      form,
      tree.nodes.map((n) => n.name),
    ),
  );
  const chosen = $derived(
    (profile?.transports ?? []).filter((t) => transportUuids.includes(t.transportUuid)),
  );
  const lines = $derived(
    placementLines(placementCheck(chosen, tree.modeGroups, pools.data ?? null)),
  );

  function toggle(uuid: string, on: boolean) {
    transportUuids = on
      ? [...new Set([...transportUuids, uuid])]
      : transportUuids.filter((u) => u !== uuid);
  }

  async function submit() {
    tried = true;
    if (problems.length > 0 || busy) return;
    busy = true;
    try {
      const op = await runWrite(qc, () =>
        createNode(slug, {
          name: name.trim(),
          address: address.trim(),
          ...(port.trim() ? { port: Number(port) } : {}),
          ...(countryCode.trim() ? { countryCode: countryCode.trim().toUpperCase() } : {}),
          configProfileUuid: profileUuid,
          activeInboundUuids: transportUuids,
        }),
      );
      if (op) open = false;
    } finally {
      busy = false;
    }
  }

  const FIELD = 'min-h-11 sm:min-h-9';
</script>

<Dialog.Root bind:open>
  <Dialog.Content class="max-h-[90dvh] overflow-y-auto sm:max-w-lg">
    <Dialog.Header>
      <Dialog.Title>Add a node</Dialog.Title>
      <Dialog.Description>
        Most nodes arrive through the node role: run it on the new machine and the node enrolls
        itself here, and FCP writes its row, its addresses and its approval. Add one by hand only
        for a machine the node role does not run.
      </Dialog.Description>
    </Dialog.Header>
    <form
      class="space-y-4"
      novalidate
      onsubmit={(e) => {
        e.preventDefault();
        void submit();
      }}
    >
      <div class="space-y-1.5">
        <Label for={`${uid}-name`}>Name</Label>
        <Input
          id={`${uid}-name`}
          class={FIELD}
          bind:value={name}
          autocomplete="off"
          spellcheck={false}
          aria-describedby={`${uid}-name-hint`}
        />
        <p id={`${uid}-name-hint`} class="text-muted-foreground text-xs">
          Members never see it. FCP finds the node by this name, so pick one and keep it.
        </p>
      </div>
      <div class="grid grid-cols-3 gap-3">
        <div class="col-span-2 space-y-1.5">
          <Label for={`${uid}-address`}>Address</Label>
          <Input
            id={`${uid}-address`}
            class={FIELD}
            bind:value={address}
            autocomplete="off"
            spellcheck={false}
          />
        </div>
        <div class="space-y-1.5">
          <Label for={`${uid}-port`}>Port</Label>
          <Input
            id={`${uid}-port`}
            class={FIELD}
            bind:value={port}
            inputmode="numeric"
            autocomplete="off"
            placeholder="Default"
          />
        </div>
      </div>
      <p class="text-muted-foreground -mt-2 text-xs">
        Where the backend reaches the node, not where members connect.
      </p>
      <div class="space-y-1.5">
        <Label for={`${uid}-country`}>Country code (optional)</Label>
        <Input
          id={`${uid}-country`}
          class="{FIELD} w-24 uppercase"
          bind:value={countryCode}
          maxlength={2}
          autocomplete="off"
        />
      </div>
      <div class="space-y-1.5">
        <Label for={`${uid}-profile`}>Profile it runs</Label>
        <select
          id={`${uid}-profile`}
          class="bg-background border-input min-h-11 w-full rounded-md border px-3 py-2 text-sm sm:min-h-9"
          bind:value={profileUuid}
        >
          <option value="">Pick a profile</option>
          {#each tree.profiles as p (p.profileUuid)}
            <option value={p.profileUuid}>{p.name}</option>
          {/each}
        </select>
      </div>
      {#if profile}
        <fieldset class="space-y-1">
          <legend class="text-sm font-medium">Transports it serves</legend>
          {#each profile.transports as t (t.transportUuid)}
            <label class="flex min-h-11 items-center gap-3 text-sm sm:min-h-8">
              <Checkbox
                checked={transportUuids.includes(t.transportUuid)}
                onCheckedChange={(v) => toggle(t.transportUuid, v === true)}
              />
              <span class="min-w-0 break-all">
                {t.tag}
                <span class="text-muted-foreground">
                  {[t.protocol, t.network, t.port === null ? null : `port ${t.port}`]
                    .filter(Boolean)
                    .join(', ')}
                </span>
              </span>
            </label>
          {/each}
        </fieldset>

        <section aria-labelledby={`${uid}-check`} class="rounded-lg border p-3">
          <h3 id={`${uid}-check`} class="text-sm font-medium">Can members reach it?</h3>
          <p class="text-muted-foreground mt-0.5 text-xs">
            A member reaches a node through a mode group that lists its transport, in a mode's pool.
          </p>
          {#if pools.isPending}
            <Skeleton class="mt-2 h-12 w-full" />
          {:else}
            <ul class="mt-2 space-y-1 text-sm" aria-label="Placement check">
              {#each lines as l (l.text)}
                <li class="flex items-start gap-2">
                  {#if l.ok}
                    <CircleCheck
                      class="mt-0.5 size-4 shrink-0 text-emerald-600 dark:text-emerald-400"
                      aria-label="Fine"
                    />
                  {:else}
                    <TriangleAlert
                      class="mt-0.5 size-4 shrink-0 text-amber-600 dark:text-amber-400"
                      aria-label="Look at this"
                    />
                  {/if}
                  <span class="min-w-0">{l.text}</span>
                </li>
              {/each}
            </ul>
            {#if pools.isError}
              <p class="text-muted-foreground mt-2 text-xs">
                The mode pools could not be checked just now.
              </p>
            {/if}
          {/if}
        </section>
      {/if}

      {#if tried && problems.length > 0}
        <ul class="text-destructive space-y-0.5 text-sm" role="alert">
          {#each problems as p (p)}
            <li>{p}</li>
          {/each}
        </ul>
      {/if}

      <Dialog.Footer>
        <Button type="button" variant="outline" class={FIELD} onclick={() => (open = false)}>
          Cancel
        </Button>
        <Button type="submit" class={FIELD} disabled={busy}>Add the node</Button>
      </Dialog.Footer>
    </form>
  </Dialog.Content>
</Dialog.Root>
