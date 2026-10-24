<script lang="ts">
  /**
   * Adopt a node that already serves members (docs/servers.md "Adopting a
   * backend"): the operator names the mode it runs; the node is live at once
   * with its current addresses, nothing a member holds changes. A direct node's
   * addresses are found by its name or address unless the operator ticks them.
   * A fronted node whose edge FCP does not run yet is marked so; Edges takes
   * over later.
   *
   * Props: open (bindable), slug, node (name + uuid), modes (the setup's), tree (the backend's)
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { Label } from '@client/components/ui/label';
  import { Switch } from '@client/components/ui/switch';
  import { adoptNode, invalidateServers } from '@client/lib/serversApi';
  import type { ModeSetupView, ServerTree } from '../../../../../shared/contracts/servers';
  import { codeOf } from '../lib/run';
  import { serverErrorWords, shapeWords } from '../lib/words';

  interface Props {
    open: boolean;
    slug: string;
    node: { nodeUuid: string; name: string } | null;
    modes: ModeSetupView[];
    tree: ServerTree | null;
  }
  let { open = $bindable(false), slug, node, modes, tree }: Props = $props();
  const qc = useQueryClient();
  const uid = $props.id();
  let mode = $state('');
  let externallyFronted = $state(false);
  let busy = $state(false);
  // Ticked addresses (none: FCP finds them by the node's name or address).
  let hostUuids = $state<string[]>([]);
  // Every opening starts blank: a tick left from another node would adopt
  // that node's address for this one.
  let openedFor: string | null = null;
  $effect(() => {
    const target = open ? (node?.nodeUuid ?? '') : null;
    if (target === openedFor) return;
    openedFor = target;
    mode = '';
    externallyFronted = false;
    hostUuids = [];
  });
  let picked = $derived(modes.find((m) => m.slug === mode) ?? null);
  let fronted = $derived(!!picked && picked.shape.fronting !== 'direct');
  // The addresses on the picked direct mode's transport, from the last look.
  let candidates = $derived.by(() => {
    if (!picked || fronted || !tree) return [];
    const uuids = new Set(
      tree.profiles.flatMap((p) =>
        p.transports.filter((x) => x.tag === picked!.tag).map((x) => x.transportUuid),
      ),
    );
    return tree.addresses.filter((a) => !!a.transportUuid && uuids.has(a.transportUuid));
  });
  const toggle = (uuid: string, on: boolean) => {
    hostUuids = on ? [...new Set([...hostUuids, uuid])] : hostUuids.filter((u) => u !== uuid);
  };

  async function submit() {
    if (!node || !mode) return;
    busy = true;
    try {
      const named = hostUuids.filter((u) => candidates.some((a) => a.addressUuid === u));
      const r = await adoptNode(slug, {
        nodeUuid: node.nodeUuid,
        mode,
        externallyFronted: fronted && externallyFronted,
        ...(!fronted && named.length > 0 ? { hostUuids: named } : {}),
      });
      toast.success(
        r.addresses > 0
          ? `${node.name} adopted with ${r.addresses} address${r.addresses === 1 ? '' : 'es'}.`
          : `${node.name} adopted.`,
      );
      open = false;
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
    } finally {
      busy = false;
      invalidateServers(qc);
    }
  }
</script>

<Dialog.Root bind:open>
  <Dialog.Content class="sm:max-w-md">
    <Dialog.Header>
      <Dialog.Title>Adopt {node?.name ?? 'this node'}</Dialog.Title>
      <Dialog.Description>
        It already serves members: it is live at once with the addresses it has, and nothing a
        member holds changes. The role is never run for it.
      </Dialog.Description>
    </Dialog.Header>
    <form
      class="space-y-4"
      onsubmit={(e) => {
        e.preventDefault();
        void submit();
      }}
    >
      <div class="space-y-1.5">
        <Label for={`${uid}-mode`}>The mode it runs</Label>
        <select
          id={`${uid}-mode`}
          class="bg-background w-full rounded-md border px-3 py-2 text-sm"
          bind:value={mode}
        >
          <option value="">Pick a mode</option>
          {#each modes as m (m.slug)}
            <option value={m.slug}>{m.name} ({shapeWords(m.shape)})</option>
          {/each}
        </select>
      </div>
      {#if candidates.length > 0}
        <fieldset class="space-y-1.5">
          <legend class="text-sm font-medium">Its addresses</legend>
          <p class="text-muted-foreground text-sm">
            Leave these unticked and FCP takes the ones that carry the node's name or address. Tick
            them when they carry neither.
          </p>
          <ul class="space-y-1">
            {#each candidates as a (a.addressUuid)}
              <li class="flex items-start gap-2">
                <Checkbox
                  id={`${uid}-h-${a.addressUuid}`}
                  checked={hostUuids.includes(a.addressUuid)}
                  onCheckedChange={(on) => toggle(a.addressUuid, on === true)}
                />
                <Label for={`${uid}-h-${a.addressUuid}`} class="font-normal break-all">
                  {a.remark} ({a.address}:{a.port})
                </Label>
              </li>
            {/each}
          </ul>
        </fieldset>
      {/if}
      {#if fronted}
        <div class="flex items-center gap-3">
          <Switch id={`${uid}-ext`} bind:checked={externallyFronted} />
          <Label for={`${uid}-ext`} class="font-normal">
            Its edge was made outside FCP (Edges takes over later)
          </Label>
        </div>
      {/if}
      <Dialog.Footer>
        <Button type="button" variant="outline" onclick={() => (open = false)}>Close</Button>
        <Button type="submit" disabled={busy || !mode}>Adopt</Button>
      </Dialog.Footer>
    </form>
  </Dialog.Content>
</Dialog.Root>
