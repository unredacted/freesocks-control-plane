<script lang="ts">
  /**
   * Adopt a node that already serves members (docs/servers.md "Adopting a
   * backend"): the operator names the mode it runs; the node is live at once
   * with its current addresses, nothing a member holds changes. A fronted
   * node whose edge FCP does not run yet is marked so; Edges takes over later.
   *
   * Props: open (bindable), slug, node (name + uuid + transports), modes (the setup's), onDone
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';
  import { Label } from '@client/components/ui/label';
  import { Switch } from '@client/components/ui/switch';
  import { adoptNode, invalidateServers } from '@client/lib/serversApi';
  import type { ModeSetupView } from '../../../../../shared/contracts/servers';
  import { codeOf } from '../lib/run';
  import { serverErrorWords, shapeWords } from '../lib/words';

  interface Props {
    open: boolean;
    slug: string;
    node: { nodeUuid: string; name: string } | null;
    modes: ModeSetupView[];
  }
  let { open = $bindable(false), slug, node, modes }: Props = $props();
  const qc = useQueryClient();
  const uid = $props.id();
  let mode = $state('');
  let externallyFronted = $state(false);
  let busy = $state(false);
  let picked = $derived(modes.find((m) => m.slug === mode) ?? null);
  let fronted = $derived(!!picked && picked.shape.fronting !== 'direct');

  async function submit() {
    if (!node || !mode) return;
    busy = true;
    try {
      const r = await adoptNode(slug, {
        nodeUuid: node.nodeUuid,
        mode,
        externallyFronted: fronted && externallyFronted,
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
