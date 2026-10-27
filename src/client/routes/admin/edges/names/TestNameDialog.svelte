<script lang="ts">
  /**
   * "Test one name" (docs/edges.md "Rollout and acceptance"): an isolated test
   * link through one of this node's addresses (one whose endpoint was already
   * proven, so a failure is the name, not the path), presenting one new name.
   * The operator connects with a real client; "It connected" is the receipt
   * that hands the names to this node's members. A plain check from outside
   * cannot stand in for it: a node that has not taken the names still answers
   * one.
   *
   * Props: open (bindable), rolloutId, node (this node behind the port).
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { ApiCallError } from '@client/lib/api';
  import { buildNameTestLink, confirmNameTest, invalidateSni } from '@client/lib/sniApi';
  import type { SniTestLink, SniTransportNode } from '../../../../../shared/contracts/sni';
  import { DIALOG_FIT, STICKY_FOOTER } from '../lib/dialogLayout';
  import TestLink from '../simple/TestLink.svelte';
  import { provenWords } from './lib/transportWords';
  import { sniErrorWords } from './lib/words';

  let {
    open = $bindable(false),
    rolloutId,
    node,
  }: { open: boolean; rolloutId: string; node: SniTransportNode } = $props();
  const qc = useQueryClient();
  const uid = $props.id();
  const codeOf = (e: unknown) => (e instanceof ApiCallError ? e.payload.error.code : null);

  let edgeId = $state('');
  let test = $state<SniTestLink | null>(null);
  let error = $state<string | null>(null);
  let failed = $state(false);
  let busy = $state(false);

  async function build() {
    if (!edgeId) return;
    test = null;
    error = null;
    failed = false;
    busy = true;
    try {
      test = await buildNameTestLink(rolloutId, edgeId);
    } catch (e) {
      error = sniErrorWords(codeOf(e));
    } finally {
      busy = false;
    }
  }
  $effect(() => {
    if (!open) return;
    edgeId = node.testable[0]?.edgeId ?? '';
    void build();
  });

  async function connected() {
    if (!test) return;
    busy = true;
    try {
      const done = await confirmNameTest(test.receiptId);
      open = false;
      toast.success(provenWords(done.activated, node.nodeName));
    } catch (e) {
      error = sniErrorWords(codeOf(e));
    } finally {
      busy = false;
      invalidateSni(qc);
    }
  }
</script>

<Dialog.Root bind:open>
  <Dialog.Content class={`${DIALOG_FIT} sm:max-w-lg`}>
    <Dialog.Header>
      <Dialog.Title>Test one name on {node.nodeName}</Dialog.Title>
      <Dialog.Description>
        Connect with a real app. Only a real connection proves the node took the new names.
      </Dialog.Description>
    </Dialog.Header>
    <div class="space-y-3 text-sm">
      {#if node.testable.length > 1}
        <label class="flex flex-wrap items-center gap-2" for={`${uid}-edge`}>
          <span class="text-muted-foreground">Through</span>
          <select
            id={`${uid}-edge`}
            bind:value={edgeId}
            onchange={build}
            class="border-input bg-background h-11 rounded-md border px-2 sm:h-9"
          >
            {#each node.testable as e (e.edgeId)}
              <option value={e.edgeId}>{e.name}</option>
            {/each}
          </select>
        </label>
      {/if}
      {#if error}
        <p class="text-destructive">{error}</p>
        <Button variant="outline" size="sm" disabled={busy} onclick={build}>Try again</Button>
      {:else if !test}
        <Skeleton class="h-40 w-full" />
      {:else}
        <p>
          Import this link, connect, and open a page. It uses the name
          <span class="font-mono break-words">{test.sni}</span>{test.isWitness
            ? ', and proves every new name on this node at once.'
            : '.'}
        </p>
        <TestLink link={test.link} label={`Copy the test link for ${test.sni}`} />
        {#if failed}
          <p class="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2">
            Nothing changes for members. The node may still be restarting: wait a minute and make a
            new link. If it keeps failing, the node has not taken the new names: check that it is
            online and up to date under Servers before trying again.
          </p>
        {/if}
      {/if}
    </div>
    <Dialog.Footer class={STICKY_FOOTER}>
      {#if test && !failed}
        <Button variant="outline" disabled={busy} onclick={() => (failed = true)}>
          It did not connect
        </Button>
        <Button disabled={busy} onclick={connected}>It connected</Button>
      {:else if failed}
        <Button variant="outline" onclick={() => (open = false)}>Close</Button>
        <Button disabled={busy} onclick={build}>Make a new link</Button>
      {:else}
        <Button variant="outline" onclick={() => (open = false)}>Cancel</Button>
      {/if}
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
