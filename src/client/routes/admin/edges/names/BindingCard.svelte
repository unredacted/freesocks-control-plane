<script lang="ts">
  /**
   * One inbound a family is bound to: what the next write would do, the write
   * itself, and then, per node, the test that lets members be given the new
   * names. Being on the panel is never treated as a node accepting a name.
   *
   * Props: binding
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { ApiCallError } from '@client/lib/api';
  import {
    buildNameTestLink,
    confirmNameTest,
    invalidateSni,
    planRollout,
    rolloutQuery,
    startRollout,
    unbindFamily,
  } from '@client/lib/sniApi';
  import type {
    SniBinding,
    SniRolloutPlan,
    SniTestLink,
  } from '../../../../../shared/contracts/sni';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import CopyButton from '../components/CopyButton.svelte';
  import { nodeLine, planWords, rolloutWords, sniErrorWords, type Dot } from './lib/words';

  let { binding }: { binding: SniBinding } = $props();
  const qc = useQueryClient();
  const rollout = rolloutQuery(() => binding.rolloutId);
  const codeOf = (e: unknown) => (e instanceof ApiCallError ? e.payload.error.code : null);

  const DOT: Record<Dot, string> = {
    green: 'bg-emerald-500',
    amber: 'bg-amber-500',
    red: 'bg-destructive',
    grey: 'bg-muted-foreground/50',
  };

  let plan = $state<SniRolloutPlan | null>(null);
  let busy = $state(false);
  let writeOpen = $state(false);
  let unbindOpen = $state(false);
  // One open test at a time, keyed by the node it is for.
  let test = $state<(SniTestLink & { nodeKey: string }) | null>(null);

  async function run<T>(work: () => Promise<T>): Promise<T | null> {
    busy = true;
    try {
      return await work();
    } catch (e) {
      toast.error(sniErrorWords(codeOf(e)));
      return null;
    } finally {
      busy = false;
      invalidateSni(qc);
    }
  }

  const look = () => run(async () => (plan = await planRollout(binding.id)));

  async function write() {
    writeOpen = false;
    const started = await run(() => startRollout(binding.id));
    if (!started) return;
    plan = null;
    toast.message(
      started.rolloutId
        ? 'Sent to the panel. It shows up here once the panel has it.'
        : 'The panel already had exactly this.',
    );
  }

  async function makeLink(nodeKey: string, edgeId: string) {
    if (!binding.rolloutId) return;
    const id = binding.rolloutId;
    const built = await run(() => buildNameTestLink(id, edgeId));
    if (built) test = { ...built, nodeKey };
  }

  async function itConnected() {
    if (!test) return;
    const receiptId = test.receiptId;
    const done = await run(() => confirmNameTest(receiptId));
    if (!done) return;
    test = null;
    toast.success(
      done.activated === 0
        ? 'Recorded. Nothing new to hand out on this node.'
        : `${done.activated} ${done.activated === 1 ? 'name is' : 'names are'} now given to members on this node.`,
    );
  }

  async function unbind() {
    unbindOpen = false;
    await run(() => unbindFamily(binding.id));
  }
</script>

<section class="rounded-lg border p-4 text-sm" aria-label={binding.inboundTag}>
  <div class="flex flex-wrap items-start gap-3">
    <div class="min-w-0 flex-1">
      <h3 class="font-medium break-all">{binding.inboundTag}</h3>
      <p class="text-muted-foreground break-all">on {binding.backendSlug}</p>
    </div>
    <Button variant="outline" size="sm" disabled={busy} onclick={look}>
      See what would be written
    </Button>
    <Button variant="ghost" size="sm" disabled={busy} onclick={() => (unbindOpen = true)}>
      Unbind
    </Button>
  </div>

  {#if plan}
    <div class="bg-muted/30 mt-3 space-y-1 rounded-md border p-3" aria-live="polite">
      {#each planWords(plan) as line (line)}
        <p>{line}</p>
      {/each}
      {#if plan.changed}
        <details class="mt-1">
          <summary class="cursor-pointer">The names</summary>
          {#each plan.added as n (n)}
            <p class="break-all text-emerald-700 dark:text-emerald-400">+ {n}</p>
          {/each}
          {#each plan.removed as n (n)}
            <p class="text-destructive break-all">- {n}</p>
          {/each}
        </details>
        <Button size="sm" class="mt-2" disabled={busy} onclick={() => (writeOpen = true)}>
          Write to the panel
        </Button>
      {/if}
    </div>
  {/if}

  {#if rollout.data}
    {@const r = rollout.data}
    {@const w = rolloutWords(r)}
    <div class="mt-3 flex items-start gap-2" aria-live="polite">
      <span
        class={`mt-1.5 inline-block size-2.5 shrink-0 rounded-full ${DOT[w.dot]}`}
        aria-hidden="true"
      ></span>
      <p>{w.sentence}</p>
    </div>

    {#if r.phase === 'panel_confirmed' && r.nodes.length > 0}
      <ul class="mt-2 divide-y rounded-md border">
        {#each r.nodes as node (node.relaySlug + node.listenerKey)}
          {@const key = `${node.relaySlug}/${node.listenerKey}`}
          <li class="space-y-2 p-3">
            <div class="flex flex-wrap items-center gap-3">
              <span class="min-w-0 flex-1">
                <span class="block font-medium break-all">{node.relaySlug}</span>
                <span class="text-muted-foreground block">{nodeLine(node)}</span>
              </span>
              {#if node.pending > 0}
                {#each node.edges as edge (edge.id)}
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={busy}
                    onclick={() => makeLink(key, edge.id)}
                  >
                    Test through {edge.name}
                  </Button>
                {/each}
                {#if node.edges.length === 0}
                  <span class="text-muted-foreground">No live address to test through</span>
                {/if}
              {/if}
            </div>

            {#if test?.nodeKey === key}
              <div class="bg-muted/30 space-y-2 rounded-md border p-3">
                <p>
                  Add this link to a client app and connect. It uses the name
                  <span class="font-medium break-all">{test.sni}</span> and an account made only for
                  this test.
                  {test.isWitness
                    ? 'If it connects, this node has taken the whole new list.'
                    : 'If it connects, this node accepts this one name.'}
                </p>
                <div class="flex gap-2">
                  <Input
                    readonly
                    value={test.link}
                    class="font-mono text-xs"
                    aria-label="Test link"
                  />
                  <CopyButton value={test.link} label="Copy the test link" />
                </div>
                <div class="flex flex-wrap gap-2">
                  <Button size="sm" disabled={busy} onclick={itConnected}>It connected</Button>
                  <Button variant="ghost" size="sm" onclick={() => (test = null)}>
                    It did not connect
                  </Button>
                </div>
                <p class="text-muted-foreground">
                  A check from outside cannot stand in for this: a node that has not taken the list
                  still completes a plain secure connection for the name.
                </p>
              </div>
            {/if}
          </li>
        {/each}
      </ul>
    {/if}
  {/if}
</section>

<ConfirmDialog
  bind:open={writeOpen}
  title="Write these names to the panel?"
  body="The panel pushes the new list to every node on this profile. People connected there are cut off for a few seconds and reconnect by themselves."
  confirmLabel="Write"
  onConfirm={write}
/>
<ConfirmDialog
  bind:open={unbindOpen}
  title={`Unbind ${binding.inboundTag}?`}
  body="The names stay on the panel and members keep theirs. The family just stops managing this inbound."
  confirmLabel="Unbind"
  danger
  onConfirm={unbind}
/>
