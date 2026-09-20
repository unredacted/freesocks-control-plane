<script lang="ts">
  /**
   * One enrolled node's way to members (docs/servers.md "Node lifecycle"):
   * its sentence, the isolated test link with its "Works" tick (direct nodes),
   * the review card with Approve and activate, and the quiet actions: finish
   * maintenance, retire. Nothing here reaches a member before the commit.
   *
   * Props: slug, intent (NodeIntentView)
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import Check from '@lucide/svelte/icons/check';
  import { Button } from '@client/components/ui/button';
  import {
    approveNode,
    buildDirectTestLink,
    confirmDirect,
    confirmWiped,
    finishMaintenance,
    invalidateServers,
    retireNode,
    reviewQuery,
  } from '@client/lib/serversApi';
  import type { DirectTestLink, NodeIntentView } from '../../../../../shared/contracts/servers';
  import ConfirmDialog from '../../edges/components/ConfirmDialog.svelte';
  import CopyButton from '../../edges/components/CopyButton.svelte';
  import StatusDot from '../../edges/simple/StatusDot.svelte';
  import { codeOf } from '../lib/run';
  import { serverErrorWords, stageWords } from '../lib/words';

  let { slug, intent }: { slug: string; intent: NodeIntentView } = $props();
  const qc = useQueryClient();
  const review = reviewQuery(
    () => slug,
    () =>
      intent.stage === 'candidates_verified' ||
      intent.stage === 'awaiting_approval' ||
      intent.stage === 'machine_ready'
        ? intent.id
        : null,
  );

  let busy = $state(false);
  let link = $state<DirectTestLink | null>(null);
  let ticked = $state(false);
  let approveOpen = $state(false);
  let retireOpen = $state(false);
  let wipedOpen = $state(false);
  let words = $derived(stageWords(intent));

  async function run(fn: () => Promise<unknown>) {
    busy = true;
    try {
      await fn();
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
    } finally {
      busy = false;
      invalidateServers(qc);
    }
  }
  const buildLink = () =>
    run(async () => {
      link = await buildDirectTestLink(slug, intent.id);
      ticked = false;
    });
  const works = () =>
    run(async () => {
      if (!link) return;
      await confirmDirect(slug, intent.id, link.binding);
      ticked = true;
    });
  const approve = () =>
    run(async () => {
      approveOpen = false;
      if (review.data) await approveNode(slug, intent.id, review.data.reviewHash);
    });
  const retire = (disposition?: 'keep-dark') =>
    run(async () => {
      retireOpen = false;
      await retireNode(slug, intent.id, disposition ? { disposition } : undefined);
    });

  let direct = $derived(intent.mode.shape.fronting === 'direct');
  let canTest = $derived(
    direct && (intent.stage === 'machine_ready' || intent.stage === 'candidates_verified'),
  );
  let canApprove = $derived(
    (intent.stage === 'candidates_verified' || intent.stage === 'awaiting_approval') &&
      !!review.data &&
      review.data.blockers.length === 0,
  );
  let needsDecision = $derived(intent.retirement?.stage === 'needs_admin');
  // The role never runs an adopted machine, so nothing reports its wipe: the
  // retirement waits for whoever cleaned it up to say so.
  let needsWipeConfirmation = $derived(
    intent.adopted && intent.retirement?.stage === 'ready_to_wipe',
  );
</script>

<section aria-labelledby="activation">
  <h2 id="activation" class="mb-3 text-base font-semibold">On its way to members</h2>
  <p class="flex items-center gap-2 text-sm" role="status">
    <StatusDot dot={words.dot} />
    <span>{intent.mode.name}. {words.sentence}</span>
  </p>
  {#if intent.origin.hostname}
    <p class="text-muted-foreground mt-1 text-sm">
      Origin name {intent.origin.hostname}{intent.origin.dns === 'resolves'
        ? ', resolving'
        : intent.origin.dns === 'conflict'
          ? ': something else holds that record'
          : ''}.
    </p>
  {/if}

  {#if canTest}
    <div class="bg-card mt-3 space-y-3 rounded-md border p-3">
      <p class="text-sm">
        Import the test link into a client (it uses FCP's own test account), connect, load a page,
        then tick Works. Nobody else can see this node yet.
      </p>
      {#if link}
        <div class="flex flex-wrap items-center justify-between gap-2">
          <span class="text-muted-foreground text-sm">{link.binding.endpoint}</span>
          <div class="flex items-center gap-2">
            <CopyButton value={link.link} label="Copy test link" />
            {#if ticked}
              <span class="flex items-center gap-1 text-sm text-emerald-700 dark:text-emerald-300">
                <Check class="size-4" aria-hidden="true" /> Works
              </span>
            {:else}
              <Button size="sm" variant="outline" disabled={busy} onclick={works}>Works</Button>
            {/if}
          </div>
        </div>
      {:else}
        <Button size="sm" variant="outline" disabled={busy} onclick={buildLink}
          >Build a test link</Button
        >
      {/if}
    </div>
  {/if}

  {#if review.data && (intent.stage === 'candidates_verified' || intent.stage === 'awaiting_approval')}
    {@const s = review.data.shape}
    <div class="bg-card mt-3 space-y-2 rounded-md border p-3 text-sm">
      <p class="font-medium">What you approve</p>
      <ul class="text-muted-foreground space-y-1">
        {#each s.addressTuples as a (a.sni ?? a.address)}
          <li>Members get {a.address}:{a.port}{a.sni ? ` as ${a.sni}` : ''}.</li>
        {/each}
        {#if s.listenerKeys.length > 0}<li>Listeners: {s.listenerKeys.join(', ')}.</li>{/if}
        <li>
          Profile revision {s.configRevision.slice(0, 8)}, templates {Object.keys(
            s.subscriptionTemplates,
          ).length} matched.
        </li>
      </ul>
      {#if review.data.blockers.length > 0}
        <ul class="space-y-1 text-amber-700 dark:text-amber-300">
          {#each review.data.blockers as b (b)}<li>{serverErrorWords(b)}</li>{/each}
        </ul>
      {/if}
      <Button disabled={busy || !canApprove} onclick={() => (approveOpen = true)}
        >Approve and activate</Button
      >
    </div>
  {/if}

  <div class="mt-3 flex flex-wrap gap-2">
    {#if intent.maintenance}
      <Button
        size="sm"
        variant="outline"
        disabled={busy}
        onclick={() => run(() => finishMaintenance(slug, intent.id))}
      >
        Finish maintenance
      </Button>
    {/if}
    {#if needsWipeConfirmation}
      <Button size="sm" variant="outline" disabled={busy} onclick={() => (wipedOpen = true)}>
        The machine is gone
      </Button>
    {/if}
    {#if needsDecision}
      <Button size="sm" variant="destructive" disabled={busy} onclick={() => (retireOpen = true)}
        >Decide the retirement</Button
      >
    {:else if !intent.retirement}
      <Button
        size="sm"
        variant="ghost"
        class="text-destructive"
        disabled={busy}
        onclick={() => (retireOpen = true)}>Retire</Button
      >
    {/if}
  </div>
</section>

<ConfirmDialog
  bind:open={approveOpen}
  title={`Release ${intent.name} to members?`}
  body="The node is enabled for members only once its real subscription bodies rehearse correctly. Until then nobody sees it."
  typed={direct ? undefined : intent.name}
  confirmLabel="Approve and activate"
  onConfirm={approve}
/>
<ConfirmDialog
  bind:open={wipedOpen}
  title={`Is ${intent.name} gone?`}
  body="This node was taken over as it was, so FCP never ran its machine and nothing reports the wipe. Confirm you have stopped and cleaned up the machine yourself; the retirement then closes and the name is free again."
  confirmLabel="It is gone"
  onConfirm={() =>
    run(async () => {
      wipedOpen = false;
      await confirmWiped(slug, intent.id);
    })}
/>
<ConfirmDialog
  bind:open={retireOpen}
  title={`Retire ${intent.name}?`}
  body={(needsDecision
    ? 'Members on this node get the unavailable answer until they are moved. Its addresses, edges and records are removed. '
    : 'Its addresses, edges and records are removed. ') +
    (intent.adopted
      ? 'FCP never ran this machine, so confirm here once you have cleaned it up yourself.'
      : 'The role then wipes the machine.')}
  typed={intent.name}
  confirmLabel="Retire"
  danger
  onConfirm={() => retire(needsDecision ? 'keep-dark' : undefined)}
/>
