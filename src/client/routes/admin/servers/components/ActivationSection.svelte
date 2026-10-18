<script lang="ts">
  /**
   * One enrolled node's way to members (docs/servers.md "Node lifecycle"):
   * its sentence, the isolated test link with its "Works" tick (direct nodes),
   * the review card with Approve (NodeApprovalCard), and the quiet actions:
   * finish maintenance. Nothing here reaches a member before the commit.
   *
   * Retiring starts from the header's More menu (NodeActions, "Retire node…");
   * once a retirement exists this section shows its steps (retirementSteps):
   * the one it is on and why it waits there. A retirement the node role asked
   * for waits here for "Decide the retirement"; an adopted node's ends here with
   * "The machine is gone".
   *
   * A fronted node goes live through its protection in Edges (Start, try each
   * address, approve go-live, all in the protect sheet): this page links there
   * ("Protect this node" / "Open progress") and mirrors the approval card while
   * the protection waits for it. A node an Edges origin already protects has
   * its edges panel on the same page: protecting it again starts there
   * ("Protect again"), never in the protect sheet.
   *
   * Props: slug, intent (NodeIntentView), origin (an Edges origin protects it)
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import Check from '@lucide/svelte/icons/check';
  import Circle from '@lucide/svelte/icons/circle';
  import CircleDot from '@lucide/svelte/icons/circle-dot';
  import { Button } from '@client/components/ui/button';
  import {
    buildDirectTestLink,
    confirmDirect,
    confirmWiped,
    finishMaintenance,
    invalidateServers,
    retireNode,
  } from '@client/lib/serversApi';
  import Link from '@client/components/Link.svelte';
  import { router } from '@client/stores/router.svelte';
  import type { DirectTestLink, NodeIntentView } from '../../../../../shared/contracts/servers';
  import ConfirmDialog from '../../edges/components/ConfirmDialog.svelte';
  import TestLink from '../../edges/simple/TestLink.svelte';
  import { edgesPaths } from '../../edges/lib/routes';
  import StatusDot from '../../edges/simple/StatusDot.svelte';
  import { codeOf } from '../lib/run';
  import { protectionWords, retirementSteps, serverErrorWords, stageWords } from '../lib/words';
  import NodeApprovalCard from './NodeApprovalCard.svelte';

  let {
    slug,
    intent,
    origin = false,
  }: { slug: string; intent: NodeIntentView; origin?: boolean } = $props();
  const qc = useQueryClient();

  let busy = $state(false);
  let link = $state<DirectTestLink | null>(null);
  let ticked = $state(false);
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
  // The decision on a retirement the node role asked for (keep-dark, the only one offered).
  const decide = () =>
    run(async () => {
      retireOpen = false;
      await retireNode(slug, intent.id, { disposition: 'keep-dark' });
    });

  let direct = $derived(intent.mode.shape.fronting === 'direct');
  let canTest = $derived(
    direct && (intent.stage === 'machine_ready' || intent.stage === 'candidates_verified'),
  );
  let reviewable = $derived(
    intent.stage === 'candidates_verified' || intent.stage === 'awaiting_approval',
  );
  // A fronted node with no protection open, at a point where protecting it is the next
  // step. A live one gets a quiet "Open in Edges" instead: the protect sheet opens on it
  // and says so when it is already protected (re-protecting after a removal starts there).
  let unprotected = $derived(!direct && !intent.protection && !intent.retirement);
  let canProtect = $derived(unprotected && (intent.stage === 'machine_ready' || reviewable));
  let canReprotect = $derived(unprotected && intent.stage === 'live' && !origin);
  // The fronted mirror of the approval card, while the protection waits for it.
  let mirrorShown = $derived(
    !direct &&
      !intent.retirement &&
      intent.protection?.state === 'needs_you' &&
      intent.protection.need === 'node_not_approved' &&
      intent.stage !== 'activating',
  );
  // The approval card carries Finish maintenance itself: the row below leaves it out.
  let cardShown = $derived((direct && reviewable) || mirrorShown);
  const protect = () =>
    router.navigate(
      edgesPaths.home({ protect: '1', server: slug, node: intent.nodeUuid ?? undefined }),
    );
  let needsDecision = $derived(intent.retirement?.stage === 'needs_admin');
  // The role never runs an adopted machine, so nothing reports its wipe: the
  // retirement waits for whoever cleaned it up to say so.
  let needsWipeConfirmation = $derived(
    intent.adopted && intent.retirement?.stage === 'ready_to_wipe',
  );
  let steps = $derived(
    intent.retirement
      ? retirementSteps({ adopted: intent.adopted, retirement: intent.retirement })
      : [],
  );
</script>

<section aria-labelledby="activation">
  <h2 id="activation" class="mb-3 text-base font-semibold">On its way to members</h2>
  <p class="flex items-center gap-2 text-sm" role="status">
    <StatusDot dot={words.dot} />
    <span>{intent.mode.name}. {words.sentence}</span>
  </p>
  {#if !intent.modeEnabled && !intent.retirement}
    <p class="mt-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm" role="status">
      Members cannot pick {intent.mode.name} yet: the mode is turned off, so nobody is given this node{intent.stage ===
      'live'
        ? ''
        : ' once it is live'}.
      <Link href="/admin/connection-modes" class="text-primary underline underline-offset-4"
        >Turn it on in Connection modes</Link
      >
    </p>
  {/if}
  {#if steps.length > 0}
    <ol class="bg-card mt-3 space-y-2 rounded-md border p-3 text-sm" aria-label="Retirement steps">
      {#each steps as st (st.key)}
        <li class="flex gap-2" aria-current={st.state === 'current' ? 'step' : undefined}>
          {#if st.state === 'done'}
            <Check
              class="mt-0.5 size-4 shrink-0 text-emerald-600 dark:text-emerald-400"
              aria-hidden="true"
            />
          {:else if st.state === 'current'}
            <CircleDot
              class="mt-0.5 size-4 shrink-0 text-amber-600 dark:text-amber-400"
              aria-hidden="true"
            />
          {:else}
            <Circle class="text-muted-foreground mt-0.5 size-4 shrink-0" aria-hidden="true" />
          {/if}
          <span class="min-w-0">
            <span
              class={st.state === 'todo'
                ? 'text-muted-foreground'
                : st.state === 'current'
                  ? 'font-medium'
                  : ''}>{st.label}</span
            ><span class="sr-only"
              >{st.state === 'done' ? ', done' : st.state === 'current' ? ', now' : ', next'}</span
            >
            {#if st.why}
              <span class="text-muted-foreground block">{st.why}</span>
            {/if}
          </span>
        </li>
      {/each}
    </ol>
  {/if}
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
        Scan or copy the test link into a client on the device you test with (it uses FCP's own test
        account), connect, load a page, then tick Works. Nobody else can see this node yet.
      </p>
      {#if link}
        <div class="flex flex-wrap items-center justify-between gap-2">
          <span class="text-muted-foreground text-sm break-all">{link.binding.endpoint}</span>
          {#if ticked}
            <span class="flex items-center gap-1 text-sm text-emerald-700 dark:text-emerald-300">
              <Check class="size-4" aria-hidden="true" /> Works
            </span>
          {/if}
        </div>
        {#if !ticked}
          <TestLink link={link.link} label={`Copy the test link for ${intent.name}`} />
          <Button class="h-11 sm:h-9" disabled={busy} onclick={works}>Works</Button>
        {/if}
      {:else}
        <Button size="sm" variant="outline" disabled={busy} onclick={buildLink}
          >Build a test link</Button
        >
      {/if}
    </div>
  {/if}

  {#if direct && reviewable}
    <div class="mt-3">
      <NodeApprovalCard
        {slug}
        intentId={intent.id}
        nodeName={intent.name}
        fronted={false}
        maintenance={intent.maintenance}
      />
    </div>
  {:else if !direct && intent.protection && !intent.retirement}
    {@const p = intent.protection}
    <div
      class="bg-card mt-3 flex flex-wrap items-center justify-between gap-2 rounded-md border p-3 text-sm"
    >
      <span>{protectionWords(p, intent.stage)}</span>
      <Button
        size="sm"
        variant="outline"
        onclick={() => router.navigate(edgesPaths.home({ run: p.runId }))}
      >
        Open progress
      </Button>
    </div>
    {#if mirrorShown}
      <div class="mt-3">
        <NodeApprovalCard
          {slug}
          intentId={intent.id}
          nodeName={intent.name}
          fronted
          maintenance={intent.maintenance}
        />
      </div>
    {/if}
  {:else if canProtect && origin}
    <p class="bg-card mt-3 rounded-md border p-3 text-sm">
      It goes live again through its edges below: Protect again makes new addresses, you try each
      one, then you approve go-live.
    </p>
  {:else if canProtect}
    <div class="bg-card mt-3 space-y-3 rounded-md border p-3 text-sm">
      <p>
        Members reach this node through provider addresses. Protect it from Edges: FCP creates them,
        you try each one, then you approve go-live there.
      </p>
      <Button size="sm" onclick={protect}>Protect this node</Button>
    </div>
  {/if}

  <div class="mt-3 flex flex-wrap gap-2">
    {#if intent.maintenance && !cardShown}
      <Button
        size="sm"
        variant="outline"
        disabled={busy}
        onclick={() => run(() => finishMaintenance(slug, intent.id))}
      >
        Finish maintenance
      </Button>
    {/if}
    {#if canReprotect}
      <Button size="sm" variant="outline" onclick={protect}>Open in Edges</Button>
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
    {/if}
  </div>
</section>

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
  body={'The node role asked to retire it. Members on this node get the unavailable answer until they are moved. Its addresses, edges and records are removed. ' +
    (intent.adopted
      ? 'FCP never ran this machine, so confirm here once you have cleaned it up yourself.'
      : 'The role then wipes the machine.')}
  typed={intent.name}
  confirmLabel="Retire"
  danger
  onConfirm={decide}
/>
