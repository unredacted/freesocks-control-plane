<script lang="ts">
  /**
   * "What you approve" for one enrolled node (docs/servers.md "Node lifecycle"):
   * the review the approval names, what keeps it from approval in words, and
   * Approve with its confirmation. A direct node lists the addresses members
   * get; a fronted node lists the new addresses its protection tested, one per
   * transport, or, after a maintenance with no protection run, the addresses it
   * already has whose tests still hold (`display.atOnce` `kept`: the approval
   * itself takes it live on them, nothing is bought or rehearsed). The Servers node page and the Edges protection progress both
   * show this card, so approving looks and works the same in either place.
   *
   * Approve is enabled iff the review is loaded and names no blocker (the
   * server words a stage it would refuse as a blocker too), or its only
   * blocker is that a live node needs its gate closed first (a new address
   * reaches members only while they are held off it): the approval then closes
   * the gate itself (`closeGate`) and the go-live opens it again, so members
   * are held off only until the commit. The card says so beside the button and
   * in the confirmation. While a maintenance opened elsewhere is open it offers
   * "Finish maintenance", the step before the approval (the Servers page then
   * leaves its own button out).
   *
   * Props: slug (the backend's), intentId, nodeName, fronted,
   *        maintenance? (the node is closed for maintenance; shown even before
   *        the review loads), onApproved?()
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import Check from '@lucide/svelte/icons/check';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import {
    approveNode,
    finishMaintenance,
    invalidateServers,
    reviewQuery,
  } from '@client/lib/serversApi';
  import ConfirmDialog from '../../edges/components/ConfirmDialog.svelte';
  import { codeOf } from '../lib/run';
  import { blockerWords, serverErrorWords, standbyWords } from '../lib/words';

  interface Props {
    slug: string;
    intentId: string;
    nodeName: string;
    fronted: boolean;
    maintenance?: boolean;
    onApproved?: () => void;
  }
  let { slug, intentId, nodeName, fronted, maintenance = false, onApproved }: Props = $props();

  const qc = useQueryClient();
  const review = reviewQuery(
    () => slug,
    () => intentId,
  );
  let open = $state(false);
  let busy = $state(false);
  // Set once the approval went through: the card says so instead of offering it again
  // while the node (and on Edges the run) moves on.
  let approved = $state(false);

  const label = $derived(fronted ? 'Approve go-live' : 'Approve and activate');
  const blocked = (code: string) => !!review.data?.blockers.some((b) => b.split(':')[0] === code);
  const inMaintenance = $derived(maintenance || blocked('servers.maintenance_open'));
  // The gate a live node needs closed is closed by the approval itself; any
  // other blocker still keeps Approve off.
  const others = $derived(
    review.data?.blockers.filter((b) => b.split(':')[0] !== 'servers.maintenance_required') ?? [],
  );
  const closesGate = $derived(blocked('servers.maintenance_required') && others.length === 0);
  const canApprove = $derived(!!review.data && others.length === 0);
  // The approval takes the node live itself: no protection run rehearses first.
  const atOnce = $derived(review.data?.display.atOnce ?? null);
  // A listener with no tested address yet is named too, so nothing is approved unseen.
  const bare = $derived(
    review.data
      ? review.data.shape.listeners.filter(
          (l) => !review.data!.display.standbys.some((s) => s.listenerKey === l.listenerKey),
        )
      : [],
  );

  async function endMaintenance() {
    busy = true;
    try {
      await finishMaintenance(slug, intentId);
      toast.success(`Maintenance on ${nodeName} is finished. Approve it to reopen it.`);
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
    } finally {
      busy = false;
      invalidateServers(qc);
    }
  }

  async function approve() {
    const data = review.data;
    open = false;
    if (!data) return;
    busy = true;
    try {
      await approveNode(slug, intentId, data.reviewHash, closesGate);
      approved = true;
      toast.success(
        atOnce
          ? `Approved. ${nodeName} is live again.`
          : fronted
            ? `Approved. ${nodeName} goes live once its rehearsal passes.`
            : `Approved. ${nodeName} is being released to members.`,
      );
      onApproved?.();
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
    } finally {
      busy = false;
      invalidateServers(qc);
    }
  }
</script>

{#snippet finishButton()}
  <Button variant="outline" disabled={busy} onclick={endMaintenance}>Finish maintenance</Button>
{/snippet}

<div class="bg-card space-y-2 rounded-md border p-3 text-sm">
  <p class="font-medium">What you approve</p>
  {#if approved}
    <p class="flex items-center gap-1 text-emerald-700 dark:text-emerald-300" role="status">
      <Check class="size-4" aria-hidden="true" />
      {atOnce
        ? 'Approved. It is live again.'
        : fronted
          ? 'Approved. Going live once the rehearsal passes.'
          : 'Approved. Releasing it now.'}
    </p>
  {:else if review.isPending}
    <Skeleton class="h-16 w-full" />
  {:else if review.isError || !review.data}
    <p class="text-destructive">{serverErrorWords(codeOf(review.error))}</p>
    <div class="flex flex-wrap gap-2">
      <Button size="sm" variant="outline" onclick={() => void review.refetch()}
        >Read it again</Button
      >
      {#if inMaintenance}{@render finishButton()}{/if}
    </div>
  {:else}
    {@const s = review.data.shape}
    <ul class="text-muted-foreground space-y-1">
      {#if fronted}
        {#each review.data.display.standbys as standby (`${standby.listenerKey}:${standby.locationLabel ?? ''}:${standby.endpoint ?? ''}`)}
          <li>{standbyWords(standby)}</li>
        {/each}
        {#each bare as l (l.listenerKey)}
          <li>{l.listenerKey}: no tested address yet.</li>
        {/each}
        {#if atOnce === 'kept'}
          <li>Approve reopens it on the addresses it already has. Nothing new is bought.</li>
        {/if}
      {:else}
        {#each s.addressTuples as a (a.sni ?? a.address)}
          <li>Members get {a.address}:{a.port}{a.sni ? ` as ${a.sni}` : ''}.</li>
        {/each}
      {/if}
      <li>
        Profile revision {s.configRevision.slice(0, 8)}, templates {Object.keys(
          s.subscriptionTemplates,
        ).length} matched.
      </li>
    </ul>
    {#if others.length > 0}
      <ul class="space-y-1 text-amber-700 dark:text-amber-300">
        {#each others as b (b)}<li>{blockerWords(b)}</li>{/each}
      </ul>
    {/if}
    {#if closesGate}
      <p class="text-muted-foreground">{blockerWords('servers.maintenance_required')}</p>
    {/if}
    <div class="flex flex-wrap gap-2">
      <Button disabled={busy || !canApprove} onclick={() => (open = true)}>{label}</Button>
      {#if inMaintenance}{@render finishButton()}{/if}
    </div>
  {/if}
</div>

<ConfirmDialog
  bind:open
  title={fronted ? `Approve go-live for ${nodeName}?` : `Release ${nodeName} to members?`}
  body={closesGate
    ? `This closes ${nodeName} for members until it goes live, about a minute: members who refresh meanwhile are given another node, or keep their configuration. FCP then rehearses the real subscription bodies and opens it with the new addresses only if that passes.`
    : atOnce === 'kept'
      ? `Members get ${nodeName} again at once, through the addresses it already has, each one tested and its test still current. Nothing new is bought.`
      : atOnce === 'external'
        ? `Members get ${nodeName} again at once, through the edge it already has.`
        : fronted
          ? 'FCP rehearses the real subscription bodies first. Members get the new addresses only if that passes, and nothing changes for them until then.'
          : 'The node is enabled for members only once its real subscription bodies rehearse correctly. Until then nobody sees it.'}
  typed={fronted || closesGate ? nodeName : undefined}
  confirmLabel={label}
  danger={closesGate}
  onConfirm={approve}
/>
