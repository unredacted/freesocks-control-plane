<script lang="ts">
  /**
   * "What you approve" for one enrolled node (docs/servers.md "Node lifecycle"):
   * the review the approval names, what keeps it from approval in words, and
   * Approve with its confirmation. A direct node lists the addresses members
   * get; a fronted node lists the new addresses its protection tested, one per
   * transport. The Servers node page and the Edges protection progress both
   * show this card, so approving looks and works the same in either place.
   *
   * Approve is enabled iff the review is loaded and names no blocker (the
   * server words a stage it would refuse as a blocker too). When the blocker is
   * that a live node needs maintenance first (a new address reaches members
   * only while they are held off it), the card offers "Start maintenance"; while
   * a maintenance is open it offers "Finish maintenance", the step before the
   * approval (the Servers page then leaves its own button out).
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
    startMaintenance,
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
  let maintenanceOpen = $state(false);
  let busy = $state(false);
  // Set once the approval went through: the card says so instead of offering it again
  // while the node (and on Edges the run) moves on.
  let approved = $state(false);

  const label = $derived(fronted ? 'Approve go-live' : 'Approve and activate');
  const canApprove = $derived(!!review.data && review.data.blockers.length === 0);
  const blocked = (code: string) => !!review.data?.blockers.some((b) => b.split(':')[0] === code);
  const needsMaintenance = $derived(blocked('servers.maintenance_required'));
  const inMaintenance = $derived(maintenance || blocked('servers.maintenance_open'));
  // A listener with no tested address yet is named too, so nothing is approved unseen.
  const bare = $derived(
    review.data
      ? review.data.shape.listeners.filter(
          (l) => !review.data!.display.standbys.some((s) => s.listenerKey === l.listenerKey),
        )
      : [],
  );

  async function closeForMaintenance() {
    maintenanceOpen = false;
    busy = true;
    try {
      await startMaintenance(slug, intentId);
      toast.success(`${nodeName} is closed for maintenance. Finish it, then approve it again.`);
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
    } finally {
      busy = false;
      invalidateServers(qc);
    }
  }

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
      await approveNode(slug, intentId, data.reviewHash);
      approved = true;
      toast.success(
        fronted
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
      {fronted ? 'Approved. Going live once the rehearsal passes.' : 'Approved. Releasing it now.'}
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
    {#if review.data.blockers.length > 0}
      <ul class="space-y-1 text-amber-700 dark:text-amber-300">
        {#each review.data.blockers as b (b)}<li>{blockerWords(b)}</li>{/each}
      </ul>
    {/if}
    <div class="flex flex-wrap gap-2">
      <Button disabled={busy || !canApprove} onclick={() => (open = true)}>{label}</Button>
      {#if inMaintenance}
        {@render finishButton()}
      {:else if needsMaintenance}
        <Button variant="outline" disabled={busy} onclick={() => (maintenanceOpen = true)}>
          Start maintenance
        </Button>
      {/if}
    </div>
  {/if}
</div>

<ConfirmDialog
  bind:open
  title={fronted ? `Approve go-live for ${nodeName}?` : `Release ${nodeName} to members?`}
  body={fronted
    ? 'FCP rehearses the real subscription bodies first. Members get the new addresses only if that passes, and nothing changes for them until then.'
    : 'The node is enabled for members only once its real subscription bodies rehearse correctly. Until then nobody sees it.'}
  typed={fronted ? nodeName : undefined}
  confirmLabel={label}
  onConfirm={approve}
/>
<ConfirmDialog
  bind:open={maintenanceOpen}
  title={`Close ${nodeName} for maintenance?`}
  body="Members of this node get the unavailable answer until it is approved again. Once you finish the maintenance, approve it to reopen it with its new address."
  typed={nodeName}
  confirmLabel="Start maintenance"
  danger
  onConfirm={closeForMaintenance}
/>
