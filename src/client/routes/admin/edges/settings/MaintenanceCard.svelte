<script lang="ts">
  /**
   * The "pause new edge work" switch: state, reason, since, and the two actions
   * (each behind a ConfirmDialog). Pausing separates admission from completion:
   * running rotations finish, nothing new starts.
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import { Skeleton } from '@client/components/ui/skeleton';
  import {
    edgeKeys,
    freezeMaintenance,
    invalidateConfig,
    invalidateOverview,
    maintenanceQuery,
    thawMaintenance,
  } from '@client/lib/edgesApi';
  import AdminListState from '../../AdminListState.svelte';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import KeyValue from '../components/KeyValue.svelte';
  import { relativeTime } from '../lib/time';

  const qc = useQueryClient();
  const maintenance = maintenanceQuery();
  const uid = $props.id();

  let reason = $state('');
  let freezeOpen = $state(false);
  let thawOpen = $state(false);

  async function freeze(): Promise<void> {
    const view = await freezeMaintenance(reason.trim() || undefined);
    qc.setQueryData(edgeKeys.maintenance, view);
    reason = '';
    invalidateConfig(qc);
    invalidateOverview(qc);
    toast.success('New edge work is paused. Running rotations will finish.');
  }
  async function thaw(): Promise<void> {
    const view = await thawMaintenance();
    qc.setQueryData(edgeKeys.maintenance, view);
    invalidateConfig(qc);
    invalidateOverview(qc);
    toast.success('New edge work is allowed again.');
  }
</script>

<section
  id="settings-maintenance"
  class="bg-card ring-foreground/15 scroll-mt-20 rounded-xl ring-1"
  aria-labelledby="settings-maintenance-title"
>
  <header class="px-4 py-3">
    <h2 id="settings-maintenance-title" class="font-medium">Maintenance</h2>
    <p class="text-muted-foreground mt-0.5 text-sm">
      Pause the admission of new edge work before a risky change, for example a panel upgrade.
    </p>
  </header>
  <div class="space-y-4 border-t px-4 py-4">
    {#if maintenance.isPending}
      <Skeleton class="h-16" />
    {:else if maintenance.isError}
      <AdminListState error={maintenance.error} onRetry={() => maintenance.refetch()} />
    {:else if maintenance.data}
      {@const m = maintenance.data}
      <KeyValue
        columns={2}
        rows={[
          {
            label: 'State',
            value: m.frozen ? 'Paused' : 'Running',
            tone: m.frozen ? 'warning' : 'success',
          },
          { label: 'Reason', value: m.frozen ? (m.reason ?? 'No reason given') : '' },
          {
            label: 'Since',
            value:
              m.frozen && m.since
                ? `${relativeTime(m.since)} (${new Date(m.since).toLocaleString()})`
                : '',
          },
        ]}
        hideEmpty
      />
      {#if m.frozen}
        <p class="text-muted-foreground text-sm">
          While paused: no provisioning, publishing or rotation can start, by hand or automatically.
          Runs that were already going carry on to their end.
        </p>
        <Button onclick={() => (thawOpen = true)}>Resume new work</Button>
      {:else}
        <div class="space-y-1.5">
          <Label for={`${uid}-reason`}>Reason (optional)</Label>
          <Input
            id={`${uid}-reason`}
            class="w-full sm:w-96"
            maxlength={200}
            placeholder="Panel upgrade in progress"
            bind:value={reason}
          />
          <p class="text-muted-foreground text-xs">
            Shown on the overview banner so other operators know why nothing starts.
          </p>
        </div>
        <Button variant="outline" onclick={() => (freezeOpen = true)}>Pause new work</Button>
      {/if}
    {/if}
  </div>
</section>

<ConfirmDialog
  bind:open={freezeOpen}
  title="Pause new edge work?"
  body="Running rotations finish. Nothing new starts until you resume: no provisioning, no publishing, no automatic or manual rotation. A blocked edge will not be replaced while paused."
  confirmLabel="Pause new work"
  danger
  onConfirm={freeze}
/>
<ConfirmDialog
  bind:open={thawOpen}
  title="Resume new edge work?"
  body="Provisioning, publishing and automatic rotation are allowed again for the whole fleet."
  confirmLabel="Resume new work"
  onConfirm={thaw}
/>
