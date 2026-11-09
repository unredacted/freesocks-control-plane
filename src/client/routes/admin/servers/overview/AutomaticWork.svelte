<script lang="ts">
  /**
   * The Overview's "Automatic work" row: the fleet-wide switches in one place,
   * each with one line saying what it does, through the calls their Settings
   * cards already use:
   *
   *   Automatic replacement        POST automation (the host page owns it: its
   *                                offer card turns it on too)
   *   New work (Running / Paused)  POST maintenance/freeze | maintenance/thaw
   *   Freedom modes only through edges  POST freedom {on, confirm}; turning it on
   *                                reads the preview first and says what it holds back
   *   Read panels every 10 minutes PATCH servers config `manage.observe`
   *   Changes from here            PATCH servers config `manage.enabled`
   *                                (only when a backend can be written to)
   *
   * Props:
   *   automation: boolean | null          null before the config is read
   *   automationNote: string | null       runWords.ts automationNote
   *   automationBusy: boolean
   *   onAutomation: (on: boolean) => void
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Label } from '@client/components/ui/label';
  import { Switch } from '@client/components/ui/switch';
  import {
    edgeKeys,
    fetchFreedomPreview,
    freedomDeliveryQuery,
    freezeMaintenance,
    invalidateConfig,
    invalidateOverview,
    maintenanceQuery,
    setFreedomEdgesOnly,
    thawMaintenance,
  } from '@client/lib/edgesApi';
  import { invalidateSni } from '@client/lib/sniApi';
  import { invalidateServers, patchServerConfig, serverSummaryQuery } from '@client/lib/serversApi';
  import type { FreedomPreview } from '@shared/contracts/edges';
  import ConfirmDialog from '../../edges/components/ConfirmDialog.svelte';
  import { edgeErrorCode, edgeErrorMessage } from '../../edges/lib/edgeErrors';
  import { relativeTime } from '../../edges/lib/time';
  import { codeOf } from '../lib/run';
  import { serverErrorWords } from '../lib/words';
  import { freedomSummary } from './overviewModel';

  interface Props {
    automation: boolean | null;
    automationNote: string | null;
    automationBusy: boolean;
    onAutomation: (on: boolean) => void;
  }
  let { automation, automationNote, automationBusy, onAutomation }: Props = $props();

  const qc = useQueryClient();
  const maintenance = maintenanceQuery();
  const freedom = freedomDeliveryQuery();
  const servers = serverSummaryQuery();

  const instances = $derived(servers.data?.instances ?? []);
  const observeOn = $derived(servers.data?.config['manage.observe'] ?? false);
  const manageOn = $derived(servers.data?.config['manage.enabled'] ?? false);
  const anyObservable = $derived(instances.some((i) => i.observable));
  const anyWritable = $derived(instances.some((i) => i.writable));

  // --- new work ---
  let freezeOpen = $state(false);
  let thawOpen = $state(false);
  async function freeze(): Promise<void> {
    qc.setQueryData(edgeKeys.maintenance, await freezeMaintenance());
    invalidateConfig(qc);
    invalidateOverview(qc);
    toast.success('New work is paused. Running replacements finish.');
  }
  async function thaw(): Promise<void> {
    qc.setQueryData(edgeKeys.maintenance, await thawMaintenance());
    invalidateConfig(qc);
    invalidateOverview(qc);
    toast.success('New work is allowed again.');
  }

  // --- freedom only through edges ---
  let freedomBusy = $state(false);
  let preview = $state<FreedomPreview | null>(null);
  let freedomOnOpen = $state(false);
  let freedomOffOpen = $state(false);
  async function readPreview(): Promise<FreedomPreview> {
    const p = await qc.fetchQuery({
      queryKey: edgeKeys.freedomPreview,
      queryFn: fetchFreedomPreview,
      staleTime: 0,
    });
    preview = p;
    return p;
  }
  async function askFreedom(on: boolean): Promise<void> {
    if (!on) {
      freedomOffOpen = true;
      return;
    }
    // Turning it on first says what it would hold back (it counts members).
    freedomBusy = true;
    try {
      await readPreview();
      freedomOnOpen = true;
    } catch (e) {
      toast.error(edgeErrorMessage(e));
    } finally {
      freedomBusy = false;
    }
  }
  const affected = $derived(preview?.totals.affectedMembers ?? 0);
  async function freedomOn(): Promise<void> {
    try {
      await setFreedomEdgesOnly(true, affected > 0);
    } catch (e) {
      // More members than the preview counted: read it again so the dialog's numbers are current.
      if (edgeErrorCode(e) === 'freedom_confirm_required') void readPreview();
      throw e;
    }
    void qc.invalidateQueries({ queryKey: edgeKeys.freedom });
    void qc.invalidateQueries({ queryKey: edgeKeys.freedomPreview });
    invalidateOverview(qc);
    toast.success('Freedom members are now handed fronted addresses only.');
  }
  async function freedomOff(): Promise<void> {
    await setFreedomEdgesOnly(false);
    void qc.invalidateQueries({ queryKey: edgeKeys.freedom });
    void qc.invalidateQueries({ queryKey: edgeKeys.freedomPreview });
    invalidateOverview(qc);
    toast.success('Freedom members may be handed a node directly again.');
  }

  // --- panel switches ---
  let panelBusy = $state(false);
  async function setPanel(key: 'manage.enabled' | 'manage.observe', on: boolean): Promise<void> {
    panelBusy = true;
    try {
      await patchServerConfig({ [key]: on });
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
    } finally {
      panelBusy = false;
      invalidateServers(qc);
      // A send to the backend is held back by this switch: say so at once.
      invalidateSni(qc);
    }
  }

  const BOX = 'bg-card rounded-lg border px-3 py-2.5';
</script>

<section aria-labelledby="automatic-work">
  <h2 id="automatic-work" class="mb-3 text-base font-semibold">Automatic work</h2>
  <ul class="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
    {#if automation !== null}
      <li class={BOX}>
        <div class="flex items-center gap-3">
          <Switch
            id="ow-automation"
            checked={automation}
            disabled={automationBusy}
            onCheckedChange={(v) => onAutomation(v)}
          />
          <Label for="ow-automation">Automatic replacement</Label>
        </div>
        <p class="text-muted-foreground mt-1 text-xs">
          A blocked address is replaced on its own.{automationNote ? ` ${automationNote}` : ''}
        </p>
      </li>
    {/if}

    {#if maintenance.data}
      {@const m = maintenance.data}
      <li class={BOX}>
        <div class="flex flex-wrap items-center justify-between gap-2">
          <p class="text-sm font-medium" role="status">
            New work is {m.frozen ? 'paused' : 'running'}
          </p>
          {#if m.frozen}
            <Button size="sm" onclick={() => (thawOpen = true)}>Resume new work</Button>
          {:else}
            <Button size="sm" variant="outline" onclick={() => (freezeOpen = true)}>
              Pause new work
            </Button>
          {/if}
        </div>
        <p class="text-muted-foreground mt-1 text-xs">
          {#if m.frozen}
            Nothing new starts; running work finishes.{m.reason
              ? ` Reason: ${m.reason}.`
              : ''}{m.since ? ` Paused ${relativeTime(m.since)}.` : ''}
          {:else}
            Pause it before a risky change, like a backend upgrade.
          {/if}
        </p>
      </li>
    {/if}

    {#if freedom.data}
      <li class={BOX}>
        <div class="flex items-center gap-3">
          <Switch
            id="ow-freedom"
            checked={freedom.data.on}
            disabled={freedomBusy}
            onCheckedChange={(v) => void askFreedom(v)}
          />
          <Label for="ow-freedom">Freedom modes only through edges</Label>
        </div>
        <p class="text-muted-foreground mt-1 text-xs">
          {freedom.data.on
            ? 'Freedom members get fronted addresses only, never a node directly.'
            : 'Off: a freedom member whose node is not fronted gets the node directly.'}
        </p>
      </li>
    {/if}

    {#if anyObservable}
      <li class={BOX}>
        <div class="flex items-center gap-3">
          <Switch
            id="ow-observe"
            checked={observeOn}
            disabled={panelBusy}
            onCheckedChange={(v) => void setPanel('manage.observe', v)}
          />
          <Label for="ow-observe">Read panels every 10 minutes</Label>
        </div>
        <p class="text-muted-foreground mt-1 text-xs">Keeps node status current.</p>
      </li>
    {/if}

    {#if anyWritable}
      <li class={BOX}>
        <div class="flex items-center gap-3">
          <Switch
            id="ow-manage"
            checked={manageOn}
            disabled={panelBusy}
            onCheckedChange={(v) => void setPanel('manage.enabled', v)}
          />
          <Label for="ow-manage">Changes from here</Label>
        </div>
        <p class="text-muted-foreground mt-1 text-xs">FCP may change nodes on the panels.</p>
      </li>
    {/if}
  </ul>
</section>

<ConfirmDialog
  bind:open={freezeOpen}
  title="Pause new work?"
  body="Running replacements finish. No provisioning, publishing or replacement starts until you resume, by hand or automatically. A blocked address is not replaced while paused. To give a reason, pause it from Settings."
  confirmLabel="Pause new work"
  danger
  onConfirm={freeze}
/>
<ConfirmDialog
  bind:open={thawOpen}
  title="Resume new work?"
  body="Provisioning, publishing and automatic replacement are allowed again for every node."
  confirmLabel="Resume new work"
  onConfirm={thaw}
/>
<ConfirmDialog
  bind:open={freedomOnOpen}
  title="Hand freedom members fronted addresses only?"
  body={preview
    ? [
        freedomSummary(preview),
        preview.totals.cutOffMembers > 0
          ? 'Members who get nothing keep their last configuration until it stops reaching the node.'
          : '',
        'Saving a freedom mode set up direct is refused from now on.',
      ]
        .filter(Boolean)
        .join(' ')
    : ''}
  confirmLabel={affected > 0 ? 'Turn on and hold them back' : 'Turn on'}
  danger={affected > 0}
  onConfirm={freedomOn}
/>
<ConfirmDialog
  bind:open={freedomOffOpen}
  title="Let freedom members be handed a node directly?"
  body="A freedom member whose node is not fronted gets that node's own address again at their next refresh. A freedom mode can be set up direct again."
  confirmLabel="Turn off"
  danger
  onConfirm={freedomOff}
/>
