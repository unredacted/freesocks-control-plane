<script lang="ts">
  /**
   * Freedom modes only through edges (`edge.freedom.edgesOnly`, docs/edges.md):
   * the switch, and before it is turned on a read-only preview of what it
   * would hold back, per freedom mode and backend (nodes, and the members on
   * them). Turning it on while members are affected sends the confirm the
   * server asks for; a preview that moved meanwhile is read again and the
   * dialog says so.
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import * as Table from '@client/components/ui/table';
  import Link from '@client/components/Link.svelte';
  import {
    edgeKeys,
    freedomDeliveryQuery,
    freedomPreviewQuery,
    invalidateOverview,
    setFreedomEdgesOnly,
  } from '@client/lib/edgesApi';
  import { codeLabel } from '@client/lib/edgeCodes';
  import type { FreedomPreview, FreedomPreviewMode } from '@shared/contracts/edges';
  import { serversPaths } from '../../servers/lib/routes';
  import AdminListState from '../../AdminListState.svelte';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import KeyValue from '../components/KeyValue.svelte';
  import { edgeErrorCode } from '../lib/edgeErrors';
  import { relativeTime } from '../lib/time';

  const qc = useQueryClient();
  const current = freedomDeliveryQuery();
  let previewAsked = $state(false);
  const preview = freedomPreviewQuery(() => previewAsked);

  let onOpen = $state(false);
  let offOpen = $state(false);

  const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

  function summary(p: FreedomPreview): string {
    const { withheldNodes, affectedMembers, cutOffMembers } = p.totals;
    if (withheldNodes === 0) return 'Every node of a freedom mode is behind a live edge.';
    const nodes = `${plural(withheldNodes, 'node')} ${p.on ? (withheldNodes === 1 ? 'is' : 'are') : 'would be'} held back from freedom members.`;
    if (affectedMembers === 0) return `${nodes} No member is on them now.`;
    const moved = affectedMembers - cutOffMembers;
    const parts = [
      ...(moved > 0
        ? [`${plural(moved, 'member')} move to a covered node at their next refresh`]
        : []),
      ...(cutOffMembers > 0
        ? [`${plural(cutOffMembers, 'member')} get nothing until an edge covers their node`]
        : []),
    ];
    return `${nodes} ${parts.join(', and ')}.${p.approximate ? ' (At least: the count stopped early.)' : ''}`;
  }

  const modeName = (m: FreedomPreviewMode) => m.label ?? m.mode;

  async function turnOn(): Promise<void> {
    const affected = preview.data?.totals.affectedMembers ?? 0;
    try {
      await setFreedomEdgesOnly(true, affected > 0);
    } catch (e) {
      // More members than the preview counted: read it again so the dialog's numbers are current.
      if (edgeErrorCode(e) === 'freedom_confirm_required') void preview.refetch();
      throw e;
    }
    void qc.invalidateQueries({ queryKey: edgeKeys.freedom });
    void qc.invalidateQueries({ queryKey: edgeKeys.freedomPreview });
    invalidateOverview(qc);
    toast.success('Freedom members are now handed edges only.');
  }

  async function turnOff(): Promise<void> {
    await setFreedomEdgesOnly(false);
    void qc.invalidateQueries({ queryKey: edgeKeys.freedom });
    void qc.invalidateQueries({ queryKey: edgeKeys.freedomPreview });
    invalidateOverview(qc);
    toast.success('Freedom members may be handed a node directly again.');
  }

  const confirmBody = $derived.by(() => {
    const p = preview.data;
    if (!p) return '';
    const cut = p.totals.cutOffMembers;
    return [
      summary(p),
      cut > 0
        ? 'Members who get nothing keep their app working on its last configuration until it stops reaching the node.'
        : '',
      'Saving a freedom mode set up direct is refused from now on.',
    ]
      .filter(Boolean)
      .join(' ');
  });
</script>

<section
  id="settings-freedom"
  class="bg-card ring-foreground/15 scroll-mt-20 rounded-xl ring-1"
  aria-labelledby="settings-freedom-title"
>
  <header class="px-4 py-3">
    <h2 id="settings-freedom-title" class="font-medium">Freedom modes only through edges</h2>
    <p class="text-muted-foreground mt-0.5 text-sm">
      Members on a freedom mode are handed edge addresses or nothing, never a node's own address. A
      node no live edge covers is held back from them, and a freedom mode cannot be set up direct.
    </p>
  </header>
  <div class="space-y-4 border-t px-4 py-4">
    {#if current.isPending}
      <Skeleton class="h-16" />
    {:else if current.isError}
      <AdminListState error={current.error} onRetry={() => current.refetch()} />
    {:else if current.data}
      {@const s = current.data}
      <KeyValue
        columns={2}
        rows={[
          { label: 'State', value: s.on ? 'On' : 'Off', tone: s.on ? 'success' : 'warning' },
          {
            label: 'Since',
            value: s.since
              ? `${relativeTime(s.since)} (${new Date(s.since).toLocaleString()})`
              : '',
          },
        ]}
        hideEmpty
      />
      {#if !s.on}
        <p class="text-muted-foreground text-sm">
          Off: a freedom member whose node no edge covers is handed that node directly.
        </p>
      {/if}

      {#if !previewAsked}
        <Button variant="outline" onclick={() => (previewAsked = true)}>
          {s.on ? 'See the nodes it holds back' : 'See what it would close'}
        </Button>
      {:else if preview.isPending}
        <Skeleton class="h-24" />
      {:else if preview.isError}
        <AdminListState error={preview.error} onRetry={() => preview.refetch()} />
      {:else if preview.data}
        {@const p = preview.data}
        <p class="text-sm">{summary(p)}</p>
        {#if p.modes.length > 0}
          <Table.Root>
            <Table.Header>
              <Table.Row>
                <Table.Head>Mode</Table.Head>
                <Table.Head>Backend</Table.Head>
                <Table.Head>Nodes covered</Table.Head>
                <Table.Head>Held back</Table.Head>
                <Table.Head class="text-right">Members affected</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {#each p.modes as m (`${m.serverSlug}:${m.mode}`)}
                <Table.Row>
                  <Table.Cell>{modeName(m)}</Table.Cell>
                  <Table.Cell class="text-muted-foreground">{m.serverSlug}</Table.Cell>
                  <Table.Cell>{m.nodes.servable} of {m.nodes.total}</Table.Cell>
                  <Table.Cell>
                    {#if m.withheldNodes.length === 0}
                      <span class="text-muted-foreground">None</span>
                    {:else}
                      <ul class="space-y-0.5">
                        {#each m.withheldNodes as n (n.node)}
                          <li>
                            {#if n.nodeUuid}
                              <Link
                                href={serversPaths.node(n.nodeUuid, { instance: m.serverSlug })}
                                class="text-primary hover:underline">{n.node}</Link
                              >
                            {:else}
                              {n.node}
                            {/if}
                            <span class="text-muted-foreground">({codeLabel(n.reason)})</span>
                          </li>
                        {/each}
                      </ul>
                    {/if}
                  </Table.Cell>
                  <Table.Cell class="text-right">
                    {#if m.members.cutOff > 0}
                      <span class="text-destructive">{m.members.cutOff} get nothing</span>
                    {:else if m.members.moved > 0}
                      {m.members.moved} move
                    {:else}
                      <span class="text-muted-foreground">0</span>
                    {/if}
                  </Table.Cell>
                </Table.Row>
              {/each}
            </Table.Body>
          </Table.Root>
        {/if}
        <div class="flex flex-wrap gap-2">
          {#if s.on}
            <Button variant="outline" onclick={() => (offOpen = true)}>Turn off</Button>
          {:else}
            <Button onclick={() => (onOpen = true)}>Turn on</Button>
          {/if}
          <Button variant="ghost" onclick={() => preview.refetch()}>Count again</Button>
        </div>
      {/if}
      {#if s.on && !previewAsked}
        <div>
          <Button variant="outline" onclick={() => (offOpen = true)}>Turn off</Button>
        </div>
      {/if}
    {/if}
  </div>
</section>

<ConfirmDialog
  bind:open={onOpen}
  title="Hand freedom members edges only?"
  body={confirmBody}
  confirmLabel={(preview.data?.totals.affectedMembers ?? 0) > 0
    ? 'Turn on and hold them back'
    : 'Turn on'}
  danger={(preview.data?.totals.affectedMembers ?? 0) > 0}
  onConfirm={turnOn}
/>
<ConfirmDialog
  bind:open={offOpen}
  title="Let freedom members be handed a node directly?"
  body="A freedom member whose node no edge covers is handed that node's own address again, at their next refresh. Saving a freedom mode set up direct is allowed again."
  confirmLabel="Turn off"
  danger
  onConfirm={turnOff}
/>
