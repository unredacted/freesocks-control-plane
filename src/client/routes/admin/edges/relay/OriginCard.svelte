<script lang="ts">
  /**
   * The target of an origin: what it is, where edges dial, who writes the backend
   * Hosts, the connection plan of a manual origin and the L7 qualification
   * credential.
   *
   * Props: origin; listeners; connectionPlan
   */
  import type { z } from 'zod';
  import type {
    RelayAdmin,
    RelayConnectionPlanEntry,
    RelayListenerAdmin,
  } from '@shared/contracts/edges';
  import * as Card from '@client/components/ui/card';
  import * as Table from '@client/components/ui/table';
  import { Button } from '@client/components/ui/button';
  import Link from '@client/components/Link.svelte';
  import {
    mintQualificationCredential,
    nodeCandidatesQuery,
    removeQualificationCredential,
  } from '@client/lib/edgesApi';
  import KeyValue from '../components/KeyValue.svelte';
  import CopyButton from '../components/CopyButton.svelte';
  import { relativeTime } from '../lib/time';
  import type { KeyValueRow } from '../lib/types';
  import ActionConfirm from './ActionConfirm.svelte';
  import { relayAction } from './actions.svelte';
  import { HOST_MODE_WORDS, ORIGIN_KIND_WORDS } from './relayLogic';

  interface Props {
    relay: RelayAdmin;
    listeners: RelayListenerAdmin[];
    connectionPlan: Array<z.infer<typeof RelayConnectionPlanEntry>>;
  }
  let { relay, listeners, connectionPlan }: Props = $props();

  const act = relayAction(() => relay.slug);
  const origin = $derived(relay.origin);
  const backendServerId = $derived(origin.kind === 'manual' ? null : origin.backendServerId);

  const nodesQ = nodeCandidatesQuery(() => (origin.kind === 'panel-node' ? backendServerId : null));
  const node = $derived.by(() => {
    if (origin.kind !== 'panel-node') return null;
    const nodes = nodesQ.data?.nodes ?? [];
    return (
      nodes.find((n) => origin.nodeUuid !== null && n.nodeUuid === origin.nodeUuid) ??
      nodes.find((n) => n.name === origin.nodeName) ??
      null
    );
  });

  const nodeState = $derived.by(
    (): { value: string; tone?: KeyValueRow['tone']; hint?: string } => {
      if (origin.kind === 'manual') return { value: '' };
      if (origin.kind === 'backend-server') {
        return relay.suspicion?.veto === 'node_offline'
          ? { value: 'Offline', tone: 'danger', hint: 'The backend server fails its health check.' }
          : { value: 'See the backend server page', hint: 'FCP health-checks the whole server.' };
      }
      if (!node) {
        return {
          value: 'Unknown',
          tone: 'muted',
          hint: nodesQ.isPending
            ? 'Loading the node list.'
            : 'The node is not in the last node list FCP pulled from the backend.',
        };
      }
      return node.online
        ? {
            value: 'Online',
            tone: 'success',
            hint: `${node.usersOnline} member(s) connected${nodesQ.data?.fetchedAt ? `, seen ${relativeTime(nodesQ.data.fetchedAt)}` : ''}.`,
          }
        : { value: 'Offline', tone: 'danger', hint: 'The backend reports this node as down.' };
    },
  );

  const rows = $derived.by((): KeyValueRow[] => {
    const out: KeyValueRow[] = [
      { label: 'Origin', value: ORIGIN_KIND_WORDS[origin.kind] },
      {
        label: 'Origin address',
        value: relay.originAddress,
        mono: true,
        copy: true,
        hint: 'What edges dial. Never handed to members.',
      },
    ];
    if (origin.kind === 'panel-node') {
      out.push({ label: 'Node', value: origin.nodeName, hint: origin.nodeUuid ?? undefined });
    }
    if (origin.kind !== 'manual') {
      out.push({ label: 'Node state', ...nodeState });
    }
    out.push({
      label: 'Backend Hosts',
      value: HOST_MODE_WORDS[relay.hostMode].label,
      hint: HOST_MODE_WORDS[relay.hostMode].explain,
    });
    out.push({ label: 'Location', value: relay.locationCode ?? '' });
    if (origin.kind === 'panel-node')
      out.push({
        label: 'Front qualification mode',
        value: relay.qualificationModeSlug ?? 'Backend default',
        hint: 'The connection mode whose placement the test user is created on. Change it under Edit.',
      });
    out.push({
      label: 'Registered by the node role',
      value: relay.lastRegisteredAt
        ? relativeTime(relay.lastRegisteredAt)
        : 'Never (created by hand)',
    });
    return out;
  });

  const hasL7 = $derived(listeners.some((l) => !l.retired && l.layers.includes('l7')));
  let removeOpen = $state(false);
</script>

<Card.Root>
  <Card.Header>
    <Card.Title>Origin</Card.Title>
    <Card.Description
      >The server behind the edges. It is fixed for the life of the origin.</Card.Description
    >
    {#if backendServerId}
      <Card.Action>
        <Link
          href="/admin/backend-servers"
          class="text-sm font-medium text-primary hover:underline"
        >
          Backend servers
        </Link>
      </Card.Action>
    {/if}
  </Card.Header>
  <Card.Content class="space-y-5">
    <KeyValue {rows} hideEmpty />

    {#if origin.kind === 'manual'}
      <div class="space-y-2">
        <h3 class="text-sm font-medium">Connection plan</h3>
        <p class="text-xs text-muted-foreground">
          FCP serves no subscription for a manual origin. Point your clients at these values; they
          change with every rotation.
        </p>
        {#if connectionPlan.length === 0}
          <p class="rounded-md border border-dashed p-3 text-sm text-muted-foreground">
            Nothing to dial yet. Publish an edge for a listener and its row appears here.
          </p>
        {:else}
          <Table.Root>
            <Table.Header>
              <Table.Row>
                <Table.Head>Listener</Table.Head>
                <Table.Head>Dial</Table.Head>
                <Table.Head>Server name</Table.Head>
                <Table.Head>Host header</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {#each connectionPlan as row (row.listenerKey)}
                <Table.Row>
                  <Table.Cell class="font-mono text-xs">{row.listenerKey}</Table.Cell>
                  <Table.Cell class="font-mono text-xs">
                    {row.address}:{row.port}
                    <CopyButton value={`${row.address}:${row.port}`} label="Copy address" />
                  </Table.Cell>
                  <Table.Cell class="font-mono text-xs">{row.sni ?? 'none'}</Table.Cell>
                  <Table.Cell class="font-mono text-xs">{row.host ?? 'none'}</Table.Cell>
                </Table.Row>
              {/each}
            </Table.Body>
          </Table.Root>
        {/if}
      </div>
    {/if}

    {#if hasL7 || relay.qualificationCredential}
      <div class="flex flex-wrap items-start justify-between gap-3 rounded-md border p-3">
        <div class="min-w-0 flex-1">
          <h3 class="text-sm font-medium">L7 qualification credential</h3>
          <p class="text-xs text-muted-foreground">
            {#if relay.qualificationCredential}
              Minted. FCP uses this test account to open a short authenticated session through each
              L7 front before it is published, and again before the proof expires.
            {:else}
              Not minted. Without it no L7 front of this relay can be proven end to end, so none can
              be published.
            {/if}
          </p>
        </div>
        {#if relay.qualificationCredential}
          <Button variant="outline" size="sm" onclick={() => (removeOpen = true)}>Remove</Button>
        {:else}
          <Button
            size="sm"
            disabled={act.isPending}
            onclick={() =>
              act.mutate({
                run: () => mintQualificationCredential(relay.id),
                success: 'Qualification credential minted.',
              })}
          >
            Mint credential
          </Button>
        {/if}
      </div>
    {/if}
  </Card.Content>
</Card.Root>

<ActionConfirm
  bind:open={removeOpen}
  title="Remove the qualification credential?"
  body="FCP deletes the test account from the panel. Published L7 fronts keep working until their proof expires; after that they cannot be re-proven and drop out of selection until a new credential is minted."
  confirmLabel="Remove credential"
  danger
  run={() =>
    act.mutateAsync({
      run: () => removeQualificationCredential(relay.id),
      success: 'Qualification credential removed.',
      quiet: true,
    })}
/>
