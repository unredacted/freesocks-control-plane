<script lang="ts">
  /**
   * One listener of an origin: what it speaks, its server names (retire /
   * reactivate, per listener or fleet-wide), which layers can front it and why
   * the others cannot, its match rule, its backend Host and who owns the row.
   *
   * Props: origin; listener; edgeCount (non-destroyed edges bound to it); highlighted?;
   *        onEdit(listener); onProvision(listenerKey)
   */
  import type { OriginAdmin, RelayListenerAdmin } from '@shared/contracts/edges';
  import * as Card from '@client/components/ui/card';
  import { Badge } from '@client/components/ui/badge';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import {
    adoptListenerHost,
    deleteRelayListener,
    disableListener,
    enableListener,
    reactivateListenerNames,
    retireListenerNameEverywhere,
    retireListenerNames,
  } from '@client/lib/edgesApi';
  import { codeExplain, codeFix, codeLabel } from '@client/lib/edgeCodes';
  import { EDGE_LAYER_IDS } from '@shared/contracts/edges';
  import KeyValue from '../components/KeyValue.svelte';
  import LayerBadge from '../components/LayerBadge.svelte';
  import ProtocolBadge from '../components/ProtocolBadge.svelte';
  import StatusBadge from '../components/StatusBadge.svelte';
  import { relativeTime } from '../lib/time';
  import type { KeyValueRow } from '../lib/types';
  import ActionConfirm from './ActionConfirm.svelte';
  import { relayAction } from './actions.svelte';
  import { matchRuleWords, originTransportWords } from './relayLogic';

  interface Props {
    relay: OriginAdmin;
    listener: RelayListenerAdmin;
    edgeCount: number;
    highlighted?: boolean;
    onEdit: (listener: RelayListenerAdmin) => void;
    onProvision: (listenerKey: string) => void;
  }
  let { relay, listener: l, edgeCount, highlighted = false, onEdit, onProvision }: Props = $props();

  const act = relayAction(() => relay.slug);
  const locked = $derived(relay.deleting || l.retired);

  const excluded = $derived(
    EDGE_LAYER_IDS.filter((layer) => !l.layers.includes(layer) && l.excluded[layer]).map(
      (layer) => ({ layer, code: l.excluded[layer]! }),
    ),
  );
  const activeNames = $derived(l.tlsNames.filter((n) => n.status === 'active'));

  let retireName = $state<string | null>(null);
  let retireEverywhere = $state<string | null>(null);
  let disableOpen = $state(false);
  let deleteOpen = $state(false);
  let adoptOpen = $state(false);
  let addressUuid = $state('');
  const uuidOk = $derived(
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(addressUuid.trim()),
  );

  const OWNERSHIP_WORDS = {
    fcp: 'Created by FCP. FCP deletes it when the listener retires.',
    adopted: 'Created by you, taken over by FCP. FCP rewrites it but never deletes it.',
  } as const;

  const detailRows = $derived.by((): KeyValueRow[] => {
    const rows: KeyValueRow[] = [
      { label: 'Origin port', value: `${l.originPort} (${l.transport.toUpperCase()})`, mono: true },
      { label: 'Origin transport', value: originTransportWords(l.originTransport) },
      { label: 'How its entry is found', value: matchRuleWords(l.matchRule, l.templateHostRemark) },
    ];
    if (l.realityTarget)
      rows.push({
        label: 'REALITY target',
        value: `${l.realityTarget.address}:${l.realityTarget.port}`,
        mono: true,
      });
    const tp = l.transportParams;
    if (tp?.path) rows.push({ label: 'Path', value: tp.path, mono: true });
    if (tp?.host) rows.push({ label: 'Host header at the node', value: tp.host, mono: true });
    if (tp?.serviceName)
      rows.push({ label: 'gRPC service name', value: tp.serviceName, mono: true });
    if (l.providerScope) {
      rows.push({
        label: 'Provider scope',
        value: `Only ${l.providerScope.provider}${l.providerScope.accountId ? ', one account' : ''}`,
      });
    }
    rows.push({
      label: 'Deployed on the node',
      value: l.deployed
        ? `Yes${l.deployedAt ? `, ${relativeTime(l.deployedAt)}` : ''}`
        : 'Not yet: nothing can be published for it',
      tone: l.deployed ? undefined : 'warning',
    });
    return rows;
  });

  const inboundRows = $derived.by((): KeyValueRow[] =>
    l.panelBinding
      ? [
          { label: 'Transport tag', value: l.panelBinding.inboundTag, mono: true },
          {
            label: 'Config profile',
            value: l.panelBinding.configProfileUuid,
            mono: true,
            copy: true,
          },
          {
            label: 'Inbound',
            value: l.panelBinding.configProfileInboundUuid,
            mono: true,
            copy: true,
          },
        ]
      : [],
  );
</script>

<Card.Root id={`listener-${l.listenerKey}`} class={highlighted ? 'ring-2 ring-primary' : ''}>
  <Card.Header>
    <Card.Title class="flex flex-wrap items-center gap-2">
      <span class="font-mono">{l.listenerKey}</span>
      <ProtocolBadge
        protocol={l.protocol}
        streamTransport={l.streamTransport}
        security={l.security}
      />
      {#each l.layers as layer (layer)}
        <LayerBadge {layer} />
      {/each}
      {#if l.retired}
        <Badge variant="muted">Retired</Badge>
      {:else if !l.enabled}
        <Badge variant="warning">Disabled</Badge>
      {/if}
      <Badge variant="outline">{l.source === 'role' ? 'From the node role' : 'Added by hand'}</Badge
      >
    </Card.Title>
    {#if l.label}
      <Card.Description>{l.label}</Card.Description>
    {/if}
    {#if !l.retired}
      <Card.Action class="flex flex-wrap gap-2">
        <Button
          variant="outline"
          size="sm"
          disabled={locked || !l.enabled || !l.deployed}
          onclick={() => onProvision(l.listenerKey)}
        >
          Provision an edge
        </Button>
        <Button variant="outline" size="sm" disabled={locked} onclick={() => onEdit(l)}>Edit</Button
        >
      </Card.Action>
    {/if}
  </Card.Header>
  <Card.Content class="space-y-5 text-sm">
    {#if excluded.length > 0 || l.layers.length === 0}
      <div class="space-y-2">
        {#if l.layers.length === 0}
          <p class="rounded-md border border-destructive/40 bg-destructive/10 p-2">
            No layer can front this listener right now, so no edge can be provisioned for it.
          </p>
        {/if}
        {#each excluded as ex (ex.layer)}
          <div class="rounded-md border bg-muted/40 p-2">
            <p class="font-medium">
              Cannot sit behind {ex.layer === 'l7'
                ? 'an L7 front (a CDN hostname)'
                : 'an L4 edge (a load balancer)'}:
              {codeLabel(ex.code)}
            </p>
            <p class="text-xs text-muted-foreground">
              {codeExplain(ex.code)}
              {codeFix(ex.code) ?? ''}
            </p>
          </div>
        {/each}
      </div>
    {/if}

    <KeyValue rows={detailRows} columns={2} />

    <!-- server names -->
    <section class="space-y-2">
      <h3 class="font-medium">Server names</h3>
      {#if l.tlsNames.length === 0}
        <p class="text-muted-foreground">
          {l.security === 'none'
            ? 'This listener presents no name.'
            : l.source === 'role'
              ? 'None registered. The node role has to send the names this listener answers to.'
              : 'None yet. Use Edit to add the names this listener answers to: without one, nothing can be published behind an L4 edge.'}
        </p>
      {:else}
        <ul class="divide-y rounded-md border">
          {#each l.tlsNames as n (n.name)}
            <li class="flex flex-wrap items-center gap-2 px-3 py-2">
              <span class="font-mono text-xs">{n.name}</span>
              {#if n.status === 'active'}
                <Badge variant="success">Active</Badge>
              {:else}
                <Badge variant="muted">
                  Retired{n.retiredBy === 'role' ? ' by the node role' : ''}
                </Badge>
                {#if n.drainUntil && new Date(n.drainUntil).getTime() > Date.now()}
                  <span class="text-xs text-muted-foreground">
                    the node keeps accepting it until {relativeTime(n.drainUntil)}
                  </span>
                {/if}
              {/if}
              <span class="ms-auto flex gap-1">
                {#if n.status === 'active'}
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={locked}
                    onclick={() => (retireName = n.name)}>Retire</Button
                  >
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={locked}
                    onclick={() => (retireEverywhere = n.name)}>Retire on every listener</Button
                  >
                {:else}
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={locked || act.isPending || n.retiredBy === 'role'}
                    title={n.retiredBy === 'role'
                      ? 'The node role retired this name. It comes back when the role registers it again.'
                      : undefined}
                    onclick={() =>
                      act.mutate({
                        run: () => reactivateListenerNames(l.id, [n.name]),
                        success: `${n.name} can be selected again.`,
                      })}>Reactivate</Button
                  >
                {/if}
              </span>
            </li>
          {/each}
        </ul>
      {/if}
    </section>

    <!-- panel Host -->
    {#if relay.hostMode !== 'none' && !l.retired}
      <section class="space-y-2">
        <h3 class="font-medium">Backend Host</h3>
        {#if l.host}
          <div class="flex flex-wrap items-center gap-2">
            <StatusBadge kind="host" value={l.host.state} />
            {#if l.host.uuid}
              <span class="font-mono text-xs">{l.host.uuid}</span>
            {/if}
            {#if l.host.pendingOp}
              <Badge variant="info">
                {l.host.pendingOp.kind === 'create' ? 'Creating' : 'Deleting'}, attempt {l.host
                  .pendingOp.attempts}
              </Badge>
            {/if}
          </div>
          {#if l.host.ownership}
            <p class="text-xs text-muted-foreground">{OWNERSHIP_WORDS[l.host.ownership]}</p>
          {/if}
          {#if l.host.state === 'ambiguous'}
            <p class="rounded-md border border-destructive/40 bg-destructive/10 p-2">
              Several backend Hosts fit this listener, so FCP will not pick one. Delete the
              duplicates in the backend; FCP looks again within a few minutes.
            </p>
          {:else if l.host.state === 'unresolved'}
            <p class="rounded-md border border-amber-500/40 bg-amber-500/10 p-2">
              FCP does not know whether its last backend call took effect. It keeps looking and
              writes nothing for this listener until the answer is clear.
            </p>
          {/if}
        {:else}
          <p class="text-muted-foreground">
            {relay.hostMode === 'fcp'
              ? 'None yet. FCP creates it when the first edge of this listener is published.'
              : 'FCP tracks none. You create it from the Hosts plan below.'}
          </p>
        {/if}
        {#if l.legacyHosts.length > 0}
          <p class="text-xs text-muted-foreground">
            Also matched, from an earlier manual setup (never deleted by FCP):
            <span class="font-mono">{l.legacyHosts.map((h) => h.remark).join(', ')}</span>
          </p>
        {/if}
        {#if relay.hostMode === 'operator' && l.panelBinding && l.host?.ownership == null}
          <div>
            <Button
              variant="outline"
              size="sm"
              disabled={locked}
              onclick={() => (adoptOpen = true)}
            >
              Adopt a Host
            </Button>
            <p class="mt-1 text-xs text-muted-foreground">
              Tell FCP which backend Host belongs to this listener. It is needed before FCP can take
              over writing the Hosts of this origin.
            </p>
          </div>
        {/if}
      </section>
    {/if}

    <!-- inbound -->
    {#if inboundRows.length > 0}
      <KeyValue
        title="Panel inbound"
        description={l.source === 'role'
          ? 'Read only: the node role owns these and sends them again with every registration.'
          : undefined}
        rows={inboundRows}
        columns={1}
      />
    {/if}

    {#if !l.retired}
      <div class="flex flex-wrap items-center gap-2 border-t pt-4">
        {#if l.enabled}
          <Button
            variant="outline"
            size="sm"
            disabled={locked}
            onclick={() => (disableOpen = true)}
          >
            Disable
          </Button>
        {:else}
          <Button
            variant="outline"
            size="sm"
            disabled={locked || act.isPending}
            onclick={() =>
              act.mutate({ run: () => enableListener(l.id), success: 'Listener enabled.' })}
          >
            Enable
          </Button>
        {/if}
        <Button
          variant="destructive"
          size="sm"
          disabled={locked}
          onclick={() => (deleteOpen = true)}
        >
          Retire listener
        </Button>
        <span class="text-xs text-muted-foreground">
          {edgeCount === 0
            ? 'No edge uses this listener.'
            : `${edgeCount} edge(s) use this listener.`}
          Revision {l.revision}, updated {relativeTime(l.updatedAt)}.
        </span>
      </div>
    {/if}
  </Card.Content>
</Card.Root>

{#if retireName}
  {@const name = retireName}
  <ActionConfirm
    open={true}
    title={`Retire ${name} on this listener?`}
    body={`New subscriptions stop presenting this name at once.${activeNames.length === 1 ? ' It is the last active name of this listener: behind an L4 edge nothing can be published for it until another name is added.' : ''} The node keeps accepting it for the drain time, so members who already hold it stay connected. A retired name is never selected again unless you reactivate it.`}
    confirmLabel="Retire name"
    danger
    onClose={() => (retireName = null)}
    run={() =>
      act.mutateAsync({
        run: () => retireListenerNames(l.id, [name]),
        success: `${name} retired on ${l.listenerKey}.`,
        quiet: true,
      })}
  />
{/if}

{#if retireEverywhere}
  {@const name = retireEverywhere}
  <ActionConfirm
    open={true}
    title={`Retire ${name} on every listener?`}
    body="This is fleet-wide: the name is retired on every listener of every relay that presents it, not only here. Use it when the name itself is blocked or burned. Subscriptions everywhere stop presenting it at once, publication epochs go up and mirrors refresh. A listener left without any active name cannot have edges published behind L4 until it gets another name."
    typed={name}
    confirmLabel="Retire everywhere"
    danger
    onClose={() => (retireEverywhere = null)}
    run={() =>
      act.mutateAsync({
        run: () => retireListenerNameEverywhere(name),
        success: `${name} retired on every listener.`,
        quiet: true,
      })}
  />
{/if}

<ActionConfirm
  bind:open={disableOpen}
  title={`Disable listener ${l.listenerKey}?`}
  body="Nothing new is published or selected for this listener, and its edges drop out of rendered subscriptions. Members who were served only through it go dark until it is enabled again. Its edges stay provisioned."
  confirmLabel="Disable listener"
  danger
  run={() =>
    act.mutateAsync({
      run: () => disableListener(l.id),
      success: 'Listener disabled.',
      quiet: true,
    })}
/>

<ActionConfirm
  bind:open={deleteOpen}
  title={`Retire listener ${l.listenerKey}?`}
  body={`The listener stops existing for FCP: nothing can be provisioned or published for it, and FCP deletes the address it created for it on the backend. ${edgeCount > 0 ? `It is refused while edges use it: ${edgeCount} still do, so destroy or delete them on the Edges tab first.` : 'No edge uses it, so this goes through.'}${l.source === 'role' ? ' The node role registered this listener and will register it again on its next run unless you remove it there too.' : ''}`}
  typed={l.listenerKey}
  confirmLabel="Retire listener"
  danger
  run={() =>
    act.mutateAsync({
      run: () => deleteRelayListener(relay.id, l.listenerKey),
      success: `Listener ${l.listenerKey} retired.`,
      quiet: true,
    })}
/>

<ActionConfirm
  bind:open={adoptOpen}
  title={`Adopt a Host for ${l.listenerKey}`}
  body="FCP checks that the Host exists in the panel, carries the inbound of this listener and dials one of its published edges. It then tracks that Host as yours: rewritten on rotations once FCP writes the Hosts, never deleted."
  confirmLabel="Adopt Host"
  disabled={!uuidOk}
  run={() =>
    act.mutateAsync({
      run: () => adoptListenerHost(relay.id, l.listenerKey, { hostUuid: addressUuid.trim() }),
      success: 'Host adopted.',
      after: () => (addressUuid = ''),
      quiet: true,
    })}
>
  <div class="space-y-1.5">
    <Label for={`adopt-${l.id}`}>Host uuid, from the backend's Hosts page</Label>
    <Input
      id={`adopt-${l.id}`}
      bind:value={addressUuid}
      class="font-mono"
      placeholder="00000000-0000-4000-8000-000000000000"
      autocomplete="off"
      aria-invalid={addressUuid !== '' && !uuidOk}
    />
    {#if addressUuid !== '' && !uuidOk}
      <p class="text-xs text-destructive">That does not look like a uuid.</p>
    {/if}
  </div>
</ActionConfirm>
