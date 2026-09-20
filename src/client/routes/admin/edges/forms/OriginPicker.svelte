<script lang="ts">
  /**
   * Choose what an origin's edges dial: a node of a backend, a whole backend
   * server, or an address described by hand. One flat draft (forms/origin.ts)
   * so switching kind keeps what was typed.
   *
   * Props:
   *   value: OriginDraft (bindable)
   *   disabled?: boolean
   *   lockKind?: boolean              the kind of an existing origin never changes
   *   onchange?: (next: OriginDraft) => void
   */
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import RefreshCw from '@lucide/svelte/icons/refresh-cw';
  import * as Combobox from '@client/components/ui/combobox';
  import * as Select from '@client/components/ui/select';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import { cn } from '@client/lib/utils';
  import { adminBackendServersQuery } from '@client/lib/queries';
  import { edgeKeys, nodeCandidatesQuery, refreshNodeCandidates } from '@client/lib/edgesApi';
  import AdminListState from '../../AdminListState.svelte';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { relativeTime } from '../lib/time';
  import { addressIssue, type OriginDraft, type OriginKind } from './origin';

  interface Props {
    value: OriginDraft;
    disabled?: boolean;
    lockKind?: boolean;
    onchange?: (next: OriginDraft) => void;
  }
  let { value = $bindable(), disabled = false, lockKind = false, onchange }: Props = $props();

  const uid = $props.id();
  const qc = useQueryClient();
  const servers = adminBackendServersQuery();

  const KINDS: Array<{ id: OriginKind; label: string; hint: string }> = [
    {
      id: 'panel-node',
      label: 'Backend node',
      hint: 'A node of a backend FCP manages. Subscriptions are rewritten for members pinned to it.',
    },
    {
      id: 'backend-server',
      label: 'Backend server',
      hint: 'A whole backend server, such as an Outline instance. Its single-key delivery is rewritten.',
    },
    {
      id: 'manual',
      label: 'Address',
      hint: 'An address you describe by hand. Nothing FCP serves maps to it, so you wire clients yourself from the connection plan.',
    },
  ];
  const kindHint = $derived(KINDS.find((k) => k.id === value.kind)?.hint ?? '');

  function patch(p: Partial<OriginDraft>) {
    value = { ...value, ...p };
    onchange?.(value);
  }
  function setKind(kind: OriginKind) {
    if (kind === value.kind) return;
    patch({ kind, backendServerId: '', backendSlug: '', nodeName: '', nodeUuid: null });
  }

  const panels = $derived((servers.data ?? []).filter((s) => s.config.type === 'remnawave'));
  const wholeServers = $derived((servers.data ?? []).filter((s) => s.config.type !== 'remnawave'));
  const serverOptions = $derived(value.kind === 'panel-node' ? panels : wholeServers);
  const serverName = $derived(
    serverOptions.find((s) => s.id === value.backendServerId)?.name ?? '',
  );
  function setServer(id: string) {
    const s = serverOptions.find((x) => x.id === id);
    patch({ backendServerId: id, backendSlug: s?.slug ?? '', nodeName: '', nodeUuid: null });
  }

  const candidates = nodeCandidatesQuery(() =>
    value.kind === 'panel-node' && value.backendServerId ? value.backendServerId : null,
  );
  let nodeQuery = $state('');
  let nodeOpen = $state(false);
  const nodes = $derived(candidates.data?.nodes ?? []);
  const filteredNodes = $derived(
    nodes.filter((n) => n.name.toLowerCase().includes(nodeQuery.trim().toLowerCase())).slice(0, 80),
  );
  function setNode(name: string) {
    const n = nodes.find((x) => x.name === name);
    if (!n) return;
    patch({
      nodeName: n.name,
      nodeUuid: n.nodeUuid,
      // The backend already knows where the node is; the operator can still correct it.
      address: n.address && addressIssue(n.address) === null ? n.address : value.address,
    });
  }

  const refresh = createMutation(() => ({
    mutationFn: () => refreshNodeCandidates(value.backendServerId),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: edgeKeys.nodeCandidates(value.backendServerId) });
      toast.success('Node list refreshed');
    },
    onError: (err: unknown) =>
      toast.error('Could not refresh the node list', { description: edgeErrorMessage(err) }),
  }));

  let addressTouched = $state(false);
  const addressProblem = $derived(
    addressTouched || value.address.trim() !== '' ? addressIssue(value.address) : null,
  );
</script>

<div class="space-y-4">
  <fieldset class="space-y-1.5" disabled={disabled || lockKind}>
    <legend class="text-sm font-medium">Origin kind</legend>
    <div class="bg-muted inline-flex rounded-lg p-0.5" role="radiogroup" aria-label="Origin kind">
      {#each KINDS as k (k.id)}
        <button
          type="button"
          role="radio"
          aria-checked={value.kind === k.id}
          class={cn(
            'focus-visible:ring-ring/60 rounded-md px-3 py-1.5 text-sm outline-none transition-colors focus-visible:ring-2 disabled:cursor-not-allowed disabled:opacity-60',
            value.kind === k.id
              ? 'bg-background text-foreground shadow-sm'
              : 'text-muted-foreground hover:text-foreground',
          )}
          onclick={() => setKind(k.id)}
        >
          {k.label}
        </button>
      {/each}
    </div>
    <p class="text-muted-foreground text-xs">{kindHint}</p>
  </fieldset>

  {#if value.kind !== 'manual'}
    <div class="space-y-1.5">
      <Label for={`${uid}-server`}>{value.kind === 'panel-node' ? 'Panel' : 'Backend server'}</Label
      >
      {#if servers.isError}
        <AdminListState error={servers.error} onRetry={() => void servers.refetch()} />
      {:else if !servers.isPending && serverOptions.length === 0}
        <AdminListState
          emptyText={value.kind === 'panel-node'
            ? 'No panel is registered yet. Add one under Backend servers, then come back.'
            : 'No whole-server backend is registered yet. Add one under Backend servers, then come back.'}
        />
      {:else}
        <Select.Root
          type="single"
          value={value.backendServerId}
          onValueChange={(v: string) => setServer(v)}
          {disabled}
        >
          <Select.Trigger id={`${uid}-server`} class="w-full">
            {serverName || (servers.isPending ? 'Loading' : 'Choose one')}
          </Select.Trigger>
          <Select.Content>
            {#each serverOptions as s (s.id)}
              <Select.Item value={s.id} label={s.name}>
                {s.name}
                {#if !s.isActive}<span class="text-muted-foreground text-xs">(inactive)</span>{/if}
              </Select.Item>
            {/each}
          </Select.Content>
        </Select.Root>
      {/if}
    </div>
  {/if}

  {#if value.kind === 'panel-node' && value.backendServerId}
    <div class="space-y-1.5">
      <div class="flex items-end justify-between gap-2">
        <Label for={`${uid}-node`}>Node</Label>
        <Button
          size="sm"
          variant="ghost"
          disabled={disabled || refresh.isPending}
          onclick={() => refresh.mutate()}
        >
          <RefreshCw
            class={cn('size-3.5', refresh.isPending && 'animate-spin')}
            aria-hidden="true"
          />
          Refresh
        </Button>
      </div>
      {#if candidates.isError}
        <AdminListState error={candidates.error} onRetry={() => void candidates.refetch()} />
      {:else}
        <Combobox.Root
          type="single"
          bind:open={nodeOpen}
          value={value.nodeName}
          onValueChange={(v: string) => setNode(v)}
          {disabled}
          onOpenChangeComplete={(o: boolean) => {
            if (!o) nodeQuery = '';
          }}
        >
          <div class="relative">
            <Combobox.Input
              id={`${uid}-node`}
              class="pe-9"
              placeholder={candidates.isPending ? 'Loading nodes' : 'Search nodes by name'}
              defaultValue={value.nodeName}
              oninput={(e) => (nodeQuery = e.currentTarget.value)}
              onfocus={() => (nodeOpen = true)}
            />
            <Combobox.Trigger class="absolute end-0.5 top-0" aria-label="Show nodes" />
          </div>
          <Combobox.Content>
            {#each filteredNodes as n (n.nodeUuid)}
              <Combobox.Item value={n.name} label={n.name} disabled={n.relaySlug !== null}>
                <span class="min-w-0 flex-1 truncate">{n.name}</span>
                <span class="text-muted-foreground text-xs">
                  {#if n.relaySlug}
                    already relay {n.relaySlug}
                  {:else}
                    {n.countryCode ?? ''} {n.online ? 'online' : 'offline'}
                  {/if}
                </span>
              </Combobox.Item>
            {:else}
              <p class="text-muted-foreground px-2 py-1.5 text-sm">
                {nodes.length === 0
                  ? 'The panel lists no node yet. Refresh after the node has joined.'
                  : 'No node matches.'}
              </p>
            {/each}
          </Combobox.Content>
        </Combobox.Root>
        <p class="text-muted-foreground text-xs">
          One relay per node: nodes that already have a relay cannot be chosen.
          {#if candidates.data?.fetchedAt}
            List fetched {relativeTime(candidates.data.fetchedAt)}.
          {/if}
        </p>
      {/if}
    </div>
  {/if}

  <div class="space-y-1.5">
    <Label for={`${uid}-address`}>Origin address</Label>
    <Input
      id={`${uid}-address`}
      class="font-mono"
      placeholder="198.51.100.10 or origin.example"
      value={value.address}
      {disabled}
      aria-invalid={addressProblem !== null}
      aria-describedby={`${uid}-address-help`}
      oninput={(e) => patch({ address: e.currentTarget.value })}
      onblur={() => (addressTouched = true)}
    />
    <p
      id={`${uid}-address-help`}
      class={cn('text-xs', addressProblem ? 'text-destructive' : 'text-muted-foreground')}
    >
      {addressProblem ?? 'What edges dial. A public IP address or DNS name. Members never see it.'}
    </p>
  </div>
</div>
