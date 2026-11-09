<script lang="ts">
  /**
   * Custom probe targets: operator-entered host and port pairs (CRUD + probe now).
   * Operator evidence only, except a REFERENCE SITE: a well-known site a CDN
   * serves, read before an automatic replacement on that CDN. A country that
   * cannot reach it (while others can) refuses the whole CDN, so FCP spends no
   * new name there (docs/edges.md "Reference sites").
   */
  import { DIALOG_FIT, STICKY_FOOTER } from '../lib/dialogLayout';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Badge } from '@client/components/ui/badge';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { Switch } from '@client/components/ui/switch';
  import * as Dialog from '@client/components/ui/dialog';
  import * as Select from '@client/components/ui/select';
  import * as Table from '@client/components/ui/table';
  import type { ProbeTargetAdmin } from '../../../../../shared/contracts/edges';
  import AdminListState from '../../AdminListState.svelte';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import {
    createProbeTarget,
    deleteProbeTarget,
    invalidateProbes,
    probeTargetsQuery,
    requestProbes,
    updateProbeTarget,
    type ProbeTargetBody,
  } from '../../../../lib/edgesApi';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { PROBE_CHECK_LABELS, probeRequestSummary } from './matrix';
  import { EDGE_PROVIDER_IDS } from '../../../../../shared/contracts/edgeProviderIds';
  import type { EdgeProviderId } from '../../../../../shared/contracts/edgeProviderIds';
  import { EDGE_PROVIDER_META } from '../../../../lib/edgeProviderMeta';

  const qc = useQueryClient();
  const targets = probeTargetsQuery();

  type ProbeProtocol = ProbeTargetBody['probeProtocol'];
  const CHECKS: Array<{ id: ProbeProtocol; help: string }> = [
    { id: 'tcp', help: 'Opens a TCP connection. Reachable when the connection is accepted.' },
    {
      id: 'tls',
      help: 'TLS handshake with the hostname as SNI. A certificate error counts as unreachable.',
    },
    { id: 'https', help: 'HTTP GET over TLS. Any status code counts as reachable.' },
  ];

  // A reference site is for a CDN (an L7 provider).
  const CDN_PROVIDERS = EDGE_PROVIDER_IDS.filter((id) => EDGE_PROVIDER_META[id].layer === 'l7');
  const NONE = 'none';
  const referenceLabel = (id: EdgeProviderId | null) =>
    id ? EDGE_PROVIDER_META[id].label : 'Not a reference site';
  const isAddressLiteral = (s: string) => /^[0-9.]+$/.test(s.trim()) || s.includes(':');

  type Draft = ProbeTargetBody & { id: string | null };
  let editor = $state<Draft | null>(null);
  const newDraft = (): Draft => ({
    id: null,
    label: '',
    address: '',
    port: 443,
    probeProtocol: 'tcp',
    enabled: true,
    notes: '',
    referenceFor: null,
  });
  const editDraft = (t: ProbeTargetAdmin): Draft => ({
    id: t.id,
    label: t.label,
    address: t.address,
    port: t.port,
    probeProtocol: t.probeProtocol,
    enabled: t.enabled,
    notes: t.notes ?? '',
    referenceFor: t.referenceFor,
  });
  const portValid = $derived(
    editor !== null &&
      Number.isInteger(Number(editor.port)) &&
      Number(editor.port) >= 1 &&
      Number(editor.port) <= 65535,
  );
  // A reference site needs a name and a TLS or HTTPS check (the server says the same).
  const referenceProblem = $derived.by(() => {
    if (!editor?.referenceFor) return null;
    if (editor.address.trim() !== '' && isAddressLiteral(editor.address))
      return 'A reference site needs a hostname, not an IP address.';
    if (editor.probeProtocol === 'tcp')
      return 'A reference site needs the TLS or HTTPS check. A network that refuses a CDN usually lets the TCP connection open.';
    return null;
  });
  const draftValid = $derived(
    editor !== null &&
      editor.label.trim() !== '' &&
      editor.address.trim() !== '' &&
      portValid &&
      referenceProblem === null,
  );

  const save = createMutation(() => ({
    mutationFn: async () => {
      const d = editor!;
      const body: ProbeTargetBody = {
        label: d.label.trim(),
        address: d.address.trim(),
        port: Number(d.port),
        probeProtocol: d.probeProtocol,
        enabled: d.enabled,
        notes: d.notes.trim(),
        referenceFor: d.referenceFor,
      };
      if (d.id) return updateProbeTarget(d.id, body);
      return createProbeTarget(body);
    },
    onSuccess: () => {
      editor = null;
      invalidateProbes(qc);
      toast.success('Target saved');
    },
    onError: (err: unknown) =>
      toast.error('Could not save the target', { description: edgeErrorMessage(err) }),
  }));

  let removing = $state<ProbeTargetAdmin | null>(null);
  let removeOpen = $state(false);
  async function confirmRemove() {
    if (!removing) return;
    await deleteProbeTarget(removing.id);
    invalidateProbes(qc);
    toast.success('Target removed');
    removing = null;
  }

  const probeNow = createMutation(() => ({
    mutationFn: (key: string) => requestProbes([key]),
    onSuccess: (res) => {
      invalidateProbes(qc);
      toast.success(probeRequestSummary(res));
    },
    onError: (err: unknown) =>
      toast.error('Probe request refused', { description: edgeErrorMessage(err) }),
  }));
</script>

<div class="mb-3 flex justify-end">
  <Button size="sm" onclick={() => (editor = newDraft())}>Add target</Button>
</div>

{#if targets.isPending}
  <Skeleton class="h-16 w-full" />
{:else if targets.isError}
  <AdminListState error={targets.error} onRetry={() => void targets.refetch()} />
{:else if (targets.data?.targets ?? []).length === 0}
  <AdminListState
    emptyText="No custom targets. Use Add target to watch any host and port from the configured countries."
  />
{:else}
  <Table.Root>
    <Table.Header>
      <Table.Row>
        <Table.Head>Label</Table.Head>
        <Table.Head>Address</Table.Head>
        <Table.Head>Check</Table.Head>
        <Table.Head>Schedule</Table.Head>
        <Table.Head><span class="sr-only">Actions</span></Table.Head>
      </Table.Row>
    </Table.Header>
    <Table.Body>
      {#each targets.data?.targets ?? [] as t (t.id)}
        <Table.Row>
          <Table.Cell>
            <div class="font-medium">
              {t.label}
              {#if t.referenceFor}
                <Badge variant="muted" class="ml-1">
                  Reference for {EDGE_PROVIDER_META[t.referenceFor].label}
                </Badge>
              {/if}
            </div>
            {#if t.notes}<div class="text-xs text-muted-foreground">{t.notes}</div>{/if}
          </Table.Cell>
          <Table.Cell class="font-mono text-xs">{t.display}</Table.Cell>
          <Table.Cell>{PROBE_CHECK_LABELS[t.probeProtocol] ?? t.probeProtocol}</Table.Cell>
          <Table.Cell>
            <Badge variant={t.enabled ? 'success' : 'muted'}
              >{t.enabled ? 'Every round' : 'On demand only'}</Badge
            >
          </Table.Cell>
          <Table.Cell class="text-right whitespace-nowrap">
            <Button
              size="sm"
              variant="outline"
              class="h-7 px-2 text-xs"
              disabled={probeNow.isPending}
              onclick={() => probeNow.mutate(t.key)}>Probe now</Button
            >
            <Button
              size="sm"
              variant="ghost"
              class="h-7 px-2 text-xs"
              onclick={() => (editor = editDraft(t))}>Edit</Button
            >
            <Button
              size="sm"
              variant="ghost"
              class="h-7 px-2 text-xs text-destructive"
              onclick={() => {
                removing = t;
                removeOpen = true;
              }}>Remove</Button
            >
          </Table.Cell>
        </Table.Row>
      {/each}
    </Table.Body>
  </Table.Root>
{/if}

<ConfirmDialog
  bind:open={removeOpen}
  title="Remove this target?"
  body={removing?.referenceFor
    ? `"${removing.label}" and its reachability history are removed. Without a reference site, FCP cannot tell when a country refuses this CDN outright, and replaces hostnames there as before.`
    : `"${removing?.label ?? ''}" and its reachability history are removed. Nothing else depends on a custom target.`}
  typed={removing?.label}
  confirmLabel="Remove target"
  danger
  onConfirm={confirmRemove}
/>

<Dialog.Root open={editor !== null} onOpenChange={(v) => !v && (editor = null)}>
  <Dialog.Content class={DIALOG_FIT}>
    <Dialog.Header>
      <Dialog.Title>{editor?.id ? 'Edit target' : 'New custom target'}</Dialog.Title>
      <Dialog.Description>
        A public hostname or IP address plus a TCP port. Changing either resets the target's
        history.
      </Dialog.Description>
    </Dialog.Header>
    {#if editor}
      <div class="grid gap-3">
        <div class="grid gap-1.5">
          <Label for="pt-label">Label</Label>
          <Input id="pt-label" bind:value={editor.label} placeholder="Decoy site" />
        </div>
        <div class="grid gap-3 sm:grid-cols-[1fr_8rem]">
          <div class="grid gap-1.5">
            <Label for="pt-address">Address</Label>
            <Input
              id="pt-address"
              class="font-mono"
              bind:value={editor.address}
              placeholder="host.example or 198.51.100.9"
            />
          </div>
          <div class="grid gap-1.5">
            <Label for="pt-port">Port</Label>
            <Input
              id="pt-port"
              type="number"
              min="1"
              max="65535"
              bind:value={editor.port}
              aria-invalid={!portValid}
            />
          </div>
        </div>
        <div class="grid gap-1.5">
          <Label for="pt-check">Check</Label>
          <Select.Root
            type="single"
            value={editor.probeProtocol}
            onValueChange={(v) => (editor!.probeProtocol = v as ProbeProtocol)}
          >
            <Select.Trigger id="pt-check" class="w-full"
              >{PROBE_CHECK_LABELS[editor.probeProtocol]}</Select.Trigger
            >
            <Select.Content>
              {#each CHECKS as c (c.id)}
                <Select.Item value={c.id}>{PROBE_CHECK_LABELS[c.id]}</Select.Item>
              {/each}
            </Select.Content>
          </Select.Root>
          <p class="text-xs text-muted-foreground">
            {CHECKS.find((c) => c.id === editor?.probeProtocol)?.help}
          </p>
        </div>
        <div class="grid gap-1.5">
          <Label for="pt-reference">Reference site for</Label>
          <Select.Root
            type="single"
            value={editor.referenceFor ?? NONE}
            onValueChange={(v) =>
              (editor!.referenceFor = v === NONE ? null : (v as EdgeProviderId))}
          >
            <Select.Trigger id="pt-reference" class="w-full"
              >{referenceLabel(editor.referenceFor)}</Select.Trigger
            >
            <Select.Content>
              <Select.Item value={NONE}>{referenceLabel(null)}</Select.Item>
              {#each CDN_PROVIDERS as id (id)}
                <Select.Item value={id}>{EDGE_PROVIDER_META[id].label}</Select.Item>
              {/each}
            </Select.Content>
          </Select.Root>
          <p class="text-xs text-muted-foreground">
            A well-known site this CDN serves. If it fails from one country while others reach it,
            that country refuses the whole CDN, so FCP does not spend a new hostname there.
          </p>
          {#if referenceProblem}
            <p class="text-xs text-destructive" role="alert">{referenceProblem}</p>
          {/if}
        </div>
        <div class="grid gap-1.5">
          <Label for="pt-notes">Notes</Label>
          <Input id="pt-notes" bind:value={editor.notes} />
        </div>
        <label class="flex items-center gap-2 text-sm">
          <Switch bind:checked={editor.enabled} />
          Probe on every scheduled round. Off: on demand only.
        </label>
      </div>
    {/if}
    <Dialog.Footer class={STICKY_FOOTER}>
      <Button variant="outline" onclick={() => (editor = null)}>Cancel</Button>
      <Button disabled={!draftValid || save.isPending} onclick={() => save.mutate()}>
        {save.isPending ? 'Saving' : 'Save target'}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
