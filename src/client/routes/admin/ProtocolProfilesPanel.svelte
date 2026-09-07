<script lang="ts">
  import {
    Card,
    CardHeader,
    CardTitle,
    CardDescription,
    CardContent,
  } from '@client/components/ui/card';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Checkbox } from '@client/components/ui/checkbox';
  import * as Dialog from '@client/components/ui/dialog';
  import * as Select from '@client/components/ui/select';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import { adminProtocolProfilesQuery } from '../../lib/queries';
  import {
    EDGE_PROVIDER_IDS,
    SLOT_PROTOCOL_IDS,
    RelayIdResponse,
    RelayOkResponse,
    type ProtocolProfileAdmin,
    type EdgeProviderId,
    type SlotProtocol,
  } from '../../../shared/contracts/relays';
  import { formatDateTime } from '../../lib/i18n/format';
  import AdminListState from './AdminListState.svelte';

  /**
   * Protocol profiles: what a relay slot's inbound speaks and what the renderer
   * needs for it. REALITY carries the impersonated target and approved server
   * names; TLS carries the certificate's names; plain carries nothing (address
   * and port only). A profile may be scoped to one provider's network (REALITY
   * names are only plausible near the edge) or left open to any provider. One
   * SNI per emitted connection is chosen per subscriber; retiring a name stops
   * new selections and starts its drain. The node role deploys one inbound per
   * slot and one template Host.
   */
  const profiles = adminProtocolProfilesQuery();
  const qc = useQueryClient();
  const invalidate = () => void qc.invalidateQueries({ queryKey: ['admin', 'relays'] });
  const onError = (title: string) => (err: unknown) =>
    toast.error(title, { description: apiErrorMessage(err) });

  const PROTOCOL_LABELS: Record<SlotProtocol, string> = {
    reality: 'REALITY',
    tls: 'TLS (real certificate)',
    plain: 'Plain (no TLS name)',
  };
  const ANY = 'any';

  type Draft = {
    id: string | null;
    slug: string;
    name: string;
    protocol: SlotProtocol;
    provider: EdgeProviderId | typeof ANY;
    targetAddress: string;
    targetPort: number;
    serverNames: string;
    enabled: boolean;
    notes: string;
  };
  let editor = $state<Draft | null>(null);
  const newDraft = (): Draft => ({
    id: null,
    slug: '',
    name: '',
    protocol: 'reality',
    provider: ANY,
    targetAddress: '',
    targetPort: 443,
    serverNames: '',
    enabled: true,
    notes: '',
  });
  const editDraft = (p: ProtocolProfileAdmin): Draft => ({
    id: p.id,
    slug: p.slug,
    name: p.name,
    protocol: p.protocol,
    provider: p.provider ?? ANY,
    targetAddress: p.targetAddress ?? '',
    targetPort: p.targetPort ?? 443,
    serverNames: p.serverNames
      .filter((s) => s.status === 'active')
      .map((s) => s.sni)
      .join('\n'),
    enabled: p.enabled,
    notes: p.notes ?? '',
  });
  const names = (s: string) =>
    s
      .split(/[\n,\s]+/)
      .map((x) => x.trim())
      .filter(Boolean);
  const usesSni = (p: SlotProtocol) => p !== 'plain';

  const save = createMutation(() => ({
    mutationFn: async () => {
      const d = editor!;
      const body = {
        name: d.name.trim(),
        provider: d.provider === ANY ? null : d.provider,
        ...(d.protocol === 'reality'
          ? { targetAddress: d.targetAddress.trim(), targetPort: Number(d.targetPort) }
          : {}),
        serverNames: usesSni(d.protocol) ? names(d.serverNames) : [],
        enabled: d.enabled,
        notes: d.notes.trim(),
      };
      if (d.id)
        return apiClient.patch(`/api/v1/admin/relay/profiles/${d.id}`, body, RelayOkResponse);
      return apiClient.post(
        '/api/v1/admin/relay/profiles',
        { ...body, slug: d.slug.trim(), protocol: d.protocol },
        RelayIdResponse,
      );
    },
    onSuccess: () => {
      editor = null;
      invalidate();
      toast.success('Profile saved');
    },
    onError: onError('Could not save the profile'),
  }));
  const sniOp = createMutation(() => ({
    mutationFn: ({
      id,
      op,
      sni,
    }: {
      id: string;
      op: 'retire-sni' | 'reactivate-sni';
      sni: string;
    }) =>
      apiClient.post(`/api/v1/admin/relay/profiles/${id}/${op}`, { snis: [sni] }, RelayOkResponse),
    onSuccess: () => {
      invalidate();
      toast.success('Server names updated');
    },
    onError: onError('Could not update the server name'),
  }));
  const remove = createMutation(() => ({
    mutationFn: (id: string) =>
      apiClient.delete(`/api/v1/admin/relay/profiles/${id}`, RelayOkResponse),
    onSuccess: () => {
      invalidate();
      toast.success('Profile removed');
    },
    onError: onError('Could not remove the profile'),
  }));
</script>

<div class="space-y-4">
  <div class="flex justify-end">
    <Button onclick={() => (editor = newDraft())}>New profile</Button>
  </div>
  {#if profiles.isError}<AdminListState
      error={profiles.error}
      onRetry={() => void profiles.refetch()}
    />{/if}
  {#if profiles.data && profiles.data.length === 0}
    <AdminListState
      emptyText="No protocol profiles. A profile says what a slot's inbound speaks (REALITY, TLS or plain) and which server names members may present, optionally for one provider's network."
    />
  {/if}
  {#each profiles.data ?? [] as p (p.id)}
    <Card>
      <CardHeader class="pb-2">
        <div class="flex flex-wrap items-start justify-between gap-2">
          <div>
            <CardTitle class="flex flex-wrap items-center gap-2 text-base">
              <span class="font-mono">{p.slug}</span><span>{p.name}</span>
              <span class="rounded-full border px-2 py-0.5 text-xs"
                >{PROTOCOL_LABELS[p.protocol]}</span
              >
              <span class="rounded-full border px-2 py-0.5 text-xs"
                >{p.provider ?? 'any provider'}</span
              >
              {#if !p.enabled}<span class="rounded-full border px-2 py-0.5 text-xs">disabled</span
                >{/if}
            </CardTitle>
            <CardDescription class="mt-1">
              {#if p.protocol === 'reality'}
                target <span class="font-mono">{p.targetAddress}:{p.targetPort}</span>
              {:else if p.protocol === 'tls'}
                the node terminates TLS with its own certificate
              {:else}
                no TLS name: address and port only
              {/if}
              {#if p.qualification}· qualified {formatDateTime(p.qualification.checkedAt)}: TLS {p
                  .qualification.tlsOk
                  ? 'ok'
                  : 'failed'}, auth {p.qualification.authOk ? 'ok' : 'failed'}{p.qualification
                  .sameAsn !== null
                  ? `, same ASN ${p.qualification.sameAsn ? 'yes' : 'no'}`
                  : ''}{/if}
            </CardDescription>
          </div>
          <div class="flex gap-1.5">
            <Button size="sm" variant="ghost" onclick={() => (editor = editDraft(p))}>Edit</Button>
            <Button
              size="sm"
              variant="ghost"
              class="text-destructive"
              onclick={() => remove.mutate(p.id)}>Remove</Button
            >
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {#if p.serverNames.length > 0}
          <ul class="flex flex-wrap gap-1.5 text-xs">
            {#each p.serverNames as s (s.sni)}
              <li
                class="flex items-center gap-1 rounded-full border px-2 py-0.5 {s.status ===
                'retired'
                  ? 'opacity-60'
                  : ''}"
              >
                <span class="font-mono">{s.sni}</span>
                {#if s.status === 'retired'}
                  <span
                    >retired{s.drainUntil
                      ? `, drains until ${formatDateTime(s.drainUntil)}`
                      : ''}</span
                  >
                  <button
                    type="button"
                    class="underline"
                    onclick={() => sniOp.mutate({ id: p.id, op: 'reactivate-sni', sni: s.sni })}
                    >reactivate</button
                  >
                {:else}
                  <button
                    type="button"
                    class="underline"
                    onclick={() => sniOp.mutate({ id: p.id, op: 'retire-sni', sni: s.sni })}
                    >retire</button
                  >
                {/if}
              </li>
            {/each}
          </ul>
        {/if}
        {#if p.notes}<p class="mt-2 text-xs text-muted-foreground">{p.notes}</p>{/if}
      </CardContent>
    </Card>
  {/each}
</div>

<Dialog.Root open={editor !== null} onOpenChange={(v) => !v && (editor = null)}>
  <Dialog.Content class="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
    <Dialog.Header>
      <Dialog.Title>{editor?.id ? 'Edit profile' : 'New protocol profile'}</Dialog.Title>
      <Dialog.Description
        >Server names become the ACTIVE set: names removed here are retired with a drain, never
        deleted. The protocol is fixed once created.</Dialog.Description
      >
    </Dialog.Header>
    {#if editor}
      <div class="grid gap-3">
        <div class="grid gap-3 sm:grid-cols-2">
          {#if !editor.id}
            <label class="text-xs"
              >Slug<Input class="mt-1" bind:value={editor.slug} placeholder="profile-a" /></label
            >
            <label class="text-xs"
              >Protocol
              <Select.Root
                type="single"
                value={editor.protocol}
                onValueChange={(v) => (editor!.protocol = v as SlotProtocol)}
              >
                <Select.Trigger class="mt-1 w-full"
                  >{PROTOCOL_LABELS[editor.protocol]}</Select.Trigger
                >
                <Select.Content
                  >{#each SLOT_PROTOCOL_IDS as p (p)}<Select.Item value={p}
                      >{PROTOCOL_LABELS[p]}</Select.Item
                    >{/each}</Select.Content
                >
              </Select.Root>
            </label>
          {/if}
          <label class="text-xs">Name<Input class="mt-1" bind:value={editor.name} /></label>
          <label class="text-xs"
            >Provider scope
            <Select.Root
              type="single"
              value={editor.provider}
              onValueChange={(v) => (editor!.provider = v as EdgeProviderId | typeof ANY)}
            >
              <Select.Trigger class="mt-1 w-full"
                >{editor.provider === ANY ? 'Any provider' : editor.provider}</Select.Trigger
              >
              <Select.Content>
                <Select.Item value={ANY}>Any provider</Select.Item>
                {#each EDGE_PROVIDER_IDS as p (p)}<Select.Item value={p}>{p}</Select.Item>{/each}
              </Select.Content>
            </Select.Root>
          </label>
          {#if editor.protocol === 'reality'}
            <label class="text-xs"
              >REALITY target address<Input
                class="mt-1"
                bind:value={editor.targetAddress}
                placeholder="target.example"
              /></label
            >
            <label class="text-xs"
              >Target port<Input class="mt-1" type="number" bind:value={editor.targetPort} /></label
            >
          {/if}
        </div>
        {#if usesSni(editor.protocol)}
          <label class="text-xs"
            >{editor.protocol === 'reality'
              ? 'Approved server names (one per line)'
              : 'Certificate names members may present (one per line)'}
            <textarea
              class="mt-1 w-full rounded-md border bg-background p-2 font-mono text-xs"
              rows="5"
              bind:value={editor.serverNames}
            ></textarea>
          </label>
        {:else}
          <p class="text-xs text-muted-foreground">
            A plain profile presents no TLS name: the renderer rewrites address and port only.
          </p>
        {/if}
        <label class="text-xs">Notes<Input class="mt-1" bind:value={editor.notes} /></label>
        <label class="flex items-center gap-2 text-sm"
          ><Checkbox bind:checked={editor.enabled} /> Enabled</label
        >
      </div>
    {/if}
    <Dialog.Footer>
      <Button variant="outline" onclick={() => (editor = null)}>Cancel</Button>
      <Button disabled={save.isPending} onclick={() => save.mutate()}>Save</Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
