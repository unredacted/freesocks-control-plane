<script lang="ts">
  /**
   * "Add a spare address" on the node page: one confirm. FCP picks the
   * transport and the account (the provision preflight's own choice); the
   * spare waits unused until someone ticks it on the test card, and only a
   * tested spare is ever put in use. Both the dry run and the provision ask
   * for an unpublished spare (`publish: false`), so an existing standby is
   * never put in use instead. The dry run shows only what blocks it.
   *
   * With `renew` the spare is a replacement for one that does not work: that
   * one is destroyed first (always allowed), then the dry run is asked again
   * and the new spare is created only when nothing blocks it. A destroyed edge
   * still counts against its account until the provider confirms it gone, so
   * an account at its limit gets the new spare later ("Add a spare" again).
   *
   * Where: Automatic (the dry run's own choice, said in words), or one location
   * of the node's set for the transport Automatic would pick. A named location
   * offers "Options for this address" (prefilled with the node's options there);
   * an address built with other options is never taken by automatic work.
   *
   * Props:
   *   open (bindable); relay; renew?: { edgeId, listenerId, listenerKey } | null
   *   listeners?: { id, listenerKey }[]   the node's transports (for a named location)
   *   onStarted?()                 after the create was accepted
   *   onClose?()                   whenever the dialog closes (for a caller that mounts it per use)
   */
  import { createQuery, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import type { OriginAdmin } from '@shared/contracts/edges';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { Label } from '@client/components/ui/label';
  import * as Select from '@client/components/ui/select';
  import { codeLabel } from '@client/lib/edgeCodes';
  import {
    deleteEdge,
    edgeConfigQuery,
    edgeKeys,
    invalidateRelay,
    preflightRelay,
    providersQuery,
    provisionRelay,
    relayProvidersQuery,
    templatesQuery,
  } from '@client/lib/edgesApi';
  import PickOptions from './PickOptions.svelte';
  import { overrides, pickBase } from '../lib/options';
  import { asParams, deepEqual, type Params } from '../templates/params';
  import CodeNote from '../components/CodeNote.svelte';
  import AdminListState from '../../AdminListState.svelte';
  import ActionConfirm from '../relay/ActionConfirm.svelte';
  import { assertEdgeOk } from '../lib/edgeErrors';
  import { spareInUseWords } from './runWords';

  interface Props {
    open: boolean;
    relay: OriginAdmin;
    renew?: { edgeId: string; listenerId: string; listenerKey: string } | null;
    listeners?: Array<{ id: string; listenerKey: string }>;
    onStarted?: () => void;
    onClose?: () => void;
  }
  let {
    open = $bindable(false),
    relay,
    renew = null,
    listeners = [],
    onStarted,
    onClose,
  }: Props = $props();

  const qc = useQueryClient();
  const uid = $props.id();
  // A node that wants more addresses in use takes a tested spare at once.
  const config = edgeConfigQuery();
  const inUseNote = $derived(config.data ? spareInUseWords(config.data.config, relay) : null);
  /** '' = Automatic; else a location of the node's set. */
  let where = $state('');
  const setQ = relayProvidersQuery({
    slug: () => relay.slug,
    id: () => relay.id,
    poll: false,
  });
  const picks = $derived((setQ.data?.picks ?? []).filter((p) => p.usable));
  // Options for this one address, at a named location: the node's there to start with.
  const providersQ = providersQuery();
  const templatesQ = templatesQuery();
  const whereOptions = $derived.by(() => {
    const p = picks.find((x) => x.locationId === where);
    const schema = p ? providersQ.data?.optionSchemas[p.provider] : undefined;
    const account = p ? providersQ.data?.accounts.find((a) => a.id === p.accountId) : undefined;
    if (!p || !schema || !account) return null;
    const base = pickBase(
      schema,
      templatesQ.data?.schemas[p.provider]?.defaults ?? {},
      templatesQ.data?.templates ?? [],
      account,
      account.locations.find((l) => l.id === p.locationId) ?? null,
    );
    return {
      pick: p,
      fields: schema.fields,
      base,
      chosen: overrides(asParams(p.options), base, schema.fields),
    };
  });
  let oneOff = $state<Params | null>(null);
  $effect(() => {
    void where;
    oneOff = null;
  });
  const spareCheck = (listenerKey?: string, locationId?: string) =>
    preflightRelay(relay.id, {
      kind: 'provision',
      trigger: 'manual',
      publish: false,
      ...(listenerKey ? { listenerKey } : {}),
      ...(locationId ? { locationId } : {}),
    });
  // A new spare is checked before the confirm; a renewal after the old one is gone.
  const preflight = createQuery(() => ({
    queryKey: [...edgeKeys.relay(relay.slug), 'preflight', 'spare'],
    queryFn: () => spareCheck(),
    enabled: open && !renew,
    staleTime: 0,
    gcTime: 0,
  }));
  // The transport Automatic would give the spare: a named location gets it too.
  const autoKey = $derived(preflight.data?.wouldSelect?.listenerKey ?? null);
  const autoListener = $derived(listeners.find((l) => l.listenerKey === autoKey) ?? null);
  const named = createQuery(() => ({
    queryKey: [...edgeKeys.relay(relay.slug), 'preflight', 'spare', where, autoKey],
    queryFn: () => spareCheck(autoKey ?? undefined, where),
    enabled: open && !renew && where !== '' && !!autoKey,
    staleTime: 0,
    gcTime: 0,
  }));
  const blockers = $derived(
    renew ? [] : where ? (named.data?.blockers ?? []) : (preflight.data?.blockers ?? []),
  );
  const autoWords = $derived.by(() => {
    const w = preflight.data?.wouldSelect;
    if (!w?.accountName || where) return null;
    return `Automatic creates it in ${w.locationLabel ? `${w.locationLabel} (${w.accountName})` : w.accountName}.`;
  });

  let destroyed = $state<string | null>(null);
  async function run(): Promise<void> {
    if (!renew) {
      await provisionRelay(
        relay.id,
        where && autoListener
          ? {
              publish: false,
              listenerId: autoListener.id,
              locationId: where,
              // Only when they differ from the node's own options there.
              ...(oneOff && whereOptions && !deepEqual(oneOff, whereOptions.chosen)
                ? { options: $state.snapshot(oneOff) }
                : {}),
            }
          : { publish: false },
      );
      toast.success('Creating a spare address. Test it here once it is ready.');
      invalidateRelay(qc, relay.slug);
      onStarted?.();
      return;
    }
    if (destroyed !== renew.edgeId) {
      assertEdgeOk(await deleteEdge(renew.edgeId));
      destroyed = renew.edgeId;
      invalidateRelay(qc, relay.slug);
    }
    const check = await spareCheck(renew.listenerKey);
    const first = check.blockers[0];
    if (first) {
      toast.message(
        `Removed that spare. A new one cannot be created yet (${codeLabel(first.code.replace(/^edge\./, '')).toLowerCase()}). Add a spare again once that is fixed.`,
      );
      return;
    }
    await provisionRelay(relay.id, { listenerId: renew.listenerId, publish: false });
    toast.success('Replacing that spare. Test the new one here once it is ready.');
    invalidateRelay(qc, relay.slug);
    onStarted?.();
  }
</script>

<ActionConfirm
  bind:open
  title={renew ? 'Replace this spare address?' : 'Add a spare address?'}
  body={`${
    renew
      ? 'FCP destroys this spare, then creates a new one for the same transport at your provider when nothing blocks it. The new spare is billed and stays unused until you test it.'
      : 'FCP creates one more address for this node at your provider and keeps it as a spare. It is billed, and it is only put in use after you test it.'
  }${inUseNote ? ` Once tested: ${inUseNote[0]!.toLowerCase()}${inUseNote.slice(1)}` : ''}`}
  confirmLabel={renew ? 'Replace the spare' : 'Add a spare'}
  disabled={!renew &&
    (preflight.isPending || (where !== '' && named.isPending) || blockers.length > 0)}
  {onClose}
  {run}
>
  {#if !renew && picks.length > 1 && autoListener}
    <div class="mb-3 space-y-1.5">
      <Label for={`${uid}-where`}>Where</Label>
      <Select.Root
        type="single"
        value={where || 'auto'}
        onValueChange={(v: string) => (where = v === 'auto' ? '' : v)}
      >
        <Select.Trigger id={`${uid}-where`} class="w-full">
          {where
            ? (picks.find((p) => p.locationId === where)?.label ?? 'That location')
            : 'Automatic, prefer a different provider'}
        </Select.Trigger>
        <Select.Content>
          <Select.Item value="auto" label="Automatic, prefer a different provider">
            Automatic, prefer a different provider
          </Select.Item>
          {#each picks as p (p.locationId)}
            <Select.Item value={p.locationId} label={p.label}>
              {p.label} ({p.accountName}): {p.spare} spare
            </Select.Item>
          {/each}
        </Select.Content>
      </Select.Root>
      {#if autoWords}<p class="text-muted-foreground text-xs">{autoWords}</p>{/if}
      {#if whereOptions}
        <PickOptions
          accountId={whereOptions.pick.accountId}
          locationId={whereOptions.pick.locationId}
          fields={whereOptions.fields}
          base={whereOptions.base}
          values={oneOff ?? whereOptions.chosen}
          onchange={(next) => (oneOff = overrides(next, whereOptions.base, whereOptions.fields))}
        />
        {#if oneOff && !deepEqual(oneOff, whereOptions.chosen)}
          <p class="text-muted-foreground text-xs">
            This address only. Automatic work never puts an address built with other options in use.
          </p>
        {/if}
      {/if}
    </div>
  {/if}
  {#if !renew}
    {#if preflight.isPending}
      <Skeleton class="h-9 w-full" />
    {:else if preflight.isError}
      <AdminListState error={preflight.error} onRetry={() => void preflight.refetch()} />
    {:else if blockers.length > 0}
      <div class="space-y-1.5">
        <p class="text-sm font-medium">It cannot start yet:</p>
        {#each blockers as b, i (`${b.code}:${i}`)}
          <CodeNote issue={b} compact />
        {/each}
      </div>
    {/if}
  {/if}
</ActionConfirm>
