<script lang="ts">
  /**
   * Replace one PUBLISHED edge (rotate = normal drain, burn = short drain, for an
   * address believed blocked), behind a dry run that says whether the run would
   * start and what it would pick. Mount it while wanted (`{#if}`) with `open={true}`.
   *
   * `plain` is the node page's wording (address, replace, spare) with only what
   * blocks the start; the Advanced pages keep the full dry run. Both say how
   * long the old address drains: the origin's drain (`drainMinutes`, its own or
   * `edge.drainMinutes`), or `edge.burnedDrainMinutes` for a burn.
   *
   * Where the replacement comes from: Automatic (a tested spare, preferring
   * another provider, then another location, else a new address; the dry run
   * says what it would use), or the operator names a tested spare of the same
   * transport, or a location of the node's set for a new address.
   *
   * Props: kind 'rotate' | 'burn'; origin; edge; edges? (the origin's, for the
   * spares); plain?; onClose(); onStarted(rotationId)
   */
  import { createQuery, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import type { EdgeAdmin, OriginAdmin } from '@shared/contracts/edges';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { Label } from '@client/components/ui/label';
  import * as Select from '@client/components/ui/select';
  import {
    burnRelayEdge,
    edgeConfigQuery,
    edgeKeys,
    invalidateRelay,
    preflightRelay,
    relayProvidersQuery,
    rotateRelayEdge,
  } from '@client/lib/edgesApi';
  import CodeNote from '../components/CodeNote.svelte';
  import PreflightPanel from '../components/PreflightPanel.svelte';
  import ActionConfirm from './ActionConfirm.svelte';
  import { edgeAddress } from './relayLogic';
  import { drainLength, replaceDrainMinutes } from '../simple/drainWords';

  interface Props {
    open: boolean;
    kind: 'rotate' | 'burn';
    relay: OriginAdmin;
    edge: EdgeAdmin;
    /** The origin's edges: the tested spares of the same transport are offered by name. */
    edges?: EdgeAdmin[];
    plain?: boolean;
    onClose: () => void;
    onStarted: (rotationId: string) => void;
  }
  let {
    open = $bindable(true),
    kind,
    relay,
    edge,
    edges = [],
    plain = false,
    onClose,
    onStarted,
  }: Props = $props();

  const qc = useQueryClient();
  const uid = $props.id();
  // Where from: 'auto', `spare:<edgeId>` or `loc:<locationId>`.
  let where = $state('auto');
  const setQ = relayProvidersQuery({
    slug: () => relay.slug,
    id: () => relay.id,
    poll: false,
  });
  const picks = $derived(setQ.data?.picks ?? []);
  const labelOf = (locationId: string | null) =>
    picks.find((p) => p.locationId === locationId)?.label ?? null;
  // An address: a TESTED spare of the same transport. A CDN front: a new one in a pick.
  const spares = $derived(
    edges.filter(
      (e) =>
        e.id !== edge.id &&
        e.listenerId === edge.listenerId &&
        e.publication === 'unpublished' &&
        e.status === 'active' &&
        e.verification.current !== false,
    ),
  );
  const l7 = $derived(edge.layer === 'l7');
  const choice = $derived(
    where.startsWith('spare:')
      ? { spareEdgeId: where.slice(6) }
      : where.startsWith('loc:')
        ? { locationId: where.slice(4) }
        : {},
  );
  const preflight = createQuery(() => ({
    queryKey: [...edgeKeys.relay(relay.slug), 'preflight', 'replace', edge.id, where] as const,
    queryFn: () =>
      preflightRelay(relay.id, {
        kind: 'replace',
        edgeId: edge.id,
        trigger: 'manual',
        ...choice,
      }),
    enabled: open,
    staleTime: 0,
    gcTime: 0,
  }));
  /** What Automatic would use, in words. */
  const autoWords = $derived.by(() => {
    const w = preflight.data?.wouldSelect;
    if (!w || where !== 'auto') return null;
    if (w.standbyEdgeId) {
      const s = edges.find((e) => e.id === w.standbyEdgeId);
      const place = labelOf(s?.locationId ?? null);
      return `Automatic uses the tested spare ${s ? edgeAddress(s) || s.name : ''}${place ? ` in ${place}` : ''}.`;
    }
    if (w.accountName)
      return `Automatic creates a new address in ${w.locationLabel ? `${w.locationLabel} (${w.accountName})` : w.accountName}.`;
    return null;
  });

  /** Limits an admin may override by hand; everything else has to be fixed first. */
  const FORCEABLE = new Set(['cooldown', 'daily_cap', 'hosts_operator_managed']);
  const blockers = $derived(preflight.data?.blockers ?? []);
  const forceable = $derived(blockers.length > 0 && blockers.every((b) => FORCEABLE.has(b.code)));
  const blocked = $derived(blockers.length > 0 && !forceable);
  let force = $state(false);

  const name = $derived(edgeAddress(edge) || edge.name);
  const config = edgeConfigQuery();
  const drainMin = $derived(
    replaceDrainMinutes(kind, relay.drainMinutes, config.data?.config.burnedDrainMinutes ?? null),
  );
  // "for 24 h" once the length is known; the burn's fleet setting may still be loading.
  const drainFor = $derived(
    drainMin === null ? 'for a short time' : `for ${drainLength(drainMin)}`,
  );

  async function start(): Promise<void> {
    const body = { edgeId: edge.id, ...(force ? { force: true } : {}), ...choice };
    const res = await (kind === 'burn'
      ? burnRelayEdge(relay.id, body)
      : rotateRelayEdge(relay.id, body));
    if (!plain) toast.success(kind === 'burn' ? 'Burn started.' : 'Rotation started.');
    invalidateRelay(qc, relay.slug);
    onStarted(res.rotationId);
  }

  const copy = $derived(
    plain
      ? {
          title: kind === 'burn' ? `Replace ${name} now?` : `Replace ${name}?`,
          body:
            kind === 'burn'
              ? `Use this when the address looks blocked. FCP puts a tested spare (or a new address) in its place and members move over at their next refresh. This one keeps working ${drainFor} for members who have not refreshed yet, then it is deleted and its billing stops. A new address is billed by your provider.`
              : `FCP puts a tested spare (or a new address) in its place and members move over at their next refresh. This one keeps working ${drainFor} for members who have not refreshed yet, then it is deleted and its billing stops. A new address is billed by your provider.`,
          confirm: kind === 'burn' ? 'Replace now' : 'Replace address',
        }
      : {
          title: kind === 'burn' ? `Burn ${name}?` : `Rotate ${name}?`,
          body:
            kind === 'burn'
              ? `Use this when the address is believed blocked. A new edge takes its pool position, members are switched over, and the old edge drains ${drainFor} (the "burned" drain) before it is destroyed. Provisioning a replacement spends provider budget unless a compatible standby exists.`
              : `A new edge takes the pool position of this one, members are switched over, and the old edge drains ${drainFor} (this origin's drain time) before it is destroyed. Provisioning a replacement spends provider budget unless a compatible standby exists.`,
          confirm: kind === 'burn' ? 'Burn and replace' : 'Rotate',
        },
  );
</script>

<ActionConfirm
  bind:open
  title={copy.title}
  body={copy.body}
  confirmLabel={copy.confirm}
  danger={kind === 'burn'}
  disabled={preflight.isPending || blocked || (forceable && !force)}
  {onClose}
  run={start}
>
  {#if spares.length > 0 || (l7 && picks.length > 0)}
    <div class="mb-3 space-y-1.5">
      <Label for={`${uid}-where`}>Where from</Label>
      <Select.Root type="single" value={where} onValueChange={(v: string) => (where = v)}>
        <Select.Trigger id={`${uid}-where`} class="w-full">
          {where === 'auto'
            ? 'Automatic, prefer a different provider'
            : where.startsWith('spare:')
              ? `The spare ${(() => {
                  const s = spares.find((x) => x.id === where.slice(6));
                  return s ? edgeAddress(s) || s.name : '';
                })()}`
              : `A new address in ${labelOf(where.slice(4)) ?? 'that location'}`}
        </Select.Trigger>
        <Select.Content>
          <Select.Item value="auto" label="Automatic, prefer a different provider">
            Automatic, prefer a different provider
          </Select.Item>
          {#each spares as s (s.id)}
            {@const place = labelOf(s.locationId)}
            <Select.Item value={`spare:${s.id}`} label={edgeAddress(s) || s.name}>
              The spare {edgeAddress(s) || s.name}{place ? ` in ${place}` : ''}
            </Select.Item>
          {/each}
          {#if l7}
            {#each picks.filter((p) => p.usable) as p (p.locationId)}
              <Select.Item value={`loc:${p.locationId}`} label={p.label}>
                A new address in {p.label} ({p.accountName})
              </Select.Item>
            {/each}
          {/if}
        </Select.Content>
      </Select.Root>
      {#if autoWords}<p class="text-muted-foreground text-xs">{autoWords}</p>{/if}
    </div>
  {/if}
  {#if !plain}
    <PreflightPanel
      result={preflight.data}
      pending={preflight.isPending}
      error={preflight.error ?? undefined}
      onRetry={() => void preflight.refetch()}
      kind="replace"
    />
  {:else if preflight.error}
    <PreflightPanel
      result={undefined}
      error={preflight.error}
      onRetry={() => void preflight.refetch()}
    />
  {:else if blockers.length > 0}
    <div class="space-y-1.5">
      <p class="text-sm font-medium">It cannot start yet:</p>
      {#each blockers as b, i (`${b.code}:${i}`)}
        <CodeNote issue={b} compact />
      {/each}
    </div>
  {/if}
  {#if forceable}
    <div class="mt-3 flex items-start gap-2">
      <Checkbox id={`force-${edge.id}`} bind:checked={force} class="mt-0.5" />
      <div>
        <Label for={`force-${edge.id}`}
          >{plain ? 'Start anyway' : 'Override and start anyway'}</Label
        >
        <p class="text-xs text-muted-foreground">
          The limits above protect budget and members. Overriding is recorded in the audit log.
          {#if blockers.some((b) => b.code === 'hosts_operator_managed') && plain}
            FCP does not update the backend for this node: change the address there yourself right
            after, or members keep the old one.
          {:else if blockers.some((b) => b.code === 'hosts_operator_managed')}
            FCP will not write the panel Hosts of this relay: you must apply the new Hosts plan
            yourself right after, or members keep dialling the old edge.
          {/if}
        </p>
      </div>
    </div>
  {:else if blocked}
    <p class="mt-3 text-xs text-muted-foreground">
      Confirm stays off until the blockers above are fixed.
    </p>
  {/if}
</ActionConfirm>
