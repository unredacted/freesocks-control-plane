<script lang="ts">
  /**
   * The block detector's view of one relay, in words, with Rotate / Burn for a
   * published edge (each behind a dry run).
   *
   * Props: relay; edges; onOpenEdge(edgeId); onRotationStarted(rotationId)
   */
  import type { EdgeAdmin, RelayAdmin } from '@shared/contracts/edges';
  import * as Card from '@client/components/ui/card';
  import * as Select from '@client/components/ui/select';
  import { Badge } from '@client/components/ui/badge';
  import { Button } from '@client/components/ui/button';
  import { Label } from '@client/components/ui/label';
  import { codeExplain, codeLabel } from '@client/lib/edgeCodes';
  import KeyValue from '../components/KeyValue.svelte';
  import { relativeTime } from '../lib/time';
  import type { KeyValueRow } from '../lib/types';
  import ReplaceDialog from './ReplaceDialog.svelte';
  import { edgeAddress, hintLevelWords } from './relayLogic';

  interface Props {
    relay: RelayAdmin;
    edges: EdgeAdmin[];
    onOpenEdge: (edgeId: string) => void;
    onRotationStarted: (rotationId: string) => void;
  }
  let { relay, edges, onOpenEdge, onRotationStarted }: Props = $props();

  const s = $derived(relay.suspicion);
  const published = $derived(
    edges
      .filter((e) => e.publication === 'published')
      .sort((a, b) => (a.poolIndex ?? 0) - (b.poolIndex ?? 0)),
  );
  const evidenceIds = $derived(new Set((s?.edgeEvidence ?? []).map((e) => e.edgeId)));

  let pickedId = $state('');
  const target = $derived(
    published.find((e) => e.id === pickedId) ??
      published.find((e) => evidenceIds.has(e.id)) ??
      published[0] ??
      null,
  );
  const edgeName = (e: EdgeAdmin): string =>
    `Position ${(e.poolIndex ?? 0) + 1}: ${edgeAddress(e) || e.name}${evidenceIds.has(e.id) ? ' (evidence points here)' : ''}`;

  let replaceKind = $state<'rotate' | 'burn' | null>(null);

  const rows = $derived.by((): KeyValueRow[] => {
    if (!s) return [];
    return [
      {
        label: 'Evidence',
        value: hintLevelWords(s.hintLevel),
        hint: `Score ${s.score.toFixed(2)} (reports ${s.reportScore.toFixed(2)}, load ${s.loadScore.toFixed(2)}, probes ${s.probeScore.toFixed(2)})`,
      },
      {
        label: 'Where',
        value:
          s.scope === 'regional'
            ? `Regional: ${s.countries.map((c) => `${c.code} (${c.count})`).join(', ')}`
            : s.scope === 'global'
              ? 'Everywhere'
              : '',
      },
      { label: 'First seen', value: s.firstSeenAt ? relativeTime(s.firstSeenAt) : '' },
      { label: 'Last evaluated', value: relativeTime(s.lastEvalAt) },
      {
        label: 'Baseline',
        value: s.baselineWarm
          ? 'Warm: the usual load at this time of day is known'
          : 'Still learning the usual load, so load drops do not count yet',
      },
      { label: 'Quiet evaluations', value: s.quietEvals > 0 ? s.quietEvals : '' },
      {
        label: 'Last automatic rotation refused',
        value: s.lastRotateError ? codeLabel(s.lastRotateError.replace(/^edge\./, '')) : '',
      },
    ];
  });
</script>

<Card.Root>
  <Card.Header>
    <Card.Title class="flex flex-wrap items-center gap-2">
      Block detector
      {#if !s}
        <Badge variant="muted">No evaluation yet</Badge>
      {:else if s.state === 'suspected'}
        <Badge variant={s.veto ? 'warning' : 'danger'}>Block suspected</Badge>
      {:else}
        <Badge variant="success">Clear</Badge>
      {/if}
    </Card.Title>
    <Card.Description>
      Watches member reports, user load and outside probes for signs that an edge address is
      blocked.
    </Card.Description>
  </Card.Header>
  <Card.Content class="space-y-4 text-sm">
    {#if !s}
      <p class="text-muted-foreground">
        The detector has not looked at this relay yet. It evaluates relays with a published edge
        every few minutes once the edge layer is on in Settings.
      </p>
    {:else}
      {#if s.veto}
        <div class="rounded-md border border-amber-500/40 bg-amber-500/10 p-3">
          <p class="font-medium">Held back: {codeLabel(s.veto)}</p>
          <p class="mt-1 text-muted-foreground">
            {codeExplain(s.veto)} The detector does not rotate while this holds.
          </p>
        </div>
      {/if}
      {#if s.state === 'suspected' && !s.veto && !relay.autoRotate}
        <p class="rounded-md border border-amber-500/40 bg-amber-500/10 p-3">
          Auto rotate is off for this relay, so nothing happens until you rotate or burn the edge
          yourself.
        </p>
      {/if}
      <KeyValue {rows} hideEmpty />
      {#if s.edgeEvidence.length > 0}
        <div>
          <h3 class="mb-1 font-medium">Edges the evidence points at</h3>
          <ul class="space-y-1">
            {#each s.edgeEvidence as ev (`${ev.edgeId}:${ev.source}`)}
              {@const e = edges.find((x) => x.id === ev.edgeId)}
              <li>
                <button
                  type="button"
                  class="font-mono text-xs text-primary hover:underline"
                  onclick={() => onOpenEdge(ev.edgeId)}
                >
                  {e ? edgeAddress(e) || e.name : 'An edge that is gone'}
                </button>
                <span class="text-muted-foreground">
                  from {ev.source === 'reports' ? 'member reports' : 'probes'}{ev.countries.length >
                  0
                    ? ` in ${ev.countries.join(', ')}`
                    : ''}
                </span>
              </li>
            {/each}
          </ul>
        </div>
      {/if}
    {/if}

    <div class="space-y-2 border-t pt-4">
      <h3 class="font-medium">Replace an edge by hand</h3>
      {#if published.length === 0}
        <p class="text-muted-foreground">
          Nothing is published, so there is nothing to replace. Provision and publish an edge from
          the Actions menu.
        </p>
      {:else}
        <div class="space-y-1.5">
          <Label>Edge to replace</Label>
          <Select.Root type="single" value={target?.id ?? ''} onValueChange={(v) => (pickedId = v)}>
            <Select.Trigger class="w-full"
              >{target ? edgeName(target) : 'Choose an edge'}</Select.Trigger
            >
            <Select.Content>
              {#each published as e (e.id)}
                <Select.Item value={e.id}>{edgeName(e)}</Select.Item>
              {/each}
            </Select.Content>
          </Select.Root>
        </div>
        <div class="flex flex-wrap gap-2">
          <Button
            variant="outline"
            disabled={!target || !!relay.activeRotationId || !!relay.quarantine}
            onclick={() => (replaceKind = 'rotate')}
          >
            Rotate
          </Button>
          <Button
            variant="destructive"
            disabled={!target || !!relay.activeRotationId || !!relay.quarantine}
            onclick={() => (replaceKind = 'burn')}
          >
            Burn
          </Button>
        </div>
        <p class="text-xs text-muted-foreground">
          Rotate swaps the edge and lets the old one drain normally. Burn is for an address you
          believe is blocked: the old edge drains only briefly.
          {#if relay.activeRotationId}
            A rotation is already running.
          {:else if relay.quarantine}
            Resolve the quarantine first.
          {/if}
        </p>
      {/if}
    </div>
  </Card.Content>
</Card.Root>

{#if replaceKind && target}
  <ReplaceDialog
    open={true}
    kind={replaceKind}
    {relay}
    edge={target}
    onClose={() => (replaceKind = null)}
    onStarted={onRotationStarted}
  />
{/if}
