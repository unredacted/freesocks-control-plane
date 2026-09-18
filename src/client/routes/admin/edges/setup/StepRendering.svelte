<script lang="ts">
  /**
   * Step 8, rendering: turn the rewrite on and look at what members receive.
   * A manual origin skips this step (nothing FCP serves maps to it): its
   * connection plan is shown instead.
   *
   * Props: StepBodyProps
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import {
    edgeConfigQuery,
    invalidateConfig,
    patchEdgeConfig,
    relayListenersQuery,
  } from '@client/lib/edgesApi';
  import AdminListState from '../../AdminListState.svelte';
  import KeyValue from '../components/KeyValue.svelte';
  import RenderPreview from '../forms/RenderPreview.svelte';
  import { RenderClientFamily } from '@shared/contracts/edges';
  import StepIssues from './StepIssues.svelte';
  import SwitchRow from './SwitchRow.svelte';
  import type { StepBodyProps } from './types';

  let { step, relay, linkCtx }: StepBodyProps = $props();

  const qc = useQueryClient();
  const config = edgeConfigQuery();
  const isManual = $derived(relay?.origin.kind === 'manual' || step.status === 'skipped');
  const listeners = relayListenersQuery({
    slug: () => (isManual ? (relay?.slug ?? null) : null),
    id: () => (isManual ? (relay?.id ?? null) : null),
  });
  const plan = $derived(listeners.data?.connectionPlan ?? []);

  const previewFamily = $derived.by(() => {
    const p = step.facts['preview'];
    const f = p && typeof p === 'object' ? (p as Record<string, unknown>)['family'] : null;
    const parsed = RenderClientFamily.safeParse(f);
    return parsed.success ? parsed.data : undefined;
  });

  async function setRender(next: boolean) {
    await patchEdgeConfig({ 'render.enabled': next });
    invalidateConfig(qc);
    toast.success(next ? 'Rendering is on' : 'Rendering is off');
  }
</script>

<div class="space-y-4">
  {#if isManual}
    <p class="text-sm">
      This step does not apply: the origin is an address you described by hand, so no subscription
      FCP serves maps to it and there is nothing to rewrite. Wire your clients from the connection
      plan below. It always names a published edge, never the origin.
    </p>
    {#if listeners.isError}
      <AdminListState error={listeners.error} onRetry={() => void listeners.refetch()} />
    {:else if plan.length === 0}
      <AdminListState
        emptyText="The connection plan is empty until an edge is published. Publish one in step 7."
      />
    {:else}
      {#each plan as p (p.listenerKey)}
        <KeyValue
          title={`Listener ${p.listenerKey}`}
          columns={2}
          hideEmpty
          rows={[
            { label: 'Address', value: p.address, mono: true, copy: true },
            { label: 'Port', value: p.port, mono: true, copy: true },
            { label: 'SNI', value: p.sni, mono: true, copy: true },
            { label: 'Host header', value: p.host, mono: true, copy: true },
          ]}
        />
      {/each}
    {/if}
  {:else}
    <StepIssues {step} ctx={linkCtx} hide={['no_relay']} />
    {#if config.isError}
      <AdminListState error={config.error} onRetry={() => void config.refetch()} />
    {:else if config.data}
      <div class="rounded-lg border px-3">
        <SwitchRow
          label="Rewrite subscriptions (all relays)"
          consequence="On: members of every relay receive edge addresses instead of the origin. Off: members covered by a relay receive a temporary failure, because the origin is never handed out."
          checked={config.data.config.render.enabled}
          onToggle={setRender}
        />
      </div>
    {/if}
    {#if relay}
      <section class="space-y-2">
        <h4 class="text-sm font-semibold">Preview per client</h4>
        <p class="text-muted-foreground text-xs">
          A sample member of this relay, rendered for each client family. Nothing is sent to anyone.
        </p>
        <RenderPreview relayId={relay.id} family={previewFamily} />
      </section>
    {:else}
      <p class="text-muted-foreground text-sm">Create the relay first (step 4).</p>
    {/if}
  {/if}
</div>
