<script lang="ts">
  /**
   * Step 9, automation (optional): probes, the edge layer, automatic rotation
   * for this relay, automatic L7 selection. Each switch says what it does.
   *
   * Props: StepBodyProps
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { buttonVariants } from '@client/components/ui/button';
  import Link from '@client/components/Link.svelte';
  import {
    edgeConfigQuery,
    invalidateConfig,
    invalidateRelay,
    patchEdgeConfig,
    relayListenersQuery,
    updateRelay,
  } from '@client/lib/edgesApi';
  import AdminListState from '../../AdminListState.svelte';
  import { assertEdgeOk } from '../lib/edgeErrors';
  import { edgesPaths } from '../lib/routes';
  import StepIssues from './StepIssues.svelte';
  import SwitchRow from './SwitchRow.svelte';
  import type { StepBodyProps } from './types';

  let { step, relay, linkCtx }: StepBodyProps = $props();

  const qc = useQueryClient();
  const config = edgeConfigQuery();
  const listeners = relayListenersQuery({
    slug: () => relay?.slug ?? null,
    id: () => relay?.id ?? null,
  });
  const cfg = $derived(config.data?.config);
  const l7AutoSelect = $derived.by(() => {
    const l7 = cfg ? (cfg as Record<string, unknown>)['l7'] : null;
    return !!l7 && typeof l7 === 'object' && (l7 as Record<string, unknown>)['autoSelect'] === true;
  });
  const hasL7Listener = $derived(
    (listeners.data?.listeners ?? []).some((l) => !l.retired && l.layers.includes('l7')),
  );

  async function setConfig(path: string, next: boolean) {
    await patchEdgeConfig({ [path]: next });
    invalidateConfig(qc);
  }
  async function setRelayAutoRotate(next: boolean) {
    if (!relay) return;
    assertEdgeOk(await updateRelay(relay.id, { autoRotate: next }));
    invalidateRelay(qc, relay.slug);
  }
</script>

<div class="space-y-4">
  <p class="text-sm">
    Everything here is optional. The relay already works; these switches decide how much FCP does on
    its own afterwards.
  </p>
  <StepIssues {step} ctx={linkCtx} />

  {#if config.isError}
    <AdminListState error={config.error} onRetry={() => void config.refetch()} />
  {:else if cfg}
    <div class="divide-y rounded-lg border px-3">
      <SwitchRow
        label="Probes"
        consequence="On: published edges are checked from outside vantage points on a schedule, within the hourly budget. Off: nothing is measured, so a block is only noticed through member reports."
        checked={cfg.probe.enabled}
        onToggle={(v) => setConfig('probe.enabled', v)}
      />
      <SwitchRow
        label="Edges master switch"
        consequence="On: the reconcile job and the block detector run for every relay. Off: edges stay as they are and only manual actions change anything."
        checked={cfg.enabled}
        onToggle={(v) => setConfig('enabled', v)}
      />
      <SwitchRow
        label="Rotate this relay automatically"
        consequence={cfg.autoRotate
          ? 'On: when the detector suspects a block, this relay replaces the edge by itself, within its cooldown and daily cap. Off: a suspicion only raises an attention item.'
          : 'On: this relay may rotate by itself once automatic rotation is also on for the fleet (Settings). Off: a suspicion only raises an attention item.'}
        checked={relay?.autoRotate ?? false}
        disabled={!relay}
        disabledReason="Create the relay first (step 4)."
        onToggle={setRelayAutoRotate}
      />
      <SwitchRow
        label="Choose CDN fronts automatically"
        consequence="On: automatic provisioning and rotation may pick an L7 account for listeners that allow it. Off: CDN fronts are only created by hand."
        checked={l7AutoSelect}
        disabled={!l7AutoSelect && !hasL7Listener}
        disabledReason="No listener of this relay can sit behind a CDN front, so there is nothing to choose. A listener needs an HTTP transport and a declared origin transport first."
        onToggle={(v) => setConfig('l7.autoSelect', v)}
      />
    </div>
  {/if}

  <div class="flex flex-wrap gap-2">
    {#if relay}
      <Link href={edgesPaths.relay(relay.slug)} class={buttonVariants({ variant: 'outline' })}>
        Skip for now
      </Link>
    {/if}
    <Link href={edgesPaths.settings()} class={buttonVariants({ variant: 'ghost' })}>
      All edge settings
    </Link>
  </div>
</div>
