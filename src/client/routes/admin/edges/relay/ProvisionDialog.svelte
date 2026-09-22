<script lang="ts">
  /**
   * Provision one more edge for the origin (spends provider budget), behind a dry
   * run. The listener may be left to FCP; "publish when ready" makes it a
   * published edge instead of a standby.
   *
   * Props: open (bindable); origin; listeners; onStarted(rotationId)
   */
  import { createQuery, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import type { OriginAdmin, RelayListenerAdmin } from '@shared/contracts/edges';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { Label } from '@client/components/ui/label';
  import * as Select from '@client/components/ui/select';
  import { edgeKeys, invalidateRelay, preflightRelay, provisionRelay } from '@client/lib/edgesApi';
  import PreflightPanel from '../components/PreflightPanel.svelte';
  import { protocolLine } from '../lib/format';
  import ActionConfirm from './ActionConfirm.svelte';

  interface Props {
    open: boolean;
    relay: OriginAdmin;
    listeners: RelayListenerAdmin[];
    /** Preselect a listener (the Listeners tab's "Provision an edge for this listener"). */
    listenerKey?: string | null;
    onStarted: (rotationId: string) => void;
  }
  let {
    open = $bindable(false),
    relay,
    listeners,
    listenerKey = null,
    onStarted,
  }: Props = $props();

  const qc = useQueryClient();
  const usable = $derived(listeners.filter((l) => !l.retired && l.enabled && l.deployed));
  let chosenKey = $state('');
  let publish = $state(false);
  $effect(() => {
    if (open) {
      chosenKey = listenerKey ?? '';
      publish = false;
    }
  });
  const chosen = $derived(usable.find((l) => l.listenerKey === chosenKey) ?? null);

  const preflight = createQuery(() => ({
    queryKey: [...edgeKeys.relay(relay.slug), 'preflight', 'provision', chosenKey] as const,
    queryFn: () =>
      preflightRelay(relay.id, {
        kind: 'provision',
        trigger: 'manual',
        ...(chosenKey ? { listenerKey: chosenKey } : {}),
      }),
    enabled: open,
    staleTime: 0,
    gcTime: 0,
  }));
  const blocked = $derived((preflight.data?.blockers.length ?? 0) > 0);

  async function run(): Promise<void> {
    const res = await provisionRelay(relay.id, {
      ...(chosen ? { listenerId: chosen.id } : {}),
      ...(publish ? { publish: true } : {}),
    });
    toast.success('Provisioning started.');
    invalidateRelay(qc, relay.slug);
    onStarted(res.rotationId);
  }
</script>

<ActionConfirm
  bind:open
  title={`Provision an edge for ${relay.slug}?`}
  body="FCP creates a new provider resource in front of this origin. That spends one allocation of the account's daily budget and starts billing at the provider."
  confirmLabel="Provision"
  disabled={preflight.isPending || blocked}
  {run}
>
  <div class="space-y-3">
    <div class="space-y-1.5">
      <Label>Listener</Label>
      <Select.Root type="single" value={chosenKey} onValueChange={(v) => (chosenKey = v)}>
        <Select.Trigger class="w-full">
          {chosen ? `${chosen.listenerKey} (${protocolLine(chosen)})` : 'Let FCP choose'}
        </Select.Trigger>
        <Select.Content>
          <Select.Item value="">Let FCP choose</Select.Item>
          {#each usable as l (l.id)}
            <Select.Item value={l.listenerKey}>{l.listenerKey} ({protocolLine(l)})</Select.Item>
          {/each}
        </Select.Content>
      </Select.Root>
      {#if usable.length === 0}
        <p class="text-xs text-muted-foreground">
          No listener is deployed and enabled yet. Add or enable one on the Listeners tab first.
        </p>
      {/if}
    </div>
    <div class="flex items-start gap-2">
      <Checkbox id="provision-publish" bind:checked={publish} class="mt-0.5" />
      <div>
        <Label for="provision-publish">Publish it when it is ready</Label>
        <p class="text-xs text-muted-foreground">
          Off: the edge waits as a standby until you publish it or a rotation needs it.
        </p>
      </div>
    </div>
    <PreflightPanel
      result={preflight.data}
      pending={preflight.isPending}
      error={preflight.error ?? undefined}
      onRetry={() => void preflight.refetch()}
      kind="provision"
    />
    {#if blocked}
      <p class="text-xs text-muted-foreground">
        Confirm stays off until the blockers above are fixed. A brand new account gets its first
        edge through "Test provision" instead.
      </p>
    {/if}
  </div>
</ActionConfirm>
