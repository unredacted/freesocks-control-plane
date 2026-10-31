<script lang="ts">
  /**
   * FCP's own client check (docs/edges.md "FCP's own client check"): whether this
   * deployment has the client-check service, whether it answered its last health
   * check, and the engines it runs. "Check now" asks it again.
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { CLIENT_CHECK_COPY, CLIENT_CHECK_ENGINE_LABELS } from '@client/lib/edgeCodes';
  import { clientCheckStatusQuery, edgeKeys, refreshClientCheckStatus } from '@client/lib/edgesApi';
  import AdminListState from '../../AdminListState.svelte';
  import KeyValue from '../components/KeyValue.svelte';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { relativeTime } from '../lib/time';

  const qc = useQueryClient();
  const status = clientCheckStatusQuery();
  let busy = $state(false);

  async function refresh(): Promise<void> {
    busy = true;
    try {
      qc.setQueryData(edgeKeys.clientCheck, await refreshClientCheckStatus());
    } catch (err) {
      toast.error(edgeErrorMessage(err));
    } finally {
      busy = false;
    }
  }

  const engineLabel = (engine: string) =>
    (CLIENT_CHECK_ENGINE_LABELS as Record<string, string>)[engine] ?? engine;
  const reason = (code: string | null) =>
    code && code in CLIENT_CHECK_COPY
      ? CLIENT_CHECK_COPY[code as keyof typeof CLIENT_CHECK_COPY].label
      : (code ?? '');
</script>

<section
  id="settings-client-check"
  class="bg-card ring-foreground/15 scroll-mt-20 rounded-xl ring-1"
  aria-labelledby="settings-client-check-title"
>
  <header class="px-4 py-3">
    <h2 id="settings-client-check-title" class="font-medium">FCP's own client check</h2>
    <p class="text-muted-foreground mt-0.5 text-sm">
      Real sing-box and Xray clients connect through an address with FCP's check account and read
      the address they come out of, which must be the node's. A test of new server names on a node
      runs Mihomo too.
    </p>
  </header>
  <div class="space-y-4 border-t px-4 py-4">
    {#if status.isPending}
      <Skeleton class="h-16" />
    {:else if status.isError}
      <AdminListState error={status.error} onRetry={() => status.refetch()} />
    {:else if status.data}
      {@const s = status.data}
      {#if !s.configured}
        <p class="text-muted-foreground text-sm">
          Not set up. Start the edge-client-check service and give it and the deployment the same
          EDGE_CLIENT_CHECK_SECRET (see the deployment guide).
        </p>
      {:else}
        <KeyValue
          columns={2}
          rows={[
            {
              label: 'Service',
              value: !s.health ? 'Not checked yet' : s.health.ok ? 'Answering' : 'Not answering',
              tone: !s.health ? 'muted' : s.health.ok ? 'success' : 'warning',
            },
            { label: 'Why', value: s.health && !s.health.ok ? reason(s.health.code) : '' },
            {
              label: 'Clients',
              value:
                s.health?.engines
                  .map((e) => `${engineLabel(e.engine)} ${e.version ?? '(missing)'}`)
                  .join(', ') ?? '',
            },
            { label: 'Egress page', value: s.health?.egressHost ?? '' },
            { label: 'Checked', value: s.health ? relativeTime(s.health.at) : '' },
          ]}
          hideEmpty
        />
        <Button variant="outline" disabled={busy} onclick={() => void refresh()}>
          {busy ? 'Checking...' : 'Check now'}
        </Button>
      {/if}
    {/if}
  </div>
</section>
