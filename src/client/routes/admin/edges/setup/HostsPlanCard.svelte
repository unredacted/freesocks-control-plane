<script lang="ts">
  /**
   * `hostMode: operator`: the backend Hosts the OPERATOR must create or keep, one
   * copyable block per listener (from the by-slug view's `hostsPlan`).
   *
   * Props:
   *   relaySlug: string
   */
  import { relayBySlugQuery } from '@client/lib/edgesApi';
  import { Skeleton } from '@client/components/ui/skeleton';
  import AdminListState from '../../AdminListState.svelte';
  import KeyValue from '../components/KeyValue.svelte';
  import type { KeyValueRow } from '../lib/types';

  interface Props {
    relaySlug: string;
  }
  let { relaySlug }: Props = $props();

  const view = relayBySlugQuery(() => relaySlug);
  const addresses = $derived(view.data?.hostsPlan.hosts ?? []);

  const rowsOf = (h: (typeof addresses)[number]): KeyValueRow[] => [
    { label: 'Remark', value: h.remark, mono: true, copy: true },
    { label: 'Address', value: h.address, mono: true, copy: true },
    { label: 'Port', value: h.port, mono: true, copy: true },
    { label: 'SNI', value: h.sni, mono: true, copy: true },
    { label: 'Host header', value: h.host, mono: true, copy: true },
    { label: 'Config profile', value: h.inbound.configProfileUuid, mono: true, copy: true },
    { label: 'Inbound', value: h.inbound.configProfileInboundUuid, mono: true, copy: true },
  ];
</script>

<section class="space-y-3 rounded-lg border p-3">
  <div>
    <h4 class="text-sm font-semibold">Create this Host</h4>
    <p class="text-muted-foreground text-xs">
      You write the backend Hosts for this origin, so FCP never touches them. Create one Host per
      listener with exactly these values, and update it whenever the published edge changes.
    </p>
  </div>
  {#if view.isError}
    <AdminListState error={view.error} onRetry={() => void view.refetch()} />
  {:else if view.isPending}
    <Skeleton class="h-24 w-full" />
  {:else if addresses.length === 0}
    <AdminListState
      emptyText="Nothing to create yet. The values appear here once an edge is published."
    />
  {:else}
    {#each addresses as h (h.listenerKey)}
      <KeyValue title={`Listener ${h.listenerKey}`} rows={rowsOf(h)} columns={2} hideEmpty />
    {/each}
  {/if}
</section>
