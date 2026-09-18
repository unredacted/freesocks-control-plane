<script lang="ts">
  /**
   * Admin → Edges. PLACEHOLDER while the section is rebuilt on the generic-relay
   * model (docs/edges.md): the previous panels spoke the slot / protocol-profile
   * contract the backend no longer serves. The guided setup, the per-relay
   * pages and the dashboard land with the next release; the API surface under
   * /api/v1/admin/edges/ is fully usable meanwhile. Admin UI is English-only.
   */
  import AdminLayout from './AdminLayout.svelte';
  import * as Card from '@client/components/ui/card';
  import { adminEdgeSummaryQuery } from '../../lib/queries';
  import AdminListState from './AdminListState.svelte';

  const summary = adminEdgeSummaryQuery();
</script>

<AdminLayout>
  <div class="mb-6">
    <h1 class="text-2xl font-semibold tracking-tight">Edges</h1>
    <p class="text-muted-foreground mt-1 text-sm">
      Relays (any origin) fronted by provider-managed edges. This page is being rebuilt; the figures
      below come from the live summary and every operation is available through the API and the node
      role.
    </p>
  </div>
  {#if summary.isPending}
    <AdminListState emptyText="Loading" />
  {:else if summary.isError}
    <AdminListState error={summary.error} onRetry={() => summary.refetch()} />
  {:else if summary.data}
    <Card.Root>
      <Card.Header>
        <Card.Title>Fleet</Card.Title>
        <Card.Description>Counts from the edges summary.</Card.Description>
      </Card.Header>
      <Card.Content>
        <dl class="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
          {#each Object.entries(summary.data.counts) as [k, v] (k)}
            <div class="rounded-md border p-3">
              <dt class="text-muted-foreground text-xs uppercase tracking-wide">{k}</dt>
              <dd class="text-lg font-medium">{v}</dd>
            </div>
          {/each}
        </dl>
        <p class="text-muted-foreground mt-4 text-xs">
          Relays: {summary.data.relays.map((r) => r.relay.slug).join(', ') || 'none registered'}
        </p>
      </Card.Content>
    </Card.Root>
  {/if}
</AdminLayout>
