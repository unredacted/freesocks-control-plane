<script lang="ts" module>
  /**
   * Recursively redact known sensitive fields client-side before showing the
   * audit payload. Server-side audit records may carry sensitive values (IP
   * hashes, token prefixes, raw payloads). Admins can reveal a single row on
   * demand, but nothing sensitive renders by default.
   */
  const SENSITIVE_KEYS = new Set([
    'ipHash',
    'ip_hash',
    'ip',
    'tokenPrefix',
    'token_prefix',
    'plaintext',
    'token',
    'rawPayload',
    'raw_payload',
  ]);

  export function redact(value: unknown): unknown {
    if (value === null || value === undefined) return value;
    if (Array.isArray(value)) return value.map(redact);
    if (typeof value === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        out[k] = SENSITIVE_KEYS.has(k) ? '[REDACTED]' : redact(v);
      }
      return out;
    }
    return value;
  }
</script>

<script lang="ts">
  import AdminLayout from './AdminLayout.svelte';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import AuditRow from './AuditRow.svelte';
  import { adminAuditQuery } from '../../lib/queries';
  import AdminListState from './AdminListState.svelte';

  // createInfiniteQuery accumulates pages: `audit.data.pages` is an array of
  // server pages; flatten for rendering. `hasNextPage` is derived from the
  // last page's `nextCursor`.
  const audit = adminAuditQuery();

  let entries = $derived(audit.data?.pages.flatMap((p) => p.entries) ?? []);
</script>

<AdminLayout>
  <h1 class="text-2xl font-bold mb-6">Audit log</h1>
  <p class="text-sm text-muted-foreground mb-4">
    Sensitive fields (IP hash, token prefix, raw payload) are redacted by default. Click "Show raw"
    on a row to reveal the unredacted payload for that entry.
  </p>

  {#if audit.isPending}
    <div class="space-y-2">
      {#each Array(5) as _, i (i)}
        <Skeleton class="h-20 w-full" />
      {/each}
    </div>
  {:else if audit.isError}
    <AdminListState error={audit.error} />
  {:else}
    <div class="space-y-2">
      {#each entries as e (e.id)}
        <AuditRow entry={e} />
      {/each}
    </div>
    {#if audit.hasNextPage}
      <div class="mt-4 flex justify-center">
        <Button
          variant="outline"
          onclick={() => audit.fetchNextPage()}
          disabled={audit.isFetchingNextPage}
        >
          {audit.isFetchingNextPage ? 'Loading…' : 'Load more'}
        </Button>
      </div>
    {/if}
  {/if}
</AdminLayout>
