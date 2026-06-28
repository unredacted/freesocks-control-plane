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
  import { Input } from '@client/components/ui/input';
  import * as Select from '@client/components/ui/select';
  import { Skeleton } from '@client/components/ui/skeleton';
  import AuditRow from './AuditRow.svelte';
  import { adminAuditQuery } from '../../lib/queries';
  import AdminListState from './AdminListState.svelte';

  // Forensic filters. `action` is committed on Enter/Apply (a free-text field,
  // so we don't re-query on every keystroke); `actorType` + `since` apply
  // immediately. `since` is a date the server takes as an epoch-ms lower bound.
  const ACTOR_OPTIONS = ['', 'system', 'admin', 'member', 'anonymous', 'webhook'] as const;
  let actionInput = $state('');
  let actionFilter = $state('');
  let actorTypeFilter = $state('');
  let sinceInput = $state(''); // YYYY-MM-DD from the date field
  let sinceMs = $derived(
    sinceInput && Number.isFinite(Date.parse(sinceInput)) ? String(Date.parse(sinceInput)) : '',
  );

  // createInfiniteQuery accumulates pages: `audit.data.pages` is an array of
  // server pages; flatten for rendering. `hasNextPage` is derived from the
  // last page's `nextCursor`.
  const audit = adminAuditQuery(() => ({
    action: actionFilter,
    actorType: actorTypeFilter,
    since: sinceMs,
  }));

  let entries = $derived(audit.data?.pages.flatMap((p) => p.entries) ?? []);
  let hasFilters = $derived(!!actionFilter || !!actorTypeFilter || !!sinceInput);

  function clearFilters() {
    actionInput = '';
    actionFilter = '';
    actorTypeFilter = '';
    sinceInput = '';
  }
</script>

<AdminLayout>
  <h1 class="text-2xl font-bold mb-6">Audit log</h1>
  <p class="text-sm text-muted-foreground mb-4">
    Sensitive fields (IP hash, token prefix, raw payload) are redacted by default. Click "Show raw"
    on a row to reveal the unredacted payload for that entry.
  </p>

  <div class="mb-5 flex flex-wrap items-end gap-2 text-sm">
    <div>
      <label class="mb-1 block text-xs text-muted-foreground" for="audit-action">Action</label>
      <Input
        id="audit-action"
        class="w-56"
        placeholder="e.g. admin.user.disable"
        bind:value={actionInput}
        onkeydown={(e) => {
          if (e.key === 'Enter') actionFilter = actionInput.trim();
        }}
      />
    </div>
    <div>
      <span class="mb-1 block text-xs text-muted-foreground">Actor</span>
      <Select.Root
        type="single"
        value={actorTypeFilter}
        onValueChange={(v) => (actorTypeFilter = v)}
      >
        <Select.Trigger class="w-36">{actorTypeFilter || 'Any actor'}</Select.Trigger>
        <Select.Content>
          {#each ACTOR_OPTIONS as opt (opt)}
            <Select.Item value={opt}>{opt || 'Any actor'}</Select.Item>
          {/each}
        </Select.Content>
      </Select.Root>
    </div>
    <div>
      <label class="mb-1 block text-xs text-muted-foreground" for="audit-since">Since</label>
      <Input id="audit-since" type="date" class="w-40" bind:value={sinceInput} />
    </div>
    <Button variant="outline" size="sm" onclick={() => (actionFilter = actionInput.trim())}>
      Apply
    </Button>
    {#if hasFilters}
      <Button variant="ghost" size="sm" onclick={clearFilters}>Clear</Button>
    {/if}
  </div>

  {#if audit.isPending}
    <div class="space-y-2">
      {#each Array(5) as _, i (i)}
        <Skeleton class="h-20 w-full" />
      {/each}
    </div>
  {:else if audit.isError}
    <AdminListState error={audit.error} />
  {:else}
    {#if entries.length === 0}
      <AdminListState
        emptyText={hasFilters ? 'No audit entries match these filters.' : 'No audit entries yet.'}
      />
    {/if}
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
