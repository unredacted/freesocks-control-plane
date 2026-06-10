<script lang="ts">
  import { Skeleton } from '@client/components/ui/skeleton';
  import { Button } from '@client/components/ui/button';
  import { Checkbox } from '@client/components/ui/checkbox';
  import AdminLayout from './AdminLayout.svelte';
  import { apiClient } from '../../lib/api';
  import { adminRateLimitsQuery, queryKeys } from '../../lib/queries';
  import {
    RateLimitListResponse,
    RateLimitUpdateRequest,
    type RateLimitPolicyAdmin,
  } from '../../../shared/contracts/rateLimits';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';

  const qc = useQueryClient();
  const policies = adminRateLimitsQuery();

  // Per-row draft edits, keyed by policy key. Seeded lazily from the query.
  let drafts = $state<Record<string, { max: number; windowMs: number; enabled: boolean }>>({});

  function draftFor(p: RateLimitPolicyAdmin) {
    return drafts[p.key] ?? { max: p.max, windowMs: p.windowMs, enabled: p.enabled };
  }
  function setDraft(key: string, patch: Partial<{ max: number; windowMs: number; enabled: boolean }>) {
    const base = drafts[key] ?? policies.data?.find((p) => p.key === key);
    if (!base) return;
    drafts = { ...drafts, [key]: { max: base.max, windowMs: base.windowMs, enabled: base.enabled, ...patch } };
  }

  function humanWindow(ms: number): string {
    if (ms % 86_400_000 === 0) return `${ms / 86_400_000}d`;
    if (ms % 3_600_000 === 0) return `${ms / 3_600_000}h`;
    if (ms % 60_000 === 0) return `${ms / 60_000}m`;
    return `${Math.round(ms / 1000)}s`;
  }

  const save = createMutation(() => ({
    mutationFn: (body: RateLimitPolicyAdmin) =>
      apiClient.patch(
        '/api/v1/admin/rate-limits',
        RateLimitUpdateRequest.parse({
          policyKey: body.key,
          max: body.max,
          windowMs: body.windowMs,
          enabled: body.enabled,
        }),
        RateLimitListResponse,
      ),
    onSuccess: (_data, body) => {
      void qc.invalidateQueries({ queryKey: queryKeys.adminRateLimits });
      drafts = Object.fromEntries(Object.entries(drafts).filter(([k]) => k !== body.key));
      toast.success(`Updated ${body.key}`);
    },
    onError: (err) =>
      toast.error('Update failed', { description: err instanceof Error ? err.message : String(err) }),
  }));
</script>

<AdminLayout>
  <h1 class="text-2xl font-bold mb-2">Rate limits</h1>
  <p class="text-sm text-muted-foreground mb-6">
    Tune anti-abuse limits live, without a deploy. Each takes effect on the next request. A disabled
    policy is not enforced. Values out of bounds are rejected; unset policies use the compiled
    default.
  </p>

  {#if policies.isPending}
    <div class="space-y-2">{#each Array(5) as _, i (i)}<Skeleton class="h-14 w-full" />{/each}</div>
  {:else if policies.isError}
    <div class="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
      {policies.error instanceof Error ? policies.error.message : String(policies.error)}
    </div>
  {:else}
    <ul class="divide-y divide-border rounded-lg border border-border bg-card">
      {#each policies.data ?? [] as p (p.key)}
        {@const d = draftFor(p)}
        {@const dirty = d.max !== p.max || d.windowMs !== p.windowMs || d.enabled !== p.enabled}
        <li class="flex flex-wrap items-center gap-3 px-4 py-3 text-sm">
          <div class="min-w-0 flex-1">
            <code class="font-mono text-foreground">{p.key}</code>
            {#if !p.isDefault}
              <span class="ms-2 rounded bg-amber-500/15 px-1.5 py-0.5 text-[11px] text-amber-600 dark:text-amber-400"
                >customized</span
              >
            {/if}
            <div class="mt-0.5 text-xs text-muted-foreground">
              default: {p.default.max} / {humanWindow(p.default.windowMs)}{p.default.enabled
                ? ''
                : ' (off)'}
            </div>
          </div>
          <label class="flex items-center gap-1">
            <span class="text-xs text-muted-foreground">max</span>
            <input
              type="number"
              min="1"
              value={d.max}
              oninput={(e) => setDraft(p.key, { max: Number((e.currentTarget as HTMLInputElement).value) })}
              class="min-h-9 w-20 rounded-md border border-border bg-background px-2 py-1 text-sm"
            />
          </label>
          <label class="flex items-center gap-1">
            <span class="text-xs text-muted-foreground">window ms</span>
            <input
              type="number"
              min="1000"
              value={d.windowMs}
              oninput={(e) =>
                setDraft(p.key, { windowMs: Number((e.currentTarget as HTMLInputElement).value) })}
              class="min-h-9 w-28 rounded-md border border-border bg-background px-2 py-1 text-sm"
            />
            <span class="text-xs text-muted-foreground">({humanWindow(d.windowMs)})</span>
          </label>
          <label class="flex items-center gap-1.5">
            <Checkbox
              checked={d.enabled}
              onCheckedChange={(v) => setDraft(p.key, { enabled: !!v })}
              id={`enabled-${p.key}`}
            />
            <span class="text-xs text-muted-foreground">enabled</span>
          </label>
          <Button
            size="sm"
            disabled={!dirty || save.isPending}
            onclick={() => save.mutate({ ...p, max: d.max, windowMs: d.windowMs, enabled: d.enabled })}
          >
            Save
          </Button>
        </li>
      {/each}
    </ul>
  {/if}
</AdminLayout>
