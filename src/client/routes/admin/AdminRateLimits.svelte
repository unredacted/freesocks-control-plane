<script lang="ts">
  import type { z } from 'zod';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { Button } from '@client/components/ui/button';
  import { Checkbox } from '@client/components/ui/checkbox';
  import AdminLayout from './AdminLayout.svelte';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage, firstIssueMessage } from '../../lib/errors';
  import { Input } from '@client/components/ui/input';
  import AdminListState from './AdminListState.svelte';
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
  function setDraft(
    key: string,
    patch: Partial<{ max: number; windowMs: number; enabled: boolean }>,
  ) {
    const base = drafts[key] ?? policies.data?.find((p) => p.key === key);
    if (!base) return;
    drafts = {
      ...drafts,
      [key]: { max: base.max, windowMs: base.windowMs, enabled: base.enabled, ...patch },
    };
  }

  function humanWindow(ms: number): string {
    if (ms % 86_400_000 === 0) return `${ms / 86_400_000}d`;
    if (ms % 3_600_000 === 0) return `${ms / 3_600_000}h`;
    if (ms % 60_000 === 0) return `${ms / 60_000}m`;
    return `${Math.round(ms / 1000)}s`;
  }

  // Window editing in human units (value + unit) instead of raw milliseconds.
  const UNIT_MS = { s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000 } as const;
  type WindowUnit = keyof typeof UNIT_MS;
  const UNIT_LABEL: Record<WindowUnit, string> = {
    s: 'seconds',
    m: 'minutes',
    h: 'hours',
    d: 'days',
  };

  function decomposeWindow(ms: number): { value: number; unit: WindowUnit } {
    if (ms % UNIT_MS.d === 0) return { value: ms / UNIT_MS.d, unit: 'd' };
    if (ms % UNIT_MS.h === 0) return { value: ms / UNIT_MS.h, unit: 'h' };
    if (ms % UNIT_MS.m === 0) return { value: ms / UNIT_MS.m, unit: 'm' };
    return { value: Math.max(1, Math.round(ms / UNIT_MS.s)), unit: 's' };
  }

  // Once an admin touches a row we track their explicit value+unit so the field
  // doesn't normalize units mid-edit (typing "60" in minutes flipping to "1 h").
  let winUi = $state<Record<string, { value: number; unit: WindowUnit }>>({});
  function winUiFor(p: RateLimitPolicyAdmin) {
    return winUi[p.key] ?? decomposeWindow(draftFor(p).windowMs);
  }
  function setWindow(key: string, value: number, unit: WindowUnit) {
    winUi = { ...winUi, [key]: { value, unit } };
    setDraft(key, { windowMs: Math.round(value * UNIT_MS[unit]) });
  }

  const save = createMutation(() => ({
    mutationFn: (body: z.infer<typeof RateLimitUpdateRequest>) =>
      apiClient.patch('/api/v1/admin/rate-limits', body, RateLimitListResponse),
    onSuccess: (_data, body) => {
      void qc.invalidateQueries({ queryKey: queryKeys.adminRateLimits });
      drafts = Object.fromEntries(Object.entries(drafts).filter(([k]) => k !== body.policyKey));
      winUi = Object.fromEntries(Object.entries(winUi).filter(([k]) => k !== body.policyKey));
      toast.success(`Updated ${body.policyKey}`);
    },
    onError: (err) => toast.error('Update failed', { description: apiErrorMessage(err) }),
  }));

  // Revert a customized policy to its compiled default (deletes the stored
  // override server-side). Fires immediately with a toast, matching the page's
  // save affordance — a policy at its default is harmless to re-derive.
  const reset = createMutation(() => ({
    mutationFn: (policyKey: string) =>
      apiClient.patch(
        '/api/v1/admin/rate-limits',
        { policyKey, reset: true },
        RateLimitListResponse,
      ),
    onSuccess: (_data, policyKey) => {
      void qc.invalidateQueries({ queryKey: queryKeys.adminRateLimits });
      // Drop any unsaved draft so the row snaps back to the (now default) value.
      drafts = Object.fromEntries(Object.entries(drafts).filter(([k]) => k !== policyKey));
      winUi = Object.fromEntries(Object.entries(winUi).filter(([k]) => k !== policyKey));
      toast.success(`Reset ${policyKey} to default`);
    },
    onError: (err) => toast.error('Reset failed', { description: apiErrorMessage(err) }),
  }));

  // Validate BEFORE mutating: an out-of-bounds value gets a readable toast
  // (firstIssueMessage), never a raw ZodError dump from inside mutationFn.
  function submitPolicy(
    p: RateLimitPolicyAdmin,
    d: { max: number; windowMs: number; enabled: boolean },
  ) {
    const parsed = RateLimitUpdateRequest.safeParse({
      policyKey: p.key,
      max: d.max,
      windowMs: d.windowMs,
      enabled: d.enabled,
    });
    if (!parsed.success) {
      toast.error('Check the form', { description: firstIssueMessage(parsed.error) });
      return;
    }
    save.mutate(parsed.data);
  }
</script>

<AdminLayout>
  <h1 class="text-2xl font-bold mb-2">Rate limits</h1>
  <p class="text-sm text-muted-foreground mb-6">
    Tune anti-abuse limits live, without a deploy. Each takes effect on the next request. A disabled
    policy is not enforced. Values out of bounds are rejected; unset policies use the compiled
    default.
  </p>

  {#if policies.isPending}
    <div class="space-y-2">
      {#each Array(5) as _, i (i)}<Skeleton class="h-14 w-full" />{/each}
    </div>
  {:else if policies.isError}
    <AdminListState error={policies.error} onRetry={() => void policies.refetch()} />
  {:else}
    <ul class="divide-y divide-border rounded-lg border border-border bg-card">
      {#each policies.data ?? [] as p (p.key)}
        {@const d = draftFor(p)}
        {@const w = winUiFor(p)}
        {@const dirty = d.max !== p.max || d.windowMs !== p.windowMs || d.enabled !== p.enabled}
        <li class="flex flex-wrap items-center gap-3 px-4 py-3 text-sm">
          <div class="min-w-0 flex-1">
            <code class="font-mono text-foreground">{p.key}</code>
            {#if !p.isDefault}
              <span
                class="ms-2 rounded bg-amber-500/15 px-1.5 py-0.5 text-[11px] text-amber-600 dark:text-amber-400"
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
            <Input
              type="number"
              min={1}
              class="min-h-9 w-20"
              value={d.max}
              oninput={(e) =>
                setDraft(p.key, { max: Number((e.currentTarget as HTMLInputElement).value) })}
            />
          </label>
          <label class="flex items-center gap-1">
            <span class="text-xs text-muted-foreground">window</span>
            <Input
              type="number"
              min={1}
              class="min-h-9 w-20"
              value={w.value}
              oninput={(e) =>
                setWindow(p.key, Number((e.currentTarget as HTMLInputElement).value), w.unit)}
            />
            <select
              class="min-h-9 rounded-md border border-input bg-background px-2 text-xs"
              value={w.unit}
              onchange={(e) =>
                setWindow(
                  p.key,
                  w.value,
                  (e.currentTarget as HTMLSelectElement).value as WindowUnit,
                )}
            >
              {#each Object.keys(UNIT_MS) as u (u)}
                <option value={u}>{UNIT_LABEL[u as WindowUnit]}</option>
              {/each}
            </select>
          </label>
          <label class="flex items-center gap-1.5">
            <Checkbox
              checked={d.enabled}
              onCheckedChange={(v) => setDraft(p.key, { enabled: !!v })}
              id={`enabled-${p.key}`}
            />
            <span class="text-xs text-muted-foreground">enabled</span>
          </label>
          <Button size="sm" disabled={!dirty || save.isPending} onclick={() => submitPolicy(p, d)}>
            Save
          </Button>
          {#if !p.isDefault}
            <Button
              size="sm"
              variant="ghost"
              disabled={reset.isPending}
              onclick={() => reset.mutate(p.key)}
            >
              Reset to default
            </Button>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
</AdminLayout>
