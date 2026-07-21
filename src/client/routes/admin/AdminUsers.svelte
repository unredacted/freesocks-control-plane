<script lang="ts">
  import { z } from 'zod';
  import { Card, CardHeader, CardTitle, CardContent } from '@client/components/ui/card';
  import { Skeleton } from '@client/components/ui/skeleton';
  import * as AlertDialog from '@client/components/ui/alert-dialog';
  import AdminLayout from './AdminLayout.svelte';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import { formatDate, formatDateTime } from '../../lib/i18n/format';
  import { formatBytes } from '../../lib/utils';
  import AdminListState from './AdminListState.svelte';
  import { UserAdmin } from '../../../shared/contracts/admin';
  import { deviceLimitsShown } from '../../lib/tiers';
  import {
    adminTiersQuery,
    adminUsersQuery,
    adminUserBackendStateQuery,
    configQuery,
  } from '../../lib/queries';
  import * as Select from '@client/components/ui/select';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';

  type UserOp = 'disable' | 're-enable' | 'reset-traffic' | 'resync';

  // Confirmation copy lives next to the operation it belongs to. `resync` is
  // non-destructive so it skips the dialog entirely.
  const OP_COPY: Record<UserOp, (label: string) => { title: string; description: string } | null> =
    {
      disable: (label) => ({
        title: `Disable ${label}?`,
        description:
          'Their backend subscription will be paused immediately and they will lose access until you re-enable.',
      }),
      'reset-traffic': (label) => ({
        title: `Reset traffic for ${label}?`,
        description:
          'This zeroes their counter on the proxy backend so they get a fresh allotment for the current period.',
      }),
      // Restorative actions fire immediately (no confirmation gate).
      're-enable': () => null,
      resync: () => null,
    };

  // Anonymous members have no name. The 4-digit account-number prefix is the
  // handle admins search by; fall back to a short id slice before issuance
  // mints one.
  function userLabel(u: z.infer<typeof UserAdmin>): string {
    if (u.supportId) return u.supportId;
    return u.accountIdPrefix ? `Account ${u.accountIdPrefix}…` : `User ${u.id.slice(0, 8)}`;
  }

  // Seed filters from the URL query string so a refresh/deep-link restores them
  // (they're otherwise $state-only). We read window.location.search directly
  // (not the router) on init and write back via history.replaceState below.
  const initialParams =
    typeof window !== 'undefined'
      ? new URLSearchParams(window.location.search)
      : new URLSearchParams();

  // The text the user has typed but not yet committed (Enter or Search button).
  // We only update the actual queryKey input on commit so each keystroke
  // doesn't fire a fresh request: that's the whole point of separating
  // input-state from query-state.
  let inputText = $state(initialParams.get('q') ?? '');
  let activeQuery = $state(initialParams.get('q') ?? '');
  // Server-supported list filters (UserSearchQuery): wired here for the first
  // time - the API honored them, the UI just never offered them.
  let statusFilter = $state(initialParams.get('status') ?? '');
  let tierFilter = $state(initialParams.get('tier') ?? '');
  // Restrict to users whose last backend push failed (entitlement drift).
  let driftFilter = $state(initialParams.get('drift') === 'true');

  // Reflect the committed filters into the URL query string (only non-default
  // values) so refresh/deep-link preserves them. replaceState (not pushState)
  // keeps the back button behaving like the pre-filter page. We don't touch the
  // router - this is a pure URL sync.
  $effect(() => {
    if (typeof window === 'undefined') return;
    const params = new URLSearchParams();
    if (activeQuery) params.set('q', activeQuery);
    if (statusFilter) params.set('status', statusFilter);
    if (tierFilter) params.set('tier', tierFilter);
    if (driftFilter) params.set('drift', 'true');
    const qs = params.toString();
    const next = qs ? `${window.location.pathname}?${qs}` : window.location.pathname;
    if (next !== window.location.pathname + window.location.search) {
      window.history.replaceState(window.history.state, '', next);
    }
  });

  const STATUS_OPTIONS = ['', 'active', 'grace', 'disabled', 'inactive', 'deleted'] as const;

  const users = adminUsersQuery(() => ({
    q: activeQuery,
    status: statusFilter,
    tier: tierFilter,
    drift: driftFilter,
  }));
  const tiers = adminTiersQuery();
  // Public config: only read for devices.enforcementEnabled, so the Live
  // details expander can say WHY a device list is empty (tracking off vs none).
  const config = configQuery();
  const qc = useQueryClient();

  // Per-user LIVE backend state (status/usage/devices), lazily fetched only for
  // the currently-expanded row - the users list itself stays a cheap DB read.
  let expandedUserId = $state<string | null>(null);
  const backendState = adminUserBackendStateQuery(
    () => expandedUserId ?? '',
    () => expandedUserId !== null,
  );

  // Flatten the infinite-query pages into a single list (P1-16).
  let userRows = $derived(users.data?.pages.flatMap((p) => p.users) ?? []);

  // Holds the user op that needs explicit confirmation, mounting the
  // AlertDialog. `null` = closed.
  let pending = $state<{ user: z.infer<typeof UserAdmin>; op: UserOp } | null>(null);

  const userAction = createMutation(() => ({
    mutationFn: async ({ user, op }: { user: z.infer<typeof UserAdmin>; op: UserOp }) => {
      await apiClient.post(`/api/v1/admin/users/${user.id}/${op}`, {}, z.object({}));
    },
    onSuccess: (_data, vars) => {
      void qc.invalidateQueries({ queryKey: ['admin', 'users'] });
      const verb =
        vars.op === 'disable'
          ? 'disabled'
          : vars.op === 're-enable'
            ? 're-enabled'
            : vars.op === 'reset-traffic'
              ? 'had traffic reset'
              : 're-synced';
      toast.success(`User ${verb}`);
      pending = null;
    },
    onError: (err) => {
      toast.error('Action failed', { description: apiErrorMessage(err) });
    },
  }));

  function startAction(user: z.infer<typeof UserAdmin>, op: UserOp) {
    const copy = OP_COPY[op](userLabel(user));
    if (!copy) {
      // No confirmation needed (resync), fire immediately.
      userAction.mutate({ user, op });
      return;
    }
    pending = { user, op };
  }

  function confirmPending() {
    if (pending) userAction.mutate(pending);
  }

  let pendingCopy = $derived(pending ? OP_COPY[pending.op](userLabel(pending.user)) : null);

  // Grant/extend a membership (a plan + N days) for a user. Separate from the
  // no-body ops above because it carries a tier + duration in the body.
  let granting = $state<z.infer<typeof UserAdmin> | null>(null);
  let grantTierId = $state('');
  let grantDays = $state(30);

  const grantMembership = createMutation(() => ({
    mutationFn: async (vars: { userId: string; tierId: string; durationDays: number }) => {
      await apiClient.post(
        `/api/v1/admin/users/${vars.userId}/grant-membership`,
        { tierId: vars.tierId, durationDays: vars.durationDays },
        z.object({ ok: z.boolean(), membershipExpiresAt: z.number().optional() }),
      );
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['admin', 'users'] });
      toast.success('Membership granted');
      granting = null;
    },
    onError: (err) => toast.error('Grant failed', { description: apiErrorMessage(err) }),
  }));

  function startGrant(user: z.infer<typeof UserAdmin>) {
    granting = user;
    grantTierId = '';
    grantDays = 30;
  }

  function confirmGrant() {
    if (!granting || !grantTierId || !Number.isFinite(grantDays) || grantDays < 1) return;
    grantMembership.mutate({ userId: granting.id, tierId: grantTierId, durationDays: grantDays });
  }

  let grantTierLabel = $derived(
    grantTierId
      ? (tiers.data?.find((t) => t.id === grantTierId)?.slug ?? 'Select a plan')
      : 'Select a plan',
  );
</script>

<AdminLayout>
  <h1 class="text-2xl font-bold mb-6">Users</h1>
  <div class="flex gap-2 mb-6">
    <Input
      placeholder="Search by FS- support ID or 4-digit account prefix…"
      bind:value={inputText}
      onkeydown={(e) => {
        if (e.key === 'Enter') activeQuery = inputText;
      }}
    />
    <Button onclick={() => (activeQuery = inputText)} disabled={users.isFetching}>
      {users.isFetching ? 'Searching…' : 'Search'}
    </Button>
  </div>
  <div class="mb-6 flex flex-wrap items-center gap-2 text-sm">
    <Select.Root type="single" value={statusFilter} onValueChange={(v) => (statusFilter = v)}>
      <Select.Trigger class="w-40">
        {statusFilter ? `Status: ${statusFilter}` : 'Any status'}
      </Select.Trigger>
      <Select.Content>
        {#each STATUS_OPTIONS as opt (opt)}
          <Select.Item value={opt}>{opt || 'Any status'}</Select.Item>
        {/each}
      </Select.Content>
    </Select.Root>
    <Select.Root type="single" value={tierFilter} onValueChange={(v) => (tierFilter = v)}>
      <Select.Trigger class="w-44">
        {tierFilter ? `Tier: ${tierFilter}` : 'Any tier'}
      </Select.Trigger>
      <Select.Content>
        <Select.Item value="">Any tier</Select.Item>
        {#each tiers.data ?? [] as tier (tier.id)}
          <Select.Item value={tier.slug}>{tier.slug}</Select.Item>
        {/each}
      </Select.Content>
    </Select.Root>
    <Button
      size="sm"
      variant={driftFilter ? 'default' : 'outline'}
      onclick={() => (driftFilter = !driftFilter)}
      title="Show only users whose last backend push failed (entitlement drift)"
    >
      Backend drift
    </Button>
    {#if statusFilter || tierFilter || driftFilter}
      <Button
        size="sm"
        variant="ghost"
        onclick={() => {
          statusFilter = '';
          tierFilter = '';
          driftFilter = false;
        }}
      >
        Clear filters
      </Button>
    {/if}
  </div>

  {#if users.isPending}
    <div class="space-y-3">
      {#each Array(4) as _, i (i)}
        <Card>
          <CardHeader>
            <Skeleton class="h-5 w-64" />
          </CardHeader>
          <CardContent class="space-y-2">
            <Skeleton class="h-4 w-48" />
            <Skeleton class="h-4 w-72" />
            <div class="flex gap-2 pt-1">
              <Skeleton class="h-7 w-24" />
              <Skeleton class="h-7 w-24" />
              <Skeleton class="h-7 w-20" />
            </div>
          </CardContent>
        </Card>
      {/each}
    </div>
  {:else if users.isError}
    <AdminListState error={users.error} onRetry={() => void users.refetch()} />
  {:else}
    <div class="space-y-3">
      {#each userRows as u (u.id)}
        {@const busy = userAction.isPending && userAction.variables?.user.id === u.id}
        <Card>
          <CardHeader>
            <CardTitle class="text-lg">
              {userLabel(u)}
            </CardTitle>
          </CardHeader>
          <CardContent class="text-sm space-y-1">
            <div>
              Status: <strong>{u.status}</strong> · Tier: <strong>{u.tierSlug}</strong>
            </div>
            <div class="text-muted-foreground">
              {#if u.supportId}
                Support ID: <code class="select-all font-mono text-foreground">{u.supportId}</code>
              {/if}
              {#if u.accountIdPrefix}
                {#if u.supportId}·{/if}
                Prefix: <code class="font-mono">{u.accountIdPrefix}…</code>
              {/if}
            </div>
            <div class="text-muted-foreground">
              Created {formatDate(u.createdAt)}
            </div>
            <div class="text-muted-foreground">
              Backend: <strong class="text-foreground">{u.backend ?? '-'}</strong>
              {#if u.backendUserId}
                · <code class="text-xs break-all">{u.backendUserId}</code>
              {/if}
              {#if u.backendPushFailedAt}
                <span
                  class="ml-2 inline-flex items-center gap-1 rounded border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 text-xs text-amber-600 dark:text-amber-400"
                  title={`Last backend push failed ${formatDate(u.backendPushFailedAt)}; the panel may be out of sync. Use Resync to re-push.`}
                >
                  backend drift
                </span>
              {/if}
            </div>
            <div class="flex flex-wrap gap-2 pt-2">
              <Button
                size="sm"
                variant="outline"
                disabled={busy}
                onclick={() => startAction(u, 'reset-traffic')}
              >
                Reset traffic
              </Button>
              <Button
                size="sm"
                variant="outline"
                disabled={busy}
                onclick={() => startAction(u, 'resync')}
              >
                Force resync
              </Button>
              {#if u.status === 'disabled'}
                <Button
                  size="sm"
                  variant="default"
                  disabled={busy}
                  onclick={() => startAction(u, 're-enable')}
                >
                  Re-enable
                </Button>
              {:else}
                <Button
                  size="sm"
                  variant="destructive"
                  disabled={busy}
                  onclick={() => startAction(u, 'disable')}
                >
                  Disable
                </Button>
              {/if}
              <Button size="sm" variant="outline" disabled={busy} onclick={() => startGrant(u)}>
                Grant membership
              </Button>
              <Button
                size="sm"
                variant="ghost"
                onclick={() => (expandedUserId = expandedUserId === u.id ? null : u.id)}
              >
                {expandedUserId === u.id ? 'Hide live' : 'Live details'}
              </Button>
            </div>
            {#if expandedUserId === u.id}
              <!-- Live backend state (lazy): the actual key status/usage on the panel,
                   vs FCP's local status - a per-user complement to the drift badge. -->
              <div class="mt-3 rounded-lg border border-border bg-muted/30 p-3 text-xs space-y-1.5">
                {#if backendState.isPending}
                  <Skeleton class="h-4 w-56" />
                {:else if backendState.isError}
                  <p class="text-muted-foreground">Couldn't load live backend state.</p>
                {:else if backendState.data?.state}
                  {@const s = backendState.data.state}
                  <div>
                    Backend status: <strong class="text-foreground">{s.status}</strong>
                    {#if (s.status === 'active') !== (u.status === 'active')}
                      <span class="ml-1 text-amber-600 dark:text-amber-400"
                        >· local "{u.status}" (mismatch)</span
                      >
                    {/if}
                  </div>
                  <div class="text-muted-foreground tabular-nums">
                    Usage: {formatBytes(s.usedTrafficBytes)} / {s.trafficLimitBytes === null
                      ? 'unlimited'
                      : formatBytes(s.trafficLimitBytes)}
                  </div>
                  <div class="text-muted-foreground">
                    Last online: <span class="text-foreground"
                      >{s.onlineAt ? formatDateTime(s.onlineAt) : 'never'}</span
                    >
                  </div>
                  {#if s.devices.length > 0}
                    <div class="text-muted-foreground">
                      {s.devices.length} registered device{s.devices.length === 1 ? '' : 's'}:
                    </div>
                    <ul class="list-disc space-y-0.5 ps-5 text-muted-foreground">
                      {#each s.devices as d (d.hwid)}
                        <li>
                          {d.platform ?? 'Unknown platform'}{d.deviceModel
                            ? ` · ${d.deviceModel}`
                            : ''}{d.lastSeenAt
                            ? ` · last seen ${formatDateTime(d.lastSeenAt)}`
                            : ''}
                        </li>
                      {/each}
                    </ul>
                  {:else if !deviceLimitsShown(config.data)}
                    <div class="text-muted-foreground">
                      No registered devices. Device tracking is off (device-limit enforcement in
                      Settings), so the panel doesn't record them.
                    </div>
                  {:else}
                    <div class="text-muted-foreground">No registered devices.</div>
                  {/if}
                {:else}
                  <p class="text-muted-foreground">
                    No live data (no subscription, or the backend is unreachable).
                  </p>
                {/if}
              </div>
            {/if}
          </CardContent>
        </Card>
      {/each}
      {#if userRows.length === 0}
        <AdminListState emptyText="No users found." />
      {/if}
      {#if users.hasNextPage}
        <div class="pt-2 text-center">
          <Button
            variant="outline"
            onclick={() => users.fetchNextPage()}
            disabled={users.isFetchingNextPage}
          >
            {users.isFetchingNextPage ? 'Loading…' : 'Load more'}
          </Button>
        </div>
      {/if}
    </div>
  {/if}

  <AlertDialog.Root open={!!pending} onOpenChange={(o) => (o ? null : (pending = null))}>
    <AlertDialog.Content>
      <AlertDialog.Header>
        <AlertDialog.Title>{pendingCopy?.title ?? ''}</AlertDialog.Title>
        <AlertDialog.Description>{pendingCopy?.description ?? ''}</AlertDialog.Description>
      </AlertDialog.Header>
      <AlertDialog.Footer>
        <AlertDialog.Cancel>Cancel</AlertDialog.Cancel>
        <AlertDialog.Action onclick={confirmPending} disabled={userAction.isPending}>
          {userAction.isPending ? 'Working…' : 'Confirm'}
        </AlertDialog.Action>
      </AlertDialog.Footer>
    </AlertDialog.Content>
  </AlertDialog.Root>

  <AlertDialog.Root open={!!granting} onOpenChange={(o) => (o ? null : (granting = null))}>
    <AlertDialog.Content>
      <AlertDialog.Header>
        <AlertDialog.Title>
          Grant membership{granting ? ` to ${userLabel(granting)}` : ''}
        </AlertDialog.Title>
        <AlertDialog.Description>
          Pick a plan and how many days to add. Extends from the later of now or the current expiry,
          and re-activates a lapsed account. The new tier is pushed to the proxy backend.
        </AlertDialog.Description>
      </AlertDialog.Header>
      <div class="space-y-3 py-2">
        <div>
          <span class="text-xs text-muted-foreground mb-1 block">Plan</span>
          <Select.Root type="single" value={grantTierId} onValueChange={(v) => (grantTierId = v)}>
            <Select.Trigger class="w-full">{grantTierLabel}</Select.Trigger>
            <Select.Content>
              {#each tiers.data ?? [] as tier (tier.id)}
                <Select.Item value={tier.id}>{tier.slug}</Select.Item>
              {/each}
            </Select.Content>
          </Select.Root>
        </div>
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="grant-days">Days</label>
          <Input
            id="grant-days"
            type="number"
            min={1}
            max={3650}
            value={grantDays}
            oninput={(e) => (grantDays = Number((e.currentTarget as HTMLInputElement).value))}
          />
        </div>
      </div>
      <AlertDialog.Footer>
        <AlertDialog.Cancel>Cancel</AlertDialog.Cancel>
        <AlertDialog.Action
          onclick={confirmGrant}
          disabled={grantMembership.isPending || !grantTierId || grantDays < 1}
        >
          {grantMembership.isPending ? 'Granting…' : 'Grant'}
        </AlertDialog.Action>
      </AlertDialog.Footer>
    </AlertDialog.Content>
  </AlertDialog.Root>
</AdminLayout>
