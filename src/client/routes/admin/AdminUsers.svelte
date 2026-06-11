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
  import { formatDate } from '../../lib/i18n/format';
  import AdminListState from './AdminListState.svelte';
  import { UserAdmin } from '../../../shared/contracts/admin';
  import { adminTiersQuery, adminUsersQuery } from '../../lib/queries';
  import * as Select from '@client/components/ui/select';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';

  type UserOp = 'disable' | 'reset-traffic' | 'resync';

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
      resync: () => null,
    };

  // Anonymous members have no name. The 4-digit account-number prefix is the
  // handle admins search by; fall back to a short id slice before issuance
  // mints one.
  function userLabel(u: z.infer<typeof UserAdmin>): string {
    if (u.supportId) return u.supportId;
    return u.accountIdPrefix ? `Account ${u.accountIdPrefix}…` : `User ${u.id.slice(0, 8)}`;
  }

  // The text the user has typed but not yet committed (Enter or Search button).
  // We only update the actual queryKey input on commit so each keystroke
  // doesn't fire a fresh request: that's the whole point of separating
  // input-state from query-state.
  let inputText = $state('');
  let activeQuery = $state('');
  // Server-supported list filters (UserSearchQuery): wired here for the first
  // time — the API honored them, the UI just never offered them.
  let statusFilter = $state('');
  let tierFilter = $state('');

  const STATUS_OPTIONS = ['', 'active', 'grace', 'disabled'] as const;

  const users = adminUsersQuery(() => ({
    q: activeQuery,
    status: statusFilter,
    tier: tierFilter,
  }));
  const tiers = adminTiersQuery();
  const qc = useQueryClient();

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
    {#if statusFilter || tierFilter}
      <Button
        size="sm"
        variant="ghost"
        onclick={() => {
          statusFilter = '';
          tierFilter = '';
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
    <AdminListState error={users.error} />
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
            </div>
            <div class="flex gap-2 pt-2">
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
              <Button
                size="sm"
                variant="destructive"
                disabled={busy || u.status === 'disabled'}
                onclick={() => startAction(u, 'disable')}
              >
                {u.status === 'disabled' ? 'Disabled' : 'Disable'}
              </Button>
            </div>
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
</AdminLayout>
