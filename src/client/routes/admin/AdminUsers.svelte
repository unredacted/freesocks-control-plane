<script lang="ts">
  import { z } from 'zod';
  import { Card, CardHeader, CardTitle, CardContent } from '@client/components/ui/card';
  import { Skeleton } from '@client/components/ui/skeleton';
  import * as AlertDialog from '@client/components/ui/alert-dialog';
  import AdminLayout from './AdminLayout.svelte';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { apiClient } from '../../lib/api';
  import { UserAdmin } from '../../../shared/contracts/admin';
  import { adminUsersQuery } from '../../lib/queries';
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

  // The text the user has typed but not yet committed (Enter or Search button).
  // We only update the actual queryKey input on commit so each keystroke
  // doesn't fire a fresh request — that's the whole point of separating
  // input-state from query-state.
  let inputText = $state('');
  let activeQuery = $state('');

  const users = adminUsersQuery(() => activeQuery);
  const qc = useQueryClient();

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
      toast.error('Action failed', {
        description: err instanceof Error ? err.message : String(err),
      });
    },
  }));

  function startAction(user: z.infer<typeof UserAdmin>, op: UserOp) {
    const copy = OP_COPY[op](user.email ?? user.authentikSubject ?? `user #${user.id}`);
    if (!copy) {
      // No confirmation needed (resync) — fire immediately.
      userAction.mutate({ user, op });
      return;
    }
    pending = { user, op };
  }

  function confirmPending() {
    if (pending) userAction.mutate(pending);
  }

  let pendingCopy = $derived(
    pending
      ? OP_COPY[pending.op](
          pending.user.email ?? pending.user.authentikSubject ?? `user #${pending.user.id}`,
        )
      : null,
  );
</script>

<AdminLayout>
  <h1 class="text-2xl font-bold mb-6">Users</h1>
  <div class="flex gap-2 mb-6">
    <Input
      placeholder="Search by email or account-number prefix..."
      bind:value={inputText}
      onkeydown={(e) => {
        if (e.key === 'Enter') activeQuery = inputText;
      }}
    />
    <Button onclick={() => (activeQuery = inputText)} disabled={users.isFetching}>
      {users.isFetching ? 'Searching…' : 'Search'}
    </Button>
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
    <div
      class="rounded-md bg-destructive/10 border border-destructive/40 px-3 py-2 text-sm text-destructive"
    >
      {users.error instanceof Error ? users.error.message : String(users.error)}
    </div>
  {:else}
    <div class="space-y-3">
      {#each users.data ?? [] as u (u.id)}
        {@const busy = userAction.isPending && userAction.variables?.user.id === u.id}
        <Card>
          <CardHeader>
            <CardTitle class="text-lg">
              {u.email ?? u.authentikSubject ?? `user #${u.id}`}
            </CardTitle>
          </CardHeader>
          <CardContent class="text-sm space-y-1">
            <div>
              Status: <strong>{u.status}</strong> · Tier: <strong>{u.tierSlug}</strong>
            </div>
            <div class="text-muted-foreground">
              Created {new Date(u.createdAt).toLocaleDateString()}
            </div>
            <div class="text-muted-foreground">
              Backend: <strong class="text-foreground">{u.backend ?? '—'}</strong>
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
