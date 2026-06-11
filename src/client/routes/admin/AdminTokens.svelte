<script lang="ts">
  import { z } from 'zod';
  import { Card, CardHeader, CardTitle, CardContent } from '@client/components/ui/card';
  import { Skeleton } from '@client/components/ui/skeleton';
  import * as AlertDialog from '@client/components/ui/alert-dialog';
  import AdminLayout from './AdminLayout.svelte';
  import { Button } from '@client/components/ui/button';
  import CreateTokenModal from './CreateTokenModal.svelte';
  import RevealModal from './RevealModal.svelte';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import { formatDateTime } from '../../lib/i18n/format';
  import AdminListState from './AdminListState.svelte';
  import { adminTokensQuery, queryKeys } from '../../lib/queries';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';

  const tokens = adminTokensQuery();
  const qc = useQueryClient();

  let creating = $state(false);
  let revealed = $state<{ plaintext: string; name: string } | null>(null);
  let pendingRevoke = $state<{ id: string; name: string } | null>(null);

  const revoke = createMutation(() => ({
    mutationFn: (id: string) =>
      apiClient.delete(`/api/v1/admin/tokens/${id}`, z.object({ ok: z.boolean() })),
    onSuccess: (_data, id) => {
      void qc.invalidateQueries({ queryKey: queryKeys.adminTokens });
      pendingRevoke = null;
      toast.success(`Token #${id} revoked`);
    },
    onError: (err) => {
      toast.error('Revoke failed', { description: apiErrorMessage(err) });
    },
  }));
</script>

<AdminLayout>
  <div class="flex items-center justify-between mb-6">
    <h1 class="text-2xl font-bold">API tokens</h1>
    <Button onclick={() => (creating = true)}>Create token</Button>
  </div>

  <p class="text-sm text-muted-foreground mb-4">
    Bearer tokens for service consumers. Send as
    <code class="bg-muted px-1 py-0.5 rounded text-xs"> Authorization: Bearer fsv1_... </code>
  </p>

  {#if tokens.isPending}
    <div class="space-y-3">
      {#each Array(3) as _, i (i)}
        <Card>
          <CardHeader><Skeleton class="h-6 w-64" /></CardHeader>
          <CardContent class="space-y-2">
            <Skeleton class="h-4 w-1/2" />
            <Skeleton class="h-4 w-3/4" />
            <Skeleton class="h-7 w-20" />
          </CardContent>
        </Card>
      {/each}
    </div>
  {:else if tokens.isError}
    <AdminListState error={tokens.error} />
  {:else}
    <div class="space-y-3">
      {#if (tokens.data?.length ?? 0) === 0}
        <AdminListState emptyText="No tokens yet." />
      {/if}
      {#each tokens.data ?? [] as tok (tok.id)}
        <Card>
          <CardHeader>
            <CardTitle class="text-lg flex items-center justify-between">
              <span>
                {tok.name}
                <code class="text-xs text-muted-foreground font-mono ml-2">{tok.tokenPrefix}…</code>
              </span>
              {#if tok.revokedAt}
                <span class="text-xs px-2 py-1 rounded bg-destructive/15 text-destructive">
                  Revoked
                </span>
              {:else if tok.expiresAt && new Date(tok.expiresAt) < new Date()}
                <span class="text-xs px-2 py-1 rounded bg-muted text-muted-foreground">
                  Expired
                </span>
              {:else}
                <span class="text-xs px-2 py-1 rounded bg-emerald-500/15 text-emerald-500">
                  Active
                </span>
              {/if}
            </CardTitle>
          </CardHeader>
          <CardContent class="text-sm space-y-1">
            <div class="flex flex-wrap gap-1">
              {#each tok.scopes as s (s)}
                <span class="text-xs px-2 py-0.5 rounded bg-secondary text-secondary-foreground">
                  {s}
                </span>
              {/each}
            </div>
            <div class="text-muted-foreground">
              Created {formatDateTime(tok.createdAt)}
              {#if tok.lastUsedAt}
                · last used {formatDateTime(tok.lastUsedAt)}
              {/if}
              {#if tok.expiresAt}
                · expires {formatDateTime(tok.expiresAt)}
              {/if}
            </div>
            {#if !tok.revokedAt}
              <Button
                size="sm"
                variant="destructive"
                onclick={() => (pendingRevoke = { id: tok.id, name: tok.name })}
                class="mt-2"
              >
                Revoke
              </Button>
            {/if}
          </CardContent>
        </Card>
      {/each}
    </div>
  {/if}

  {#if creating}
    <CreateTokenModal
      onClose={() => (creating = false)}
      onCreated={(plaintext, name) => {
        revealed = { plaintext, name };
        creating = false;
        void qc.invalidateQueries({ queryKey: queryKeys.adminTokens });
      }}
    />
  {/if}

  {#if revealed}
    <RevealModal open={true} token={revealed} onClose={() => (revealed = null)} />
  {/if}

  <AlertDialog.Root
    open={!!pendingRevoke}
    onOpenChange={(o) => (o ? null : (pendingRevoke = null))}
  >
    <AlertDialog.Content>
      <AlertDialog.Header>
        <AlertDialog.Title>Revoke "{pendingRevoke?.name}"?</AlertDialog.Title>
        <AlertDialog.Description>
          Any clients using this token will be locked out immediately. This cannot be undone.
        </AlertDialog.Description>
      </AlertDialog.Header>
      <AlertDialog.Footer>
        <AlertDialog.Cancel>Cancel</AlertDialog.Cancel>
        <AlertDialog.Action
          onclick={() => pendingRevoke && revoke.mutate(pendingRevoke.id)}
          disabled={revoke.isPending}
        >
          {revoke.isPending ? 'Revoking…' : 'Revoke'}
        </AlertDialog.Action>
      </AlertDialog.Footer>
    </AlertDialog.Content>
  </AlertDialog.Root>
</AdminLayout>
