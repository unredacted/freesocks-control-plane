<script lang="ts">
  import type { z } from 'zod';
  import AdminLayout from './AdminLayout.svelte';
  import ClientEditor from './ClientEditor.svelte';
  import { Card, CardHeader, CardTitle, CardContent } from '@client/components/ui/card';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { Button } from '@client/components/ui/button';
  import * as AlertDialog from '@client/components/ui/alert-dialog';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import AdminListState from './AdminListState.svelte';
  import { adminClientsQuery, queryKeys } from '../../lib/queries';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { ClientAdmin } from '../../../shared/contracts/admin';
  import { toast } from 'svelte-sonner';
  import Plus from '@lucide/svelte/icons/plus';
  import { z as zod } from 'zod';

  type Client = z.infer<typeof ClientAdmin>;
  const clients = adminClientsQuery();
  const qc = useQueryClient();

  let editing = $state<Client | null>(null);
  let creating = $state(false);
  let pendingDelete = $state<Client | null>(null);

  const remove = createMutation(() => ({
    mutationFn: async (id: string) => {
      await apiClient.delete(`/api/v1/admin/clients/${id}`, zod.object({ ok: zod.boolean() }));
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.adminClients });
      pendingDelete = null;
      toast.success('Client removed');
    },
    onError: (err) => {
      toast.error('Could not delete client', { description: apiErrorMessage(err) });
    },
  }));
</script>

<AdminLayout>
  <div class="flex items-center justify-between mb-6">
    <div>
      <h1 class="text-2xl font-bold">Client apps</h1>
      <p class="text-sm text-muted-foreground mt-1">
        The recommended VPN apps shown to members in the "set up your app" section. Add, disable, or
        reorder them here. The import scheme (one-tap import) is a code builder referenced by id;
        while this list is empty the member section falls back to the built-in defaults.
      </p>
    </div>
    <Button onclick={() => (creating = true)}>
      <Plus class="size-4" />
      Add client
    </Button>
  </div>

  {#if clients.isPending}
    <div class="space-y-3">
      {#each Array(3) as _, i (i)}
        <Card>
          <CardHeader><Skeleton class="h-5 w-48" /></CardHeader>
          <CardContent><Skeleton class="h-4 w-2/3" /></CardContent>
        </Card>
      {/each}
    </div>
  {:else if clients.isError}
    <AdminListState error={clients.error} onRetry={() => void clients.refetch()} />
  {:else if (clients.data?.length ?? 0) === 0}
    <div
      class="text-sm text-muted-foreground border border-dashed rounded-lg p-8 text-center space-y-2"
    >
      <p>No clients configured.</p>
      <p class="text-xs">
        The member section is showing the built-in defaults. Add a client to override them.
      </p>
    </div>
  {:else}
    <div class="space-y-3">
      {#each clients.data ?? [] as c (c.id)}
        <Card>
          <CardHeader>
            <CardTitle class="text-lg flex items-center justify-between flex-wrap gap-2">
              <span>{c.name}</span>
              <span class="flex items-center gap-2">
                {#if c.schemeId}
                  <span class="text-xs px-2 py-1 rounded bg-primary/10 text-primary font-medium">
                    {c.schemeId}
                  </span>
                {:else}
                  <span class="text-xs px-2 py-1 rounded bg-muted text-muted-foreground"
                    >manual</span
                  >
                {/if}
                {#if !c.enabled}
                  <span class="text-xs px-2 py-1 rounded bg-muted text-muted-foreground">
                    Disabled
                  </span>
                {/if}
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent class="text-sm space-y-1">
            <div class="text-muted-foreground">
              Platforms: <strong class="text-foreground">{c.platforms.join(', ') || '—'}</strong> ·
              Backends: <strong class="text-foreground">{c.backends.join(', ')}</strong>
            </div>
            <div class="text-muted-foreground">
              Install: <code class="font-mono break-all">{c.homepageUrl}</code>
            </div>
            <div class="text-muted-foreground">
              Device limit (HWID): <strong class="text-foreground">{c.hwid ? 'yes' : 'no'}</strong>
              · Priority: <strong class="text-foreground tabular-nums">{c.priority}</strong>
            </div>
            <div class="flex flex-wrap gap-2 pt-2">
              <Button size="sm" variant="outline" onclick={() => (editing = c)}>Edit</Button>
              <Button size="sm" variant="destructive" onclick={() => (pendingDelete = c)}>
                Remove
              </Button>
            </div>
          </CardContent>
        </Card>
      {/each}
    </div>
  {/if}

  {#if creating}
    <ClientEditor
      onClose={() => (creating = false)}
      onSaved={() => {
        creating = false;
        void qc.invalidateQueries({ queryKey: queryKeys.adminClients });
      }}
    />
  {/if}
  {#if editing}
    <ClientEditor
      client={editing}
      onClose={() => (editing = null)}
      onSaved={() => {
        editing = null;
        void qc.invalidateQueries({ queryKey: queryKeys.adminClients });
      }}
    />
  {/if}

  <AlertDialog.Root
    open={!!pendingDelete}
    onOpenChange={(o) => (o ? null : (pendingDelete = null))}
  >
    <AlertDialog.Content>
      <AlertDialog.Header>
        <AlertDialog.Title>Remove "{pendingDelete?.name}"?</AlertDialog.Title>
        <AlertDialog.Description>
          It will no longer appear in the member "set up your app" section.
        </AlertDialog.Description>
      </AlertDialog.Header>
      <AlertDialog.Footer>
        <AlertDialog.Cancel>Cancel</AlertDialog.Cancel>
        <AlertDialog.Action
          onclick={() => pendingDelete && remove.mutate(pendingDelete.id)}
          disabled={remove.isPending}
        >
          {remove.isPending ? 'Removing…' : 'Remove'}
        </AlertDialog.Action>
      </AlertDialog.Footer>
    </AlertDialog.Content>
  </AlertDialog.Root>
</AdminLayout>
