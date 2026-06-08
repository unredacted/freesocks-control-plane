<script lang="ts">
  import type { z } from 'zod';
  import AdminLayout from './AdminLayout.svelte';
  import OutlineServerEditor from './OutlineServerEditor.svelte';
  import { Card, CardHeader, CardTitle, CardContent } from '@client/components/ui/card';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { Button } from '@client/components/ui/button';
  import * as AlertDialog from '@client/components/ui/alert-dialog';
  import { apiClient } from '../../lib/api';
  import { adminOutlineServersQuery, queryKeys } from '../../lib/queries';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { OutlineServerAdmin } from '../../../shared/contracts/admin';
  import { toast } from 'svelte-sonner';
  import Plus from '@lucide/svelte/icons/plus';
  import { z as zod } from 'zod';

  const servers = adminOutlineServersQuery();
  const qc = useQueryClient();

  let editing = $state<z.infer<typeof OutlineServerAdmin> | null>(null);
  let creating = $state(false);
  let pendingDelete = $state<z.infer<typeof OutlineServerAdmin> | null>(null);

  const remove = createMutation(() => ({
    mutationFn: async (id: string) => {
      await apiClient.delete(
        `/api/v1/admin/outline-servers/${id}`,
        zod.object({ ok: zod.boolean() }),
      );
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.adminOutlineServers });
      pendingDelete = null;
      toast.success('Outline server removed');
    },
    onError: (err) => {
      toast.error('Could not delete server', {
        description: err instanceof Error ? err.message : String(err),
      });
    },
  }));

  // Display badge for the "is reachable right now?" indicator. Five-minute
  // freshness window matches the cron interval; longer-stale becomes amber,
  // never-seen becomes red.
  function healthBadge(lastHealthOkAt: string | null) {
    if (!lastHealthOkAt) {
      return { label: 'No check yet', tone: 'bg-destructive/15 text-destructive' };
    }
    const age = Date.now() - new Date(lastHealthOkAt).getTime();
    if (age < 5 * 60_000) return { label: 'Healthy', tone: 'bg-emerald-500/15 text-emerald-600' };
    if (age < 60 * 60_000) return { label: 'Stale', tone: 'bg-amber-500/15 text-amber-600' };
    return { label: 'Unreachable', tone: 'bg-destructive/15 text-destructive' };
  }
</script>

<AdminLayout>
  <div class="flex items-center justify-between mb-6">
    <div>
      <h1 class="text-2xl font-bold">Outline servers</h1>
      <p class="text-sm text-muted-foreground mt-1">
        Outline Manager endpoints used for issuing Shadowsocks keys.
      </p>
    </div>
    <Button onclick={() => (creating = true)}>
      <Plus class="size-4" />
      Add server
    </Button>
  </div>

  {#if servers.isPending}
    <div class="space-y-3">
      {#each Array(3) as _, i (i)}
        <Card>
          <CardHeader><Skeleton class="h-5 w-64" /></CardHeader>
          <CardContent><Skeleton class="h-4 w-1/2" /></CardContent>
        </Card>
      {/each}
    </div>
  {:else if servers.isError}
    <div
      class="rounded-md bg-destructive/10 border border-destructive/40 px-3 py-2 text-sm text-destructive"
    >
      {servers.error instanceof Error ? servers.error.message : String(servers.error)}
    </div>
  {:else if (servers.data?.length ?? 0) === 0}
    <div
      class="text-sm text-muted-foreground border border-dashed rounded-lg p-8 text-center space-y-2"
    >
      <p>No Outline servers registered.</p>
      <p class="text-xs">
        Add one to enable issuing Outline-backed keys. The Outline server must have a valid TLS
        certificate (Cloudflare-fronted or Let's Encrypt; self-signed certs are rejected).
      </p>
    </div>
  {:else}
    <div class="space-y-3">
      {#each servers.data ?? [] as s (s.id)}
        {@const health = healthBadge(s.lastHealthOkAt)}
        <Card>
          <CardHeader>
            <CardTitle class="text-lg flex items-center justify-between flex-wrap gap-2">
              <span>
                {s.name}
                <code class="text-xs text-muted-foreground font-mono ml-2">{s.slug}</code>
              </span>
              <span class="flex items-center gap-2">
                <span class="text-xs px-2 py-1 rounded {health.tone}">{health.label}</span>
                {#if s.websocketEnabled}
                  <span class="text-xs px-2 py-1 rounded bg-secondary text-secondary-foreground">
                    WSS
                  </span>
                {/if}
                {#if !s.isActive}
                  <span class="text-xs px-2 py-1 rounded bg-muted text-muted-foreground">
                    Disabled
                  </span>
                {/if}
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent class="text-sm space-y-1">
            <div class="text-muted-foreground">
              API URL: <code class="font-mono">{s.apiUrlMasked}</code>
            </div>
            <div class="text-muted-foreground">
              Priority: <strong class="text-foreground tabular-nums">{s.priority}</strong> · Keys
              issued: <strong class="text-foreground tabular-nums">{s.accessKeyCount}</strong>
              {#if s.websocketEnabled && s.websocketDomain}
                · WSS domain: <code class="font-mono">{s.websocketDomain}</code>
              {/if}
            </div>
            <div class="flex gap-2 pt-2">
              <Button size="sm" variant="outline" onclick={() => (editing = s)}>Edit</Button>
              <Button size="sm" variant="destructive" onclick={() => (pendingDelete = s)}>
                Remove
              </Button>
            </div>
          </CardContent>
        </Card>
      {/each}
    </div>
  {/if}

  {#if creating}
    <OutlineServerEditor
      onClose={() => (creating = false)}
      onSaved={() => {
        creating = false;
        void qc.invalidateQueries({ queryKey: queryKeys.adminOutlineServers });
      }}
    />
  {/if}
  {#if editing}
    <OutlineServerEditor
      server={editing}
      onClose={() => (editing = null)}
      onSaved={() => {
        editing = null;
        void qc.invalidateQueries({ queryKey: queryKeys.adminOutlineServers });
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
          De-registers the server from the pool. Existing keys on this server keep working
          server-side but will fail on next regenerate. Migrate users off first if you want a clean
          shutdown.
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
