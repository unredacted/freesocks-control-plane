<script lang="ts">
  import type { z } from 'zod';
  import AdminLayout from './AdminLayout.svelte';
  import BackendServerEditor from './BackendServerEditor.svelte';
  import { Card, CardHeader, CardTitle, CardContent } from '@client/components/ui/card';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { Button } from '@client/components/ui/button';
  import * as AlertDialog from '@client/components/ui/alert-dialog';
  import { apiClient } from '../../lib/api';
  import { adminBackendServersQuery, queryKeys } from '../../lib/queries';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { BackendServerAdmin } from '../../../shared/contracts/admin';
  import type { BackendId } from '../../../shared/contracts/backends';
  import { toast } from 'svelte-sonner';
  import Plus from '@lucide/svelte/icons/plus';
  import { z as zod } from 'zod';

  type Server = z.infer<typeof BackendServerAdmin>;
  const servers = adminBackendServersQuery();
  const qc = useQueryClient();
  const BACKEND_LABELS: Record<BackendId, string> = { remnawave: 'Remnawave', outline: 'Outline' };

  let editing = $state<Server | null>(null);
  let creating = $state(false);
  let pendingDelete = $state<Server | null>(null);

  const remove = createMutation(() => ({
    mutationFn: async (id: string) => {
      await apiClient.delete(
        `/api/v1/admin/backend-servers/${id}`,
        zod.object({ ok: zod.boolean() }),
      );
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.adminBackendServers });
      pendingDelete = null;
      toast.success('Instance removed');
    },
    onError: (err) => {
      toast.error('Could not delete instance', {
        description: err instanceof Error ? err.message : String(err),
      });
    },
  }));

  // Reachability badge. The healthcheck cron runs every 10 min; fresh-within-15
  // is green, longer-stale amber, never-seen red.
  function healthBadge(lastHealthOkAt: string | null) {
    if (!lastHealthOkAt) {
      return { label: 'No check yet', tone: 'bg-destructive/15 text-destructive' };
    }
    const age = Date.now() - new Date(lastHealthOkAt).getTime();
    if (age < 15 * 60_000) return { label: 'Healthy', tone: 'bg-emerald-500/15 text-emerald-600' };
    if (age < 60 * 60_000) return { label: 'Stale', tone: 'bg-amber-500/15 text-amber-600' };
    return { label: 'Unreachable', tone: 'bg-destructive/15 text-destructive' };
  }
</script>

<AdminLayout>
  <div class="flex items-center justify-between mb-6">
    <div>
      <h1 class="text-2xl font-bold">Backend servers</h1>
      <p class="text-sm text-muted-foreground mt-1">
        Proxy backend instances used to issue keys. Each tier issues against its backend type; the
        pool picks the best-scored active instance of that type.
      </p>
    </div>
    <Button onclick={() => (creating = true)}>
      <Plus class="size-4" />
      Add instance
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
      <p>No backend instances registered.</p>
      <p class="text-xs">Add a Remnawave or Outline instance to start issuing keys.</p>
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
                <span class="text-xs px-2 py-1 rounded bg-primary/10 text-primary font-medium">
                  {BACKEND_LABELS[s.backend]}
                </span>
                <span class="text-xs px-2 py-1 rounded {health.tone}">{health.label}</span>
                {#if s.config.type === 'outline' && s.config.websocketEnabled}
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
            {#if s.config.type === 'remnawave'}
              <div class="text-muted-foreground">
                Base URL: <code class="font-mono">{s.config.baseUrl}</code> · Token:
                <strong class="text-foreground">{s.config.apiTokenSet ? 'set' : 'not set'}</strong>
              </div>
            {:else}
              <div class="text-muted-foreground">
                API URL: <code class="font-mono">{s.config.apiUrlMasked}</code>
                {#if s.config.websocketEnabled && s.config.websocketDomain}
                  · WSS domain: <code class="font-mono">{s.config.websocketDomain}</code>
                {/if}
              </div>
            {/if}
            <div class="text-muted-foreground">
              Priority: <strong class="text-foreground tabular-nums">{s.priority}</strong> · Keys:
              <strong class="text-foreground tabular-nums">{s.keyCount}</strong>
              {#if s.lastHealthRttMs != null}
                · Last RTT: <strong class="text-foreground tabular-nums">{s.lastHealthRttMs}ms</strong>
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
    <BackendServerEditor
      onClose={() => (creating = false)}
      onSaved={() => {
        creating = false;
        void qc.invalidateQueries({ queryKey: queryKeys.adminBackendServers });
      }}
    />
  {/if}
  {#if editing}
    <BackendServerEditor
      server={editing}
      onClose={() => (editing = null)}
      onSaved={() => {
        editing = null;
        void qc.invalidateQueries({ queryKey: queryKeys.adminBackendServers });
      }}
    />
  {/if}

  <AlertDialog.Root open={!!pendingDelete} onOpenChange={(o) => (o ? null : (pendingDelete = null))}>
    <AlertDialog.Content>
      <AlertDialog.Header>
        <AlertDialog.Title>Remove "{pendingDelete?.name}"?</AlertDialog.Title>
        <AlertDialog.Description>
          De-registers the instance from the pool. Existing keys on it keep working server-side but
          will fail on next regenerate. Migrate users off first for a clean shutdown.
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
