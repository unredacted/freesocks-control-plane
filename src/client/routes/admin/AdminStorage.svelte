<script lang="ts">
  import type { z } from 'zod';
  import AdminLayout from './AdminLayout.svelte';
  import MirrorProviderEditor from './MirrorProviderEditor.svelte';
  import { Card, CardHeader, CardTitle, CardContent } from '@client/components/ui/card';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { Button } from '@client/components/ui/button';
  import * as AlertDialog from '@client/components/ui/alert-dialog';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import AdminListState from './AdminListState.svelte';
  import { adminMirrorProvidersQuery, queryKeys } from '../../lib/queries';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { MirrorProviderAdmin } from '../../../shared/contracts/admin';
  import { toast } from 'svelte-sonner';
  import Plus from '@lucide/svelte/icons/plus';
  import { z as zod } from 'zod';

  type Provider = z.infer<typeof MirrorProviderAdmin>;
  const providers = adminMirrorProvidersQuery();
  const qc = useQueryClient();

  let editing = $state<Provider | null>(null);
  let creating = $state(false);
  let pendingDelete = $state<Provider | null>(null);

  // Mirroring is active iff ≥1 provider is enabled — the same gate the issuance
  // saga + refresh cron use. Surface it so an operator knows the feature's state.
  const activeCount = $derived((providers.data ?? []).filter((p) => p.isActive).length);

  const remove = createMutation(() => ({
    mutationFn: async (id: string) => {
      await apiClient.delete(
        `/api/v1/admin/mirror-providers/${id}`,
        zod.object({ ok: zod.boolean() }),
      );
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.adminMirrorProviders });
      pendingDelete = null;
      toast.success('Mirror provider removed');
    },
    onError: (err) => {
      toast.error('Could not delete provider', { description: apiErrorMessage(err) });
    },
  }));
</script>

<AdminLayout>
  <div class="flex items-center justify-between mb-6">
    <div>
      <h1 class="text-2xl font-bold">Storage mirrors</h1>
      <p class="text-sm text-muted-foreground mt-1">
        S3-compatible buckets the subscription content is mirrored to — the censorship-resistance
        hedge, so a client can still fetch its key if the control plane is blocked. Mirroring runs
        while at least one provider below is enabled.
      </p>
    </div>
    <Button onclick={() => (creating = true)}>
      <Plus class="size-4" />
      Add provider
    </Button>
  </div>

  {#if providers.isPending}
    <div class="space-y-3">
      {#each Array(2) as _, i (i)}
        <Card>
          <CardHeader><Skeleton class="h-5 w-64" /></CardHeader>
          <CardContent><Skeleton class="h-4 w-1/2" /></CardContent>
        </Card>
      {/each}
    </div>
  {:else if providers.isError}
    <AdminListState error={providers.error} onRetry={() => void providers.refetch()} />
  {:else if (providers.data?.length ?? 0) === 0}
    <div
      class="text-sm text-muted-foreground border border-dashed rounded-lg p-8 text-center space-y-2"
    >
      <p>No mirror providers configured.</p>
      <p class="text-xs">
        Subscription mirroring is off. Add an S3-compatible bucket to enable it.
      </p>
    </div>
  {:else}
    <div
      class="mb-4 rounded-md px-3 py-2 text-xs {activeCount > 0
        ? 'bg-emerald-500/10 border border-emerald-500/40 text-emerald-600'
        : 'bg-amber-500/10 border border-amber-500/40 text-amber-600'}"
    >
      {#if activeCount > 0}
        Mirroring is <strong>active</strong> — new and refreshed keys are copied to {activeCount}
        enabled {activeCount === 1 ? 'provider' : 'providers'}.
      {:else}
        Mirroring is <strong>paused</strong> — no provider is enabled.
      {/if}
    </div>
    <div class="space-y-3">
      {#each providers.data ?? [] as p (p.id)}
        <Card>
          <CardHeader>
            <CardTitle class="text-lg flex items-center justify-between flex-wrap gap-2">
              <span>
                {p.name}
                <code class="text-xs text-muted-foreground font-mono ml-2">{p.bucket}</code>
              </span>
              <span class="flex items-center gap-2">
                <span
                  class="text-xs px-2 py-1 rounded {p.secretAccessKeySet
                    ? 'bg-primary/10 text-primary'
                    : 'bg-destructive/15 text-destructive'} font-medium"
                >
                  {p.secretAccessKeySet ? 'Secret set' : 'No secret'}
                </span>
                {#if !p.isActive}
                  <span class="text-xs px-2 py-1 rounded bg-muted text-muted-foreground">
                    Disabled
                  </span>
                {/if}
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent class="text-sm space-y-1">
            <div class="text-muted-foreground">
              Endpoint: <code class="font-mono">{p.endpoint}</code> · Region:
              <code class="font-mono">{p.region}</code>
            </div>
            <div class="text-muted-foreground">
              Public URL: <code class="font-mono break-all">{p.publicUrl}</code>
            </div>
            <div class="text-muted-foreground">
              Access key ID: <code class="font-mono">{p.accessKeyId}</code> · Priority:
              <strong class="text-foreground tabular-nums">{p.priority}</strong>
            </div>
            <div class="text-muted-foreground">
              Regions:
              <strong class="text-foreground">
                {p.countryCodes.length ? p.countryCodes.join(', ') : 'Global (any country)'}
              </strong>
            </div>
            <div class="flex flex-wrap gap-2 pt-2">
              <Button size="sm" variant="outline" onclick={() => (editing = p)}>Edit</Button>
              <Button size="sm" variant="destructive" onclick={() => (pendingDelete = p)}>
                Remove
              </Button>
            </div>
          </CardContent>
        </Card>
      {/each}
    </div>
  {/if}

  {#if creating}
    <MirrorProviderEditor
      onClose={() => (creating = false)}
      onSaved={() => {
        creating = false;
        void qc.invalidateQueries({ queryKey: queryKeys.adminMirrorProviders });
      }}
    />
  {/if}
  {#if editing}
    <MirrorProviderEditor
      provider={editing}
      onClose={() => (editing = null)}
      onSaved={() => {
        editing = null;
        void qc.invalidateQueries({ queryKey: queryKeys.adminMirrorProviders });
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
          New keys will no longer be mirrored to this bucket. Existing mirror objects already
          uploaded there are left in place (delete them from the bucket directly if needed).
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
