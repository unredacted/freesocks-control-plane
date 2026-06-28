<script lang="ts">
  import { z } from 'zod';
  import { Card, CardHeader, CardTitle, CardContent } from '@client/components/ui/card';
  import { Skeleton } from '@client/components/ui/skeleton';
  import * as AlertDialog from '@client/components/ui/alert-dialog';
  import AdminLayout from './AdminLayout.svelte';
  import AdminListState from './AdminListState.svelte';
  import { Button } from '@client/components/ui/button';
  import TierEditor from './TierEditor.svelte';
  import Plus from '@lucide/svelte/icons/plus';
  import Copy from '@lucide/svelte/icons/copy';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import { TierAdmin, type TierUpsert } from '../../../shared/contracts/admin';
  import { adminTiersQuery, queryKeys } from '../../lib/queries';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';

  const tiers = adminTiersQuery();
  const qc = useQueryClient();

  let editing = $state<TierAdmin | null>(null);
  let creating = $state(false);
  let cloning = $state<TierUpsert | null>(null);
  let pendingDelete = $state<TierAdmin | null>(null);

  // Duplicate: copy a tier's fields into a fresh create form. The slug must be
  // unique, so suffix it; never inherit the default-free flag (one per backend).
  function cloneDraft(src: TierAdmin): TierUpsert {
    const { id: _id, createdAt: _c, updatedAt: _u, ...rest } = src;
    return { ...rest, slug: `${src.slug}-copy`, name: `${src.name} (copy)`, isDefaultFree: false };
  }

  function invalidate() {
    void qc.invalidateQueries({ queryKey: queryKeys.adminTiers });
    // Tier limits feed the public /api/v1/config (TierComparison reads them).
    void qc.invalidateQueries({ queryKey: queryKeys.config });
  }

  // One mutation for both modes: PATCH an existing row, POST a new one.
  // Optimistic updates aren't worth the complexity here: tier edits are
  // infrequent and we'd rather show the authoritative server response.
  const saveTier = createMutation(() => ({
    mutationFn: ({ id, body }: { id: string | null; body: TierUpsert }) =>
      id
        ? apiClient.patch(`/api/v1/admin/tiers/${id}`, body, TierAdmin)
        : apiClient.post('/api/v1/admin/tiers', body, TierAdmin),
    onSuccess: (_tier, vars) => {
      editing = null;
      creating = false;
      cloning = null;
      invalidate();
      toast.success(vars.id ? 'Tier saved' : 'Tier created', {
        description: vars.id ? 'Existing users are being updated in the background.' : undefined,
      });
    },
    onError: (err) => {
      toast.error('Save failed', { description: apiErrorMessage(err) });
    },
  }));

  const deleteTier = createMutation(() => ({
    mutationFn: (id: string) =>
      apiClient.delete(`/api/v1/admin/tiers/${id}`, z.object({ ok: z.boolean() })),
    onSuccess: () => {
      pendingDelete = null;
      invalidate();
      toast.success('Tier deleted');
    },
    onError: (err) => {
      // Server guards (default-free / users still on it) surface here as
      // friendly tier.in_use messages.
      toast.error('Delete failed', { description: apiErrorMessage(err) });
    },
  }));
</script>

<AdminLayout>
  <div class="flex items-center justify-between mb-6">
    <h1 class="text-2xl font-bold">Tiers</h1>
    <Button onclick={() => (creating = true)}>
      <Plus class="size-4" />
      New tier
    </Button>
  </div>
  {#if tiers.isPending}
    <!-- Skeleton stack: three placeholder cards (free/member/patron typical). -->
    <div class="space-y-4">
      {#each Array(3) as _, i (i)}
        <Card>
          <CardHeader>
            <Skeleton class="h-6 w-40" />
          </CardHeader>
          <CardContent class="space-y-2">
            <Skeleton class="h-4 w-full" />
            <Skeleton class="h-4 w-3/4" />
            <Skeleton class="h-8 w-16" />
          </CardContent>
        </Card>
      {/each}
    </div>
  {:else if tiers.isError}
    <AdminListState error={tiers.error} />
  {:else}
    <div class="space-y-4">
      {#each tiers.data ?? [] as tier (tier.id)}
        <Card>
          <CardHeader>
            <CardTitle class="flex flex-wrap items-center gap-2">
              {tier.name}
              <span class="text-sm text-muted-foreground">({tier.slug})</span>
              {#if tier.isDefaultFree}
                <span class="rounded bg-primary/10 px-1.5 py-0.5 text-[11px] text-primary">
                  default free
                </span>
              {/if}
              {#if !tier.isActive}
                <span class="rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">
                  inactive
                </span>
              {/if}
            </CardTitle>
          </CardHeader>
          <CardContent class="space-y-2 text-sm">
            <div>
              Traffic: <strong>{tier.monthlyTrafficGb || 'unlimited'} GB/month</strong> · Devices:
              <strong>{tier.deviceLimit}</strong> · Strategy:
              <strong>{tier.trafficStrategy}</strong>
            </div>
            <div class="flex gap-2">
              <Button size="sm" variant="outline" onclick={() => (editing = tier)}>Edit</Button>
              <Button size="sm" variant="outline" onclick={() => (cloning = cloneDraft(tier))}>
                <Copy class="size-3.5" />
                Duplicate
              </Button>
              <Button
                size="sm"
                variant="destructive"
                disabled={deleteTier.isPending}
                onclick={() => (pendingDelete = tier)}
              >
                Delete
              </Button>
            </div>
          </CardContent>
        </Card>
      {/each}
    </div>
  {/if}
  {#if editing}
    <TierEditor
      tier={editing}
      allTiers={tiers.data ?? []}
      busy={saveTier.isPending}
      onCancel={() => (editing = null)}
      onSave={(body) => saveTier.mutate({ id: editing!.id, body })}
    />
  {/if}
  {#if creating}
    <TierEditor
      allTiers={tiers.data ?? []}
      busy={saveTier.isPending}
      onCancel={() => (creating = false)}
      onSave={(body) => saveTier.mutate({ id: null, body })}
    />
  {/if}
  {#if cloning}
    <TierEditor
      initial={cloning}
      allTiers={tiers.data ?? []}
      busy={saveTier.isPending}
      onCancel={() => (cloning = null)}
      onSave={(body) => saveTier.mutate({ id: null, body })}
    />
  {/if}

  <AlertDialog.Root
    open={!!pendingDelete}
    onOpenChange={(o) => (o ? null : (pendingDelete = null))}
  >
    <AlertDialog.Content>
      <AlertDialog.Header>
        <AlertDialog.Title>Delete tier "{pendingDelete?.name}"?</AlertDialog.Title>
        <AlertDialog.Description>
          The server refuses if the tier is the default-free tier or still has users on it. This
          cannot be undone.
        </AlertDialog.Description>
      </AlertDialog.Header>
      <AlertDialog.Footer>
        <AlertDialog.Cancel>Cancel</AlertDialog.Cancel>
        <AlertDialog.Action
          onclick={() => pendingDelete && deleteTier.mutate(pendingDelete.id)}
          disabled={deleteTier.isPending}
        >
          {deleteTier.isPending ? 'Deleting…' : 'Delete'}
        </AlertDialog.Action>
      </AlertDialog.Footer>
    </AlertDialog.Content>
  </AlertDialog.Root>
</AdminLayout>
