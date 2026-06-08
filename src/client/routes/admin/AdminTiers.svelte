<script lang="ts">
  import type { z } from 'zod';
  import { Card, CardHeader, CardTitle, CardContent } from '@client/components/ui/card';
  import { Skeleton } from '@client/components/ui/skeleton';
  import AdminLayout from './AdminLayout.svelte';
  import { Button } from '@client/components/ui/button';
  import TierEditor from './TierEditor.svelte';
  import { apiClient } from '../../lib/api';
  import { TierAdmin } from '../../../shared/contracts/admin';
  import { adminTiersQuery, queryKeys } from '../../lib/queries';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';

  const tiers = adminTiersQuery();
  const qc = useQueryClient();

  let editing = $state<z.infer<typeof TierAdmin> | null>(null);

  // Mutation: PATCH a tier. Optimistic updates aren't worth the complexity
  // here: tier edits are infrequent and we'd rather show the authoritative
  // server response (in case the propagation job kicks in async).
  const saveTier = createMutation(() => ({
    mutationFn: (tier: z.infer<typeof TierAdmin>) => {
      const { id, createdAt: _ca, updatedAt: _ua, ...rest } = tier;
      void _ca;
      void _ua;
      return apiClient.patch(`/api/v1/admin/tiers/${id}`, rest, TierAdmin);
    },
    onSuccess: () => {
      editing = null;
      void qc.invalidateQueries({ queryKey: queryKeys.adminTiers });
      toast.success('Tier saved', {
        description: 'Existing users are being updated in the background.',
      });
    },
    onError: (err) => {
      toast.error('Save failed', {
        description: err instanceof Error ? err.message : String(err),
      });
    },
  }));
</script>

<AdminLayout>
  <h1 class="text-2xl font-bold mb-6">Tiers</h1>
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
    <div
      class="rounded-md bg-destructive/10 border border-destructive/40 px-3 py-3 text-sm text-destructive"
    >
      {tiers.error instanceof Error ? tiers.error.message : String(tiers.error)}
    </div>
  {:else}
    <div class="space-y-4">
      {#each tiers.data ?? [] as tier (tier.id)}
        <Card>
          <CardHeader>
            <CardTitle>
              {tier.name}
              <span class="text-sm text-muted-foreground">({tier.slug})</span>
            </CardTitle>
          </CardHeader>
          <CardContent class="space-y-2 text-sm">
            <div>
              Traffic: <strong>{tier.monthlyTrafficGb || 'unlimited'} GB/month</strong> · Devices:
              <strong>{tier.deviceLimit}</strong> · Strategy:
              <strong>{tier.trafficStrategy}</strong>
            </div>
            <Button size="sm" variant="outline" onclick={() => (editing = tier)}>Edit</Button>
          </CardContent>
        </Card>
      {/each}
    </div>
  {/if}
  {#if editing}
    <TierEditor
      tier={editing}
      onCancel={() => (editing = null)}
      onSave={(t) => saveTier.mutate(t)}
    />
  {/if}
</AdminLayout>
