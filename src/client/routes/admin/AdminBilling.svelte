<script lang="ts">
  import { Skeleton } from '@client/components/ui/skeleton';
  import { Button } from '@client/components/ui/button';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { Input } from '@client/components/ui/input';
  import AdminLayout from './AdminLayout.svelte';
  import AdminListState from './AdminListState.svelte';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import { adminBillingQuery, queryKeys } from '../../lib/queries';
  import {
    AdminBillingConfigResponse,
    type BillingConfigView,
    type BillingProcessor,
  } from '../../../shared/contracts/billing';
  import { formatDate, formatMoney } from '../../lib/i18n/format';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';

  const qc = useQueryClient();
  let statusFilter = $state('');
  const billing = adminBillingQuery(() => statusFilter);

  // Editable copy of the config, seeded once from the query.
  let draft = $state<BillingConfigView | null>(null);
  $effect(() => {
    if (!draft && billing.data) draft = JSON.parse(JSON.stringify(billing.data.config));
  });

  const RAILS: { key: BillingProcessor; label: string }[] = [
    { key: 'nowpayments', label: 'Crypto (NOWPayments)' },
    { key: 'stripe', label: 'Card (Stripe)' },
    { key: 'paypal', label: 'PayPal' },
  ];
  const STATUS_FILTERS = ['', 'pending', 'confirming', 'paid', 'failed', 'expired'];

  function addDuration() {
    if (!draft) return;
    draft.durations = [...draft.durations, { months: 1, amountCents: 0 }];
  }
  function removeDuration(i: number) {
    if (!draft) return;
    draft.durations = draft.durations.filter((_, idx) => idx !== i);
  }

  const save = createMutation(() => ({
    mutationFn: (body: BillingConfigView) =>
      apiClient.patch('/api/v1/admin/billing/config', body, AdminBillingConfigResponse),
    onSuccess: (res) => {
      draft = JSON.parse(JSON.stringify(res.config));
      // Refresh the admin view AND the public config (the member panel reads it).
      void qc.invalidateQueries({ queryKey: ['admin', 'billing'] });
      void qc.invalidateQueries({ queryKey: queryKeys.config });
      toast.success('Billing config saved');
    },
    onError: (err) => toast.error('Save failed', { description: apiErrorMessage(err) }),
  }));

  const STATUS_TONE: Record<string, string> = {
    paid: 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400',
    pending: 'bg-blue-500/15 text-blue-600 dark:text-blue-400',
    confirming: 'bg-amber-500/15 text-amber-600 dark:text-amber-400',
    failed: 'bg-destructive/15 text-destructive',
    expired: 'bg-muted text-muted-foreground',
  };
</script>

<AdminLayout>
  <h1 class="mb-2 text-2xl font-bold">Billing</h1>
  <p class="mb-6 text-sm text-muted-foreground">
    Self-service membership purchases. Prices are admin-editable here (no deploy). A rail also needs
    its processor secrets set as Convex env vars, or its checkout/webhook returns 503. Turn
    <code class="font-mono">enabled</code> on only once prices are set and a rail is live.
  </p>

  {#if billing.isPending && !draft}
    <Skeleton class="mb-6 h-64 w-full" />
  {:else if billing.isError}
    <AdminListState error={billing.error} onRetry={() => billing.refetch()} />
  {:else if draft}
    <!-- Config editor -->
    <section class="mb-8 space-y-5 rounded-xl border border-border bg-card p-5">
      <label class="flex items-center gap-2">
        <Checkbox checked={draft.enabled} onCheckedChange={(v) => draft && (draft.enabled = !!v)} />
        <span class="text-sm font-medium">Billing enabled (members can purchase)</span>
      </label>

      <div>
        <p class="mb-2 text-xs font-medium text-muted-foreground">Payment rails</p>
        <div class="space-y-1.5">
          {#each RAILS as rail (rail.key)}
            <label class="flex items-center gap-2">
              <Checkbox
                checked={draft.rails[rail.key]}
                onCheckedChange={(v) => draft && (draft.rails[rail.key] = !!v)}
              />
              <span class="text-sm">{rail.label}</span>
            </label>
          {/each}
        </div>
      </div>

      <div class="flex flex-wrap gap-4">
        <label class="flex items-center gap-2">
          <span class="text-xs text-muted-foreground">Currency</span>
          <Input
            class="min-h-9 w-24"
            value={draft.currency}
            oninput={(e) =>
              draft && (draft.currency = (e.currentTarget as HTMLInputElement).value.toUpperCase())}
          />
        </label>
        <label class="flex items-center gap-2">
          <span class="text-xs text-muted-foreground">Membership tier slug</span>
          <Input
            class="min-h-9 w-40"
            value={draft.tierSlug}
            oninput={(e) => draft && (draft.tierSlug = (e.currentTarget as HTMLInputElement).value)}
          />
        </label>
      </div>

      <div>
        <p class="mb-2 text-xs font-medium text-muted-foreground">Durations &amp; prices</p>
        <div class="space-y-2">
          {#each draft.durations as d, i (i)}
            <div class="flex flex-wrap items-center gap-2">
              <label class="flex items-center gap-1">
                <Input
                  type="number"
                  min={1}
                  class="min-h-9 w-20"
                  value={d.months}
                  oninput={(e) =>
                    (d.months = Math.max(
                      1,
                      Math.round(Number((e.currentTarget as HTMLInputElement).value)),
                    ))}
                />
                <span class="text-xs text-muted-foreground">months</span>
              </label>
              <label class="flex items-center gap-1">
                <span class="text-xs text-muted-foreground">{draft.currency}</span>
                <Input
                  type="number"
                  min={0}
                  step="0.01"
                  class="min-h-9 w-28"
                  value={(d.amountCents / 100).toFixed(2)}
                  oninput={(e) =>
                    (d.amountCents = Math.max(
                      0,
                      Math.round(Number((e.currentTarget as HTMLInputElement).value) * 100),
                    ))}
                />
              </label>
              <Button variant="ghost" size="sm" onclick={() => removeDuration(i)}>Remove</Button>
            </div>
          {/each}
        </div>
        <Button variant="outline" size="sm" class="mt-2" onclick={addDuration}>Add duration</Button>
      </div>

      <div class="flex justify-end">
        <Button disabled={save.isPending} onclick={() => draft && save.mutate(draft)}>
          {save.isPending ? 'Saving…' : 'Save config'}
        </Button>
      </div>
    </section>

    <!-- Orders -->
    <div class="mb-3 flex flex-wrap items-center gap-2">
      <h2 class="text-lg font-semibold">Orders</h2>
      <div class="flex flex-wrap gap-1">
        {#each STATUS_FILTERS as s (s)}
          <button
            type="button"
            onclick={() => (statusFilter = s)}
            class="rounded-full px-2.5 py-1 text-xs capitalize transition {statusFilter === s
              ? 'bg-primary text-primary-foreground'
              : 'bg-muted text-muted-foreground hover:text-foreground'}"
          >
            {s || 'all'}
          </button>
        {/each}
      </div>
    </div>

    {#if (billing.data?.orders ?? []).length === 0}
      <AdminListState emptyText="No orders yet." />
    {:else}
      <ul class="divide-y divide-border rounded-lg border border-border bg-card">
        {#each billing.data?.orders ?? [] as o (o.id)}
          <li class="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-3 text-sm">
            <span
              class="rounded px-1.5 py-0.5 text-[11px] font-medium capitalize {STATUS_TONE[
                o.status
              ] ?? 'bg-muted text-muted-foreground'}"
            >
              {o.status}
            </span>
            <code class="font-mono text-xs text-muted-foreground">{o.refPrefix}…</code>
            <span class="capitalize">{o.processor}</span>
            <span class="tabular-nums">{formatMoney(o.amountCents, o.currency)}</span>
            <span class="text-xs text-muted-foreground">{o.durationDays}d</span>
            <span class="ms-auto text-xs text-muted-foreground tabular-nums">
              {o.paidAt ? `paid ${formatDate(o.paidAt)}` : formatDate(o.createdAt)}
            </span>
          </li>
        {/each}
      </ul>
    {/if}
  {/if}
</AdminLayout>
