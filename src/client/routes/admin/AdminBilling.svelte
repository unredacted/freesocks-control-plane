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
    type BillingConfigPatch,
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

  // Write-only credential inputs. Secrets start blank (the server never returns
  // them; a blank box is left unchanged on save). The non-secret URLs are seeded
  // from the masked status so the admin can see + edit the current value.
  let secretsDraft = $state({
    publicBaseUrl: '',
    nowpayments: { apiKey: '', ipnSecret: '', apiUrl: '' },
    stripe: { apiKey: '', webhookSecret: '' },
    paypal: { clientId: '', secret: '', webhookId: '', apiBase: '' },
  });
  let seeded = false;
  $effect(() => {
    if (!seeded && billing.data) {
      draft = JSON.parse(JSON.stringify(billing.data.config));
      const s = billing.data.secretStatus;
      secretsDraft.publicBaseUrl = s.publicBaseUrl;
      secretsDraft.nowpayments.apiUrl = s.nowpayments.apiUrl;
      secretsDraft.paypal.apiBase = s.paypal.apiBase;
      seeded = true;
    }
  });

  // Masked credential status (booleans + non-secret URLs) for the field badges.
  let ss = $derived(billing.data?.secretStatus);

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
    mutationFn: (body: BillingConfigPatch) =>
      apiClient.patch('/api/v1/admin/billing/config', body, AdminBillingConfigResponse),
    onSuccess: (res) => {
      draft = JSON.parse(JSON.stringify(res.config));
      // Clear the write-only secret boxes; keep the non-secret URLs from the new status.
      secretsDraft = {
        publicBaseUrl: res.secretStatus.publicBaseUrl,
        nowpayments: { apiKey: '', ipnSecret: '', apiUrl: res.secretStatus.nowpayments.apiUrl },
        stripe: { apiKey: '', webhookSecret: '' },
        paypal: {
          clientId: '',
          secret: '',
          webhookId: '',
          apiBase: res.secretStatus.paypal.apiBase,
        },
      };
      // Refresh the admin view AND the public config (the member panel reads it).
      void qc.invalidateQueries({ queryKey: ['admin', 'billing'] });
      void qc.invalidateQueries({ queryKey: queryKeys.config });
      toast.success('Billing settings saved');
    },
    onError: (err) => toast.error('Save failed', { description: apiErrorMessage(err) }),
  }));

  // One PATCH carries both the config and the (write-only) credentials.
  function submitAll() {
    if (!draft) return;
    save.mutate({
      ...draft,
      publicBaseUrl: secretsDraft.publicBaseUrl,
      secrets: {
        nowpayments: secretsDraft.nowpayments,
        stripe: secretsDraft.stripe,
        paypal: secretsDraft.paypal,
      },
    });
  }

  // Render helper: a "set ✓ / not set" badge for a write-only credential.
  const setBadge = (isSet: boolean) => (isSet ? 'set ✓ — leave blank to keep' : 'not set');

  const STATUS_TONE: Record<string, string> = {
    paid: 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400',
    pending: 'bg-blue-500/15 text-blue-600 dark:text-blue-400',
    confirming: 'bg-amber-500/15 text-amber-600 dark:text-amber-400',
    failed: 'bg-destructive/15 text-destructive',
    expired: 'bg-muted text-muted-foreground',
  };

  // --- W3-8b: per-rail readiness ---------------------------------------------
  // A rail can actually take payments only when its credentials AND the public
  // base URL are set; a rail toggled on without them returns 503 on its
  // checkout/webhook. A typed-but-unsaved secret counts (it persists in the same
  // PATCH), so the warning clears as the admin fills the form in rather than
  // false-alarming mid-edit.
  function railState(key: BillingProcessor): {
    enabled: boolean;
    ready: boolean;
    missing: string[];
  } {
    const enabled = !!draft?.rails[key];
    const missing: string[] = [];
    const has = (saved: boolean | undefined, typed: string) => !!saved || typed.trim().length > 0;
    if (secretsDraft.publicBaseUrl.trim().length === 0) missing.push('public base URL');
    if (key === 'nowpayments') {
      if (!has(ss?.nowpayments.apiKey, secretsDraft.nowpayments.apiKey)) missing.push('API key');
      if (!has(ss?.nowpayments.ipnSecret, secretsDraft.nowpayments.ipnSecret))
        missing.push('IPN secret');
    } else if (key === 'stripe') {
      if (!has(ss?.stripe.apiKey, secretsDraft.stripe.apiKey)) missing.push('API key');
      if (!has(ss?.stripe.webhookSecret, secretsDraft.stripe.webhookSecret))
        missing.push('webhook secret');
    } else {
      if (!has(ss?.paypal.clientId, secretsDraft.paypal.clientId)) missing.push('client ID');
      if (!has(ss?.paypal.secret, secretsDraft.paypal.secret)) missing.push('secret');
      if (!has(ss?.paypal.webhookId, secretsDraft.paypal.webhookId)) missing.push('webhook ID');
    }
    return { enabled, ready: missing.length === 0, missing };
  }

  let billingReadinessWarning = $derived.by(() => {
    if (!draft) return null;
    const states = RAILS.map((r) => railState(r.key));
    if (draft.enabled && !states.some((s) => s.ready))
      return 'Billing is enabled but no payment rail is ready — members would see a purchase option that cannot complete. Set a rail’s credentials and the public base URL below, then Save.';
    if (states.some((s) => s.enabled && !s.ready))
      return 'An enabled rail is missing credentials — its checkout and webhook return 503 until you set them and Save.';
    return null;
  });
</script>

<AdminLayout>
  <h1 class="mb-2 text-2xl font-bold">Billing</h1>
  <p class="mb-6 text-sm text-muted-foreground">
    Self-service membership purchases. Prices and processor credentials are admin-editable here (no
    deploy) — set a rail's credentials below, or its checkout/webhook returns 503. Turn
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

      {#if billingReadinessWarning}
        <div
          class="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-300"
          role="status"
        >
          <span aria-hidden="true">⚠</span>
          <span>{billingReadinessWarning}</span>
        </div>
      {/if}

      <div>
        <p class="mb-2 text-xs font-medium text-muted-foreground">Payment rails</p>
        <div class="space-y-1.5">
          {#each RAILS as rail (rail.key)}
            {@const rs = railState(rail.key)}
            <label class="flex flex-wrap items-center gap-2">
              <Checkbox
                checked={draft.rails[rail.key]}
                onCheckedChange={(v) => draft && (draft.rails[rail.key] = !!v)}
              />
              <span class="text-sm">{rail.label}</span>
              {#if rs.enabled && rs.ready}
                <span
                  class="rounded bg-emerald-500/15 px-1.5 py-0.5 text-[11px] text-emerald-600 dark:text-emerald-400"
                >
                  ready
                </span>
              {:else if rs.enabled && !rs.ready}
                <span class="rounded bg-destructive/15 px-1.5 py-0.5 text-[11px] text-destructive">
                  enabled · missing {rs.missing.join(', ')}
                </span>
              {:else if rs.ready}
                <span class="rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">
                  configured · off
                </span>
              {:else}
                <span class="rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">
                  not configured
                </span>
              {/if}
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

      <label class="block">
        <span class="mb-1 block text-xs font-medium text-muted-foreground"
          >Crypto minimum term (months)</span
        >
        <Input
          type="number"
          min={1}
          class="min-h-9 w-24"
          value={draft.cryptoMinMonths}
          oninput={(e) =>
            draft &&
            (draft.cryptoMinMonths = Math.max(
              1,
              Math.round(Number((e.currentTarget as HTMLInputElement).value)),
            ))}
        />
        <span class="mt-1 block text-xs text-muted-foreground">
          Shortest term the crypto rail (NOWPayments) offers. Coins like XMR have a per-payment
          minimum that floats with fees, so the cheapest crypto term must clear it; card/PayPal
          aren't affected.
        </span>
      </label>
    </section>

    <!-- Processor credentials: DB-stored (an env var is the fallback). Secret
         fields are WRITE-ONLY — the server never returns them; a blank box is
         left unchanged on save. -->
    {#snippet cred(label: string, isSet: boolean, value: string, onInput: (v: string) => void)}
      <label class="block space-y-1">
        <span class="text-xs text-muted-foreground">
          {label}
          <span class={isSet ? 'text-emerald-600 dark:text-emerald-400' : 'text-muted-foreground'}>
            ({setBadge(isSet)})
          </span>
        </span>
        <Input
          type="password"
          autocomplete="off"
          class="min-h-9"
          {value}
          oninput={(e) => onInput((e.currentTarget as HTMLInputElement).value)}
        />
      </label>
    {/snippet}

    <section class="mb-8 space-y-5 rounded-xl border border-border bg-card p-5">
      <div>
        <h2 class="text-base font-semibold">Processor credentials</h2>
        <p class="text-sm text-muted-foreground">
          Stored in the database (an env var is the fallback). Secret fields are write-only — leave
          a box blank to keep the current value.
        </p>
      </div>

      <label class="block space-y-1">
        <span class="text-xs text-muted-foreground">Public base URL (for IPN/return URLs)</span>
        <Input
          class="min-h-9"
          placeholder="https://beta.freesocks.org"
          value={secretsDraft.publicBaseUrl}
          oninput={(e) =>
            (secretsDraft.publicBaseUrl = (e.currentTarget as HTMLInputElement).value)}
        />
      </label>

      <div class="space-y-2 rounded-lg border border-border/60 p-3">
        <p class="text-xs font-semibold">Crypto (NOWPayments)</p>
        {@render cred(
          'API key',
          !!ss?.nowpayments.apiKey,
          secretsDraft.nowpayments.apiKey,
          (v) => (secretsDraft.nowpayments.apiKey = v),
        )}
        {@render cred(
          'IPN secret',
          !!ss?.nowpayments.ipnSecret,
          secretsDraft.nowpayments.ipnSecret,
          (v) => (secretsDraft.nowpayments.ipnSecret = v),
        )}
        <label class="block space-y-1">
          <span class="text-xs text-muted-foreground">API URL (blank = production default)</span>
          <Input
            class="min-h-9"
            placeholder="https://api.nowpayments.io"
            value={secretsDraft.nowpayments.apiUrl}
            oninput={(e) =>
              (secretsDraft.nowpayments.apiUrl = (e.currentTarget as HTMLInputElement).value)}
          />
        </label>
      </div>

      <div class="space-y-2 rounded-lg border border-border/60 p-3">
        <p class="text-xs font-semibold">Card (Stripe)</p>
        {@render cred(
          'Secret API key',
          !!ss?.stripe.apiKey,
          secretsDraft.stripe.apiKey,
          (v) => (secretsDraft.stripe.apiKey = v),
        )}
        {@render cred(
          'Webhook signing secret',
          !!ss?.stripe.webhookSecret,
          secretsDraft.stripe.webhookSecret,
          (v) => (secretsDraft.stripe.webhookSecret = v),
        )}
      </div>

      <div class="space-y-2 rounded-lg border border-border/60 p-3">
        <p class="text-xs font-semibold">PayPal</p>
        {@render cred(
          'Client ID',
          !!ss?.paypal.clientId,
          secretsDraft.paypal.clientId,
          (v) => (secretsDraft.paypal.clientId = v),
        )}
        {@render cred(
          'Secret',
          !!ss?.paypal.secret,
          secretsDraft.paypal.secret,
          (v) => (secretsDraft.paypal.secret = v),
        )}
        {@render cred(
          'Webhook ID',
          !!ss?.paypal.webhookId,
          secretsDraft.paypal.webhookId,
          (v) => (secretsDraft.paypal.webhookId = v),
        )}
        <label class="block space-y-1">
          <span class="text-xs text-muted-foreground">API base (blank = live default)</span>
          <Input
            class="min-h-9"
            placeholder="https://api-m.paypal.com"
            value={secretsDraft.paypal.apiBase}
            oninput={(e) =>
              (secretsDraft.paypal.apiBase = (e.currentTarget as HTMLInputElement).value)}
          />
        </label>
      </div>
    </section>

    <div class="mb-8 flex justify-end">
      <Button disabled={save.isPending} onclick={submitAll}>
        {save.isPending ? 'Saving…' : 'Save settings'}
      </Button>
    </div>

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
