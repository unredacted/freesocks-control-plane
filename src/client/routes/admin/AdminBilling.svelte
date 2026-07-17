<script lang="ts">
  import { z } from 'zod';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { Button } from '@client/components/ui/button';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { Input } from '@client/components/ui/input';
  import AdminLayout from './AdminLayout.svelte';
  import AdminListState from './AdminListState.svelte';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import { adminBillingQuery, adminReferralConfigQuery, queryKeys } from '../../lib/queries';
  import {
    AdminBillingConfigResponse,
    type BillingConfigPatch,
    type BillingConfigView,
    type BillingProcessor,
  } from '../../../shared/contracts/billing';
  import { AdminReferralConfig } from '../../../shared/contracts/admin';
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
    btcpay: { apiKey: '', webhookSecret: '', apiUrl: '', storeId: '' },
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
      secretsDraft.btcpay.apiUrl = s.btcpay.apiUrl;
      secretsDraft.btcpay.storeId = s.btcpay.storeId;
      secretsDraft.paypal.apiBase = s.paypal.apiBase;
      seeded = true;
    }
  });

  // Masked credential status (booleans + non-secret URLs) for the field badges.
  let ss = $derived(billing.data?.secretStatus);

  const RAILS: { key: BillingProcessor; label: string }[] = [
    { key: 'nowpayments', label: 'Crypto (NOWPayments)' },
    { key: 'btcpay', label: 'Bitcoin (BTCPay Server)' },
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

  function addAmount() {
    if (!draft) return;
    draft.donation.suggestedAmountsCents = [...draft.donation.suggestedAmountsCents, 0];
  }
  function removeAmount(i: number) {
    if (!draft) return;
    draft.donation.suggestedAmountsCents = draft.donation.suggestedAmountsCents.filter(
      (_, idx) => idx !== i,
    );
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
        btcpay: {
          apiKey: '',
          webhookSecret: '',
          apiUrl: res.secretStatus.btcpay.apiUrl,
          storeId: res.secretStatus.btcpay.storeId,
        },
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
        btcpay: secretsDraft.btcpay,
        stripe: secretsDraft.stripe,
        paypal: secretsDraft.paypal,
      },
    });
  }

  // Render helper: a "set ✓ / not set" badge for a write-only credential.
  const setBadge = (isSet: boolean) => (isSet ? 'set ✓ - leave blank to keep' : 'not set');

  // --- Referral program (own endpoint; the growth surface lives on this page) ---
  const referralConfig = adminReferralConfigQuery();
  let referralDraft = $state<z.infer<typeof AdminReferralConfig> | null>(null);
  let referralSeeded = false;
  $effect(() => {
    if (!referralSeeded && referralConfig.data) {
      referralDraft = { ...referralConfig.data };
      referralSeeded = true;
    }
  });

  const saveReferrals = createMutation(() => ({
    mutationFn: (body: z.infer<typeof AdminReferralConfig>) =>
      apiClient.patch('/api/v1/admin/referrals/config', body, AdminReferralConfig),
    onSuccess: (res) => {
      referralDraft = { ...res };
      void qc.invalidateQueries({ queryKey: queryKeys.adminReferralConfig });
      void qc.invalidateQueries({ queryKey: queryKeys.config });
      toast.success('Referral settings saved');
    },
    onError: (err) => toast.error('Save failed', { description: apiErrorMessage(err) }),
  }));

  function referralNum(
    field: 'refereeBonusDays' | 'referrerBonusDays' | 'vestingDays' | 'maxRewardsPerMonth',
    e: Event,
  ) {
    if (!referralDraft) return;
    referralDraft[field] = Math.max(
      field === 'vestingDays' ? 0 : 1,
      Math.round(Number((e.currentTarget as HTMLInputElement).value)),
    );
  }

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
    } else if (key === 'btcpay') {
      // The API URL + store id are non-secret; the status returns their values.
      const hasStr = (saved: string | undefined, typed: string) =>
        (saved ?? '').trim().length > 0 || typed.trim().length > 0;
      if (!hasStr(ss?.btcpay.apiUrl, secretsDraft.btcpay.apiUrl)) missing.push('server URL');
      if (!hasStr(ss?.btcpay.storeId, secretsDraft.btcpay.storeId)) missing.push('store ID');
      if (!has(ss?.btcpay.apiKey, secretsDraft.btcpay.apiKey)) missing.push('API key');
      if (!has(ss?.btcpay.webhookSecret, secretsDraft.btcpay.webhookSecret))
        missing.push('webhook secret');
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
      return 'Billing is enabled but no payment rail is ready - members would see a purchase option that cannot complete. Set a rail’s credentials and the public base URL below, then Save.';
    if (states.some((s) => s.enabled && !s.ready))
      return 'An enabled rail is missing credentials - its checkout and webhook return 503 until you set them and Save.';
    return null;
  });
</script>

<AdminLayout>
  <h1 class="mb-2 text-2xl font-bold">Billing</h1>
  <p class="mb-6 text-sm text-muted-foreground">
    Self-service membership purchases. Prices and processor credentials are admin-editable here (no
    deploy) - set a rail's credentials below, or its checkout/webhook returns 503. Turn
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

      <label class="block">
        <span class="mb-1 block text-xs font-medium text-muted-foreground"
          >Bitcoin (BTCPay) minimum term (months)</span
        >
        <Input
          type="number"
          min={1}
          class="min-h-9 w-24"
          value={draft.btcpayMinMonths}
          oninput={(e) =>
            draft &&
            (draft.btcpayMinMonths = Math.max(
              1,
              Math.round(Number((e.currentTarget as HTMLInputElement).value)),
            ))}
        />
        <span class="mt-1 block text-xs text-muted-foreground">
          Shortest term the BTCPay rail offers. Lightning has no floor (keep 1); raise it if you run
          on-chain-only and small payments would be dwarfed by network fees.
        </span>
      </label>

      <!-- Donations: an optional add-on at checkout + a standalone give. Donations
           this month raise every free user's monthly bandwidth cap. -->
      <div class="border-t border-border pt-4">
        <label class="flex items-center gap-2">
          <Checkbox
            checked={draft.donation.enabled}
            onCheckedChange={(v) => draft && (draft.donation.enabled = !!v)}
          />
          <span class="text-sm font-medium">Donations enabled</span>
        </label>
        <p class="mt-1 text-xs text-muted-foreground">
          Members can add a donation to a membership or give on its own. Donations in a calendar
          month raise every free user's monthly bandwidth by the rate below (shared pool), capped,
          then reset next month.
        </p>

        <p class="mb-2 mt-4 text-xs font-medium text-muted-foreground">Suggested amounts</p>
        <div class="space-y-2">
          {#each draft.donation.suggestedAmountsCents as amt, i (i)}
            <div class="flex flex-wrap items-center gap-2">
              <span class="text-xs text-muted-foreground">{draft.currency}</span>
              <Input
                type="number"
                min={0}
                step="0.01"
                class="min-h-9 w-28"
                value={(amt / 100).toFixed(2)}
                oninput={(e) =>
                  draft &&
                  (draft.donation.suggestedAmountsCents[i] = Math.max(
                    0,
                    Math.round(Number((e.currentTarget as HTMLInputElement).value) * 100),
                  ))}
              />
              <Button variant="ghost" size="sm" onclick={() => removeAmount(i)}>Remove</Button>
            </div>
          {/each}
        </div>
        <Button variant="outline" size="sm" class="mt-2" onclick={addAmount}>Add amount</Button>

        <label class="mt-4 block">
          <span class="mb-1 block text-xs font-medium text-muted-foreground"
            >Minimum donation ({draft.currency})</span
          >
          <Input
            type="number"
            min={0}
            step="0.01"
            class="min-h-9 w-28"
            value={(draft.donation.minAmountCents / 100).toFixed(2)}
            oninput={(e) =>
              draft &&
              (draft.donation.minAmountCents = Math.max(
                0,
                Math.round(Number((e.currentTarget as HTMLInputElement).value) * 100),
              ))}
          />
        </label>

        <label class="mt-4 block">
          <span class="mb-1 block text-xs font-medium text-muted-foreground"
            >Bandwidth per {draft.currency} donated (GB)</span
          >
          <Input
            type="number"
            min={0}
            step="0.1"
            class="min-h-9 w-24"
            value={draft.donation.bonusGbPerUsd}
            oninput={(e) =>
              draft &&
              (draft.donation.bonusGbPerUsd = Math.max(
                0,
                Number((e.currentTarget as HTMLInputElement).value),
              ))}
          />
          <span class="mt-1 block text-xs text-muted-foreground">
            Each unit of currency donated adds this many GB to the shared monthly pool every free
            user receives.
          </span>
        </label>

        <label class="mt-4 block">
          <span class="mb-1 block text-xs font-medium text-muted-foreground"
            >Monthly bonus cap (GB)</span
          >
          <Input
            type="number"
            min={0}
            step="1"
            class="min-h-9 w-24"
            value={draft.donation.monthlyBonusCapGb}
            oninput={(e) =>
              draft &&
              (draft.donation.monthlyBonusCapGb = Math.max(
                0,
                Number((e.currentTarget as HTMLInputElement).value),
              ))}
          />
          <span class="mt-1 block text-xs text-muted-foreground">
            Ceiling on the shared monthly bonus regardless of how much is donated (protects node
            capacity).
          </span>
        </label>
      </div>
    </section>

    <!-- Referral program: word-of-mouth growth. Rewards vest only on a
         referee's first PAID conversion (any rail, gift/redemption codes
         included) — farming free accounts is worthless by construction. -->
    <section class="mb-8 space-y-5 rounded-xl border border-border bg-card p-5">
      <div>
        <h2 class="text-base font-semibold">Referral program</h2>
        <p class="mt-1 text-sm text-muted-foreground">
          Members share an invite link; a new account that signs up with it binds to them. On the
          referee's first paid membership, the referee gets bonus days immediately and the
          referrer's bonus vests after a holding period (anti self-referral). Rewards come from the
          membership tier above.
        </p>
      </div>
      {#if referralConfig.isPending || !referralDraft}
        <Skeleton class="h-24 w-full" />
      {:else}
        <label class="flex items-center gap-2">
          <Checkbox
            checked={referralDraft.enabled}
            onCheckedChange={(v) => referralDraft && (referralDraft.enabled = !!v)}
          />
          <span class="text-sm font-medium">Referrals enabled</span>
        </label>
        <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <label class="block">
            <span class="mb-1 block text-xs font-medium text-muted-foreground">
              Referee bonus (days)
            </span>
            <Input
              type="number"
              min={1}
              max={365}
              class="min-h-9 w-24"
              value={referralDraft.refereeBonusDays}
              oninput={(e) => referralNum('refereeBonusDays', e)}
            />
            <span class="mt-1 block text-xs text-muted-foreground">
              Added instantly to the referee's first paid membership.
            </span>
          </label>
          <label class="block">
            <span class="mb-1 block text-xs font-medium text-muted-foreground">
              Referrer bonus (days)
            </span>
            <Input
              type="number"
              min={1}
              max={365}
              class="min-h-9 w-24"
              value={referralDraft.referrerBonusDays}
              oninput={(e) => referralNum('referrerBonusDays', e)}
            />
            <span class="mt-1 block text-xs text-muted-foreground">
              Granted to the referrer once the reward vests.
            </span>
          </label>
          <label class="block">
            <span class="mb-1 block text-xs font-medium text-muted-foreground">
              Vesting period (days)
            </span>
            <Input
              type="number"
              min={0}
              max={365}
              class="min-h-9 w-24"
              value={referralDraft.vestingDays}
              oninput={(e) => referralNum('vestingDays', e)}
            />
            <span class="mt-1 block text-xs text-muted-foreground">
              The referee must still be a member when this elapses. 0 = instant.
            </span>
          </label>
          <label class="block">
            <span class="mb-1 block text-xs font-medium text-muted-foreground">
              Max rewards / month
            </span>
            <Input
              type="number"
              min={1}
              max={1000}
              class="min-h-9 w-24"
              value={referralDraft.maxRewardsPerMonth}
              oninput={(e) => referralNum('maxRewardsPerMonth', e)}
            />
            <span class="mt-1 block text-xs text-muted-foreground">
              Per-referrer cap on rewards vesting per calendar month.
            </span>
          </label>
        </div>
        <div>
          <Button
            size="sm"
            disabled={saveReferrals.isPending}
            onclick={() => referralDraft && saveReferrals.mutate(referralDraft)}
          >
            Save referral settings
          </Button>
        </div>
      {/if}
    </section>

    <!-- Processor credentials: DB-stored (an env var is the fallback). Secret
         fields are WRITE-ONLY - the server never returns them; a blank box is
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
          Stored in the database (an env var is the fallback). Secret fields are write-only - leave
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
        <p class="text-xs font-semibold">Bitcoin (BTCPay Server)</p>
        <label class="block space-y-1">
          <span class="text-xs text-muted-foreground">Server URL (your own BTCPay instance)</span>
          <Input
            class="min-h-9"
            placeholder="https://pay.example.org"
            value={secretsDraft.btcpay.apiUrl}
            oninput={(e) =>
              (secretsDraft.btcpay.apiUrl = (e.currentTarget as HTMLInputElement).value)}
          />
        </label>
        <label class="block space-y-1">
          <span class="text-xs text-muted-foreground">Store ID</span>
          <Input
            class="min-h-9"
            value={secretsDraft.btcpay.storeId}
            oninput={(e) =>
              (secretsDraft.btcpay.storeId = (e.currentTarget as HTMLInputElement).value)}
          />
        </label>
        {@render cred(
          'API key (restricted: invoice create)',
          !!ss?.btcpay.apiKey,
          secretsDraft.btcpay.apiKey,
          (v) => (secretsDraft.btcpay.apiKey = v),
        )}
        {@render cred(
          'Webhook secret',
          !!ss?.btcpay.webhookSecret,
          secretsDraft.btcpay.webhookSecret,
          (v) => (secretsDraft.btcpay.webhookSecret = v),
        )}
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

    <!-- Failed webhook claims: a grant that threw and exhausted the sender's
         redelivery = a paid-but-ungranted order. Loud, above the orders list. -->
    {#if (billing.data?.failedWebhooks?.count ?? 0) > 0}
      <div
        class="mb-6 rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm space-y-2"
      >
        <p class="font-medium text-destructive">
          {billing.data!.failedWebhooks.count} failed webhook grant{billing.data!.failedWebhooks
            .count === 1
            ? ''
            : 's'}
        </p>
        <p class="text-xs text-muted-foreground">
          These events verified but the grant threw. The sender retries for a while; once its
          retries run out the buyer has paid with nothing granted. Check the audit log
          (billing.webhook.grant_failed) and grant manually via the user's page if needed.
        </p>
        <ul class="space-y-1">
          {#each billing.data!.failedWebhooks.recent as w (w.eventId)}
            <li class="flex flex-wrap items-center gap-x-3 text-xs">
              <code class="font-mono text-muted-foreground">{w.eventId}</code>
              <span class="text-muted-foreground">{w.source}</span>
              <span class="tabular-nums text-muted-foreground">{formatDate(w.at)}</span>
            </li>
          {/each}
        </ul>
      </div>
    {/if}

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

    {#if billing.isPending}
      <!-- Each status filter is its own query key; a cold filter switch has no
           cached data yet — show a loading row, not a misleading "No orders". -->
      <div class="space-y-2">
        <Skeleton class="h-10 w-full rounded-lg" />
        <Skeleton class="h-10 w-full rounded-lg" />
      </div>
    {:else if (billing.data?.orders ?? []).length === 0}
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
            {#if o.userHandle}
              <code class="font-mono text-xs text-muted-foreground">{o.userHandle}</code>
            {/if}
            <span class="capitalize">{o.processor}</span>
            <span class="tabular-nums">{formatMoney(o.amountCents, o.currency)}</span>
            {#if o.donationCents > 0}
              <span
                class="rounded bg-primary/10 px-1.5 py-0.5 text-[11px] text-primary tabular-nums"
              >
                +{formatMoney(o.donationCents, o.currency)} donated
              </span>
            {/if}
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
