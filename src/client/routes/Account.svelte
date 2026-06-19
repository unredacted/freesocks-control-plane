<script lang="ts">
  import { z } from 'zod';
  import { Card, CardHeader, CardTitle, CardContent } from '@client/components/ui/card';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import SubscriptionHero from '../components/SubscriptionHero.svelte';
  import MirrorHelp from '../components/MirrorHelp.svelte';
  import RawConfig from '../components/RawConfig.svelte';
  import InlineError from '../components/InlineError.svelte';
  import DeliveryPreference from '../components/DeliveryPreference.svelte';
  import { deliveryPref } from '../lib/deliveryPref.svelte';
  import MembershipCallout from '../components/MembershipCallout.svelte';
  import RegenerateModal from '../components/RegenerateModal.svelte';
  import SwitchBackendModal from '../components/SwitchBackendModal.svelte';
  import TierComparison from '../components/TierComparison.svelte';
  import UpgradeMembership from '../components/UpgradeMembership.svelte';
  import MemberImpact from '../components/MemberImpact.svelte';
  import AccountNumberReveal from '../components/AccountNumberReveal.svelte';
  import RotateAccountIdModal from '../components/RotateAccountIdModal.svelte';
  import SetupGuidance from '../components/SetupGuidance.svelte';
  import { t, normalizeDigits } from '../lib/i18n/index.svelte';
  import { formatDate } from '../lib/i18n/format';
  import { RedeemCodeRequest, RedeemCodeResponse } from '../../shared/contracts/membershipCodes';
  import RotateCcw from '@lucide/svelte/icons/rotate-ccw';
  import Plus from '@lucide/svelte/icons/plus';
  import LogOut from '@lucide/svelte/icons/log-out';
  import Smartphone from '@lucide/svelte/icons/smartphone';
  import ArrowLeftRight from '@lucide/svelte/icons/arrow-left-right';
  import Loader2 from '@lucide/svelte/icons/loader-2';
  import { apiClient, ApiCallError } from '../lib/api';
  import { apiErrorMessage } from '../lib/errors';
  import { clearSessionKey } from '../lib/pop';
  import { accountQuery, billingOrderQuery, configQuery, queryKeys } from '../lib/queries';
  import { router } from '../stores/router.svelte';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { AccountIdRevealResponse } from '../../shared/contracts/subscription';

  const account = accountQuery();
  const config = configQuery();
  const qc = useQueryClient();

  // Convenience accessor: Svelte's narrowing reads better than account.data
  // sprinkled across the template.
  let data = $derived(account.data);

  // Delivery emphasis: the member's explicit (client-side) choice wins, else the
  // server's country-based suggestion, else evade. Orders the panels below.
  let effectiveDelivery = $derived(deliveryPref() ?? data?.suggestedDelivery ?? 'evade');

  // a11y: sonner toasts aren't reliably announced; this feeds a visually
  // hidden role="status" region so async outcomes are spoken once. Keep the
  // messages short and NEVER include the account number.
  let liveMessage = $state('');

  let regenerateOpen = $state(false);
  let switchBackendOpen = $state(false);
  // Which backend is the user about to switch TO when they confirm. Computed
  // at button-click time from `oppositeBackend` so the modal can render the
  // right "from X to Y" copy even after the mutation lands and the account
  // query updates `data.subscription.backend` to the new value.
  let pendingSwitchTarget = $state<'remnawave' | 'outline' | null>(null);

  // 401 from /api/v1/account means the cookie session is missing or expired;
  // bounce to the account-number sign-in form (no OIDC anymore). The once-flag
  // keeps refetch-error churn from re-firing the navigation.
  let redirectedToLogin = false;
  $effect(() => {
    const err = account.error;
    if (!redirectedToLogin && err instanceof ApiCallError && err.status === 401) {
      redirectedToLogin = true;
      // Signal WHY they landed on the sign-in form (session gone/expired) so it
      // isn't a silent, anxiety-inducing bounce for a surveillance-wary user.
      router.navigate('/login?expired=1');
    }
  });

  // Post-payment return: the processor sends the member back to
  // /account?order=<ref>. Poll the order until a terminal status; on 'paid',
  // refresh entitlement (account + me) and clear the param. The only polling
  // query in the SPA — crypto 'confirming' can take minutes (refetchInterval).
  let orderRef = $derived(router.searchParams.get('order'));
  const order = billingOrderQuery(() => orderRef);
  let orderPaidHandled = false;
  $effect(() => {
    if (orderRef && order.data?.status === 'paid' && !orderPaidHandled) {
      orderPaidHandled = true;
      void qc.invalidateQueries({ queryKey: queryKeys.account });
      void qc.invalidateQueries({ queryKey: queryKeys.me });
      liveMessage = t('upgrade.paidTitle');
      toast.success(t('upgrade.paidTitle'), { description: t('upgrade.paidBody') });
      router.navigate('/account', { replace: true });
    }
  });

  // Mutation: regenerate the subscription. Invalidates ['account'] on success
  // so the SubscriptionHero re-fetches with the new URL automatically.
  const regenerate = createMutation(() => ({
    mutationFn: () =>
      apiClient.post(
        '/api/v1/account/regenerate',
        { confirm: true },
        z.object({ subscriptionUrl: z.string(), shortUuid: z.string() }),
      ),
    onSuccess: () => {
      regenerateOpen = false;
      void qc.invalidateQueries({ queryKey: queryKeys.account });
      liveMessage = t('account.regenSuccessTitle');
      toast.success(t('account.regenSuccessTitle'), {
        description: t('account.regenSuccessBody'),
      });
    },
    onError: (err) => {
      liveMessage = t('account.regenFailedTitle');
      toast.error(t('account.regenFailedTitle'), { description: apiErrorMessage(err) });
    },
  }));

  // Mutation: switch the subscription to the peer backend. The server picks
  // the matching tier (same membership type, opposite backend) and tombstones
  // the old subscription with a 24h grace window. We invalidate account so
  // the SubscriptionHero re-renders with the new URL + backend badge.
  const switchBackend = createMutation(() => ({
    mutationFn: () => {
      if (!pendingSwitchTarget) throw new Error('No target backend selected');
      return apiClient.post(
        '/api/v1/account/switch-backend',
        { backend: pendingSwitchTarget, confirm: true },
        z.object({
          subscriptionUrl: z.string(),
          shortUuid: z.string(),
          backend: z.enum(['remnawave', 'outline']),
          tier: z.object({
            slug: z.string(),
            name: z.string(),
            monthlyTrafficGb: z.number(),
            deviceLimit: z.number(),
          }),
          // Nullable: null when there was no live previous subscription
          // to tombstone (e.g. a rapid double-switch). Suppress the
          // "24h grace" toast detail in that case rather than telling
          // the user about a window that may not apply.
          oldSubscriptionDeletedAt: z.string().nullable(),
        }),
      );
    },
    onSuccess: (result) => {
      switchBackendOpen = false;
      pendingSwitchTarget = null;
      void qc.invalidateQueries({ queryKey: queryKeys.account });
      // P2: the switch moves the user to the peer tier, so the header's `me`
      // tier label is now stale — refresh it too.
      void qc.invalidateQueries({ queryKey: queryKeys.me });
      liveMessage = t('account.switchSuccessTitle', { tier: result.tier.name });
      toast.success(t('account.switchSuccessTitle', { tier: result.tier.name }), {
        description: result.oldSubscriptionDeletedAt
          ? t('account.switchSuccessBodyGrace')
          : t('account.switchSuccessBody'),
      });
    },
    onError: (err) => {
      liveMessage = t('account.switchFailedTitle');
      toast.error(t('account.switchFailedTitle'), { description: apiErrorMessage(err) });
    },
  }));

  const refreshMembership = createMutation(() => ({
    mutationFn: () =>
      apiClient.post(
        '/api/v1/account/refresh-membership',
        {},
        z.object({
          tierSlug: z.string(),
          tierName: z.string(),
          membershipExpiresAt: z.string().nullable(),
          isCurrent: z.boolean(),
        }),
      ),
    onSuccess: (result) => {
      void qc.invalidateQueries({ queryKey: queryKeys.account });
      void qc.invalidateQueries({ queryKey: queryKeys.me });
      if (result.isCurrent) {
        toast.success(t('account.refreshWelcome', { tier: result.tierName }));
      } else {
        toast.info(t('account.refreshNoneTitle'), {
          description: t('account.refreshNoneBody'),
        });
      }
    },
    onError: (err) => {
      toast.error(t('account.refreshFailedTitle'), { description: apiErrorMessage(err) });
    },
  }));

  async function logout() {
    // P1-11: the local clear + redirect must run even if the network POST fails
    // (offline / backend down), otherwise the user is stuck on a dead session.
    try {
      await apiClient.post('/api/v1/auth/logout', {}, z.object({ ok: z.boolean() }));
    } catch {
      /* best-effort server-side revoke; the cookie clears on redirect regardless */
    } finally {
      await clearSessionKey('member').catch(() => {});
      window.location.href = '/';
    }
  }

  // W4: redeem a membership code.
  let redeemCode = $state('');
  const redeem = createMutation(() => ({
    mutationFn: () =>
      apiClient.post(
        '/api/v1/account/redeem-code',
        RedeemCodeRequest.parse({ code: redeemCode.trim() }),
        RedeemCodeResponse,
      ),
    onSuccess: (result) => {
      redeemCode = '';
      void qc.invalidateQueries({ queryKey: queryKeys.account });
      void qc.invalidateQueries({ queryKey: queryKeys.me });
      liveMessage = t('account.redeemSuccess', {
        tier: result.tierName,
        days: result.durationDays,
      });
      toast.success(
        t('account.redeemSuccess', { tier: result.tierName, days: result.durationDays }),
      );
    },
    onError: () => {
      // Generic, no oracle (matches the server). Don't echo a specific reason.
      liveMessage = t('account.redeemFailed');
      toast.error(t('account.redeemFailed'));
    },
  }));

  // One-time reveal of a freshly rotated account number. Held in volatile state
  // only, never re-fetchable (the server stores just a hash). The old number
  // stops working immediately.
  let revealedAccountId = $state<string | null>(null);
  let revealOpen = $state(false);
  let rotateConfirmOpen = $state(false);
  // a11y: the rotate→reveal two-modal chain leaves bits-ui's FocusScope unable to
  // restore focus (the rotate confirm button it captured has unmounted by the time
  // the reveal closes), so focus falls to <body>. Hold the trigger to refocus it.
  let rotateTriggerEl = $state<HTMLElement | null>(null);
  const rotateAccountId = createMutation(() => ({
    mutationFn: () =>
      apiClient.post('/api/v1/account/account-id/rotate', {}, AccountIdRevealResponse),
    onSuccess: (result) => {
      rotateConfirmOpen = false;
      revealedAccountId = result.accountId;
      revealOpen = true; // A2: same blocking, gated reveal as initial issuance
    },
    onError: (err) => {
      liveMessage = t('account.rotateFailedTitle');
      toast.error(t('account.rotateFailedTitle'), { description: apiErrorMessage(err) });
    },
  }));

  // Compute membership state explicitly so the UI can render the right CTA.
  // States:
  //   - 'no-membership':  signed in, on the free tier (no paid entitlement).
  //   - 'active':         membership current.
  //   - 'expiring-soon':  membership ends within 14 days.
  //   - 'expired':        membership end date in the past.
  let membership = $derived(data?.user.membership ?? null);
  let expiresAt = $derived(membership?.expiresAt ? new Date(membership.expiresAt) : null);
  let daysUntilExpiry = $derived(
    expiresAt ? Math.ceil((expiresAt.getTime() - Date.now()) / 86_400_000) : null,
  );
  let membershipState = $derived<'no-membership' | 'active' | 'expiring-soon' | 'expired'>(
    !membership
      ? 'no-membership'
      : !membership.isCurrent
        ? 'expired'
        : daysUntilExpiry !== null && daysUntilExpiry <= 14
          ? 'expiring-soon'
          : 'active',
  );

  // Operational account status — a DIFFERENT axis from the membership
  // (entitlement) state above. `grace`/`disabled` come from the lifecycle sweep
  // and mean the account itself is winding down; without surfacing it the user
  // would see a normal-looking dashboard while their keys are about to stop.
  let userStatus = $derived(data?.user.status ?? 'active');
  let actionsDisabled = $derived(userStatus === 'disabled');

  // Backend-switch eligibility. The button is visible only when:
  //   - both backends are enabled in app settings (the chooser-enabled
  //     condition; we don't require user-choice-enabled here because backend
  //     switching is a member-side feature distinct from free-tier picking),
  //   - the user has an active subscription,
  //   - both Remnawave and Outline are configured to serve this user's
  //     membership type (server-side: we render the button optimistically and
  //     surface a 409 toast if no peer tier exists).
  let oppositeBackend = $derived<'remnawave' | 'outline' | null>(
    data?.subscription?.backend === 'remnawave'
      ? 'outline'
      : data?.subscription?.backend === 'outline'
        ? 'remnawave'
        : null,
  );
  let canSwitchBackend = $derived(
    !!data?.subscription &&
      !!oppositeBackend &&
      !!config.data?.backends.remnawaveEnabled &&
      !!config.data?.backends.outlineEnabled,
  );
</script>

{#if account.isError && !(account.error instanceof ApiCallError && account.error.status === 401)}
  <div class="max-w-4xl mx-auto py-8">
    <Card>
      <CardHeader>
        <CardTitle>{t('account.title')}</CardTitle>
      </CardHeader>
      <CardContent>
        <InlineError message={apiErrorMessage(account.error)} />
      </CardContent>
    </Card>
  </div>
{:else if !data}
  <!-- Skeleton placeholder while the initial fetch is in flight. Mirrors the
       three-card layout the loaded state will show, so the page doesn't
       re-flow when data arrives. -->
  <div class="max-w-4xl mx-auto py-8 space-y-6">
    <Card>
      <CardHeader class="space-y-2">
        <Skeleton class="h-6 w-48" />
        <Skeleton class="h-4 w-64" />
      </CardHeader>
      <CardContent class="space-y-2">
        <Skeleton class="h-9 w-44" />
      </CardContent>
    </Card>
    <Card>
      <CardHeader class="space-y-2">
        <Skeleton class="h-5 w-40" />
        <Skeleton class="h-3 w-56" />
      </CardHeader>
      <CardContent class="space-y-3">
        <Skeleton class="h-9 w-full" />
        <Skeleton class="h-2 w-full" />
      </CardContent>
    </Card>
  </div>
{:else}
  <div class="max-w-4xl mx-auto py-8 space-y-8">
    <div class="sr-only" role="status" aria-live="polite">{liveMessage}</div>
    <!-- Welcome strip, slim, not a card. Visual rhythm is set by spacing,
         not by everything being framed. -->
    <header class="flex items-start justify-between gap-4 flex-wrap">
      <div>
        <h1 class="text-3xl font-display font-bold tracking-tight">{t('account.title')}</h1>
        <p class="text-sm text-muted-foreground mt-1 flex flex-wrap items-center gap-2">
          <span>
            {t('account.tierLabel')}:
            <strong class="text-foreground">{data.user.tier.name}</strong>
          </span>
          {#if userStatus === 'grace'}
            <span
              class="rounded-full bg-amber-500/15 px-2 py-0.5 text-xs text-amber-600 dark:text-amber-400"
            >
              {t('account.statusGrace')}
            </span>
          {:else if userStatus === 'disabled'}
            <span class="rounded-full bg-destructive/15 px-2 py-0.5 text-xs text-destructive">
              {t('account.statusDisabled')}
            </span>
          {/if}
        </p>
        {#if data.user.supportId}
          <p class="mt-1 text-xs text-muted-foreground">
            {t('support.label')}:
            <code class="select-all font-mono text-foreground">{data.user.supportId}</code>
            <span class="block text-[0.7rem] opacity-80">{t('support.hint')}</span>
          </p>
        {/if}
      </div>
      <div class="flex items-center gap-1 shrink-0">
        <Button
          bind:ref={rotateTriggerEl}
          onclick={() => (rotateConfirmOpen = true)}
          variant="ghost"
          size="sm"
          class="min-h-11"
        >
          <RotateCcw class="size-4" />
          <span class="hidden sm:inline">{t('account.rotate')}</span>
        </Button>
        <Button onclick={logout} variant="ghost" size="sm" class="min-h-11">
          <LogOut class="size-4" />
          {t('account.signOut')}
        </Button>
      </div>
    </header>

    <!-- A2: one-time reveal of a freshly rotated account number. Same blocking,
         checkbox-gated modal as the initial issuance — losing the NEW number is
         equally fatal (the old one already stopped working). -->
    {#if revealedAccountId}
      <AccountNumberReveal
        bind:open={revealOpen}
        accountId={revealedAccountId}
        rotated
        onClose={() => {
          revealedAccountId = null;
          rotateTriggerEl?.focus();
        }}
      />
    {/if}

    <!-- Rotate confirmation: a proper Dialog, consistent with Regenerate/Switch
         (rotating invalidates the only credential — it deserves no less). -->
    <RotateAccountIdModal
      bind:open={rotateConfirmOpen}
      onCancel={() => (rotateConfirmOpen = false)}
      onConfirm={() => rotateAccountId.mutate()}
      busy={rotateAccountId.isPending}
    />

    <!-- Post-payment confirmation (return from the processor's hosted page).
         The webhook — not this redirect — is the source of truth; we just poll. -->
    {#if orderRef && order.data?.status !== 'paid'}
      {#if order.isError || order.data?.status === 'failed' || order.data?.status === 'expired'}
        <MembershipCallout
          tone="error"
          title={t('upgrade.failedTitle')}
          body={t('upgrade.failedBody')}
        >
          {#snippet secondaryAction()}
            <button
              type="button"
              class="rounded-sm text-xs text-muted-foreground underline hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              onclick={() => router.navigate('/account', { replace: true })}
            >
              {t('common.close')}
            </button>
          {/snippet}
        </MembershipCallout>
      {:else}
        <div class="rounded-xl border border-primary/30 bg-primary/5 p-4 sm:p-5">
          <p class="flex items-center gap-2 text-sm font-semibold">
            <Loader2 class="size-4 animate-spin text-primary" aria-hidden="true" />
            {t('upgrade.confirmingTitle')}
          </p>
          <p class="mt-1 text-sm text-muted-foreground">{t('upgrade.confirmingBody')}</p>
        </div>
      {/if}
    {/if}

    <!-- Operational status callouts (lifecycle grace/disabled) — distinct from
         the membership-entitlement callouts below; both can apply. -->
    {#if userStatus === 'grace'}
      <MembershipCallout
        tone="warn"
        title={t('account.graceTitle')}
        body={t('account.graceBody')}
        ctaUrl={config.data?.donateUrl}
        ctaLabel={t('renew.donate')}
      />
    {:else if userStatus === 'disabled'}
      <MembershipCallout
        tone="error"
        title={t('account.disabledTitle')}
        body={t('account.disabledBody')}
        ctaUrl={config.data?.donateUrl}
        ctaLabel={t('renew.donate')}
      />
    {/if}

    <!-- Membership-state callouts: only shown when there's something to say.
         No-membership free users lead with the upgrade panel below (upsell first)
         instead of a clutter callout; the "refresh membership" recovery action
         moves to a slim link under it. -->
    {#if membershipState === 'expiring-soon' && expiresAt && daysUntilExpiry !== null}
      <MembershipCallout
        tone="warn"
        title={t('renew.expiringTitle')}
        body={t('renew.body')}
        ctaUrl={config.data?.donateUrl}
        ctaLabel={t('renew.donate')}
      >
        {#snippet secondaryAction()}
          {#if config.data?.contactUrl}
            <a
              class="text-xs text-muted-foreground underline hover:text-foreground"
              href={config.data.contactUrl}
              target="_blank"
              rel="noopener noreferrer">{t('renew.contact')}</a
            >
          {/if}
        {/snippet}
      </MembershipCallout>
    {/if}
    {#if membershipState === 'expired'}
      <MembershipCallout
        tone="error"
        title={t('renew.expiredTitle')}
        body={t('renew.body')}
        ctaUrl={config.data?.donateUrl}
        ctaLabel={t('renew.donate')}
      >
        {#snippet secondaryAction()}
          {#if config.data?.contactUrl}
            <a
              class="text-xs text-muted-foreground underline hover:text-foreground"
              href={config.data.contactUrl}
              target="_blank"
              rel="noopener noreferrer">{t('renew.contact')}</a
            >
          {/if}
        {/snippet}
      </MembershipCallout>
    {/if}

    <!-- Upsell-first: free users see what each tier includes immediately above
         the purchase panel (bundled together, no scroll-to CTA needed). -->
    {#if membershipState === 'no-membership'}
      <TierComparison currentTierSlug={data.user.tier.slug} />
    {/if}

    <!-- Self-service purchase panel (renders only when billing is enabled).
         Shown for every non-active state; 'upgrade' for free users, 'extend'
         for expiring/expired members. -->
    {#if membershipState !== 'active'}
      <UpgradeMembership mode={membershipState === 'no-membership' ? 'upgrade' : 'extend'} />
    {/if}

    <!-- Already-paid recovery: re-read entitlement state (e.g. a payment that
         hasn't propagated yet). Slim now that the verbose callout is gone. -->
    {#if membershipState === 'no-membership'}
      <p class="text-xs text-muted-foreground">
        <button
          type="button"
          class="rounded-sm underline hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          onclick={() => refreshMembership.mutate()}
          disabled={refreshMembership.isPending}
        >
          {refreshMembership.isPending ? t('account.refreshing') : t('account.refreshMembership')}
        </button>
      </p>
    {/if}

    <!-- W4: redeem a membership code (extends/upgrades the tier). Available to
         any signed-in member; the renew callouts above point here. -->
    <section class="rounded-xl border border-border bg-card p-4 sm:p-5">
      <h2 id="redeem-title" class="text-sm font-semibold">{t('account.redeemTitle')}</h2>
      <div class="mt-3 flex flex-col gap-2 sm:flex-row">
        <input
          id="redeem-code"
          aria-labelledby="redeem-title"
          aria-label={t('account.redeemAriaLabel')}
          inputmode="text"
          autocomplete="off"
          spellcheck="false"
          placeholder={t('account.redeemPlaceholder')}
          value={redeemCode}
          oninput={(e) =>
            (redeemCode = normalizeDigits(
              (e.currentTarget as HTMLInputElement).value,
            ).toUpperCase())}
          onkeydown={(e) => {
            if (e.key === 'Enter' && redeemCode.trim() && !redeem.isPending) redeem.mutate();
          }}
          class="min-h-11 w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm tracking-wider focus:outline-none focus:ring-2 focus:ring-primary"
        />
        <Button
          onclick={() => redeem.mutate()}
          disabled={!redeemCode.trim() || redeem.isPending}
          class="min-h-11 shrink-0"
        >
          {redeem.isPending ? t('common.loading') : t('account.redeemSubmit')}
        </Button>
      </div>
    </section>

    <!-- Delivery focus FIRST — chosen above the key, since it shapes how the key
         below is presented (privacy promotes the raw E2EE config + warns that the
         subscription link is fetched through a CDN; evade keeps the link as the star). -->
    <DeliveryPreference suggested={data.suggestedDelivery} />

    <!-- HERO: the subscription is the main thing on this page -->
    {#if data.subscription}
      <SubscriptionHero
        eyebrow={t('hero.eyebrowAccessKey')}
        backendLabel={config.data?.backends.labels[data.subscription.backend]}
        subscriptionUrl={data.subscription.url}
        expiresAt={data.subscription.expiresAt}
        trafficLimitBytes={data.subscription.trafficLimitBytes}
        trafficUsedBytes={data.subscription.trafficUsedBytes}
        tierName={data.user.tier.name}
        backend={data.subscription.backend}
        hideUrl={effectiveDelivery === 'privacy'}
      />
      {#if effectiveDelivery === 'privacy'}
        <!-- Privacy: the raw config IS the deliverable (the CDN-fetched link is
             hidden above). No public mirrors — they'd expose the config to third parties. -->
        <RawConfig prominent />
        <SetupGuidance backend={data.subscription.backend} />
      {:else}
        <!-- Stay connected: the subscription link is the star; mirrors next, raw config secondary. -->
        <SetupGuidance backend={data.subscription.backend} />
        {#if config.data?.mirrorsEnabled}
          <MirrorHelp
            mirrors={data.subscription.mirrors}
            geoCountry={data.geoCountry}
            subscriptionUrl={data.subscription.url}
          />
        {/if}
        <RawConfig />
      {/if}
    {:else}
      <!-- Empty state when the user has no subscription yet -->
      <div class="rounded-xl border border-dashed border-border p-8 text-center space-y-3">
        <h2 class="text-lg font-semibold">{t('account.noSubTitle')}</h2>
        <p class="text-sm text-muted-foreground max-w-sm mx-auto">
          {t('account.noSubBody')}
        </p>
        <Button
          onclick={() => regenerate.mutate()}
          disabled={regenerate.isPending || actionsDisabled}
          size="lg"
          class="min-h-11"
        >
          <Plus class="size-4" />
          {regenerate.isPending ? t('account.creating') : t('account.createSub')}
        </Button>
        {#if regenerate.error}
          <InlineError
            message={apiErrorMessage(regenerate.error)}
            class="mx-auto max-w-sm text-start"
          />
        {/if}
      </div>
    {/if}

    <!-- Subscription actions, only when there IS a subscription -->
    {#if data.subscription}
      <div class="flex flex-wrap gap-2">
        <Button
          onclick={() => (regenerateOpen = true)}
          disabled={regenerate.isPending || switchBackend.isPending || actionsDisabled}
          variant="outline"
          size="sm"
          class="min-h-11"
        >
          <RotateCcw class="size-4" />
          {regenerate.isPending ? t('common.working') : t('account.regenerate')}
        </Button>
        {#if canSwitchBackend && oppositeBackend && config.data}
          <Button
            onclick={() => {
              pendingSwitchTarget = oppositeBackend;
              switchBackendOpen = true;
            }}
            disabled={regenerate.isPending || switchBackend.isPending || actionsDisabled}
            variant="outline"
            size="sm"
            class="min-h-11"
          >
            <ArrowLeftRight class="size-4" />
            {switchBackend.isPending
              ? t('switch.working')
              : t('account.switchTo', { label: config.data.backends.labels[oppositeBackend] })}
          </Button>
        {/if}
      </div>
    {/if}
    {#if data.subscription && data.subscription.devices.length > 0}
      <section class="space-y-3">
        <div class="flex items-baseline justify-between">
          <h2 class="text-lg font-display font-semibold flex items-center gap-2">
            <Smartphone class="size-4 text-muted-foreground" />
            {t('account.devicesTitle')}
          </h2>
          <span class="text-xs text-muted-foreground tabular-nums">
            {t('common.deviceCount', { count: data.subscription.devices.length })}
          </span>
        </div>
        <ul class="rounded-lg border border-border divide-y divide-border bg-card">
          {#each data.subscription.devices as d (d.hwid)}
            <li class="flex items-center justify-between px-4 py-3">
              <div class="flex items-center gap-3 min-w-0">
                <Smartphone class="size-4 text-muted-foreground shrink-0" />
                <code class="font-mono text-xs truncate">{d.hwid.slice(0, 24)}…</code>
              </div>
              <span class="text-muted-foreground text-xs tabular-nums shrink-0 ms-3">
                {d.lastSeenAt ? t('account.lastSeen', { date: formatDate(d.lastSeenAt) }) : '-'}
              </span>
            </li>
          {/each}
        </ul>
      </section>
    {/if}

    <!-- Member-impact / mission transparency, free-tier members only. The tier
         comparison moved up next to the upgrade panel (upsell-first). -->
    {#if membershipState === 'no-membership'}
      <MemberImpact />
    {/if}
    {#if data.subscription}
      <RegenerateModal
        bind:open={regenerateOpen}
        shortUuid={data.subscription.shortUuid}
        deviceCount={data.subscription.devices.length}
        onCancel={() => (regenerateOpen = false)}
        onConfirm={() => regenerate.mutate()}
        busy={regenerate.isPending}
      />
      {#if pendingSwitchTarget && config.data}
        <SwitchBackendModal
          bind:open={switchBackendOpen}
          targetBackend={pendingSwitchTarget}
          currentBackend={data.subscription.backend}
          labels={config.data.backends.labels}
          deviceCount={data.subscription.devices.length}
          onCancel={() => {
            switchBackendOpen = false;
            pendingSwitchTarget = null;
          }}
          onConfirm={() => switchBackend.mutate()}
          busy={switchBackend.isPending}
        />
      {/if}
    {/if}
  </div>
{/if}
