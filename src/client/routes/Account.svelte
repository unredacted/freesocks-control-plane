<script lang="ts">
  import { z } from 'zod';
  import { Card, CardHeader, CardTitle, CardContent } from '@client/components/ui/card';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import SubscriptionHero from '../components/SubscriptionHero.svelte';
  import MirrorHelp from '../components/MirrorHelp.svelte';
  import RawConfig from '../components/RawConfig.svelte';
  import InlineError from '../components/InlineError.svelte';
  import GiftCodes from '../components/GiftCodes.svelte';
  import GiftRevealModal from '../components/GiftRevealModal.svelte';
  import DeliveryPreference from '../components/DeliveryPreference.svelte';
  import SwitchProfileModal from '../components/SwitchProfileModal.svelte';
  import { deliveryPref, setDeliveryPref } from '../lib/deliveryPref.svelte';
  import MembershipCallout from '../components/MembershipCallout.svelte';
  import RegenerateModal from '../components/RegenerateModal.svelte';
  import RevokeDeviceModal from '../components/RevokeDeviceModal.svelte';
  import SwitchBackendModal from '../components/SwitchBackendModal.svelte';
  import TierComparison from '../components/TierComparison.svelte';
  import UpgradeMembership from '../components/UpgradeMembership.svelte';
  import MemberImpact from '../components/MemberImpact.svelte';
  import AccountNumberReveal from '../components/AccountNumberReveal.svelte';
  import RotateAccountIdModal from '../components/RotateAccountIdModal.svelte';
  import SetupGuidance from '../components/SetupGuidance.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { formatDate } from '../lib/i18n/format';
  import RedeemCode from '../components/RedeemCode.svelte';
  import RotateCcw from '@lucide/svelte/icons/rotate-ccw';
  import Plus from '@lucide/svelte/icons/plus';
  import LogOut from '@lucide/svelte/icons/log-out';
  import Smartphone from '@lucide/svelte/icons/smartphone';
  import ArrowLeftRight from '@lucide/svelte/icons/arrow-left-right';
  import Loader2 from '@lucide/svelte/icons/loader-2';
  import KeyRound from '@lucide/svelte/icons/key-round';
  import Hash from '@lucide/svelte/icons/hash';
  import Sparkles from '@lucide/svelte/icons/sparkles';
  import Gift from '@lucide/svelte/icons/gift';
  import ShieldCheck from '@lucide/svelte/icons/shield-check';
  import Gauge from '@lucide/svelte/icons/gauge';
  import Sparkline from '../components/Sparkline.svelte';
  import { formatBytes } from '../lib/utils';
  import { apiClient, ApiCallError } from '../lib/api';
  import { apiErrorMessage } from '../lib/errors';
  import { clearSessionKey } from '../lib/pop';
  import {
    accountQuery,
    accountUsageQuery,
    billingOrderQuery,
    configQuery,
    queryKeys,
  } from '../lib/queries';
  import { router } from '../stores/router.svelte';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { AccountIdRevealResponse } from '../../shared/contracts/subscription';

  const account = accountQuery();
  const config = configQuery();
  const qc = useQueryClient();

  // Usage trend: lazy — only fetched once the member opens the panel, so it never
  // adds a second live backend call to the main account load.
  let usageOpen = $state(false);
  const usage = accountUsageQuery(() => usageOpen);

  // Convenience accessor: Svelte's narrowing reads better than account.data
  // sprinkled across the template.
  let data = $derived(account.data);

  // Connection-profile (transport) catalog from public config. `available` means
  // the profile's Remnawave squad is bound; until at least one is bound (and the
  // member has a key to re-issue) the picker is a local presentation preference
  // only — choosing wouldn't change the issued squad, so we skip the server round-trip.
  let boundProfiles = $derived(config.data?.connectionProfiles ?? []);
  let profileAvailability = $derived({
    evade: boundProfiles.find((p) => p.id === 'evade')?.available ?? false,
    privacy: boundProfiles.find((p) => p.id === 'privacy')?.available ?? false,
  });
  let profileServerBacked = $derived(
    !!data?.subscription && (profileAvailability.evade || profileAvailability.privacy),
  );

  // Delivery emphasis. Server-backed → the member's server-side profile is
  // authoritative (localStorage is just an optimistic bridge); otherwise the
  // local device-only choice wins, then the server's country suggestion, else evade.
  let effectiveDelivery = $derived<'privacy' | 'evade'>(
    profileServerBacked
      ? (data?.user.connectionProfileId ?? deliveryPref() ?? data?.suggestedDelivery ?? 'evade')
      : (deliveryPref() ?? data?.suggestedDelivery ?? 'evade'),
  );

  // Localized profile title for toasts + the confirm dialog. The server's stored
  // label is English-only; the SPA is i18n'd, so copy is keyed off the profile id.
  function profileLabel(id: 'privacy' | 'evade'): string {
    return id === 'privacy' ? t('delivery.privacyTitle') : t('delivery.evadeTitle');
  }

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

  // Connection-profile switch (transport → squad). Mirrors the backend switch:
  // a confirm dialog, then a re-issue with 24h grace. `pendingProfile` also drives
  // the picker optimistically while the mutation + account refetch are in flight.
  let switchProfileOpen = $state(false);
  let pendingProfile = $state<'privacy' | 'evade' | null>(null);

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
  // Gift purchase: the buyer's OWN membership is untouched — instead the freshly
  // minted shareable codes are revealed ONCE here on return, then acknowledged.
  let giftRevealCodes = $state<string[]>([]);
  let giftRevealOpen = $state(false);
  let giftAckRef = '';
  $effect(() => {
    if (orderRef && order.data?.status === 'paid' && !orderPaidHandled) {
      orderPaidHandled = true;
      if (order.data.kind === 'gift') {
        giftAckRef = orderRef;
        giftRevealCodes = order.data.giftCodes ?? [];
        giftRevealOpen = giftRevealCodes.length > 0;
        void qc.invalidateQueries({ queryKey: queryKeys.accountCodes });
      } else {
        void qc.invalidateQueries({ queryKey: queryKeys.account });
        void qc.invalidateQueries({ queryKey: queryKeys.me });
        liveMessage = t('upgrade.paidTitle');
        toast.success(t('upgrade.paidTitle'), { description: t('upgrade.paidBody') });
      }
      router.navigate('/account', { replace: true });
    }
  });
  async function ackGiftReveal() {
    giftRevealOpen = false;
    const ref = giftAckRef;
    giftAckRef = '';
    giftRevealCodes = [];
    if (ref) {
      // Best-effort: clear the server's transient reveal buffer now (the
      // gift-reveal sweep is the backstop if this fails).
      try {
        await apiClient.post(
          '/api/v1/account/gift-codes/ack',
          { orderRef: ref },
          z.object({ ok: z.boolean() }),
        );
      } catch {
        /* ignore */
      }
    }
    void qc.invalidateQueries({ queryKey: queryKeys.accountCodes });
  }

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

  // Mutation: switch the connection profile (transport → Remnawave squad) within
  // the same backend. Re-issues the key into the chosen profile's squad and
  // tombstones the old one with a 24h grace window (same saga as switch-backend).
  const switchProfile = createMutation(() => ({
    mutationFn: () => {
      if (!pendingProfile) throw new Error('No profile selected');
      return apiClient.post(
        '/api/v1/account/switch-profile',
        { profile: pendingProfile, confirm: true },
        z.object({
          subscriptionUrl: z.string(),
          shortUuid: z.string(),
          profile: z.object({ id: z.enum(['evade', 'privacy']), label: z.string() }),
          // Null when there was no live previous subscription to tombstone.
          oldSubscriptionDeletedAt: z.string().nullable(),
        }),
      );
    },
    onSuccess: (result) => {
      switchProfileOpen = false;
      // Keep the local presentation hint in sync so the delivery panels don't
      // flash the old focus before the account query returns the new profile.
      setDeliveryPref(result.profile.id);
      pendingProfile = null;
      void qc.invalidateQueries({ queryKey: queryKeys.account });
      liveMessage = t('delivery.switchSuccessTitle', { label: profileLabel(result.profile.id) });
      toast.success(t('delivery.switchSuccessTitle', { label: profileLabel(result.profile.id) }), {
        description: result.oldSubscriptionDeletedAt
          ? t('delivery.switchSuccessBodyGrace')
          : t('delivery.switchSuccessBody'),
      });
    },
    onError: (err) => {
      pendingProfile = null;
      liveMessage = t('delivery.switchFailedTitle');
      toast.error(t('delivery.switchFailedTitle'), { description: apiErrorMessage(err) });
    },
  }));

  // The delivery picker's choice handler. Server-backed → open the confirm dialog
  // (a real key re-issue); otherwise it's a local device-only presentation toggle.
  function chooseProfile(mode: 'privacy' | 'evade') {
    if (!profileServerBacked) {
      setDeliveryPref(mode);
      return;
    }
    if (mode === effectiveDelivery || switchProfile.isPending || actionsDisabled) return;
    pendingProfile = mode;
    switchProfileOpen = true;
  }

  // Mutation: revoke one HWID device (frees a slot under the tier's device cap
  // without a full regenerate). Confirmation-gated; the server verifies the
  // hwid belongs to this member's key.
  let revokeTargetHwid = $state<string | null>(null);
  let revokeDeviceOpen = $state(false);
  const revokeDevice = createMutation(() => ({
    mutationFn: () => {
      if (!revokeTargetHwid) throw new Error('No device selected');
      return apiClient.post(
        '/api/v1/account/devices/revoke',
        { hwid: revokeTargetHwid },
        z.object({ ok: z.literal(true) }),
      );
    },
    onSuccess: () => {
      revokeDeviceOpen = false;
      revokeTargetHwid = null;
      void qc.invalidateQueries({ queryKey: queryKeys.account });
      liveMessage = t('account.deviceRevokedTitle');
      toast.success(t('account.deviceRevokedTitle'), {
        description: t('account.deviceRevokedBody'),
      });
    },
    onError: (err) => {
      liveMessage = t('account.deviceRevokeFailedTitle');
      toast.error(t('account.deviceRevokeFailedTitle'), { description: apiErrorMessage(err) });
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

  // Pinned status band: a payment-return callout plus any lifecycle/expiry
  // callouts, grouped into one container. `hasCallout` gates that container so an
  // empty wrapper never adds phantom spacing between sections.
  let showOrderCallout = $derived(!!orderRef && order.data?.status !== 'paid');
  let hasCallout = $derived(
    showOrderCallout ||
      userStatus === 'grace' ||
      userStatus === 'disabled' ||
      membershipState === 'expiring-soon' ||
      membershipState === 'expired',
  );
</script>

<!-- Consistent titled-section header (icon + title + one-line description),
     mirroring the admin CMS's section style. Groups the page's framed blocks
     under clear headings instead of one flat stack. -->
{#snippet sectionHead(Icon: typeof KeyRound, title: string, description: string)}
  <div class="space-y-1">
    <h2 class="text-lg font-display font-semibold flex items-center gap-2">
      <Icon class="size-4 text-muted-foreground" aria-hidden="true" />
      {title}
    </h2>
    <p class="text-sm text-muted-foreground">{description}</p>
  </div>
{/snippet}

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
  <div class="max-w-4xl mx-auto py-8 space-y-10">
    <div class="sr-only" role="status" aria-live="polite">{liveMessage}</div>

    <!-- Always-available overlays (portal out when closed — order-independent). -->
    <!-- One-time reveal of freshly-purchased gift codes (on return from checkout). -->
    <GiftRevealModal bind:open={giftRevealOpen} codes={giftRevealCodes} onAck={ackGiftReveal} />
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

    <!-- Welcome strip, slim, not a card. Identity controls (support ID, rotate)
         live in the Account & security section below; this keeps the header to the
         title, plan, lifecycle status, and sign-out. -->
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
              class="rounded-full bg-amber-500/15 px-2 py-0.5 text-xs text-amber-700 dark:text-amber-400"
            >
              {t('account.statusGrace')}
            </span>
          {:else if userStatus === 'disabled'}
            <span class="rounded-full bg-destructive/15 px-2 py-0.5 text-xs text-destructive">
              {t('account.statusDisabled')}
            </span>
          {/if}
        </p>
      </div>
      <Button onclick={logout} variant="ghost" size="sm" class="min-h-11 shrink-0">
        <LogOut class="size-4" />
        {t('account.signOut')}
      </Button>
    </header>

    <!-- PINNED STATUS BAND: payment-return + lifecycle + membership-expiry
         callouts, grouped tightly so they read as one band instead of piling up
         down the page. Rendered above the key because they're time-sensitive. -->
    {#if hasCallout}
      <div class="space-y-3">
        <!-- Post-payment confirmation (return from the processor's hosted page).
             The webhook — not this redirect — is the source of truth; we just poll. -->
        {#if showOrderCallout}
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

        <!-- Operational lifecycle (grace/disabled) — a different axis from the
             membership-entitlement callouts; both can apply. -->
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

        <!-- Membership-entitlement expiry. No-membership free users get no callout
             here — they lead with the Membership section below (upsell-first). -->
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
      </div>
    {/if}

    <!-- SECTION: Your connection — the proxy key is the main thing on this page,
         so it leads. Delivery focus first (it shapes how the key is presented),
         then the key + setup panels, key actions, and connected devices. -->
    <section class="space-y-4">
      {@render sectionHead(
        KeyRound,
        t('account.section.connection.title'),
        t('account.section.connection.desc'),
      )}

      <!-- Delivery focus: privacy promotes the raw E2EE config + warns the
           subscription link is fetched through a CDN; evade keeps the link as the star. -->
      <DeliveryPreference
        selected={pendingProfile ?? effectiveDelivery}
        suggested={data.suggestedDelivery}
        serverBacked={profileServerBacked}
        available={profileAvailability}
        busy={switchProfile.isPending}
        onChoose={chooseProfile}
      />

      {#if data.subscription}
        <SubscriptionHero
          eyebrow={t('hero.eyebrowAccessKey')}
          backendLabel={config.data?.backends.labels[data.subscription.backend]}
          subscriptionUrl={data.subscription.url}
          expiresAt={data.subscription.expiresAt}
          trafficLimitBytes={data.subscription.trafficLimitBytes}
          trafficUsedBytes={data.subscription.trafficUsedBytes}
          status={data.subscription.status}
          resetStrategy={data.subscription.resetStrategy}
          lastResetAt={data.subscription.lastResetAt}
          tierName={data.user.tier.name}
          backend={data.subscription.backend}
          hideUrl={effectiveDelivery === 'privacy'}
        />
        {#if effectiveDelivery === 'privacy'}
          <!-- Privacy: the raw config IS the deliverable (the CDN-fetched link is
               hidden above). No public mirrors — they'd expose the config to third parties. -->
          <RawConfig prominent />
          <SetupGuidance backend={data.subscription.backend} privacy />
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

        <!-- Usage trend: lazy panel. The query is disabled until the member opens
             it, so a live backend usage call never rides on the main account load. -->
        {#if !usageOpen}
          <button
            type="button"
            class="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground"
            onclick={() => (usageOpen = true)}
          >
            <Gauge class="size-4" />
            {t('usage.show')}
          </button>
        {:else}
          <div class="rounded-lg border border-border bg-card p-4 space-y-3">
            <h3 class="text-sm font-semibold flex items-center gap-2">
              <Gauge class="size-4 text-muted-foreground" />
              {t('usage.title')}
            </h3>
            {#if usage.isPending}
              <Skeleton class="h-12 w-full" />
            {:else if usage.isError}
              <p class="text-sm text-muted-foreground">{t('usage.unavailable')}</p>
            {:else if usage.data?.usage && usage.data.usage.points.some((p) => p > 0)}
              {@const u = usage.data.usage}
              <div class="text-primary">
                <Sparkline points={u.points} class="w-full h-12" />
              </div>
              <p class="text-xs text-muted-foreground tabular-nums">
                {t('usage.total', { amount: formatBytes(u.total) })}
              </p>
            {:else}
              <p class="text-sm text-muted-foreground">{t('usage.none')}</p>
            {/if}
          </div>
        {/if}

        <!-- Key actions: regenerate, and switch backend when eligible. -->
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
        <p class="text-xs text-muted-foreground">{t('account.keyActionsHint')}</p>

        {#if data.subscription.devices.length > 0}
          <div class="space-y-3">
            <div class="flex items-baseline justify-between">
              <h3 class="text-sm font-semibold flex items-center gap-2">
                <Smartphone class="size-4 text-muted-foreground" />
                {t('account.devicesTitle')}
              </h3>
              <span class="text-xs text-muted-foreground tabular-nums">
                {t('common.deviceCount', { count: data.subscription.devices.length })}
              </span>
            </div>
            <ul class="rounded-lg border border-border divide-y divide-border bg-card">
              {#each data.subscription.devices as d (d.hwid)}
                {@const label = [d.platform, d.deviceModel].filter(Boolean).join(' · ')}
                <li class="flex items-center justify-between gap-3 px-4 py-3">
                  <div class="flex items-center gap-3 min-w-0">
                    <Smartphone class="size-4 text-muted-foreground shrink-0" />
                    <div class="min-w-0">
                      {#if label}
                        <p class="text-sm font-medium truncate">{label}</p>
                        <code class="font-mono text-xs text-muted-foreground truncate block">
                          {d.hwid.slice(0, 24)}…
                        </code>
                      {:else}
                        <code class="font-mono text-xs truncate block">{d.hwid.slice(0, 24)}…</code>
                      {/if}
                    </div>
                  </div>
                  <div class="flex items-center gap-3 shrink-0">
                    <span class="text-muted-foreground text-xs tabular-nums">
                      {d.lastSeenAt
                        ? t('account.lastSeen', { date: formatDate(d.lastSeenAt) })
                        : '-'}
                    </span>
                    <Button
                      variant="ghost"
                      size="sm"
                      class="min-h-9 text-destructive hover:text-destructive"
                      disabled={revokeDevice.isPending || actionsDisabled}
                      onclick={() => {
                        revokeTargetHwid = d.hwid;
                        revokeDeviceOpen = true;
                      }}
                    >
                      {t('account.deviceRevoke')}
                    </Button>
                  </div>
                </li>
              {/each}
            </ul>
          </div>
        {/if}
      {:else}
        <!-- Empty state when the user has no subscription yet -->
        <div class="rounded-xl border border-dashed border-border p-8 text-center space-y-3">
          <h3 class="text-lg font-semibold">{t('account.noSubTitle')}</h3>
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
    </section>

    <!-- SECTION: Membership — plan + upgrade/extend. Only rendered when there's
         something to act on; an active member has nothing to do here. Free users
         get the comparison + the mission/impact card (upsell-first). -->
    {#if membershipState !== 'active'}
      <section class="space-y-4">
        {@render sectionHead(
          Sparkles,
          t('account.section.membership.title'),
          t('account.section.membership.desc'),
        )}

        {#if membershipState === 'no-membership'}
          <TierComparison currentTierSlug={data.user.tier.slug} />
        {/if}

        <!-- Self-service purchase panel (self-gates on billing being enabled).
             'upgrade' for free users, 'extend' for expiring/expired members. -->
        <UpgradeMembership mode={membershipState === 'no-membership' ? 'upgrade' : 'extend'} />

        {#if membershipState === 'no-membership'}
          <!-- Already-paid recovery: re-read entitlement (e.g. a payment that
               hasn't propagated yet). Slim link rather than a verbose callout. -->
          <p class="text-xs text-muted-foreground">
            <button
              type="button"
              class="rounded-sm underline hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              onclick={() => refreshMembership.mutate()}
              disabled={refreshMembership.isPending}
            >
              {refreshMembership.isPending
                ? t('account.refreshing')
                : t('account.refreshMembership')}
            </button>
          </p>
          <MemberImpact />
        {/if}
      </section>
    {/if}

    <!-- SECTION: Codes & gifts — redeem a membership code, or buy codes to share.
         Redeem is always available; GiftCodes self-gates on billing. -->
    <section class="space-y-4">
      {@render sectionHead(Gift, t('account.section.codes.title'), t('account.section.codes.desc'))}

      <!-- W4: redeem a membership code (extends/upgrades the tier). -->
      <RedeemCode />

      <!-- Buy membership codes to share with friends/family (distinct from the
           self-upgrade; doesn't touch your own membership). Self-gates on billing. -->
      <GiftCodes />
    </section>

    <!-- SECTION: Account & security — support ID + account-number rotation. -->
    <section class="space-y-4">
      {@render sectionHead(
        ShieldCheck,
        t('account.section.security.title'),
        t('account.section.security.desc'),
      )}
      <div class="rounded-xl border border-border bg-card p-4 sm:p-5 space-y-4">
        {#if data.user.supportId}
          <div>
            <p class="text-sm font-medium">{t('support.label')}</p>
            <code class="mt-1 block select-all font-mono text-sm text-foreground"
              >{data.user.supportId}</code
            >
            <p class="mt-1 text-xs text-muted-foreground">{t('support.hint')}</p>
          </div>
        {/if}
        <div
          class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between {data.user
            .supportId
            ? 'border-t border-border/60 pt-4'
            : ''}"
        >
          <p class="text-xs text-muted-foreground sm:max-w-md">{t('account.rotateHint')}</p>
          <Button
            bind:ref={rotateTriggerEl}
            onclick={() => (rotateConfirmOpen = true)}
            variant="outline"
            size="sm"
            class="min-h-11 shrink-0"
          >
            <Hash class="size-4" />
            {t('account.rotate')}
          </Button>
        </div>
      </div>
    </section>

    <!-- Subscription confirm modals (only when there IS a subscription). -->
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
      {#if pendingProfile}
        <SwitchProfileModal
          bind:open={switchProfileOpen}
          targetLabel={profileLabel(pendingProfile)}
          deviceCount={data.subscription.devices.length}
          onCancel={() => {
            switchProfileOpen = false;
            pendingProfile = null;
          }}
          onConfirm={() => switchProfile.mutate()}
          busy={switchProfile.isPending}
        />
      {/if}
      {#if revokeTargetHwid}
        <RevokeDeviceModal
          bind:open={revokeDeviceOpen}
          hwid={revokeTargetHwid}
          onCancel={() => {
            revokeDeviceOpen = false;
            revokeTargetHwid = null;
          }}
          onConfirm={() => revokeDevice.mutate()}
          busy={revokeDevice.isPending}
        />
      {/if}
    {/if}
  </div>
{/if}
