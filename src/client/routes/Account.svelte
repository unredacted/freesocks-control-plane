<script lang="ts">
  import { z } from 'zod';
  import { Card, CardHeader, CardTitle, CardContent } from '@client/components/ui/card';
  import * as Tabs from '@client/components/ui/tabs';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import SubscriptionHero from '../components/SubscriptionHero.svelte';
  import SectionHead from '../components/SectionHead.svelte';
  import MirrorHelp from '../components/MirrorHelp.svelte';
  import RawConfig from '../components/RawConfig.svelte';
  import InlineError from '../components/InlineError.svelte';
  import GiftCodes from '../components/GiftCodes.svelte';
  import GiftRevealModal from '../components/GiftRevealModal.svelte';
  import PasskeyManager from '../components/PasskeyManager.svelte';
  import ConnectionModeSwitcher from '../components/ConnectionModeSwitcher.svelte';
  import { connectionModePref } from '../lib/connectionModePref.svelte';
  import { resolveEffectiveModeId } from '../lib/connectionMode';
  import MembershipCallout from '../components/MembershipCallout.svelte';
  import RegenerateModal from '../components/RegenerateModal.svelte';
  import RevokeDeviceModal from '../components/RevokeDeviceModal.svelte';
  import SwitchBackendModal from '../components/SwitchBackendModal.svelte';
  import UpgradeMembership from '../components/UpgradeMembership.svelte';
  import MemberImpact from '../components/MemberImpact.svelte';
  import DonateCard from '../components/DonateCard.svelte';
  import Heart from '@lucide/svelte/icons/heart';
  import AccountNumberReveal from '../components/AccountNumberReveal.svelte';
  import RotateAccountIdModal from '../components/RotateAccountIdModal.svelte';
  import ConnectClient from '../components/ConnectClient.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { formatDate } from '../lib/i18n/format';
  import RedeemCode from '../components/RedeemCode.svelte';
  import ReferralsCard from '../components/ReferralsCard.svelte';
  import RotateCcw from '@lucide/svelte/icons/rotate-ccw';
  import LogOut from '@lucide/svelte/icons/log-out';
  import Smartphone from '@lucide/svelte/icons/smartphone';
  import ArrowLeftRight from '@lucide/svelte/icons/arrow-left-right';
  import Loader2 from '@lucide/svelte/icons/loader-2';
  import KeyRound from '@lucide/svelte/icons/key-round';
  import Hash from '@lucide/svelte/icons/hash';
  import Sparkles from '@lucide/svelte/icons/sparkles';
  import Gift from '@lucide/svelte/icons/gift';
  import Share2 from '@lucide/svelte/icons/share-2';
  import ShieldCheck from '@lucide/svelte/icons/shield-check';
  import Copy from '@lucide/svelte/icons/copy';
  import Check from '@lucide/svelte/icons/check';
  import { copyText, subscriptionDisplayUrl } from '../lib/utils';
  import { apiClient, ApiCallError } from '../lib/api';
  import { apiErrorMessage } from '../lib/errors';
  import { clearSessionKey, popUnavailable } from '../lib/pop';
  import { deviceLimitsShown } from '../lib/tiers';
  import LocationPicker from '../components/LocationPicker.svelte';
  import {
    accountQuery,
    accountUsageQuery,
    billingOrderQuery,
    configQuery,
    nodeStatusQuery,
    queryKeys,
  } from '../lib/queries';
  import { router } from '../stores/router.svelte';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { AccountIdRevealResponse } from '../../shared/contracts/subscription';
  import {
    ConnectionModeResponse,
    RefreshMembershipResponse,
    RegenerateResponse,
  } from '../../shared/contracts/account';

  const account = accountQuery();
  const config = configQuery();
  const qc = useQueryClient();

  // Usage trend: eager (fetched whenever there's a subscription) so it renders by
  // default under the traffic stats in the hero. Degrades to null (Outline/outage).
  const usage = accountUsageQuery(() => !!account.data?.subscription);

  // Live node status: polled (30s) while a subscription exists so the badge in
  // the hero stays current. Degrades silently to "unknown" on error.
  const nodeStatus = nodeStatusQuery(() => !!account.data?.subscription);

  // Node-location catalog + the member's pick for the NEXT issued key. Seeded
  // from the stored server-side preference once the account view loads; 'auto'
  // = let the server pick the least-loaded node anywhere.
  let locations = $derived(config.data?.locations ?? []);
  let pickedLocation = $state('auto');
  let locationSeeded = false;
  $effect(() => {
    if (!locationSeeded && account.data) {
      locationSeeded = true;
      pickedLocation = account.data.preferredLocation ?? 'auto';
    }
  });

  // Convenience accessor: Svelte's narrowing reads better than account.data
  // sprinkled across the template.
  let data = $derived(account.data);

  // Connection-mode (transport) catalog from public config. `available` means
  // the mode's placement pool is bound; until at least one is bound (and the
  // member has a key to re-issue) the picker is a local presentation preference
  // only - choosing wouldn't change the issued node, so we skip the server round-trip.
  let connectionModes = $derived(config.data?.connectionModes ?? []);
  let defaultModeId = $derived(
    connectionModes.find((m) => m.isDefault)?.id ?? connectionModes[0]?.id ?? 'evade',
  );
  let profileServerBacked = $derived(
    !!data?.subscription && connectionModes.some((m) => m.available),
  );

  // Delivery emphasis. Server-backed → the member's server-side mode is
  // authoritative (localStorage is just an optimistic bridge); otherwise the
  // local device-only choice wins, then the server's country suggestion, else default.
  let effectiveModeId = $derived(
    resolveEffectiveModeId({
      serverBacked: profileServerBacked,
      connectionModeId: data?.user.connectionModeId,
      pref: connectionModePref(),
      suggested: data?.suggestedModeId,
      fallback: defaultModeId,
    }),
  );

  // The selected mode's delivery behavior (data-driven; replaces `=== 'privacy'`).
  let rawConfigFirst = $derived(
    connectionModes.find((m) => m.id === effectiveModeId)?.deliveryStyle === 'rawConfig',
  );

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
  // keeps refetch-error churn from re-firing the navigation. EXCEPTION: a
  // PoP-broken browser (Workers blocked) fails every signed request under
  // POP_REQUIRED — bouncing to login would loop (login also fails there), so
  // render the distinct browser-support error instead.
  let popBroken = $state(false);
  let redirectedToLogin = false;
  $effect(() => {
    const err = account.error;
    if (!redirectedToLogin && err instanceof ApiCallError && err.status === 401) {
      if (popUnavailable()) {
        popBroken = true;
        return;
      }
      redirectedToLogin = true;
      // Signal WHY they landed on the sign-in form (session gone/expired) so it
      // isn't a silent, anxiety-inducing bounce for a surveillance-wary user.
      router.navigate('/login?expired=1');
    }
  });

  // Post-payment return: the processor sends the member back to
  // /account?order=<ref>. Poll the order until a terminal status; on 'paid',
  // refresh entitlement (account + me) and clear the param. The only polling
  // query in the SPA - crypto 'confirming' can take minutes (refetchInterval).
  let orderRef = $derived(router.searchParams.get('order'));
  const order = billingOrderQuery(() => orderRef);
  let orderPaidHandled = false;

  // --- Tabbed sections (in-page strip, ?tab= synced) ----------------------
  // The page groups into 4 tabs; the active one is reflected into the URL
  // (?tab=) via replaceState - deep-linkable + reload-safe, WITHOUT a router
  // navigation (mirrors AdminUsers' filter URL-sync), so it never disturbs the
  // billing `?order=` param or the router's scroll-restoration state. The old
  // `codes` tab (folded into Membership, now Gifts & referrals) redirects.
  type AccountTab = 'connection' | 'membership' | 'gifts' | 'security';
  const ACCOUNT_TABS: readonly string[] = ['connection', 'membership', 'gifts', 'security'];
  const initialTab = router.searchParams.get('tab');
  let activeTab = $state<AccountTab>(
    initialTab === 'codes'
      ? 'gifts'
      : initialTab && ACCOUNT_TABS.includes(initialTab)
        ? (initialTab as AccountTab)
        : 'connection',
  );
  $effect(() => {
    const url = new URL(window.location.href);
    if (activeTab === 'connection') url.searchParams.delete('tab');
    else url.searchParams.set('tab', activeTab);
    window.history.replaceState(history.state, '', url);
  });
  // Gift purchase: the buyer's OWN membership is untouched - instead the freshly
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

  // First-key create from the no-subscription empty state: persist the picked
  // connection mode BEFORE issuing, so the first key lands in that mode's
  // placement. Without a subscription the switcher above only sets a local
  // pref (serverBacked=false) the server never sees — this closes that gap,
  // mirroring GetAccount's createSubscription. Best-effort: a failure just
  // means the first key issues into the default mode.
  let persistingMode = $state(false);
  async function createFirstSub() {
    persistingMode = true;
    try {
      await apiClient.post(
        '/api/v1/account/connection-mode',
        { modeId: effectiveModeId },
        ConnectionModeResponse,
      );
    } catch {
      // Non-fatal: the first key just issues into the default mode.
    } finally {
      persistingMode = false;
    }
    regenerate.mutate();
  }

  // Mutation: regenerate the subscription. Invalidates ['account'] on success
  // so the SubscriptionHero re-fetches with the new URL automatically. The
  // location pick rides along when the deployment has a choice to make (≥2
  // locations); 'auto' clears the stored preference server-side.
  const regenerate = createMutation(() => ({
    mutationFn: () =>
      apiClient.post(
        '/api/v1/account/regenerate',
        {
          confirm: true,
          ...(locations.length >= 2
            ? { location: pickedLocation === 'auto' ? null : pickedLocation }
            : {}),
        },
        RegenerateResponse,
      ),
    onSuccess: () => {
      regenerateOpen = false;
      void qc.invalidateQueries({ queryKey: queryKeys.account });
      // Keep the usage graph in step with the traffic counter (same cadence).
      void qc.invalidateQueries({ queryKey: queryKeys.accountUsage });
      // The raw-config viewer reads a SEPARATE query key; invalidate it too so it
      // re-fetches the newly-issued config instead of showing the previous one.
      void qc.invalidateQueries({ queryKey: queryKeys.subscriptionContent });
      // The new key may live on a different node/location.
      void qc.invalidateQueries({ queryKey: queryKeys.nodeStatus });
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
      // Keep the usage graph in step with the traffic counter (same cadence).
      void qc.invalidateQueries({ queryKey: queryKeys.accountUsage });
      // P2: the switch moves the user to the peer tier, so the header's `me`
      // tier label is now stale - refresh it too.
      void qc.invalidateQueries({ queryKey: queryKeys.me });
      // Re-fetch the raw-config viewer (separate key) so it shows the new backend's config.
      void qc.invalidateQueries({ queryKey: queryKeys.subscriptionContent });
      // The new key may live on a different node/location.
      void qc.invalidateQueries({ queryKey: queryKeys.nodeStatus });
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
      void qc.invalidateQueries({ queryKey: queryKeys.accountUsage });
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
      apiClient.post('/api/v1/account/refresh-membership', {}, RefreshMembershipResponse),
    onSuccess: (result) => {
      void qc.invalidateQueries({ queryKey: queryKeys.account });
      void qc.invalidateQueries({ queryKey: queryKeys.accountUsage });
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
  // Support ID one-click copy (mirrors the Access Pass copy affordance).
  let supportIdCopied = $state(false);
  async function copySupportId(id: string) {
    if (await copyText(id)) {
      supportIdCopied = true;
      toast.success(t('common.copied'), { duration: 1500 });
      setTimeout(() => {
        supportIdCopied = false;
      }, 1500);
    } else {
      toast.error(t('common.copyFailed'));
    }
  }
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

  // Operational account status - a DIFFERENT axis from the membership
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

  // In-app renew CTA target: point the expiry/lifecycle callouts at the Membership
  // tab when self-service purchase is available, instead of the external donate
  // URL. (Review #4.)
  let billingEnabled = $derived(!!config.data?.billing?.enabled);

  // One-time "your membership expired" banner: Login stashes a flag when the server
  // auto-downgraded a lapsed member; read + clear it once so it shows only on the
  // first /account load after that login. (Review #4.)
  let justLapsed = $state(false);
  $effect(() => {
    try {
      if (sessionStorage.getItem('fs_lapsed_downgrade') === '1') {
        sessionStorage.removeItem('fs_lapsed_downgrade');
        justLapsed = true;
      }
    } catch {
      /* storage disabled - the banner just won't show */
    }
  });

  // Pinned status band: a payment-return callout plus any lifecycle/expiry
  // callouts, grouped into one container. `hasCallout` gates that container so an
  // empty wrapper never adds phantom spacing between sections.
  let showOrderCallout = $derived(!!orderRef && order.data?.status !== 'paid');
  let hasCallout = $derived(
    justLapsed ||
      showOrderCallout ||
      userStatus === 'grace' ||
      userStatus === 'disabled' ||
      membershipState === 'expiring-soon' ||
      membershipState === 'expired',
  );
</script>

{#if account.isError && (!(account.error instanceof ApiCallError && account.error.status === 401) || popBroken)}
  <div class="max-w-4xl mx-auto py-8">
    <Card>
      <CardHeader>
        <CardTitle>{t('account.title')}</CardTitle>
      </CardHeader>
      <CardContent>
        <div class="space-y-2">
          {#if popBroken}
            <InlineError message={t('login.popBroken')} />
          {:else}
            <InlineError message={apiErrorMessage(account.error)} />
          {/if}
          <Button variant="outline" size="sm" onclick={() => account.refetch()}>
            {t('common.retry')}
          </Button>
        </div>
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

    <!-- Always-available overlays (portal out when closed - order-independent). -->
    <!-- One-time reveal of freshly-purchased gift codes (on return from checkout). -->
    <GiftRevealModal bind:open={giftRevealOpen} codes={giftRevealCodes} onAck={ackGiftReveal} />
    <!-- A2: one-time reveal of a freshly rotated account number. Same blocking,
         checkbox-gated modal as the initial issuance - losing the NEW number is
         equally fatal (the old one already stopped working). -->
    {#if revealedAccountId}
      <AccountNumberReveal
        bind:open={revealOpen}
        accountId={revealedAccountId}
        rotated
        onClose={() => {
          revealedAccountId = null;
          // Drop the plaintext from the mutation cache too (its data holds the
          // accountId for up to gcTime after the modal closes).
          rotateAccountId.reset();
          rotateTriggerEl?.focus();
        }}
      />
    {/if}
    <!-- Rotate confirmation: a proper Dialog, consistent with Regenerate/Switch
         (rotating invalidates the only credential - it deserves no less). -->
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
          {#if data.user.donorSince}
            <span
              class="relative inline-flex items-center gap-1 overflow-hidden rounded-full border border-amber-500/40 px-2 py-0.5 text-xs font-medium text-amber-700 ring-1 ring-amber-500/20 dark:text-amber-300"
              title={t('donate.badgeTooltip')}
            >
              <Heart class="size-3" aria-hidden="true" />
              {t('donate.badge')}
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
        <!-- One-time "your membership expired → you're on the free tier now" banner
             after an auto-downgrade at login (Review #4). The renew CTA opens the
             Membership tab in-app. -->
        {#if justLapsed}
          <MembershipCallout
            tone="info"
            title={t('renew.expiredTitle')}
            body={t('renew.lapsedBody')}
            onCta={() => {
              justLapsed = false;
              activeTab = 'membership';
            }}
            ctaLabel={t('renew.renewCta')}
          />
        {/if}
        <!-- Post-payment confirmation (return from the processor's hosted page).
             The webhook - not this redirect - is the source of truth; we just poll. -->
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

        <!-- Operational lifecycle (grace/disabled) - a different axis from the
             membership-entitlement callouts; both can apply. -->
        {#if userStatus === 'grace'}
          <MembershipCallout
            tone="warn"
            title={t('account.graceTitle')}
            body={t('account.graceBody')}
            ctaUrl={config.data?.donateUrl}
            onCta={billingEnabled ? () => (activeTab = 'membership') : undefined}
            ctaLabel={billingEnabled ? t('renew.renewCta') : t('renew.donate')}
          />
        {:else if userStatus === 'disabled'}
          <MembershipCallout
            tone="error"
            title={t('account.disabledTitle')}
            body={t('account.disabledBody')}
            ctaUrl={config.data?.donateUrl}
            onCta={billingEnabled ? () => (activeTab = 'membership') : undefined}
            ctaLabel={billingEnabled ? t('renew.renewCta') : t('renew.donate')}
          />
        {/if}

        <!-- Membership-entitlement expiry. No-membership free users get no callout
             here - they lead with the Membership section below (upsell-first). -->
        {#if membershipState === 'expiring-soon' && expiresAt && daysUntilExpiry !== null}
          <MembershipCallout
            tone="warn"
            title={t('renew.expiringTitle')}
            body={t('renew.body')}
            ctaUrl={config.data?.donateUrl}
            onCta={billingEnabled ? () => (activeTab = 'membership') : undefined}
            ctaLabel={billingEnabled ? t('renew.renewCta') : t('renew.donate')}
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
            onCta={billingEnabled ? () => (activeTab = 'membership') : undefined}
            ctaLabel={billingEnabled ? t('renew.renewCta') : t('renew.donate')}
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

    <!-- Tabbed sections (in-page strip, ?tab= synced). Page-global chrome - the
         header, pinned status band, and confirm modals - stays OUTSIDE the tabs. -->
    <Tabs.Root bind:value={activeTab} class="gap-6">
      <!-- 44px-tall tabs on touch widths (WCAG target size); compact from sm up. -->
      <div class="overflow-x-auto -mx-1 px-1">
        <Tabs.List class="w-full min-w-max sm:w-fit h-12 sm:h-9">
          <Tabs.Trigger value="connection" class="h-11 sm:h-7">
            <KeyRound class="size-4" />{t('account.tab.connection')}
          </Tabs.Trigger>
          <Tabs.Trigger value="membership" class="h-11 sm:h-7">
            <Sparkles class="size-4" />{t('account.tab.membership')}
          </Tabs.Trigger>
          <Tabs.Trigger value="gifts" class="h-11 sm:h-7">
            <Gift class="size-4" />{t('account.tab.gifts')}
          </Tabs.Trigger>
          <Tabs.Trigger value="security" class="h-11 sm:h-7">
            <ShieldCheck class="size-4" />{t('account.tab.security')}
          </Tabs.Trigger>
        </Tabs.List>
      </div>

      <!-- TAB: Your connection - the pass is the focal object. Delivery focus
           first (it shapes presentation), then the pass WITH its key actions,
           setup, trouble-connecting disclosures, and devices. -->
      <Tabs.Content value="connection">
        <section class="space-y-6">
          <SectionHead
            icon={KeyRound}
            title={t('account.section.connection.title')}
            description={t('account.section.connection.desc')}
          />

          <!-- Free members: a flat pointer to the Membership tab. Hidden once
               they have a membership. -->
          {#if membershipState === 'no-membership'}
            <button
              type="button"
              onclick={() => (activeTab = 'membership')}
              class="w-full rounded-lg border border-primary/30 bg-primary/5 px-4 py-3 text-start transition-colors hover:bg-primary/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <span class="flex items-center gap-3">
                <Sparkles class="size-4 shrink-0 text-primary" aria-hidden="true" />
                <span class="min-w-0 flex-1">
                  <span class="block text-sm font-semibold"
                    >{t('account.membershipNudge.title')}</span
                  >
                  <span class="block text-sm text-muted-foreground">
                    {deviceLimitsShown(config.data)
                      ? t('account.membershipNudge.body')
                      : t('account.membershipNudge.bodyNoDevices')}
                  </span>
                </span>
                <span class="shrink-0 text-sm font-medium text-primary"
                  >{t('account.membershipNudge.cta')}</span
                >
              </span>
            </button>
          {/if}

          <!-- Delivery focus: a rawConfig mode promotes the raw E2EE config + warns the
           subscription link is fetched through a CDN; url modes keep the link as the star. -->
          <ConnectionModeSwitcher
            modes={connectionModes}
            selected={effectiveModeId}
            suggested={data.suggestedModeId ?? null}
            serverBacked={profileServerBacked}
            deviceCount={data.subscription?.devices.length ?? 0}
            disabled={actionsDisabled}
          />

          {#if data.subscription}
            {@const subUrl = subscriptionDisplayUrl(
              data.subscription.subToken,
              data.subscription.url,
            )}
            <SubscriptionHero
              backendLabel={config.data?.backends.labels[data.subscription.backend]}
              subscriptionUrl={subUrl}
              expiresAt={data.subscription.expiresAt}
              trafficLimitBytes={data.subscription.trafficLimitBytes}
              trafficUsedBytes={data.subscription.trafficUsedBytes}
              status={data.subscription.status}
              resetStrategy={data.subscription.resetStrategy}
              lastResetAt={data.subscription.lastResetAt}
              tierName={data.user.tier.name}
              backend={data.subscription.backend}
              hideUrl={rawConfigFirst}
              usagePoints={usage.data?.usage?.points}
              usageTotal={usage.data?.usage?.total}
              nodeOnline={nodeStatus.data ? (nodeStatus.data.node?.online ?? null) : undefined}
              nodeLocationLabel={nodeStatus.data?.node?.location?.label ??
                data.subscription.location?.label ??
                null}
              nodeLocationCode={nodeStatus.data?.node?.location?.code ??
                data.subscription.location?.code ??
                null}
              nodeLabel={nodeStatus.data?.node?.label ?? null}
              nodeLoad={nodeStatus.data ? (nodeStatus.data.node?.load ?? null) : undefined}
            >
              {#snippet actions()}
                <!-- Key actions live on the pass: regenerate, and switch backend
                     when eligible. -->
                <div class="flex flex-wrap items-center gap-2">
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
                        : t('account.switchTo', {
                            label: config.data.backends.labels[oppositeBackend],
                          })}
                    </Button>
                  {/if}
                  <p class="w-full text-xs text-muted-foreground">{t('account.keyActionsHint')}</p>
                </div>
              {/snippet}
            </SubscriptionHero>
            {#if rawConfigFirst}
              <!-- rawConfig mode: the raw config IS the deliverable (the CDN-fetched link
               is hidden above). No public mirrors - they'd expose the config to third parties. -->
              <RawConfig prominent />
              <ConnectClient
                backend={data.subscription.backend}
                rawConfigFirst
                deviceLimited={data.user.tier.deviceLimited ?? false}
              />
            {:else}
              <!-- url mode: the subscription link is the star; mirrors next, raw config secondary. -->
              <ConnectClient
                backend={data.subscription.backend}
                subscriptionUrl={subUrl}
                deviceLimited={data.user.tier.deviceLimited ?? false}
              />
              <!-- Always rendered: mirror AVAILABILITY is member-visible state
                   (the component shows a "not available here" note when the
                   deployment has no mirror provider). -->
              <MirrorHelp
                mirrors={data.subscription.mirrors}
                geoCountry={data.geoCountry}
                subscriptionUrl={subUrl}
                available={config.data?.mirrorsEnabled ?? false}
              />
              <RawConfig />
            {/if}

            {#if deviceLimitsShown(config.data) && data.subscription.devices.length > 0}
              <div class="space-y-3 border-t border-border pt-6">
                <div class="flex items-baseline justify-between">
                  <h3 class="text-sm font-semibold flex items-center gap-2">
                    <Smartphone class="size-4 text-muted-foreground" />
                    {t('account.devicesTitle')}
                  </h3>
                  <span class="text-xs text-muted-foreground tabular-nums">
                    {t('common.deviceCount', { count: data.subscription.devices.length })}
                  </span>
                </div>
                <ul class="rounded-lg border border-border divide-y divide-border">
                  {#each data.subscription.devices as d (d.hwid)}
                    {@const label = [d.platform, d.deviceModel].filter(Boolean).join(' · ')}
                    {@const hwidText = d.hwid.length > 24 ? `${d.hwid.slice(0, 24)}…` : d.hwid}
                    <li class="flex items-center justify-between gap-3 px-4 py-3">
                      <div class="flex items-center gap-3 min-w-0">
                        <Smartphone class="size-4 text-muted-foreground shrink-0" />
                        <div class="min-w-0">
                          {#if label}
                            <p class="text-sm font-medium truncate">{label}</p>
                            <code class="font-mono text-xs text-muted-foreground truncate block">
                              {hwidText}
                            </code>
                          {:else}
                            <code class="font-mono text-xs truncate block">{hwidText}</code>
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
            <!-- Empty state when the user has no key yet (the dither disc is
                 the brand-art variant of the empty state). -->
            <EmptyState dither title={t('account.noSubTitle')} body={t('account.noSubBody')}>
              {#if locations.length >= 2}
                <div class="mx-auto max-w-sm text-start">
                  <LocationPicker
                    {locations}
                    bind:value={pickedLocation}
                    disabled={regenerate.isPending || persistingMode || actionsDisabled}
                    id="first-sub-location"
                  />
                </div>
              {/if}
              <Button
                onclick={createFirstSub}
                disabled={regenerate.isPending || persistingMode || actionsDisabled}
                size="lg"
                class="min-h-11"
              >
                <KeyRound class="size-4" />
                {regenerate.isPending || persistingMode
                  ? t('account.creating')
                  : t('account.createSub')}
              </Button>
              {#if regenerate.error}
                <InlineError
                  message={apiErrorMessage(regenerate.error)}
                  class="mx-auto max-w-sm text-start"
                />
              {/if}
            </EmptyState>
          {/if}
        </section>
      </Tabs.Content>

      <!-- TAB: Membership - plan + upgrade/extend + donations. An active
           member sees a compact status + refresh instead of the upsell. Codes,
           gifts, and referrals live on their own tab now. -->
      <Tabs.Content value="membership">
        <section class="space-y-6">
          <SectionHead
            icon={Sparkles}
            title={t('account.section.membership.title')}
            description={t('account.section.membership.desc')}
          />

          {#if membershipState === 'active'}
            <!-- Active member: confirm the state + a refresh, with a collapsed
                 top-up panel below (added time stacks on the current end date,
                 so buying early never wastes days). -->
            <div class="space-y-1">
              <p class="text-sm font-medium">{t('account.memberActiveTitle')}</p>
              {#if data.user.membership?.expiresAt}
                <p class="text-sm text-muted-foreground">
                  {t('account.memberActiveExpiry', {
                    date: formatDate(data.user.membership.expiresAt),
                  })}
                </p>
              {/if}
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
            </div>

            <UpgradeMembership mode="extend" collapsible currentTierSlug={data.user.tier.slug} />
          {:else}
            <!-- Self-service purchase panel (self-gates on billing being enabled).
             'upgrade' for free users, 'extend' for expiring/expired members. The
             panel carries the compact current-vs-membership limits comparison. -->
            <UpgradeMembership
              mode={membershipState === 'no-membership' ? 'upgrade' : 'extend'}
              currentTierSlug={data.user.tier.slug}
            />

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
            {/if}
          {/if}

          <!-- "Have a membership code?" — the day-1 upgrade path, always
               available in every membership state. -->
          <div class="border-t border-border pt-6">
            <RedeemCode flat />
          </div>

          <!-- Donation impact + nonprofit framing (every membership state; shows
               the collective bonus stats/graph + the member's own contribution). -->
          <div class="border-t border-border pt-6">
            <MemberImpact />
          </div>

          <!-- Standalone donation (available in every membership state; self-gates
               on billing + donations being enabled). -->
          <div class="border-t border-border pt-6">
            <DonateCard />
          </div>
        </section>
      </Tabs.Content>

      <!-- TAB: Gifts & referrals - buy codes to share, invite. -->
      <Tabs.Content value="gifts">
        <section class="space-y-6">
          <SectionHead
            icon={Gift}
            title={t('account.section.gifts.title')}
            description={t('account.section.gifts.desc')}
          />

          <!-- GiftCodes self-gates on billing. (Redeem lives on the Membership
               tab — that's where a member looks for their upgrade path.) -->
          <GiftCodes />

          <!-- Referrals (self-gates on the program being enabled): the member's
               share link + invite stats. -->
          <div class="border-t border-border pt-6 space-y-4">
            <SectionHead icon={Share2} title={t('referral.cardTitle')} />
            <ReferralsCard />
          </div>
        </section>
      </Tabs.Content>

      <!-- TAB: Account & security - support ID + account-number rotation + passkeys. -->
      <Tabs.Content value="security">
        <section class="space-y-6">
          <SectionHead
            icon={ShieldCheck}
            title={t('account.section.security.title')}
            description={t('account.section.security.desc')}
          />
          <div class="space-y-6">
            {#if data.user.supportId}
              <div>
                <p class="text-sm font-medium">{t('support.label')}</p>
                <div class="mt-1 flex items-center gap-1.5">
                  <code dir="ltr" class="select-all font-mono text-sm text-foreground"
                    >{data.user.supportId}</code
                  >
                  <Button
                    variant="ghost"
                    size="sm"
                    class="min-h-11 sm:min-h-8 px-2 text-muted-foreground"
                    aria-label={t('support.copyAria')}
                    onclick={() => copySupportId(data.user.supportId!)}
                  >
                    {#if supportIdCopied}
                      <Check class="size-3.5 text-primary" />
                    {:else}
                      <Copy class="size-3.5" />
                    {/if}
                  </Button>
                </div>
                <p class="mt-1 text-xs text-muted-foreground">{t('support.hint')}</p>
                {#if config.data?.site?.supportEmail}
                  <!-- Subject prefills the (non-secret) support ID - never the account number. -->
                  <p class="mt-1 text-xs text-muted-foreground">
                    {t('support.emailUs')}
                    <a
                      class="text-primary underline"
                      href="mailto:{config.data.site.supportEmail}?subject={encodeURIComponent(
                        `FreeSocks support - ID ${data.user.supportId}`,
                      )}"
                    >
                      {config.data.site.supportEmail}
                    </a>
                  </p>
                {/if}
              </div>
            {/if}
            <div
              class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between {data.user
                .supportId
                ? 'border-t border-border pt-6'
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
          <div class="border-t border-border pt-6">
            <PasskeyManager />
          </div>
        </section>
      </Tabs.Content>
    </Tabs.Root>

    <!-- Subscription confirm modals (only when there IS a subscription). -->
    {#if data.subscription}
      <RegenerateModal
        bind:open={regenerateOpen}
        subToken={data.subscription.subToken ?? null}
        shortUuid={data.subscription.shortUuid}
        deviceCount={data.subscription.devices.length}
        {locations}
        bind:location={pickedLocation}
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
