<script lang="ts">
  import { z } from 'zod';
  import {
    Card,
    CardHeader,
    CardTitle,
    CardDescription,
    CardContent,
  } from '@client/components/ui/card';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import SubscriptionHero from '../components/SubscriptionHero.svelte';
  import MembershipCallout from '../components/MembershipCallout.svelte';
  import RegenerateModal from '../components/RegenerateModal.svelte';
  import SwitchBackendModal from '../components/SwitchBackendModal.svelte';
  import TierComparison from '../components/TierComparison.svelte';
  import MemberImpact from '../components/MemberImpact.svelte';
  import RotateCcw from '@lucide/svelte/icons/rotate-ccw';
  import Plus from '@lucide/svelte/icons/plus';
  import LogOut from '@lucide/svelte/icons/log-out';
  import Smartphone from '@lucide/svelte/icons/smartphone';
  import ArrowLeftRight from '@lucide/svelte/icons/arrow-left-right';
  import { apiClient, ApiCallError } from '../lib/api';
  import { accountQuery, configQuery, queryKeys } from '../lib/queries';
  import { router } from '../stores/router.svelte';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { AccountIdRevealResponse } from '../../shared/contracts/subscription';

  const account = accountQuery();
  const config = configQuery();
  const qc = useQueryClient();

  // Convenience accessor — Svelte's narrowing reads better than account.data
  // sprinkled across the template.
  let data = $derived(account.data);

  let regenerateOpen = $state(false);
  let switchBackendOpen = $state(false);
  // Which backend is the user about to switch TO when they confirm. Computed
  // at button-click time from `oppositeBackend` so the modal can render the
  // right "from X to Y" copy even after the mutation lands and the account
  // query updates `data.subscription.backend` to the new value.
  let pendingSwitchTarget = $state<'remnawave' | 'outline' | null>(null);

  // 401 from /api/v1/account means the cookie session is missing or expired —
  // bounce to the account-number sign-in form (no OIDC anymore).
  $effect(() => {
    const err = account.error;
    if (err instanceof ApiCallError && err.status === 401) {
      router.navigate('/login');
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
      toast.success('New subscription URL generated', {
        description: 'Re-import it on each of your devices. The old URL works for 24 more hours.',
      });
    },
    onError: (err) => {
      const msg = err instanceof ApiCallError ? err.payload.error.message : String(err);
      toast.error('Regenerate failed', { description: msg });
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
          // Nullable — null when there was no live previous subscription
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
      toast.success(`Switched to ${result.tier.name}`, {
        description: result.oldSubscriptionDeletedAt
          ? 'Re-import the new subscription URL on each device. The old subscription works for 24 more hours.'
          : 'Re-import the new subscription URL on each device.',
      });
    },
    onError: (err) => {
      const msg = err instanceof ApiCallError ? err.payload.error.message : String(err);
      toast.error('Switch failed', { description: msg });
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
        toast.success(`Welcome to ${result.tierName}`);
      } else {
        toast.info('No active membership found yet', {
          description: 'If you just paid, give it a moment and try again.',
        });
      }
    },
    onError: (err) => {
      const msg = err instanceof ApiCallError ? err.payload.error.message : String(err);
      toast.error('Refresh failed', { description: msg });
    },
  }));

  async function logout() {
    await apiClient.post('/api/v1/auth/logout', {}, z.object({ ok: z.boolean() }));
    window.location.href = '/';
  }

  // One-time reveal of a freshly rotated account number. Held in volatile state
  // only — never re-fetchable (the server stores just a hash). The old number
  // stops working immediately.
  let revealedAccountId = $state<string | null>(null);
  let rotateConfirmOpen = $state(false);
  let formattedRevealed = $derived(
    revealedAccountId ? revealedAccountId.replace(/(\d{4})(?=\d)/g, '$1 ') : '',
  );
  const rotateAccountId = createMutation(() => ({
    mutationFn: () =>
      apiClient.post('/api/v1/account/account-id/rotate', {}, AccountIdRevealResponse),
    onSuccess: (result) => {
      rotateConfirmOpen = false;
      revealedAccountId = result.accountId;
      toast.success('New account number generated', {
        description:
          'Save it now — the old number no longer works and this is the only time it’s shown.',
      });
    },
    onError: (err) => {
      const msg = err instanceof ApiCallError ? err.payload.error.message : String(err);
      toast.error('Rotate failed', { description: msg });
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
  <div class="max-w-2xl mx-auto py-8">
    <Card>
      <CardHeader>
        <CardTitle>Account</CardTitle>
        <CardDescription class="text-destructive">
          {account.error instanceof ApiCallError
            ? account.error.payload.error.message
            : String(account.error)}
        </CardDescription>
      </CardHeader>
    </Card>
  </div>
{:else if !data}
  <!-- Skeleton placeholder while the initial fetch is in flight. Mirrors the
       three-card layout the loaded state will show, so the page doesn't
       re-flow when data arrives. -->
  <div class="max-w-2xl mx-auto py-8 space-y-6">
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
  <div class="max-w-3xl mx-auto py-8 space-y-8">
    <!-- Welcome strip — slim, not a card. Visual rhythm is set by spacing,
         not by everything being framed. -->
    <header class="flex items-start justify-between gap-4 flex-wrap">
      <div>
        <h1 class="text-3xl font-display font-bold tracking-tight">Welcome</h1>
        <p class="text-sm text-muted-foreground mt-1">
          Tier <strong class="text-foreground">{data.user.tier.name}</strong>
        </p>
      </div>
      <div class="flex items-center gap-1 shrink-0">
        <Button onclick={() => (rotateConfirmOpen = true)} variant="ghost" size="sm">
          <RotateCcw class="size-4" />
          <span class="hidden sm:inline">Rotate number</span>
        </Button>
        <Button onclick={logout} variant="ghost" size="sm">
          <LogOut class="size-4" />
          Sign out
        </Button>
      </div>
    </header>

    <!-- One-time reveal of a freshly rotated account number (volatile state). -->
    {#if revealedAccountId}
      <div class="rounded-xl border-2 border-primary bg-primary/5 p-5 space-y-3">
        <h2 class="text-sm font-semibold uppercase tracking-wider text-primary">
          Your new account number — save it now
        </h2>
        <p
          class="font-mono text-lg md:text-xl tracking-normal tabular-nums select-all break-words leading-relaxed"
        >
          {formattedRevealed}
        </p>
        <p class="text-xs text-muted-foreground">
          This is the only time it's shown, and your old number no longer works. Store it somewhere
          safe — it's the only way to sign in, and it can't be recovered.
        </p>
        <div class="flex gap-2">
          <Button
            size="sm"
            variant="outline"
            onclick={() => {
              if (revealedAccountId) navigator.clipboard?.writeText(revealedAccountId);
              toast.success('Copied');
            }}
          >
            Copy
          </Button>
          <Button size="sm" onclick={() => (revealedAccountId = null)}>I've saved it</Button>
        </div>
      </div>
    {/if}

    <!-- Rotate confirmation. -->
    {#if rotateConfirmOpen}
      <div class="rounded-xl border border-destructive/40 bg-destructive/5 p-5 space-y-3">
        <h2 class="text-sm font-semibold">Rotate your account number?</h2>
        <p class="text-xs text-muted-foreground">
          A new 32-digit number is generated and shown once. Your current number stops working
          immediately — anyone who has it loses access. Do this if your number may have leaked.
        </p>
        <div class="flex gap-2">
          <Button
            size="sm"
            variant="destructive"
            onclick={() => rotateAccountId.mutate()}
            disabled={rotateAccountId.isPending}
          >
            {rotateAccountId.isPending ? 'Rotating…' : 'Yes, rotate'}
          </Button>
          <Button size="sm" variant="ghost" onclick={() => (rotateConfirmOpen = false)}
            >Cancel</Button
          >
        </div>
      </div>
    {/if}

    <!-- Membership-state callouts: only shown when there's something to say. -->
    {#if membershipState === 'no-membership'}
      <!--
        Membership signup is being redesigned around the in-house billing
        portal. Surface the placeholder rather than linking out to a join
        page that isn't ready. The "Already paid? Refresh membership"
        secondary action re-reads the user's local entitlement state.
      -->
      <MembershipCallout
        tone="info"
        title="You're on the free tier"
        body="Higher Unredacted membership tiers — raising device count and monthly bandwidth — are coming soon. In the meantime, donations keep free keys funded."
        ctaUrl="https://unredacted.org/donate"
        ctaLabel="Donate"
      >
        {#snippet secondaryAction()}
          <button
            type="button"
            class="text-xs text-muted-foreground underline hover:text-foreground"
            onclick={() => refreshMembership.mutate()}
            disabled={refreshMembership.isPending}
          >
            {refreshMembership.isPending ? 'Refreshing…' : 'Already paid? Refresh membership'}
          </button>
        {/snippet}
      </MembershipCallout>
    {/if}
    {#if membershipState === 'expiring-soon' && expiresAt && daysUntilExpiry !== null}
      <MembershipCallout
        tone="warn"
        title={`Your membership ends in ${daysUntilExpiry} day${daysUntilExpiry === 1 ? '' : 's'}`}
        body="Renew now to avoid losing access to your tier benefits."
        ctaUrl={config.data?.membersAccountUrl}
        ctaLabel="Renew membership"
      />
    {/if}
    {#if membershipState === 'expired'}
      <MembershipCallout
        tone="error"
        title="Your membership has lapsed"
        body="Your subscription has been moved to the free tier. Renew to restore your previous tier."
        ctaUrl={config.data?.membersAccountUrl}
        ctaLabel="Renew membership"
      />
    {/if}

    <!-- HERO: the subscription is the main thing on this page -->
    {#if data.subscription}
      <SubscriptionHero
        eyebrow="Your access key"
        subscriptionUrl={data.subscription.url}
        fallbackUrl={data.subscription.mirrors[0]?.publicUrl}
        expiresAt={data.subscription.expiresAt}
        trafficLimitBytes={data.subscription.trafficLimitBytes}
        trafficUsedBytes={data.subscription.trafficUsedBytes}
        tierName={data.user.tier.name}
        backend={data.subscription.backend}
      />
    {:else}
      <!-- Empty state when the user has no subscription yet -->
      <div class="rounded-xl border border-dashed border-border p-8 text-center space-y-3">
        <h2 class="text-lg font-semibold">No subscription yet</h2>
        <p class="text-sm text-muted-foreground max-w-sm mx-auto">
          Create your first subscription to get an Xray subscription URL you can use in any
          compatible VPN client.
        </p>
        <Button onclick={() => regenerate.mutate()} disabled={regenerate.isPending} size="lg">
          <Plus class="size-4" />
          {regenerate.isPending ? 'Creating…' : 'Create subscription'}
        </Button>
      </div>
    {/if}

    <!-- Subscription actions, only when there IS a subscription -->
    {#if data.subscription}
      <div class="flex flex-wrap gap-2">
        <Button
          onclick={() => (regenerateOpen = true)}
          disabled={regenerate.isPending || switchBackend.isPending}
          variant="outline"
          size="sm"
        >
          <RotateCcw class="size-4" />
          {regenerate.isPending ? 'Working…' : 'Regenerate URL'}
        </Button>
        {#if canSwitchBackend && oppositeBackend && config.data}
          <Button
            onclick={() => {
              pendingSwitchTarget = oppositeBackend;
              switchBackendOpen = true;
            }}
            disabled={regenerate.isPending || switchBackend.isPending}
            variant="outline"
            size="sm"
          >
            <ArrowLeftRight class="size-4" />
            {switchBackend.isPending
              ? 'Switching…'
              : `Switch to ${config.data.backends.labels[oppositeBackend]}`}
          </Button>
        {/if}
      </div>
    {/if}
    {#if data.subscription && data.subscription.devices.length > 0}
      <section class="space-y-3">
        <div class="flex items-baseline justify-between">
          <h2 class="text-lg font-display font-semibold flex items-center gap-2">
            <Smartphone class="size-4 text-muted-foreground" />
            Connected devices
          </h2>
          <span class="text-xs text-muted-foreground tabular-nums">
            {data.subscription.devices.length} device{data.subscription.devices.length === 1
              ? ''
              : 's'}
          </span>
        </div>
        <ul class="rounded-lg border border-border divide-y divide-border bg-card">
          {#each data.subscription.devices as d (d.hwid)}
            <li class="flex items-center justify-between px-4 py-3">
              <div class="flex items-center gap-3 min-w-0">
                <Smartphone class="size-4 text-muted-foreground shrink-0" />
                <code class="font-mono text-xs truncate">{d.hwid.slice(0, 24)}…</code>
              </div>
              <span class="text-muted-foreground text-xs tabular-nums shrink-0 ml-3">
                {d.lastSeenAt ? `Last seen ${new Date(d.lastSeenAt).toLocaleDateString()}` : '—'}
              </span>
            </li>
          {/each}
        </ul>
      </section>
    {/if}

    <!-- Tier comparison + member-impact section, free-tier members only.
         Honest framing: factual feature comparison, mission transparency.
         No nags, no urgency, just information. -->
    {#if membershipState === 'no-membership'}
      <TierComparison currentTierSlug={data.user.tier.slug} />
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
