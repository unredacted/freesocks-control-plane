<script lang="ts">
  import { z } from 'zod';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import CapWidget from '../components/CapWidget.svelte';
  import AccountNumberReveal from '../components/AccountNumberReveal.svelte';
  import PasskeyManager from '../components/PasskeyManager.svelte';
  import { passkeysSupported } from '../lib/memberPasskey';
  import SubscriptionHero from '../components/SubscriptionHero.svelte';
  import MirrorHelp from '../components/MirrorHelp.svelte';
  import RawConfig from '../components/RawConfig.svelte';
  import InlineError from '../components/InlineError.svelte';
  import ConnectionModeSwitcher from '../components/ConnectionModeSwitcher.svelte';
  import { connectionModePref } from '../lib/connectionModePref.svelte';
  import { resolveEffectiveModeId } from '../lib/connectionMode';
  import ConnectClient from '../components/ConnectClient.svelte';
  import RedeemCode from '../components/RedeemCode.svelte';
  import Link from '../components/Link.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import LocationPicker from '../components/LocationPicker.svelte';
  import { readStoredReferralCode, clearStoredReferralCode } from '../lib/referral';
  import {
    meQuery,
    configQuery,
    accountQuery,
    accountUsageQuery,
    nodeStatusQuery,
    queryKeys,
  } from '../lib/queries';
  import { freeTier, deviceLimitsShown } from '../lib/tiers';
  import { apiClient, ApiCallError } from '../lib/api';
  import { apiErrorMessage } from '../lib/errors';
  import { subscriptionDisplayUrl } from '../lib/utils';
  import {
    ConnectionModeResponse,
    CreateAccountRequest,
    CreateAccountResponse,
    RegenerateResponse,
  } from '../../shared/contracts/account';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import SocksIcon from '../components/SocksIcon.svelte';
  import Check from '@lucide/svelte/icons/check';
  import KeyRound from '@lucide/svelte/icons/key-round';

  type CreateAccountPayload = z.infer<typeof CreateAccountResponse>;

  const me = meQuery();
  const config = configQuery();
  const qc = useQueryClient();

  let token = $state<string | null>(null);
  // Instance ref so a failed create remounts the captcha - the server consumes
  // (spends) the Cap token on verify, so a stale token makes every retry fail.
  // (Third-pass audit; see CapWidget.reset().)
  let capWidget = $state<ReturnType<typeof CapWidget>>();
  // Tracked separately from `config.data?.backends.defaultBackend` because the
  // user can pick a non-default; seeded in $effect once config loads.
  let chosenBackend = $state<'remnawave' | 'outline' | null>(null);

  // Set once account creation succeeds. The reveal-once number stays visible in
  // its modal while the user saves it.
  let revealedAccountId = $state<string | null>(null);
  let revealOpen = $state(false);
  // Optional post-signup passkey step (shown after the account-number reveal).
  const passkeySupported = passkeysSupported();
  let showPasskeyPrompt = $state(false);
  let accountTier = $state<CreateAccountPayload['tier'] | null>(null);
  let created = $state(false);
  // Inline gift-code expander in step 3 (pre-issuance, so the upgrade binds at issuance).
  let redeemOpen = $state(false);

  // Referral code: prefilled from the captured ?ref= link (localStorage),
  // editable for a manually-quoted code. Hidden unless the program is enabled.
  let referralsEnabled = $derived(config.data?.referrals?.enabled ?? false);
  let referralInput = $state(readStoredReferralCode());

  // The visitor has an account either because they just made one (created) or
  // they arrived already signed in. Step 3 + the account view key off this.
  let isAuthed = $derived(created || !!me.data?.authenticated);

  // The guided flow position: 1 create account → 2 save your number → 3 get
  // connected. Step 2 covers BOTH the blocking reveal modal and the skippable
  // passkey offer that follows it; a signed-in arrival skips straight to 3.
  let securing = $derived(created && (revealOpen || (showPasskeyPrompt && passkeySupported)));
  let currentStep = $derived<1 | 2 | 3>(!isAuthed ? 1 : securing ? 2 : 3);

  // Subscription source of truth once signed in. Gated on auth so it does not
  // 401 while the visitor is still anonymous on this page.
  const account = accountQuery(() => isAuthed);
  let subscription = $derived(account.data?.subscription ?? null);
  // Usage trend for the step-3 pass (same wiring as /account: 60s stale +
  // refetch, enabled once a key exists; Outline degrades to null → no trend).
  const usage = accountUsageQuery(() => isAuthed && !!subscription);
  // Live node status for the step-3 pass badge (same wiring as /account).
  const nodeStatus = nodeStatusQuery(() => isAuthed && !!subscription);
  // Node-location catalog + the visitor's pick for the first key ('auto' = the
  // server picks the least-loaded node anywhere). Picker renders only with ≥2.
  let locations = $derived(config.data?.locations ?? []);
  let pickedLocation = $state('auto');
  // Connection-mode catalog + emphasis (client choice → country suggestion →
  // catalog default); orders the panels. `rawConfigFirst` is data-driven off the
  // selected mode's deliveryStyle (replaces the hardcoded `=== 'privacy'`).
  let connectionModes = $derived(config.data?.connectionModes ?? []);
  let defaultModeId = $derived(
    connectionModes.find((m) => m.isDefault)?.id ?? connectionModes[0]?.id ?? 'evade',
  );
  // Server-backed once a key exists AND a placement pool is bound - then the
  // mode switcher re-issues (like /account) instead of only setting a local pref.
  let profileServerBacked = $derived(!!subscription && connectionModes.some((m) => m.available));
  // Server-backed → the persisted mode is authoritative (local pref is just an
  // optimistic bridge); otherwise the local choice wins, then the suggestion, else default.
  let effectiveModeId = $derived(
    resolveEffectiveModeId({
      serverBacked: profileServerBacked,
      connectionModeId: account.data?.user.connectionModeId,
      pref: connectionModePref(),
      suggested: account.data?.suggestedModeId,
      fallback: defaultModeId,
    }),
  );
  let actionsDisabled = $derived(account.data?.user.status === 'disabled');
  let rawConfigFirst = $derived(
    connectionModes.find((m) => m.id === effectiveModeId)?.deliveryStyle === 'rawConfig',
  );
  // Hide the gift-code redeem once they're a member.
  let isCurrentMember = $derived(account.data?.user.membership?.isCurrent ?? false);

  // Self-hosted Cap captcha config from /api/v1/config (same-origin endpoint).
  let captchaEndpoint = $derived(config.data?.captcha.apiEndpoint ?? '/cap');
  let captchaSiteKey = $derived(config.data?.captcha.siteKey ?? '');

  // Free-tier note: validity + device limit straight from the DB (the
  // `freetier.expiryDays` setting + the free tier's deviceLimit), so the copy
  // never drifts from what the server actually enforces.
  let freeDays = $derived(config.data?.freeTierDays ?? 90);
  let freeDevicesLabel = $derived.by(() => {
    const ft = freeTier(config.data);
    if (!ft) return t('common.deviceCount', { count: 1 });
    return ft.deviceLimit === 0
      ? t('hero.unlimited')
      : t('common.deviceCount', { count: ft.deviceLimit });
  });

  // Chooser is visible only when BOTH backends are enabled AND the admin has
  // turned on user-choice. It selects which default-free tier (backend) the new
  // account lands on; it never depends on a proxy server being available.
  let showChooser = $derived(
    !!config.data &&
      config.data.backends.remnawaveEnabled &&
      config.data.backends.outlineEnabled &&
      config.data.backends.userChoiceEnabled,
  );

  $effect(() => {
    if (chosenBackend === null && config.data) {
      chosenBackend = config.data.backends.defaultBackend;
    }
  });

  // Reduced-motion-aware scroll helper (same pattern as Home).
  function scrollToId(id: string) {
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    document.getElementById(id)?.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth' });
  }

  // Step transitions: bring the active panel into view. The 1→2 transition is
  // the blocking reveal modal (no scroll needed); 2→3 reveals the key panel.
  let lastStep = 0;
  $effect(() => {
    const s = currentStep;
    if (lastStep === 2 && s === 3 && !subscription) scrollToId('step-3');
    lastStep = s;
  });

  // After issuance, scroll the freshly-rendered pass into view once the account
  // query lands and it mounts (the flag is set in the mutation's onSuccess).
  let scrollToKeyPending = false;
  $effect(() => {
    if (scrollToKeyPending && subscription) {
      scrollToKeyPending = false;
      scrollToId('get-key');
    }
  });

  // WAI-ARIA radiogroup roving focus: arrows move + select between the two
  // options, then focus the newly-checked radio. Lives on the focusable radios.
  function chooserKeydown(e: KeyboardEvent) {
    if (!['ArrowRight', 'ArrowDown', 'ArrowLeft', 'ArrowUp'].includes(e.key)) return;
    e.preventDefault();
    chosenBackend = chosenBackend === 'remnawave' ? 'outline' : 'remnawave';
    (e.currentTarget as HTMLElement).parentElement
      ?.querySelector<HTMLElement>('[aria-checked="true"]')
      ?.focus();
  }

  // Step 1: create the account. No proxy backend is touched, so this succeeds
  // even when every backend is down/empty. On success the server sets the
  // session cookie (auto sign-in) and reveals the one-time account number.
  const createAccount = createMutation(() => ({
    mutationFn: async () => {
      const referralCode = referralInput.trim();
      const body =
        showChooser && chosenBackend
          ? CreateAccountRequest.parse({
              captchaToken: token!,
              backend: chosenBackend,
              ...(referralCode ? { referralCode } : {}),
            })
          : CreateAccountRequest.parse({
              captchaToken: token!,
              ...(referralCode ? { referralCode } : {}),
            });
      return apiClient.post('/api/v1/account', body, CreateAccountResponse);
    },
    onSuccess: (data) => {
      revealedAccountId = data.accountId;
      revealOpen = true; // A2: blocking, verification-gated reveal modal
      accountTier = data.tier;
      created = true;
      showPasskeyPrompt = true; // offer a passkey once they've saved the number
      if (data.referralApplied) {
        clearStoredReferralCode();
        toast.success(t('referral.applied'), { duration: 4000 });
      }
      // Cookie is set; reflect the new authenticated identity everywhere.
      void qc.invalidateQueries({ queryKey: queryKeys.me });
    },
    // Failures render inline next to the CTA (see the destructive box below); no
    // duplicate toast - one error surface per failure. onError only remounts the
    // captcha: the verify consumed the token, so without a fresh challenge every
    // retry would fail with a stale-captcha error.
    onError: () => {
      token = null;
      capWidget?.reset();
    },
  }));

  // Step 3: provision the proxy key. Separate request from step 1, so a backend
  // outage here leaves the account intact and is shown as a retryable notice.
  // Reuses the member regenerate endpoint (create-or-replace).
  const createSubscription = createMutation(() => ({
    mutationFn: async () => {
      // Persist the chosen mode to the account (best-effort) BEFORE issuing the
      // first key, so it lands in that mode's placement. No key exists yet, so this
      // is a plain set (no re-issue); a keyed member switches via /switch-mode.
      try {
        await apiClient.post(
          '/api/v1/account/connection-mode',
          { modeId: effectiveModeId },
          ConnectionModeResponse,
        );
      } catch {
        // Non-fatal: the first key just issues into the default mode.
      }
      return apiClient.post(
        '/api/v1/account/regenerate',
        {
          confirm: true,
          ...(locations.length >= 2
            ? { location: pickedLocation === 'auto' ? null : pickedLocation }
            : {}),
        },
        RegenerateResponse,
      );
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.account });
      void qc.invalidateQueries({ queryKey: queryKeys.accountUsage });
      void qc.invalidateQueries({ queryKey: queryKeys.nodeStatus });
      scrollToKeyPending = true;
      toast.success(t('get.createSubToastTitle'), {
        description: t('get.createSubToastBody'),
      });
    },
    // Failures render inline next to the CTA; no duplicate toast.
  }));

  // A 503 "no proxy server available" is retryable and not the user's fault, so
  // we soften the copy and point them at /account for later.
  let subErrorIsUnavailable = $derived(
    createSubscription.error instanceof ApiCallError &&
      createSubscription.error.payload.error.code === 'backend.unavailable',
  );

  // The pass's display URL (empty until a key exists).
  let subUrl = $derived(
    subscription ? subscriptionDisplayUrl(subscription.subToken, subscription.url) : '',
  );

  const STEP_LABELS = $derived([
    t('get.progress.step1'),
    t('get.progress.step2'),
    t('get.progress.step3'),
  ]);
</script>

<div class="max-w-3xl mx-auto py-8 md:py-12 space-y-8">
  <header class="text-center">
    <h1 class="text-3xl md:text-4xl font-display font-bold tracking-tight">
      {t('get.title')}
    </h1>
  </header>

  <!-- Guided-flow progress: ① Create account → ② Save your number → ③ Get
       connected. Always visible - it IS the page's map. -->
  <nav aria-label={t('get.progressAria')}>
    <ol class="flex items-start justify-center">
      {#each STEP_LABELS as label, i (label)}
        {@const n = i + 1}
        {@const done = currentStep > n}
        {@const current = currentStep === n}
        <li class="flex items-start" aria-current={current ? 'step' : undefined}>
          <div class="flex w-20 sm:w-24 flex-col items-center gap-1.5 text-center">
            <span
              class="flex size-7 items-center justify-center rounded-full border text-xs font-semibold transition-colors {done
                ? 'border-primary bg-primary text-primary-foreground'
                : current
                  ? 'border-primary text-primary'
                  : 'border-border text-muted-foreground'}"
            >
              {#if done}<Check class="size-3.5" aria-hidden="true" />{:else}{n}{/if}
            </span>
            <span
              class="text-xs leading-tight {current
                ? 'font-medium text-foreground'
                : 'text-muted-foreground'}"
            >
              {label}
            </span>
          </div>
          {#if n < STEP_LABELS.length}
            <span
              class="mt-3.5 h-px w-8 sm:w-14 {done ? 'bg-primary' : 'bg-border'}"
              aria-hidden="true"
            ></span>
          {/if}
        </li>
      {/each}
    </ol>
  </nav>

  {#if me.isPending && !created}
    <!-- Mirrors the step-1 panel so a signed-in visitor never sees the
         create-account form flash before their key/setup view. -->
    <div class="rounded-xl border border-border bg-card p-6 md:p-8 space-y-5">
      <Skeleton class="h-6 w-40" />
      <Skeleton class="h-16 w-full rounded-lg" />
      <Skeleton class="h-11 w-full rounded-md" />
      <Skeleton class="mx-auto h-3 w-3/4" />
    </div>
  {:else if currentStep === 1}
    <!-- STEP 1: create account (no proxy server required). -->
    <div
      class="max-w-xl mx-auto w-full rounded-xl border border-border bg-card p-6 md:p-8 space-y-5"
    >
      <h2 class="text-lg font-display font-semibold">{t('get.step1Title')}</h2>

      {#if showChooser && config.data}
        <div class="space-y-2">
          <p class="text-xs uppercase tracking-wider text-muted-foreground font-semibold">
            {t('get.chooseBackend')}
          </p>
          <div
            role="radiogroup"
            aria-label={t('get.backendAria')}
            class="grid grid-cols-1 sm:grid-cols-2 gap-2 rounded-lg border border-border p-1"
          >
            <button
              type="button"
              role="radio"
              aria-checked={chosenBackend === 'remnawave'}
              tabindex={chosenBackend === 'remnawave' ? 0 : -1}
              onclick={() => (chosenBackend = 'remnawave')}
              onkeydown={chooserKeydown}
              class="rounded-md px-3 py-2.5 text-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background {chosenBackend ===
              'remnawave'
                ? 'bg-primary text-primary-foreground shadow-sm'
                : 'text-muted-foreground hover:bg-muted'}"
            >
              <div class="font-semibold">{config.data.backends.labels.remnawave}</div>
              <div
                class="text-[11px] leading-tight mt-0.5 {chosenBackend === 'remnawave'
                  ? 'text-primary-foreground/80'
                  : 'text-muted-foreground/80'}"
              >
                {t('get.backendMultiProtocol')}
              </div>
            </button>
            <button
              type="button"
              role="radio"
              aria-checked={chosenBackend === 'outline'}
              tabindex={chosenBackend === 'outline' ? 0 : -1}
              onclick={() => (chosenBackend = 'outline')}
              onkeydown={chooserKeydown}
              class="rounded-md px-3 py-2.5 text-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background {chosenBackend ===
              'outline'
                ? 'bg-primary text-primary-foreground shadow-sm'
                : 'text-muted-foreground hover:bg-muted'}"
            >
              <div class="font-semibold">{config.data.backends.labels.outline}</div>
              <div
                class="text-[11px] leading-tight mt-0.5 {chosenBackend === 'outline'
                  ? 'text-primary-foreground/80'
                  : 'text-muted-foreground/80'}"
              >
                {t('get.backendShadowsocks')}
              </div>
            </button>
          </div>
        </div>
      {/if}

      <!-- The captcha config comes from /api/v1/config; without it the widget
           would render with an empty site key and fail opaquely. Surface the
           load failure with a retry instead of a silent dead-end. -->
      {#if config.isError}
        <div class="space-y-2">
          <InlineError message={apiErrorMessage(config.error)} />
          <Button variant="outline" size="sm" onclick={() => config.refetch()}>
            {t('common.retry')}
          </Button>
        </div>
      {:else if !config.data}
        <div
          class="flex min-h-11 items-center rounded-md border border-border px-3 text-sm text-muted-foreground"
          role="status"
        >
          {t('common.loading')}
        </div>
      {:else}
        <CapWidget
          bind:this={capWidget}
          apiEndpoint={captchaEndpoint}
          siteKey={captchaSiteKey}
          onVerify={(t) => (token = t || null)}
        />
      {/if}

      {#if createAccount.error}
        <InlineError message={apiErrorMessage(createAccount.error)} />
      {/if}

      {#if referralsEnabled}
        <div class="space-y-1.5">
          <label
            for="referral-code"
            class="text-xs text-muted-foreground flex items-center justify-between"
          >
            <span>{t('referral.fieldLabel')}</span>
          </label>
          <input
            id="referral-code"
            type="text"
            bind:value={referralInput}
            placeholder={t('referral.fieldPlaceholder')}
            autocomplete="off"
            spellcheck="false"
            class="w-full min-h-11 rounded-md border border-border bg-background px-3 py-2 font-mono text-sm uppercase focus:outline-none focus:ring-2 focus:ring-primary"
          />
          <p class="text-[11px] text-muted-foreground">{t('referral.fieldHint')}</p>
        </div>
      {/if}

      <Button
        onclick={() => createAccount.mutate()}
        disabled={createAccount.isPending || !token}
        size="lg"
        class="w-full min-h-11"
      >
        <SocksIcon class="size-4" />
        {createAccount.isPending ? t('common.working') : t('get.createAccount')}
      </Button>

      <p class="text-xs text-muted-foreground text-center">
        {#if deviceLimitsShown(config.data)}
          {t('get.freeAccountNote', { days: freeDays, devices: freeDevicesLabel })}
        {:else}
          {t('get.freeAccountNoteNoDevices', { days: freeDays })}
        {/if}
      </p>

      <p class="text-xs text-muted-foreground text-center">
        {t('get.haveAccountPrefix')}
        <Link href="/login" class="text-primary underline">{t('nav.signIn')}</Link>.
      </p>
    </div>
  {:else if currentStep === 2}
    <!-- STEP 2: save the account number. The blocking reveal modal does the
         work; once it closes, the (skippable) passkey offer completes the
         "secure your account" step. -->
    {#if showPasskeyPrompt && !revealOpen && passkeySupported}
      <div class="max-w-xl mx-auto w-full space-y-2">
        <PasskeyManager showList={false} onEnrolled={() => (showPasskeyPrompt = false)} />
        <button
          type="button"
          class="mx-auto block text-xs text-muted-foreground underline hover:text-foreground"
          onclick={() => (showPasskeyPrompt = false)}
        >
          {t('passkey.notNow')}
        </button>
      </div>
    {/if}
  {:else if account.isPending && !subscription}
    <!-- STEP 3 loading: mirror the panel so the create-key UI doesn't flash
         for a signed-in member whose key is still loading. -->
    <div class="rounded-xl border border-border bg-card p-6 md:p-8 space-y-5">
      <Skeleton class="h-6 w-40" />
      <Skeleton class="h-24 w-full rounded-lg" />
      <Skeleton class="h-11 w-full rounded-md" />
    </div>
  {:else if !subscription}
    <!-- STEP 3 (pre-key): delivery focus, optional gift code, location, then
         the one primary action. -->
    <div
      id="step-3"
      class="scroll-mt-24 rounded-xl border border-border bg-card p-6 md:p-8 space-y-5"
    >
      <div class="space-y-1">
        <h2 class="text-lg font-display font-semibold">{t('get.step3Title')}</h2>
        <p class="text-sm text-muted-foreground">{t('get.step3Intro')}</p>
        {#if created}
          <!-- Recovery pointer for fresh sign-ups: the reveal-once number is
               volatile, so if it wasn't saved the only recourse is rotating to
               a fresh (re-revealed) number on /account. -->
          <p class="text-xs text-muted-foreground">
            {t('get.lostNumberHint')}
            <Link href="/account" class="underline">{t('get.lostNumberLinkLabel')}</Link>.
          </p>
        {/if}
      </div>

      <!-- Delivery focus - flat (the step panel is the surface). Before the
           first key it's a local pref that shapes issuance; once a key exists
           it re-issues via the confirm modal, exactly like /account. -->
      <ConnectionModeSwitcher
        modes={connectionModes}
        selected={effectiveModeId}
        suggested={account.data?.suggestedModeId ?? null}
        serverBacked={profileServerBacked}
        deviceCount={0}
        disabled={actionsDisabled}
        signup
        flat
      />

      {#if !isCurrentMember}
        {#if !redeemOpen}
          <p class="text-xs text-muted-foreground">
            <button
              type="button"
              class="rounded-sm underline hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              onclick={() => (redeemOpen = true)}
            >
              {t('get.redeemPrompt')}
            </button>
          </p>
        {:else}
          <div class="border-t border-border/60 pt-4">
            <RedeemCode titleKey="get.redeemTitle" descriptionKey="get.redeemBody" flat />
          </div>
        {/if}
      {/if}

      {#if locations.length >= 2}
        <LocationPicker
          {locations}
          bind:value={pickedLocation}
          disabled={createSubscription.isPending}
          id="get-account-location"
        />
      {/if}

      {#if createSubscription.error}
        <div
          class="rounded-md bg-destructive/10 border border-destructive/40 px-3 py-2 text-sm text-destructive space-y-1"
        >
          <p>{apiErrorMessage(createSubscription.error)}</p>
          {#if subErrorIsUnavailable}
            <p class="text-xs text-muted-foreground">
              {t('get.subErrorSafePrefix')}
              <Link href="/account" class="underline">{t('get.manageLinkLabel')}</Link>
              {t('get.subErrorSafeSuffix')}
            </p>
          {/if}
        </div>
      {/if}

      <Button
        onclick={() => createSubscription.mutate()}
        disabled={createSubscription.isPending}
        size="lg"
        class="w-full min-h-11"
      >
        <KeyRound class="size-4" />
        {createSubscription.isPending ? t('account.creating') : t('account.createSub')}
      </Button>
    </div>
  {:else}
    <!-- STEP 3 (key issued): the pass + setup. This is the flow's destination. -->
    <div id="get-key" class="scroll-mt-24 space-y-6">
      <SubscriptionHero
        eyebrow={t('hero.eyebrowAccessKey')}
        title={subscription.backend === 'outline'
          ? t('hero.urlLabelAccessKey')
          : t('hero.urlLabelSubscription')}
        backendLabel={config.data?.backends.labels[subscription.backend]}
        subscriptionUrl={subUrl}
        expiresAt={subscription.expiresAt}
        trafficLimitBytes={subscription.trafficLimitBytes}
        trafficUsedBytes={subscription.trafficUsedBytes}
        status={subscription.status}
        resetStrategy={subscription.resetStrategy}
        lastResetAt={subscription.lastResetAt}
        tierName={account.data?.user.tier.name ?? accountTier?.name ?? ''}
        backend={subscription.backend}
        hideUrl={rawConfigFirst}
        usagePoints={usage.data?.usage?.points}
        usageTotal={usage.data?.usage?.total}
        nodeOnline={nodeStatus.data ? (nodeStatus.data.node?.online ?? null) : undefined}
        nodeLocationLabel={nodeStatus.data?.node?.location?.label ??
          subscription.location?.label ??
          null}
        nodeLocationCode={nodeStatus.data?.node?.location?.code ??
          subscription.location?.code ??
          null}
        nodeLabel={nodeStatus.data?.node?.label ?? null}
        nodeLoad={nodeStatus.data ? (nodeStatus.data.node?.load ?? null) : undefined}
      />
      {#if rawConfigFirst}
        <!-- rawConfig mode: raw config is the deliverable; CDN link hidden; no mirrors. -->
        <RawConfig prominent />
        <ConnectClient
          backend={subscription.backend}
          rawConfigFirst
          deviceLimited={account.data?.user.tier.deviceLimited ?? false}
        />
      {:else}
        <ConnectClient
          backend={subscription.backend}
          subscriptionUrl={subUrl}
          deviceLimited={account.data?.user.tier.deviceLimited ?? false}
        />
        {#if config.data?.mirrorsEnabled}
          <MirrorHelp
            mirrors={subscription.mirrors}
            geoCountry={account.data?.geoCountry}
            subscriptionUrl={subUrl}
          />
        {/if}
        <RawConfig />
      {/if}
      <p class="text-xs text-muted-foreground text-center">
        {t('get.manageHintPrefix')}
        <Link href="/account" class="text-primary underline">{t('get.manageLinkLabel')}</Link>.
      </p>
    </div>
  {/if}

  <!-- A2: one-time reveal of the freshly minted account number, in a blocking
       two-step modal (required download, then paste-back verification) with a
       beforeunload guard. Rendered outside the step panels (it overlays). -->
  {#if revealedAccountId}
    <AccountNumberReveal
      bind:open={revealOpen}
      accountId={revealedAccountId}
      onClose={() => {
        // Once acknowledged, drop the plaintext from component state so it does
        // not linger in memory after the moment has passed — and from the
        // mutation cache (its data holds the accountId for up to gcTime).
        revealedAccountId = null;
        createAccount.reset();
      }}
    />
  {/if}

  {#if config.data?.site?.supportEmail}
    <p class="text-xs text-muted-foreground text-center max-w-sm mx-auto">
      {t('support.getAccountLine')}
      <a class="text-primary underline" href="mailto:{config.data.site.supportEmail}">
        {config.data.site.supportEmail}
      </a>
    </p>
  {/if}
</div>
