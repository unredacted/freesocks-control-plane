<script lang="ts">
  import { z } from 'zod';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import CapWidget from '../components/CapWidget.svelte';
  import AccountNumberReveal from '../components/AccountNumberReveal.svelte';
  import SubscriptionHero from '../components/SubscriptionHero.svelte';
  import MirrorHelp from '../components/MirrorHelp.svelte';
  import RawConfig from '../components/RawConfig.svelte';
  import InlineError from '../components/InlineError.svelte';
  import ConnectionModeSwitcher from '../components/ConnectionModeSwitcher.svelte';
  import { connectionModePref } from '../lib/connectionModePref.svelte';
  import { resolveEffectiveModeId } from '../lib/connectionMode';
  import ConnectClient from '../components/ConnectClient.svelte';
  import UpgradeMembership from '../components/UpgradeMembership.svelte';
  import RedeemCode from '../components/RedeemCode.svelte';
  import Link from '../components/Link.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { meQuery, configQuery, accountQuery, queryKeys } from '../lib/queries';
  import { freeTier } from '../lib/tiers';
  import { apiClient, ApiCallError } from '../lib/api';
  import { apiErrorMessage } from '../lib/errors';
  import { subscriptionDisplayUrl } from '../lib/utils';
  import { CreateAccountRequest, CreateAccountResponse } from '../../shared/contracts/account';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import SocksIcon from '../components/SocksIcon.svelte';
  import CheckCircle from '@lucide/svelte/icons/check-circle';
  import Plus from '@lucide/svelte/icons/plus';

  type CreateAccountPayload = z.infer<typeof CreateAccountResponse>;

  const me = meQuery();
  const config = configQuery();
  const qc = useQueryClient();

  let token = $state<string | null>(null);
  // Instance ref so a failed create remounts the captcha — the server consumes
  // (spends) the Cap token on verify, so a stale token makes every retry fail.
  // (Third-pass audit; see CapWidget.reset().)
  let capWidget = $state<ReturnType<typeof CapWidget>>();
  // Tracked separately from `config.data?.backends.defaultBackend` because the
  // user can pick a non-default; seeded in $effect once config loads.
  let chosenBackend = $state<'remnawave' | 'outline' | null>(null);

  // Set once account creation succeeds. The reveal-once number stays visible in
  // its panel while the user creates a subscription in card 2.
  let revealedAccountId = $state<string | null>(null);
  let revealOpen = $state(false);
  let accountTier = $state<CreateAccountPayload['tier'] | null>(null);
  let created = $state(false);

  // The visitor has an account either because they just made one (created) or
  // they arrived already signed in. Card 2 + the account view key off this.
  let isAuthed = $derived(created || !!me.data?.authenticated);

  // Subscription source of truth once signed in. Gated on auth so it does not
  // 401 while the visitor is still anonymous on this page.
  const account = accountQuery(() => isAuthed);
  let subscription = $derived(account.data?.subscription ?? null);
  // Connection-mode catalog + emphasis (client choice → country suggestion →
  // catalog default); orders the panels. `rawConfigFirst` is data-driven off the
  // selected mode's deliveryStyle (replaces the hardcoded `=== 'privacy'`).
  let connectionModes = $derived(config.data?.connectionModes ?? []);
  let defaultModeId = $derived(
    connectionModes.find((m) => m.isDefault)?.id ?? connectionModes[0]?.id ?? 'evade',
  );
  // Server-backed once a key exists AND a placement pool is bound — then the
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
  // Hide the upgrade prompts (redeem a gift code + buy) once they're a member.
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
      const body =
        showChooser && chosenBackend
          ? CreateAccountRequest.parse({ captchaToken: token!, backend: chosenBackend })
          : CreateAccountRequest.parse({ captchaToken: token! });
      return apiClient.post('/api/v1/account', body, CreateAccountResponse);
    },
    onSuccess: (data) => {
      revealedAccountId = data.accountId;
      revealOpen = true; // A2: blocking, checkbox-gated reveal modal
      accountTier = data.tier;
      created = true;
      // Cookie is set; reflect the new authenticated identity everywhere.
      void qc.invalidateQueries({ queryKey: queryKeys.me });
    },
    // Failures render inline next to the CTA (see the destructive box below); no
    // duplicate toast — one error surface per failure. onError only remounts the
    // captcha: the verify consumed the token, so without a fresh challenge every
    // retry would fail with a stale-captcha error.
    onError: () => {
      token = null;
      capWidget?.reset();
    },
  }));

  // Step 2: provision the proxy key. Separate request from step 1, so a backend
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
          z.object({ ok: z.boolean(), modeId: z.string() }),
        );
      } catch {
        // Non-fatal: the first key just issues into the default mode.
      }
      return apiClient.post(
        '/api/v1/account/regenerate',
        { confirm: true },
        z.object({ subscriptionUrl: z.string(), shortUuid: z.string() }),
      );
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.account });
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
</script>

<div class="max-w-4xl mx-auto py-8 md:py-12 space-y-6">
  <header class="text-center space-y-3">
    <h1
      class="text-3xl md:text-4xl font-display font-bold tracking-tight bg-gradient-to-br from-foreground to-foreground/70 bg-clip-text text-transparent"
    >
      {t('get.title')}
    </h1>
    <!-- Pre-creation guidance only. Once authed, the success callout below is
         the single "account ready" message — no redundant restatement here.
         Suppressed while the auth check is still pending (the skeleton below is
         the sole loading affordance), so a signed-in visitor never sees the
         anonymous intro flash. -->
    {#if !me.isPending && !isAuthed}
      <p class="text-sm text-muted-foreground max-w-md mx-auto">{t('get.introTwoSteps')}</p>
    {/if}
  </header>

  <!-- STEP 1: create account (no proxy server required). While the auth check
       is still pending, a skeleton mirrors this card so a signed-in visitor
       never sees the create-account form flash before their account view. -->
  {#if me.isPending && !created}
    <div class="max-w-xl mx-auto rounded-xl border border-border bg-card p-6 md:p-8 space-y-5">
      <div class="flex items-center gap-2.5">
        <Skeleton class="size-7 rounded-full" />
        <Skeleton class="h-6 w-40" />
      </div>
      <Skeleton class="h-16 w-full rounded-lg" />
      <Skeleton class="h-11 w-full rounded-md" />
      <Skeleton class="mx-auto h-3 w-3/4" />
    </div>
  {:else if !created && !me.data?.authenticated}
    <div class="max-w-xl mx-auto rounded-xl border border-border bg-card p-6 md:p-8 space-y-5">
      <div class="flex items-center gap-2.5">
        <span
          class="size-7 rounded-full bg-primary/10 text-primary font-display font-bold flex items-center justify-center text-sm tabular-nums"
          >1</span
        >
        <h2 class="text-lg font-display font-semibold">{t('get.step1Title')}</h2>
      </div>

      {#if showChooser && config.data}
        <div class="space-y-2">
          <p class="text-xs uppercase tracking-wider text-muted-foreground font-semibold">
            {t('get.chooseBackend')}
          </p>
          <div
            role="radiogroup"
            aria-label={t('get.backendAria')}
            class="grid grid-cols-2 gap-2 rounded-lg border border-border p-1"
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

      <Button
        onclick={() => createAccount.mutate()}
        disabled={createAccount.isPending || !token}
        size="lg"
        class="w-full"
      >
        <SocksIcon class="size-4" />
        {createAccount.isPending ? t('common.working') : t('get.createAccount')}
      </Button>

      <p class="text-xs text-muted-foreground text-center">
        {t('get.freeAccountNote', { days: freeDays, devices: freeDevicesLabel })}
      </p>
    </div>
  {:else}
    <div
      class="mx-auto max-w-xl rounded-xl border border-primary/40 bg-primary/5 px-4 py-3 flex items-center gap-2.5 text-sm"
    >
      <CheckCircle class="size-4 text-primary shrink-0" />
      <span>
        {t('get.accountReady')}
        <!-- Recovery pointer on BOTH paths (just-created and reload): the
             reveal-once number is volatile, so if it wasn't saved the only
             recourse is rotating to a fresh (re-revealed) number on /account.
             The copy is conditional ("lost it before saving?"), so it reads as
             an offer, not an alarm. -->
        <span class="block text-xs text-muted-foreground mt-0.5">
          {t('get.lostNumberHint')}
          <Link href="/account" class="underline">{t('get.lostNumberLinkLabel')}</Link>.
        </span>
      </span>
    </div>
  {/if}

  <!-- A2: one-time reveal of the freshly minted account number, in a blocking,
       checkbox-gated modal with copy/download + a beforeunload guard. -->
  {#if revealedAccountId}
    <AccountNumberReveal
      bind:open={revealOpen}
      accountId={revealedAccountId}
      onClose={() => {
        // Once acknowledged, drop the plaintext from component state so it does
        // not linger in memory after the moment has passed.
        revealedAccountId = null;
      }}
    />
    {#if !revealOpen}
      <div
        class="flex items-center gap-2 rounded-md border border-primary/30 bg-primary/5 px-4 py-3 text-sm"
      >
        <CheckCircle class="size-4 text-primary" aria-hidden="true" />
        <span>{t('reveal.confirmCheckbox')} ✓</span>
      </div>
    {/if}
  {/if}

  <!-- Got a gift code? Redeem during onboarding so the upgrade lands BEFORE the
       subscription is created (the backend binds the tier at issuance), and the
       new key is issued on the member tier. Hidden once they're already a member. -->
  {#if isAuthed && !isCurrentMember}
    <div class="mx-auto max-w-xl">
      <RedeemCode titleKey="get.redeemTitle" descriptionKey="get.redeemBody" />
    </div>
  {/if}

  <!-- Upsell: grouped directly under the gift-code box (both above Step 2) so the
       two paths to the member tier sit together. A collapsible accordion with the
       tier-sheen flair — the trigger shows the price/month + a prompt to upgrade;
       expanding reveals the payment options. Self-gates on billing being live. -->
  {#if isAuthed && !isCurrentMember && config.data?.billing?.enabled}
    <UpgradeMembership mode="upgrade" collapsible />
  {/if}

  <!-- STEP 2: create the proxy subscription (needs a proxy server). -->
  {#if isAuthed}
    <div class="rounded-xl border border-border bg-card p-6 md:p-8 space-y-5">
      <div class="flex items-center gap-2.5">
        <span
          class="size-7 rounded-full bg-primary/10 text-primary font-display font-bold flex items-center justify-center text-sm tabular-nums"
          >2</span
        >
        <h2 class="text-lg font-display font-semibold">{t('get.step2Title')}</h2>
      </div>

      <!-- Delivery focus FIRST — above the key (and the create button), so the
           choice shapes how the subscription is presented. Before the first key
           it's a local pref (shapes issuance at "Create subscription"); once a key
           exists it re-issues via the confirm modal, exactly like /account. -->
      <ConnectionModeSwitcher
        modes={connectionModes}
        selected={effectiveModeId}
        suggested={account.data?.suggestedModeId ?? null}
        serverBacked={profileServerBacked}
        deviceCount={subscription?.devices.length ?? 0}
        disabled={actionsDisabled}
        signup={!subscription}
      />

      {#if subscription}
        {@const subUrl = subscriptionDisplayUrl(subscription.subToken, subscription.url)}
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
          tierName={account.data?.user.tier.name ?? accountTier?.name ?? ''}
          backend={subscription.backend}
          hideUrl={rawConfigFirst}
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
      {:else}
        <p class="text-sm text-muted-foreground">
          {t('get.step2Intro')}
        </p>

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
          class="w-full"
        >
          <Plus class="size-4" />
          {createSubscription.isPending ? t('account.creating') : t('account.createSub')}
        </Button>
      {/if}
    </div>
  {/if}

  {#if !me.isPending && !isAuthed}
    <p class="text-xs text-muted-foreground text-center max-w-sm mx-auto">
      {t('get.haveAccountPrefix')}
      <Link href="/login" class="text-primary underline">{t('nav.signIn')}</Link>.
    </p>
  {/if}
</div>
