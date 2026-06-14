<script lang="ts">
  import { z } from 'zod';
  import { Button } from '@client/components/ui/button';
  import CapWidget from '../components/CapWidget.svelte';
  import AccountNumberReveal from '../components/AccountNumberReveal.svelte';
  import SubscriptionHero from '../components/SubscriptionHero.svelte';
  import MirrorHelp from '../components/MirrorHelp.svelte';
  import SetupGuidance from '../components/SetupGuidance.svelte';
  import UpgradeMembership from '../components/UpgradeMembership.svelte';
  import Link from '../components/Link.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { meQuery, configQuery, accountQuery, queryKeys } from '../lib/queries';
  import { apiClient, ApiCallError } from '../lib/api';
  import { apiErrorMessage } from '../lib/errors';
  import { CreateAccountRequest, CreateAccountResponse } from '../../shared/contracts/account';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import KeyIcon from '@lucide/svelte/icons/key-round';
  import CheckCircle from '@lucide/svelte/icons/check-circle';
  import Plus from '@lucide/svelte/icons/plus';

  type CreateAccountPayload = z.infer<typeof CreateAccountResponse>;

  const me = meQuery();
  const config = configQuery();
  const qc = useQueryClient();

  let token = $state<string | null>(null);
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

  // Self-hosted Cap captcha config from /api/v1/config (same-origin endpoint).
  let captchaEndpoint = $derived(config.data?.captcha.apiEndpoint ?? '/cap');
  let captchaSiteKey = $derived(config.data?.captcha.siteKey ?? '');

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
    // Failures render inline next to the CTA (see the destructive box below);
    // no duplicate toast — one error surface per failure.
  }));

  // Step 2: provision the proxy key. Separate request from step 1, so a backend
  // outage here leaves the account intact and is shown as a retryable notice.
  // Reuses the member regenerate endpoint (create-or-replace).
  const createSubscription = createMutation(() => ({
    mutationFn: () =>
      apiClient.post(
        '/api/v1/account/regenerate',
        { confirm: true },
        z.object({ subscriptionUrl: z.string(), shortUuid: z.string() }),
      ),
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

<div class="max-w-xl mx-auto py-8 md:py-12 space-y-6">
  <header class="text-center space-y-3">
    <div
      class="inline-flex items-center gap-2 rounded-full border border-primary/30 bg-primary/5 text-primary px-3 py-1 text-xs font-semibold uppercase tracking-wider"
    >
      <KeyIcon class="size-3.5" />
      {t('get.badge')}
    </div>
    <h1 class="text-3xl md:text-4xl font-display font-bold tracking-tight">
      {t('get.title')}
    </h1>
    <!-- Pre-creation guidance only. Once authed, the success callout below is
         the single "account ready" message — no redundant restatement here. -->
    {#if me.isPending && !created}
      <p class="text-sm text-muted-foreground max-w-md mx-auto">{t('common.loading')}</p>
    {:else if !isAuthed}
      <p class="text-sm text-muted-foreground max-w-md mx-auto">{t('get.introTwoSteps')}</p>
    {/if}
  </header>

  <!-- STEP 1: create account (no proxy server required) -->
  {#if !created && !me.data?.authenticated}
    <div class="rounded-xl border border-border bg-card p-6 md:p-8 space-y-5">
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
              class="rounded-md px-3 py-2.5 text-sm transition-colors {chosenBackend === 'remnawave'
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
              class="rounded-md px-3 py-2.5 text-sm transition-colors {chosenBackend === 'outline'
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

      <CapWidget
        apiEndpoint={captchaEndpoint}
        siteKey={captchaSiteKey}
        onVerify={(t) => (token = t || null)}
      />

      {#if createAccount.error}
        <div
          class="rounded-md bg-destructive/10 border border-destructive/40 px-3 py-2 text-sm text-destructive"
        >
          {apiErrorMessage(createAccount.error)}
        </div>
      {/if}

      <Button
        onclick={() => createAccount.mutate()}
        disabled={createAccount.isPending || !token}
        size="lg"
        class="w-full"
      >
        <KeyIcon class="size-4" />
        {createAccount.isPending ? t('common.working') : t('get.createAccount')}
      </Button>

      <p class="text-xs text-muted-foreground text-center">
        {t('get.freeAccountNote')}
      </p>
    </div>
  {:else}
    <div
      class="rounded-xl border border-primary/40 bg-primary/5 px-4 py-3 flex items-center gap-2.5 text-sm"
    >
      <CheckCircle class="size-4 text-primary shrink-0" />
      <span>
        {t('get.accountReady')}
        {#if !created}
          <!-- Refresh-recovery path: the reveal-once state is volatile, so a
               reload right after creation must not be a dead end. The rotate
               action on /account mints (and properly reveals) a NEW number. -->
          <span class="block text-xs text-muted-foreground mt-0.5">
            {t('get.lostNumberHint')}
            <Link href="/account" class="underline">{t('get.lostNumberLinkLabel')}</Link>.
          </span>
        {/if}
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

      {#if subscription}
        <SubscriptionHero
          eyebrow={t('hero.eyebrowAccessKey')}
          title={subscription.backend === 'outline'
            ? t('hero.urlLabelAccessKey')
            : t('hero.urlLabelSubscription')}
          backendLabel={config.data?.backends.labels[subscription.backend]}
          subscriptionUrl={subscription.url}
          expiresAt={subscription.expiresAt}
          trafficLimitBytes={subscription.trafficLimitBytes}
          trafficUsedBytes={subscription.trafficUsedBytes}
          tierName={account.data?.user.tier.name ?? accountTier?.name ?? ''}
          backend={subscription.backend}
        />
        <SetupGuidance backend={subscription.backend} />
        {#if config.data?.mirrorsEnabled}
          <MirrorHelp
            mirrors={subscription.mirrors}
            geoCountry={account.data?.geoCountry}
            subscriptionUrl={subscription.url}
          />
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

  <!-- Upsell: the moment the free account exists, offer the paid membership —
       not gated on first creating the free subscription. The panel self-gates
       on billing being live (and the member is signed in here, so checkout
       works). -->
  {#if isAuthed && config.data?.billing?.enabled}
    <div class="space-y-3">
      <div class="space-y-1">
        <h2 class="font-display text-lg font-semibold">{t('get.upsellTitle')}</h2>
        <p class="text-sm text-muted-foreground">{t('get.upsellBody')}</p>
      </div>
      <UpgradeMembership mode="upgrade" />
    </div>
  {/if}

  {#if !isAuthed}
    <p class="text-xs text-muted-foreground text-center max-w-sm mx-auto">
      {t('get.haveAccountPrefix')}
      <Link href="/login" class="text-primary underline">{t('nav.signIn')}</Link>.
    </p>
  {/if}
</div>
