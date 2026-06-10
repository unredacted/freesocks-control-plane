<script lang="ts">
  import { z } from 'zod';
  import { Button } from '@client/components/ui/button';
  import Turnstile from '../components/Turnstile.svelte';
  import SubscriptionHero from '../components/SubscriptionHero.svelte';
  import Link from '../components/Link.svelte';
  import { meQuery, configQuery, accountQuery, queryKeys } from '../lib/queries';
  import { apiClient, ApiCallError } from '../lib/api';
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
  let accountTier = $state<CreateAccountPayload['tier'] | null>(null);
  let created = $state(false);

  // The visitor has an account either because they just made one (created) or
  // they arrived already signed in. Card 2 + the account view key off this.
  let isAuthed = $derived(created || !!me.data?.authenticated);

  // Subscription source of truth once signed in. Gated on auth so it does not
  // 401 while the visitor is still anonymous on this page.
  const account = accountQuery(() => isAuthed);
  let subscription = $derived(account.data?.subscription ?? null);

  // Prefer the server-side site key from /api/v1/config; fall back to Turnstile
  // test key so dev still works if the API call fails.
  let siteKey = $derived(config.data?.freeTierTurnstileSiteKey ?? '1x00000000000000000000AA');

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

  // Step 1: create the account. No proxy backend is touched, so this succeeds
  // even when every backend is down/empty. On success the server sets the
  // session cookie (auto sign-in) and reveals the one-time account number.
  const createAccount = createMutation(() => ({
    mutationFn: async () => {
      const body =
        showChooser && chosenBackend
          ? CreateAccountRequest.parse({ turnstileToken: token!, backend: chosenBackend })
          : CreateAccountRequest.parse({ turnstileToken: token! });
      return apiClient.post('/api/v1/account', body, CreateAccountResponse);
    },
    onSuccess: (data) => {
      revealedAccountId = data.accountId;
      accountTier = data.tier;
      created = true;
      // Cookie is set; reflect the new authenticated identity everywhere.
      void qc.invalidateQueries({ queryKey: queryKeys.me });
    },
    onError: (err) => {
      const msg = err instanceof ApiCallError ? err.payload.error.message : String(err);
      toast.error('Could not create account', { description: msg });
    },
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
      toast.success('Subscription created', {
        description: 'Copy the URL into your VPN client, or scan the QR code.',
      });
    },
    onError: (err) => {
      const msg = err instanceof ApiCallError ? err.payload.error.message : String(err);
      toast.error('Could not create subscription', { description: msg });
    },
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
      Free account
    </div>
    <h1 class="text-3xl md:text-4xl font-display font-bold tracking-tight">
      Get a FreeSocks account
    </h1>
    <p class="text-sm text-muted-foreground max-w-md mx-auto">
      {#if me.isPending && !created}
        Loading…
      {:else if isAuthed}
        {#if subscription}
          Your account and subscription are ready.
        {:else}
          Your account is ready. Create a subscription below to get your key.
        {/if}
      {:else}
        Two quick steps: solve the human-check to create a free account, then create your
        subscription.
      {/if}
    </p>
  </header>

  <!-- STEP 1: create account (no proxy server required) -->
  {#if !created && !me.data?.authenticated}
    <div class="rounded-xl border border-border bg-card p-6 md:p-8 space-y-5">
      <div class="flex items-center gap-2.5">
        <span
          class="size-7 rounded-full bg-primary/10 text-primary font-display font-bold flex items-center justify-center text-sm tabular-nums"
          >1</span
        >
        <h2 class="text-lg font-display font-semibold">Create your account</h2>
      </div>

      {#if showChooser && config.data}
        <div class="space-y-2">
          <p class="text-xs uppercase tracking-wider text-muted-foreground font-semibold">
            Choose a backend
          </p>
          <div
            role="radiogroup"
            aria-label="Backend"
            class="grid grid-cols-2 gap-2 rounded-lg border border-border p-1"
          >
            <button
              type="button"
              role="radio"
              aria-checked={chosenBackend === 'remnawave'}
              onclick={() => (chosenBackend = 'remnawave')}
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
                Multi-protocol (VLESS, Trojan, Shadowsocks)
              </div>
            </button>
            <button
              type="button"
              role="radio"
              aria-checked={chosenBackend === 'outline'}
              onclick={() => (chosenBackend = 'outline')}
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
                Shadowsocks via Outline
              </div>
            </button>
          </div>
        </div>
      {/if}

      <Turnstile {siteKey} onVerify={(t) => (token = t)} />

      {#if createAccount.error}
        <div
          class="rounded-md bg-destructive/10 border border-destructive/40 px-3 py-2 text-sm text-destructive"
        >
          {createAccount.error instanceof ApiCallError
            ? createAccount.error.payload.error.message
            : String(createAccount.error)}
        </div>
      {/if}

      <Button
        onclick={() => createAccount.mutate()}
        disabled={createAccount.isPending || !token}
        size="lg"
        class="w-full"
      >
        <KeyIcon class="size-4" />
        {createAccount.isPending ? 'Working…' : 'Create my account'}
      </Button>

      <p class="text-xs text-muted-foreground text-center">
        Free accounts are valid for 30 days and limited to one device. No email or password.
      </p>
    </div>
  {:else}
    <div
      class="rounded-xl border border-primary/40 bg-primary/5 px-4 py-3 flex items-center gap-2.5 text-sm"
    >
      <CheckCircle class="size-4 text-primary shrink-0" />
      <span>Your account is ready{accountTier ? ` on the ${accountTier.name} tier` : ''}.</span>
    </div>
  {/if}

  <!-- One-time reveal of the freshly minted account number. -->
  {#if revealedAccountId}
    <div class="rounded-xl border-2 border-primary bg-primary/5 p-5 space-y-3">
      <h2 class="text-sm font-semibold uppercase tracking-wider text-primary">
        Save your account number
      </h2>
      <p
        class="font-mono text-lg md:text-xl tracking-normal tabular-nums select-all break-words leading-relaxed"
      >
        {revealedAccountId.replace(/(\d{4})(?=\d)/g, '$1 ')}
      </p>
      <p class="text-xs text-muted-foreground">
        This is the <strong>only</strong> way to sign back in: there's no email or password, and it can't
        be recovered. Store it somewhere safe. It's shown only once.
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
          Copy number
        </Button>
      </div>
    </div>
  {/if}

  <!-- STEP 2: create the proxy subscription (needs a proxy server). -->
  {#if isAuthed}
    <div class="rounded-xl border border-border bg-card p-6 md:p-8 space-y-5">
      <div class="flex items-center gap-2.5">
        <span
          class="size-7 rounded-full bg-primary/10 text-primary font-display font-bold flex items-center justify-center text-sm tabular-nums"
          >2</span
        >
        <h2 class="text-lg font-display font-semibold">Create your subscription</h2>
      </div>

      {#if subscription}
        <SubscriptionHero
          eyebrow="Your access key"
          title={subscription.backend === 'outline' ? 'Access key' : 'Subscription URL'}
          subscriptionUrl={subscription.url}
          fallbackUrl={subscription.mirrors[0]?.publicUrl}
          expiresAt={subscription.expiresAt}
          trafficLimitBytes={subscription.trafficLimitBytes}
          trafficUsedBytes={subscription.trafficUsedBytes}
          tierName={account.data?.user.tier.name ?? accountTier?.name ?? ''}
          backend={subscription.backend}
        />
        <p class="text-xs text-muted-foreground text-center">
          Manage this subscription anytime from
          <Link href="/account" class="text-primary underline">your account</Link>.
        </p>
      {:else}
        <p class="text-sm text-muted-foreground">
          Create a proxy subscription to get a URL you can paste into any compatible VPN client.
        </p>

        {#if createSubscription.error}
          <div
            class="rounded-md bg-destructive/10 border border-destructive/40 px-3 py-2 text-sm text-destructive space-y-1"
          >
            <p>
              {createSubscription.error instanceof ApiCallError
                ? createSubscription.error.payload.error.message
                : String(createSubscription.error)}
            </p>
            {#if subErrorIsUnavailable}
              <p class="text-xs text-muted-foreground">
                Your account is safe. You can create the subscription later from
                <Link href="/account" class="underline">your account</Link> once a server is available.
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
          {createSubscription.isPending ? 'Creating…' : 'Create subscription'}
        </Button>
      {/if}
    </div>
  {/if}

  {#if !isAuthed}
    <p class="text-xs text-muted-foreground text-center max-w-sm mx-auto">
      Already have an account?
      <Link href="/login" class="text-primary underline">Sign in</Link>.
    </p>
  {/if}
</div>
