<script lang="ts">
  import type { z } from 'zod';
  import { Button } from '@client/components/ui/button';
  import Turnstile from '../components/Turnstile.svelte';
  import SubscriptionHero from '../components/SubscriptionHero.svelte';
  import { meQuery, configQuery } from '../lib/queries';
  import { apiClient, ApiCallError } from '../lib/api';
  import { SubscriptionRequest, SubscriptionResponse } from '../../shared/contracts/subscription';
  import { createMutation } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import KeyIcon from '@lucide/svelte/icons/key-round';
  import Sparkles from '@lucide/svelte/icons/sparkles';

  type SubscriptionPayload = z.infer<typeof SubscriptionResponse>;

  const me = meQuery();
  const config = configQuery();

  let token = $state<string | null>(null);
  let result = $state<SubscriptionPayload | null>(null);
  // Tracked separately from `config.data?.backends.defaultBackend` because the
  // user can pick a non-default, initialized lazily in $effect once config
  // loads so the UI doesn't flicker between undefined → default.
  let chosenBackend = $state<'remnawave' | 'outline' | null>(null);

  // Prefer the server-side site key from /api/v1/config; fall back to Turnstile
  // test key so dev still works if the API call fails.
  let siteKey = $derived(config.data?.freeTierTurnstileSiteKey ?? '1x00000000000000000000AA');

  // Chooser is visible only when BOTH backends are enabled AND the admin has
  // turned on user-choice. If either condition fails, server picks for us and
  // we hide the UI to avoid teasing an option that won't be honored.
  let showChooser = $derived(
    !!config.data &&
      config.data.backends.remnawaveEnabled &&
      config.data.backends.outlineEnabled &&
      config.data.backends.userChoiceEnabled,
  );

  // Seed `chosenBackend` from the server's default once config arrives. Done
  // in $effect rather than $derived because we want this to be writable user
  // state, not a reactive read.
  $effect(() => {
    if (chosenBackend === null && config.data) {
      chosenBackend = config.data.backends.defaultBackend;
    }
  });

  // createMutation handles in-flight state (mutation.isPending) and surfaces
  // errors via mutation.error, and we layer toast feedback on top.
  const getAccount = createMutation(() => ({
    mutationFn: async () => {
      // Only send `backend` when the user could actually pick one; otherwise
      // the server ignores it. Authenticated members go through the member
      // path which doesn't read this field at all (their tier dictates the
      // backend), so we omit it there too.
      const backendField =
        showChooser && !me.data?.authenticated && chosenBackend ? { backend: chosenBackend } : {};
      const body = me.data?.authenticated
        ? SubscriptionRequest.parse({})
        : SubscriptionRequest.parse({ turnstileToken: token!, ...backendField });
      return apiClient.post('/api/v1/subscription', body, SubscriptionResponse);
    },
    onSuccess: (data) => {
      result = data;
    },
    onError: (err) => {
      const msg = err instanceof ApiCallError ? err.payload.error.message : String(err);
      toast.error('Could not create account', { description: msg });
    },
  }));
</script>

{#if result}
  <div class="max-w-3xl mx-auto py-8 space-y-6">
    <header class="text-center space-y-2">
      <div
        class="inline-flex items-center gap-2 rounded-full bg-primary/10 text-primary px-3 py-1 text-xs font-semibold uppercase tracking-wider"
      >
        <Sparkles class="size-3.5" />
        Ready to use
      </div>
      <h1 class="text-3xl md:text-4xl font-display font-bold tracking-tight">
        Your subscription is ready
      </h1>
      <p class="text-sm text-muted-foreground">
        Copy the URL into your VPN client, or scan the QR code from another device.
      </p>
    </header>

    {#if result.accountId}
      <div class="rounded-xl border-2 border-primary bg-primary/5 p-5 space-y-3">
        <h2 class="text-sm font-semibold uppercase tracking-wider text-primary">
          Save your account number
        </h2>
        <p
          class="font-mono text-lg md:text-xl tracking-normal tabular-nums select-all break-words leading-relaxed"
        >
          {result.accountId.replace(/(\d{4})(?=\d)/g, '$1 ')}
        </p>
        <p class="text-xs text-muted-foreground">
          This is the <strong>only</strong> way to sign back in: there's no email or password, and it
          can't be recovered. Store it somewhere safe. It's shown only once.
        </p>
        <div class="flex gap-2">
          <Button
            size="sm"
            variant="outline"
            onclick={() => {
              if (result?.accountId) navigator.clipboard?.writeText(result.accountId);
              toast.success('Copied');
            }}
          >
            Copy number
          </Button>
        </div>
      </div>
    {/if}

    <SubscriptionHero
      eyebrow="New subscription"
      title={result.backend === 'outline' ? 'Access key' : 'Subscription URL'}
      subscriptionUrl={result.subscriptionUrl}
      fallbackUrl={result.fallbackUrl}
      expiresAt={result.expiresAt}
      trafficLimitBytes={result.trafficLimitBytes}
      trafficUsedBytes={result.trafficUsedBytes}
      tierName={result.tier.name}
      banner={result.banner}
      backend={result.backend}
    />

    {#if !me.data?.authenticated}
      <div class="text-center text-sm text-muted-foreground pt-2">
        <!--
          Member tiers (more devices, more bandwidth) are being designed;
          the signup flow isn't wired end-to-end yet. The sign-in path
          still works for existing Unredacted members; everything past
          that is a placeholder until the membership flow ships.
        -->
        Want to help keep FreeSocks running?{' '}
        <a
          href="https://unredacted.org/donate"
          target="_blank"
          rel="noopener noreferrer"
          class="text-primary underline"
        >
          Donate
        </a>{' '}(member tiers with more devices and bandwidth are coming soon).
      </div>
    {/if}
  </div>
{:else}
  <div class="max-w-xl mx-auto py-8 md:py-12 space-y-8">
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
        {#if me.isPending}
          Loading…
        {:else if me.data?.authenticated}
          Signed in on the
          <strong class="text-foreground">{me.data.member?.tier.name}</strong> tier.
        {:else}
          Solve the human-check below to create a free account.
        {/if}
      </p>
    </header>

    <div class="rounded-xl border border-border bg-card p-6 md:p-8 space-y-5">
      {#if showChooser && !me.data?.authenticated && config.data}
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
      {#if !me.data?.authenticated}
        <Turnstile {siteKey} onVerify={(t) => (token = t)} />
      {/if}
      {#if getAccount.error}
        <div
          class="rounded-md bg-destructive/10 border border-destructive/40 px-3 py-2 text-sm text-destructive"
        >
          {getAccount.error instanceof ApiCallError
            ? getAccount.error.payload.error.message
            : String(getAccount.error)}
        </div>
      {/if}
      <Button
        onclick={() => getAccount.mutate()}
        disabled={getAccount.isPending || (!me.data?.authenticated && !token)}
        size="lg"
        class="w-full"
      >
        <KeyIcon class="size-4" />
        {getAccount.isPending ? 'Working…' : 'Create my account'}
      </Button>
    </div>

    <p class="text-xs text-muted-foreground text-center max-w-sm mx-auto">
      Free accounts are valid for 30 days and limited to one device. Sign in for higher tiers.
    </p>
  </div>
{/if}
