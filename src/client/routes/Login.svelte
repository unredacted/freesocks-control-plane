<script lang="ts">
  import { z } from 'zod';
  import { Button } from '@client/components/ui/button';
  import Turnstile from '../components/Turnstile.svelte';
  import { configQuery } from '../lib/queries';
  import { apiClient, ApiCallError } from '../lib/api';
  import { queryClient } from '../lib/query-client';
  import { queryKeys } from '../lib/queries';
  import { router } from '../stores/router.svelte';
  import { createMutation } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import LogIn from '@lucide/svelte/icons/log-in';

  // The ONLY member sign-in path post-migration: the random account number
  // (no OIDC, no password). Turnstile gates every attempt server-side; we just
  // collect the token + number and POST. On success the server sets the signed
  // fs_session cookie and we bounce to /account.
  const config = configQuery();
  let token = $state<string | null>(null);
  let accountId = $state('');
  let siteKey = $derived(config.data?.freeTierTurnstileSiteKey ?? '1x00000000000000000000AA');

  // Display helper: group the digits the user types into 4s, like the reveal
  // panel shows them. Stored/submitted value is digits-only (server normalizes
  // again defensively).
  const ACCOUNT_ID_LEN = 32;
  let formatted = $derived(
    accountId
      .replace(/\D/g, '')
      .slice(0, ACCOUNT_ID_LEN)
      .replace(/(\d{4})(?=\d)/g, '$1 '),
  );

  const LoginResult = z.object({ ok: z.boolean() });

  const login = createMutation(() => ({
    mutationFn: () =>
      apiClient.post(
        '/api/v1/auth/account-login',
        { accountId: accountId.replace(/\D/g, ''), turnstileToken: token! },
        LoginResult,
      ),
    onSuccess: async () => {
      // The cookie is set; refresh identity-derived caches before navigating.
      await queryClient.invalidateQueries({ queryKey: queryKeys.me });
      await queryClient.invalidateQueries({ queryKey: queryKeys.account });
      toast.success('Signed in');
      router.navigate('/account');
    },
    onError: (err) => {
      const msg = err instanceof ApiCallError ? err.payload.error.message : String(err);
      toast.error('Sign-in failed', { description: msg });
    },
  }));

  let canSubmit = $derived(
    accountId.replace(/\D/g, '').length === ACCOUNT_ID_LEN && !!token && !login.isPending,
  );
</script>

<div class="max-w-md mx-auto py-10 md:py-16 space-y-8">
  <header class="text-center space-y-3">
    <div
      class="inline-flex items-center gap-2 rounded-full border border-primary/30 bg-primary/5 text-primary px-3 py-1 text-xs font-semibold uppercase tracking-wider"
    >
      <LogIn class="size-3.5" />
      Sign in
    </div>
    <h1 class="text-3xl md:text-4xl font-display font-bold tracking-tight">
      Sign in with your account number
    </h1>
    <p class="text-sm text-muted-foreground">
      Enter the 32-digit account number you saved when you got your key. It's the only way to sign
      in — there's no email or password to recover.
    </p>
  </header>

  <div class="rounded-xl border border-border bg-card p-6 md:p-8 space-y-5">
    <div class="space-y-2">
      <label
        for="account-number"
        class="text-xs uppercase tracking-wider text-muted-foreground font-semibold"
      >
        Account number
      </label>
      <input
        id="account-number"
        inputmode="numeric"
        autocomplete="off"
        spellcheck="false"
        placeholder="1234 5678 9012 3456 7890 1234 5678 9012"
        value={formatted}
        oninput={(e) => (accountId = (e.currentTarget as HTMLInputElement).value)}
        onkeydown={(e) => {
          if (e.key === 'Enter' && canSubmit) login.mutate();
        }}
        class="w-full rounded-md border border-border bg-background px-3 py-2.5 font-mono text-base tracking-normal tabular-nums focus:outline-none focus:ring-2 focus:ring-primary"
      />
    </div>

    <Turnstile {siteKey} onVerify={(t) => (token = t)} />

    {#if login.error}
      <div
        class="rounded-md bg-destructive/10 border border-destructive/40 px-3 py-2 text-sm text-destructive"
      >
        {login.error instanceof ApiCallError
          ? login.error.payload.error.message
          : String(login.error)}
      </div>
    {/if}

    <Button onclick={() => login.mutate()} disabled={!canSubmit} size="lg" class="w-full">
      <LogIn class="size-4" />
      {login.isPending ? 'Signing in…' : 'Sign in'}
    </Button>
  </div>

  <p class="text-xs text-muted-foreground text-center">
    Don't have an account number yet?{' '}
    <a href="/get-key" class="text-primary underline">Get a free key</a> — you'll be shown one to save.
  </p>
</div>
