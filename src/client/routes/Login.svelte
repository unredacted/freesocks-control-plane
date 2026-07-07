<script lang="ts">
  import { z } from 'zod';
  import { Button } from '@client/components/ui/button';
  import CapWidget from '../components/CapWidget.svelte';
  import InlineError from '../components/InlineError.svelte';
  import Link from '../components/Link.svelte';
  import { configQuery } from '../lib/queries';
  import { apiClient } from '../lib/api';
  import { apiErrorMessage } from '../lib/errors';
  import { t, normalizeDigits } from '../lib/i18n/index.svelte';
  import { queryClient } from '../lib/query-client';
  import { queryKeys } from '../lib/queries';
  import { router } from '../stores/router.svelte';
  import { createMutation } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import LogIn from '@lucide/svelte/icons/log-in';
  import Eye from '@lucide/svelte/icons/eye';
  import EyeOff from '@lucide/svelte/icons/eye-off';

  // The ONLY member sign-in path post-migration: the random account number
  // (no OIDC, no password). A Cap proof-of-work check gates every attempt; we just
  // collect the token + number and POST. On success the server sets the signed
  // fs_session cookie and we bounce to /account.
  const config = configQuery();
  let token = $state<string | null>(null);
  // P1-12: store the digits-only value the user has typed. We do NOT reformat the
  // input's bound value on every keystroke (that's what jumped the caret to the
  // end mid-edit); grouping is shown via the placeholder + monospace tracking,
  // and on blur. Persian/Arabic-Indic numerals are normalized to ASCII.
  let accountId = $state('');
  let reveal = $state(false);
  let captchaEndpoint = $derived(config.data?.captcha.apiEndpoint ?? '/cap');
  let captchaSiteKey = $derived(config.data?.captcha.siteKey ?? '');

  const ACCOUNT_ID_LEN = 32;
  const digitsOnly = $derived(accountId.replace(/\D/g, '').slice(0, ACCOUNT_ID_LEN));

  const LoginResult = z.object({
    ok: z.boolean(),
    popSessionToken: z.string().optional(),
    lapsedDowngrade: z.boolean().optional(),
  });

  const login = createMutation(() => ({
    mutationFn: () =>
      apiClient.post(
        '/api/v1/auth/account-login',
        { accountId: digitsOnly, captchaToken: token! },
        LoginResult,
      ),
    onSuccess: async (res) => {
      // Server auto-downgraded a lapsed membership → stash a one-time flag so
      // /account shows the "membership expired" banner once. (Review #4.)
      if (res?.lapsedDowngrade) {
        try {
          sessionStorage.setItem('fs_lapsed_downgrade', '1');
        } catch {
          /* private mode / storage disabled — the banner just won't show */
        }
      }
      // The cookie is set; refresh identity-derived caches before navigating.
      await queryClient.invalidateQueries({ queryKey: queryKeys.me });
      await queryClient.invalidateQueries({ queryKey: queryKeys.account });
      toast.success(t('login.success'));
      router.navigate('/account');
    },
    onError: (err) => {
      toast.error(t('login.failed'), { description: apiErrorMessage(err) });
    },
  }));

  function onInput(e: Event) {
    // Normalize non-ASCII digits, then keep what the user typed (incl. their own
    // spaces) — no reformat, so the caret stays put.
    accountId = normalizeDigits((e.currentTarget as HTMLInputElement).value);
  }
  function onBlur() {
    // Tidy into groups of 4 once focus leaves (purely cosmetic).
    accountId = digitsOnly.replace(/(\d{4})(?=\d)/g, '$1 ');
  }

  let canSubmit = $derived(digitsOnly.length === ACCOUNT_ID_LEN && !!token && !login.isPending);

  // Account.svelte bounces a 401'd member here with ?expired=1; surface a calm
  // explanation rather than dropping them on a bare form with no context.
  let sessionExpired = $derived(router.searchParams.get('expired') === '1');
</script>

<div class="max-w-md mx-auto py-10 md:py-16 space-y-8">
  <header class="text-center space-y-3">
    <div
      class="inline-flex items-center gap-2 rounded-full border border-primary/30 bg-primary/5 text-primary px-3 py-1 text-xs font-semibold uppercase tracking-wider"
    >
      <LogIn class="size-3.5" />
      {t('nav.signIn')}
    </div>
    <h1
      class="text-3xl md:text-4xl font-display font-bold tracking-tight bg-gradient-to-br from-foreground to-foreground/70 bg-clip-text text-transparent"
    >
      {t('login.title')}
    </h1>
    <p class="text-sm text-muted-foreground">
      {t('login.subtitle')}
    </p>
  </header>

  {#if sessionExpired}
    <div
      class="rounded-md border border-primary/30 bg-primary/5 px-3 py-2 text-sm text-muted-foreground"
      role="status"
    >
      {t('login.sessionExpired')}
    </div>
  {/if}

  <div class="rounded-xl border border-border bg-card p-6 md:p-8 space-y-5">
    <div class="space-y-2">
      <label
        for="account-number"
        class="text-xs uppercase tracking-wider text-muted-foreground font-semibold"
      >
        {t('login.label')}
      </label>
      <!-- A hidden, stable "username" so password managers index this credential
           as a saveable entry (the account number is the "password"). -->
      <input
        type="text"
        name="username"
        autocomplete="username"
        value="freesocks-account"
        readonly
        tabindex="-1"
        aria-hidden="true"
        class="sr-only"
      />
      <div class="relative">
        <input
          id="account-number"
          type={reveal ? 'text' : 'password'}
          inputmode="numeric"
          autocomplete="current-password"
          spellcheck="false"
          placeholder="1234 5678 9012 3456 7890 1234 5678 9012"
          value={accountId}
          oninput={onInput}
          onblur={onBlur}
          onkeydown={(e) => {
            if (e.key === 'Enter' && canSubmit) login.mutate();
          }}
          class="min-h-11 w-full rounded-md border border-border bg-background px-3 py-2.5 pe-10 font-mono text-base tracking-wider tabular-nums focus:outline-none focus:ring-2 focus:ring-primary"
        />
        <button
          type="button"
          onclick={() => (reveal = !reveal)}
          class="absolute inset-y-0 end-0 flex items-center px-3 text-muted-foreground hover:text-foreground"
          aria-label={reveal ? t('login.hide') : t('login.show')}
        >
          {#if reveal}<EyeOff class="size-4" />{:else}<Eye class="size-4" />{/if}
        </button>
      </div>
      <!-- Why-is-the-button-disabled feedback: a partial paste otherwise leaves
           a dead submit button with no explanation. aria-live so screen readers
           hear the progress without polling. -->
      {#if digitsOnly.length > 0 && digitsOnly.length < ACCOUNT_ID_LEN}
        <p class="text-xs text-muted-foreground tabular-nums" aria-live="polite">
          {t('login.digitProgress', { count: digitsOnly.length, total: ACCOUNT_ID_LEN })}
        </p>
      {/if}
    </div>

    <CapWidget
      apiEndpoint={captchaEndpoint}
      siteKey={captchaSiteKey}
      onVerify={(tok) => (token = tok || null)}
    />

    {#if login.error}
      <InlineError message={apiErrorMessage(login.error)} />
    {/if}

    <Button onclick={() => login.mutate()} disabled={!canSubmit} size="lg" class="w-full min-h-11">
      <LogIn class="size-4" />
      {login.isPending ? t('login.submitting') : t('login.submit')}
    </Button>
  </div>

  <p class="text-xs text-muted-foreground text-center">
    {t('login.noAccount')}{' '}
    <Link href="/get-account" class="text-primary underline">{t('login.getOne')}</Link>
  </p>
</div>
