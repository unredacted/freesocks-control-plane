<script lang="ts">
  import { Button } from '@client/components/ui/button';
  import Heart from '@lucide/svelte/icons/heart';
  import UserRound from '@lucide/svelte/icons/user-round';
  import EyeOff from '@lucide/svelte/icons/eye-off';
  import Loader2 from '@lucide/svelte/icons/loader-2';
  import CircleCheck from '@lucide/svelte/icons/circle-check';
  import Link from '../components/Link.svelte';
  import DonateCard from '../components/DonateCard.svelte';
  import MemberImpact from '../components/MemberImpact.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { meQuery, configQuery, billingOrderQuery } from '../lib/queries';
  import { router } from '../stores/router.svelte';

  /**
   * Public donate page: the one URL every donate CTA points an ANONYMOUS
   * visitor at (a signed-in member's CTAs keep going to the account Membership
   * tab, where their gift also earns the badge).
   *
   * Signed out, it offers the explicit choice: sign in first (the gift lands on
   * your account - badge + history) or donate anonymously (no account at all;
   * the checkout is captcha-gated and the order carries no user). Signed-in
   * visitors who land here anyway just get the normal authed card.
   *
   * Also the RETURN page for anonymous checkouts (?order=<ref>): the processor
   * can't send a session-less payer back to /account, so the poll runs here via
   * the same order endpoint, which answers for anonymous donation orders on the
   * strength of the unguessable ref alone.
   */
  const me = meQuery();
  const config = configQuery();

  let billing = $derived(config.data?.billing);
  let donationsLive = $derived(
    !!billing?.enabled &&
      !!billing.donation?.enabled &&
      Object.values(billing.rails ?? {}).some(Boolean),
  );
  let windowDays = $derived(billing?.donation?.bonusWindowDays ?? 30);
  let authed = $derived(!!me.data?.authenticated);

  // Post-payment return (?order=<ref>): poll until terminal, exactly like the
  // /account return leg - but session-less-capable.
  let orderRef = $derived(router.searchParams.get('order'));
  const order = billingOrderQuery(() => orderRef);
  function clearOrder() {
    router.navigate('/donate', { replace: true });
  }

  // The signed-out fork: nothing chosen → the two options; 'anon' → the
  // captcha-gated card. ("Sign in" is a plain link; Login returns here.)
  let anonChosen = $state(false);
</script>

<div class="max-w-2xl mx-auto py-8 md:py-12 space-y-8">
  <header class="space-y-2 text-center">
    <h1
      class="flex items-center justify-center gap-2.5 text-3xl md:text-4xl font-display font-bold tracking-tight"
    >
      <Heart class="size-7 text-amber-500" aria-hidden="true" />
      {t('donate.pageTitle')}
    </h1>
    <p class="mx-auto max-w-xl text-muted-foreground">
      {t('donate.pageIntro', { days: windowDays })}
    </p>
  </header>

  {#if orderRef}
    <!-- RETURN STATE: the processor sent the donor back here. -->
    {#if order.data?.status === 'paid'}
      <section
        class="space-y-3 rounded-xl border border-primary/40 bg-primary/5 p-6 text-center md:p-8"
      >
        <CircleCheck class="mx-auto size-8 text-primary" aria-hidden="true" />
        <h2 class="font-display text-xl font-semibold">{t('donate.paidTitle')}</h2>
        <p class="text-sm text-muted-foreground">
          {t('donate.paidBody', { days: windowDays })}
        </p>
        <Button variant="outline" class="min-h-11" onclick={clearOrder}>
          {t('common.close')}
        </Button>
      </section>
    {:else if order.isError || order.data?.status === 'failed' || order.data?.status === 'expired'}
      <section
        class="space-y-3 rounded-xl border border-destructive/40 bg-destructive/10 p-6 text-center md:p-8"
      >
        <h2 class="font-display text-xl font-semibold">{t('upgrade.failedTitle')}</h2>
        <p class="text-sm text-muted-foreground">{t('donate.orderFailedBody')}</p>
        <Button variant="outline" class="min-h-11" onclick={clearOrder}>
          {t('common.retry')}
        </Button>
      </section>
    {:else}
      <section class="rounded-xl border border-primary/30 bg-primary/5 p-6 md:p-8">
        <p class="flex items-center gap-2 text-sm font-semibold">
          <Loader2 class="size-4 animate-spin text-primary" aria-hidden="true" />
          {t('upgrade.confirmingTitle')}
        </p>
        <p class="mt-1 text-sm text-muted-foreground">{t('upgrade.confirmingBody')}</p>
      </section>
    {/if}
  {:else if config.data && !donationsLive}
    <!-- Donations disabled on this deployment: an honest note, not a dead form. -->
    <p class="text-center text-sm text-muted-foreground">{t('donate.unavailable')}</p>
  {:else if authed}
    <DonateCard />
  {:else if anonChosen}
    <div class="space-y-3">
      <DonateCard anonymous />
      <p class="text-center text-xs text-muted-foreground">
        <Link href="/login?returnTo=/donate" class="underline hover:text-foreground">
          {t('donate.signInInstead')}
        </Link>
      </p>
    </div>
  {:else if config.data}
    <!-- SIGNED-OUT FORK: sign in (gift lands on your account) or stay anonymous. -->
    <section class="grid gap-3 sm:grid-cols-2">
      <Link
        href="/login?returnTo=/donate"
        class="group rounded-xl border border-border bg-card p-5 text-start transition hover:border-primary/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <span class="flex items-center gap-2 text-sm font-semibold">
          <UserRound class="size-4 shrink-0 text-primary" aria-hidden="true" />
          {t('donate.signInTitle')}
        </span>
        <span class="mt-1.5 block text-xs text-muted-foreground">
          {t('donate.signInBody')}
        </span>
      </Link>
      <button
        type="button"
        onclick={() => (anonChosen = true)}
        class="rounded-xl border border-border bg-card p-5 text-start transition hover:border-primary/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <span class="flex items-center gap-2 text-sm font-semibold">
          <EyeOff class="size-4 shrink-0 text-primary" aria-hidden="true" />
          {t('donate.anonTitle')}
        </span>
        <span class="mt-1.5 block text-xs text-muted-foreground">
          {t('donate.anonBody')}
        </span>
      </button>
    </section>
  {/if}

  <!-- What donations are doing right now (collective stats + the dated gift
       list). Renders fine anonymously - the personal block simply stays absent. -->
  {#if donationsLive}
    <MemberImpact />
  {/if}
</div>
