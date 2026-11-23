<script lang="ts">
  /**
   * Direct crypto checkout: the payment details on FreeSocks' own page, so a
   * payer who can't reach the processor's domain can still pay. Rendered by
   * the order-return pages (Account, Donate) in place of the "waiting" card
   * while the order poll carries `payment`; every other status keeps the
   * existing cards. The details come from our own API (the order poll), the
   * QR is drawn locally (QrCode.svelte), and nothing loads from a third party.
   *
   * Safety copy is deliberate: the network is named next to the amount and
   * again as a warning, a memo gets its own boxed warning, and an expired
   * address says plainly not to send to it.
   */
  import { Button } from '@client/components/ui/button';
  import QrCode from './QrCode.svelte';
  import { copyText } from '../lib/utils';
  import { t } from '../lib/i18n/index.svelte';
  import { toast } from 'svelte-sonner';
  import type { OrderPayment } from '../../shared/contracts/billing';
  import Copy from '@lucide/svelte/icons/copy';
  import Loader2 from '@lucide/svelte/icons/loader-2';
  import TriangleAlert from '@lucide/svelte/icons/triangle-alert';

  interface Props {
    payment: OrderPayment;
    /** 'confirming' = a payment was seen: the details shrink to a disclosure. */
    status: 'pending' | 'confirming';
    /** Start over (a fresh checkout) once the address has expired. */
    onRestart: () => void;
  }
  let { payment, status, onRestart }: Props = $props();

  let methodIdx = $state(0);
  // The contract guarantees at least one method (OrderPayment.methods.min(1)).
  let method = $derived(
    payment.methods[
      Math.min(methodIdx, payment.methods.length - 1)
    ] as OrderPayment['methods'][number],
  );

  /** BTCPay carries no network text: its method id says it. */
  function networkOf(m: OrderPayment['methods'][number]): string {
    if (m.network) return m.network;
    if (/-LN$|LightningLike$|LightningNetwork$/i.test(m.id)) return t('direct.lightning');
    if (/^BTC(-CHAIN)?$/i.test(m.id)) return t('direct.bitcoinOnchain');
    return m.id;
  }
  let isLightning = $derived(/-LN$|LightningLike$|LightningNetwork$/i.test(method.id));
  let network = $derived(networkOf(method));

  // Countdown to the processor's deadline (null = it gave none: no timer).
  let now = $state(Date.now());
  $effect(() => {
    const id = setInterval(() => (now = Date.now()), 1000);
    return () => clearInterval(id);
  });
  let expiresMs = $derived(payment.expiresAt ? Date.parse(payment.expiresAt) : null);
  let leftMs = $derived(expiresMs != null ? Math.max(0, expiresMs - now) : null);
  let expired = $derived(leftMs === 0 && status === 'pending');
  function clock(ms: number): string {
    const s = Math.floor(ms / 1000);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    const pad = (n: number) => String(n).padStart(2, '0');
    return h > 0 ? `${h}:${pad(m)}:${pad(sec)}` : `${m}:${pad(sec)}`;
  }

  async function copy(value: string) {
    if (await copyText(value)) toast.success(t('common.copied'));
  }
</script>

{#snippet field(label: string, value: string, mono: boolean)}
  <div class="space-y-1">
    <div class="text-xs font-medium text-muted-foreground">{label}</div>
    <div class="flex items-start gap-2">
      <code
        class="min-w-0 flex-1 break-all rounded-md border border-border bg-muted/40 px-2.5 py-2 text-sm {mono
          ? 'font-mono'
          : 'font-semibold tabular-nums'}"
        dir="ltr">{value}</code
      >
      <Button
        variant="outline"
        size="icon"
        class="size-10 shrink-0"
        onclick={() => copy(value)}
        aria-label={t('direct.copyLabel', { what: label })}
      >
        <Copy class="size-4" aria-hidden="true" />
      </Button>
    </div>
  </div>
{/snippet}

{#snippet details()}
  {#if payment.methods.length > 1}
    <div class="flex flex-wrap gap-2" role="group" aria-label={t('direct.methodLabel')}>
      {#each payment.methods as m, i (m.id)}
        <button
          type="button"
          onclick={() => (methodIdx = i)}
          aria-pressed={methodIdx === i}
          class="rounded-lg border px-3 py-1.5 text-sm font-semibold transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring {methodIdx ===
          i
            ? 'border-primary bg-primary/5 ring-1 ring-primary/30'
            : 'border-border hover:border-primary/40'}"
        >
          {networkOf(m)}
        </button>
      {/each}
    </div>
  {/if}

  <p class="text-sm">
    {t('direct.sendExactly', { amount: method.amount, unit: method.unit, network })}
  </p>
  <p class="flex items-start gap-2 text-xs text-muted-foreground">
    <TriangleAlert class="mt-0.5 size-4 shrink-0 text-amber-500" aria-hidden="true" />
    {isLightning ? t('direct.lightningOnly') : t('direct.networkWarning', { network })}
  </p>

  <div class="grid gap-4 sm:grid-cols-[1fr_auto] sm:items-start">
    <div class="min-w-0 space-y-3">
      {@render field(t('direct.amountLabel', { unit: method.unit }), method.amount, false)}
      {@render field(
        isLightning ? t('direct.invoiceLabel') : t('direct.addressLabel', { network }),
        method.address,
        true,
      )}
      {#if method.memo}
        <div class="space-y-2 rounded-lg border border-amber-500/50 bg-amber-500/10 p-3">
          <p class="flex items-start gap-2 text-sm font-semibold">
            <TriangleAlert class="mt-0.5 size-4 shrink-0 text-amber-500" aria-hidden="true" />
            {t('direct.memoWarning')}
          </p>
          {@render field(t('direct.memoLabel'), method.memo, true)}
        </div>
      {/if}
    </div>
    <div class="flex flex-col items-center gap-1">
      <QrCode text={method.qr} size={176} />
      <span class="text-[0.7rem] text-muted-foreground">
        {method.qr === method.address ? t('direct.qrAddressOnly') : t('direct.qrWithAmount')}
      </span>
    </div>
  </div>

  <p class="text-xs text-muted-foreground">{t('upgrade.exchangeFeeNote')}</p>
{/snippet}

<section
  class="space-y-4 rounded-xl border border-primary/30 bg-card p-4 sm:p-5"
  aria-labelledby="direct-payment-title"
>
  {#if expired}
    <div class="space-y-3">
      <h2 id="direct-payment-title" class="font-display text-base font-semibold">
        {t('direct.expiredTitle')}
      </h2>
      <p class="text-sm text-muted-foreground">{t('direct.expiredBody')}</p>
      <Button class="min-h-11" onclick={onRestart}>{t('direct.startAgain')}</Button>
    </div>
  {:else if status === 'confirming'}
    <div class="space-y-1">
      <p id="direct-payment-title" class="flex items-center gap-2 text-sm font-semibold">
        <Loader2 class="size-4 animate-spin text-primary" aria-hidden="true" />
        {t('upgrade.confirmingTitle')}
      </p>
      <p class="text-sm text-muted-foreground">{t('direct.seenBody')}</p>
    </div>
    <details class="space-y-4">
      <summary class="cursor-pointer text-sm font-medium">{t('direct.showDetails')}</summary>
      <div class="mt-4 space-y-4">{@render details()}</div>
    </details>
  {:else}
    <div class="flex flex-wrap items-start justify-between gap-2">
      <div>
        <h2 id="direct-payment-title" class="font-display text-base font-semibold">
          {t('direct.title')}
        </h2>
        <p class="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 class="size-3.5 animate-spin text-primary" aria-hidden="true" />
          {t('direct.waiting')}
        </p>
      </div>
      {#if leftMs != null}
        <div class="text-end">
          <div class="text-xs text-muted-foreground">{t('direct.timeLeft')}</div>
          <div class="font-mono text-lg font-semibold tabular-nums" dir="ltr" aria-live="off">
            {clock(leftMs)}
          </div>
        </div>
      {/if}
    </div>
    {@render details()}
  {/if}

  <p class="text-xs text-muted-foreground">
    {t('direct.hostedFallback')}
    <a
      href={payment.hostedUrl}
      rel="noreferrer noopener"
      target="_blank"
      class="underline hover:text-foreground">{t('direct.hostedFallbackLink')}</a
    >
  </p>
</section>
