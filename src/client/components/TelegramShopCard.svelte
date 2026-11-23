<script lang="ts">
  /**
   * The official Telegram gift shop, shown only while the bot would answer as
   * open: `publicConfig.telegram` is null otherwise (shop off, nothing to sell,
   * or the webhook not registered for the saved token), and then this renders
   * nothing. The bot username is the one set on Admin -> Billing -> Telegram
   * gift shop, read live from the config.
   *
   * It names the exact @username so buyers can tell the real bot from copies,
   * and links it twice: `tg://resolve` opens the Telegram app directly (it
   * works where t.me is blocked), and t.me is the web fallback. No Stars
   * prices here: the bot is the one place prices appear.
   */
  import { configQuery } from '../lib/queries';
  import { t } from '../lib/i18n/index.svelte';
  import { copyText } from '../lib/utils';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import Send from '@lucide/svelte/icons/send';
  import Copy from '@lucide/svelte/icons/copy';
  import ShieldCheck from '@lucide/svelte/icons/shield-check';

  interface Props {
    /** `full`: the Home card. `compact`: a few lines inside another card. */
    variant?: 'full' | 'compact';
  }
  let { variant = 'full' }: Props = $props();

  const config = configQuery();
  const bot = $derived(config.data?.telegram?.botUsername ?? null);
  const appUrl = $derived(bot ? `tg://resolve?domain=${encodeURIComponent(bot)}` : '');
  const webUrl = $derived(bot ? `https://t.me/${encodeURIComponent(bot)}` : '');

  async function copyHandle() {
    if (!bot) return;
    if (await copyText(`@${bot}`)) toast.success(t('common.copied'));
    else toast.error(t('common.copyFailed'));
  }
</script>

{#snippet handle(size: 'lg' | 'sm')}
  <div class="flex items-center gap-2">
    <bdi
      dir="ltr"
      class="min-w-0 break-all rounded-md border border-border bg-muted/40 px-2.5 py-1.5 font-mono font-semibold text-foreground {size ===
      'lg'
        ? 'text-lg'
        : 'text-sm'}"
    >
      @{bot}
    </bdi>
    <Button
      variant="ghost"
      size="icon"
      class="size-11 shrink-0"
      aria-label={t('telegramShop.copyHandle')}
      title={t('telegramShop.copyHandle')}
      onclick={copyHandle}
    >
      <Copy class="size-4" aria-hidden="true" />
    </Button>
  </div>
{/snippet}

{#snippet links(size: 'lg' | 'sm')}
  <div class="flex flex-wrap gap-3">
    <Button
      href={appUrl}
      size={size === 'lg' ? 'lg' : 'sm'}
      class={size === 'lg' ? 'h-13 px-6 text-[17px]' : ''}
    >
      <Send class="size-4" aria-hidden="true" />
      {t('telegramShop.openApp')}
    </Button>
    <Button
      href={webUrl}
      target="_blank"
      rel="noopener noreferrer"
      size={size === 'lg' ? 'lg' : 'sm'}
      variant="outline"
      class={size === 'lg' ? 'h-13 text-[15px]' : ''}
    >
      {t('telegramShop.openWeb')}
    </Button>
  </div>
{/snippet}

{#if bot}
  {#if variant === 'full'}
    <article
      class="grid gap-8 rounded-lg border-2 border-border bg-background p-[clamp(24px,3vw,32px)] md:grid-cols-2 md:gap-12"
      aria-labelledby="telegram-shop-title"
    >
      <div class="flex flex-col gap-4">
        <span
          class="flex size-12 items-center justify-center rounded-sm bg-primary/15 text-primary"
        >
          <Send class="size-6" aria-hidden="true" />
        </span>
        <h3
          id="telegram-shop-title"
          class="font-display text-[30px] font-bold leading-tight tracking-[-0.02em] text-foreground rtl:tracking-normal"
        >
          {t('telegramShop.title')}
        </h3>
        <p class="max-w-[30em] text-[17px] leading-relaxed text-body">
          {t('telegramShop.body')}
        </p>
        <div class="space-y-2">
          <p class="flex items-center gap-2 text-sm font-medium text-foreground">
            <ShieldCheck class="size-4 text-primary" aria-hidden="true" />
            {t('telegramShop.officialLabel')}
          </p>
          {@render handle('lg')}
          <p class="max-w-[34em] text-sm text-muted-foreground">
            {t('telegramShop.officialNote')}
          </p>
        </div>
        <div class="mt-auto pt-2">{@render links('lg')}</div>
      </div>

      <div class="flex flex-col gap-4">
        <h4 class="font-display text-lg font-semibold text-foreground">
          {t('telegramShop.stepsTitle')}
        </h4>
        <ol class="space-y-3 text-[15px] leading-relaxed text-body">
          {#each ['step1', 'step2', 'step3'] as const as step, i (step)}
            <li class="flex gap-3">
              <span
                class="flex size-7 shrink-0 items-center justify-center rounded-full bg-primary/15 text-sm font-semibold text-primary"
                aria-hidden="true"
              >
                {i + 1}
              </span>
              <span>{t(`telegramShop.${step}`)}</span>
            </li>
          {/each}
        </ol>
        <p class="text-sm text-muted-foreground">{t('telegramShop.privacy')}</p>
      </div>
    </article>
  {:else}
    <div class="space-y-2 rounded-md border border-border bg-muted/20 p-3">
      <p class="text-sm text-muted-foreground">{t('telegramShop.compact')}</p>
      {@render handle('sm')}
      <p class="text-xs text-muted-foreground">{t('telegramShop.officialNote')}</p>
      {@render links('sm')}
    </div>
  {/if}
{/if}
