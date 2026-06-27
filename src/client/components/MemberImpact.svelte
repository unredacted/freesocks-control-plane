<script lang="ts">
  import Heart from '@lucide/svelte/icons/heart';
  import { t } from '../lib/i18n/index.svelte';

  /**
   * Brief framing card explaining how the service is funded. We deliberately
   * don't enumerate specific programs / impact items here, since doing so
   * requires knowing the real allocation, which lives on the Unredacted
   * website itself. We just link there. Membership upgrades are a live,
   * self-service flow (UpgradeMembership / GiftCodes panels); this card is
   * only the donation + nonprofit framing.
   */
</script>

<section class="rounded-xl border border-border bg-card p-6 md:p-8 space-y-4">
  <div class="flex items-start gap-3">
    <div class="rounded-full bg-primary/10 p-2 text-primary shrink-0" aria-hidden="true">
      <Heart class="size-5" />
    </div>
    <div>
      <h2 class="text-xl font-display font-bold tracking-tight">{t('impact.title')}</h2>
      <p class="text-sm text-muted-foreground mt-1 max-w-xl leading-relaxed">
        {t('impact.body')}
      </p>
    </div>
  </div>

  <div class="pt-2 flex flex-wrap gap-3">
    <a href="https://unredacted.org/donate" target="_blank" rel="noopener noreferrer">
      <span
        class="inline-flex items-center gap-1.5 text-sm underline hover:text-foreground text-muted-foreground"
      >
        {t('renew.donate')}
      </span>
    </a>
    <a href="https://unredacted.org" target="_blank" rel="noopener noreferrer">
      <span
        class="inline-flex items-center gap-1.5 text-sm underline hover:text-foreground text-muted-foreground"
      >
        unredacted.org
      </span>
    </a>
  </div>
</section>
