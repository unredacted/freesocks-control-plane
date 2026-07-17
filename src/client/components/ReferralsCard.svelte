<script lang="ts">
  /**
   * The member's referral card: their share link + invite stats. Word-of-mouth
   * is the realistic growth channel for this audience; the card makes sharing
   * one tap. Rendered only when the program is enabled (publicConfig gate);
   * the stats read lazily mints the member's code server-side (older accounts
   * get one on first view). Chromeless (`flat`-style): the caller provides the
   * surrounding surface.
   */
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import Copy from '@lucide/svelte/icons/copy';
  import Check from '@lucide/svelte/icons/check';
  import { t } from '../lib/i18n/index.svelte';
  import { accountReferralsQuery, configQuery } from '../lib/queries';
  import { copyText } from '../lib/utils';
  import { toast } from 'svelte-sonner';

  const config = configQuery();
  const enabled = $derived(config.data?.referrals?.enabled ?? false);
  const vestingDays = $derived(config.data?.referrals?.vestingDays ?? 30);
  const referrals = accountReferralsQuery(() => enabled);

  // The share URL is built from our own origin (the subscriptionDisplayUrl
  // pattern) so no deployment-origin env is needed.
  const shareUrl = $derived(
    referrals.data?.code ? `${window.location.origin}/?ref=${referrals.data.code}` : null,
  );

  let copied = $state(false);
  async function copyLink() {
    if (!shareUrl) return;
    if (await copyText(shareUrl)) {
      copied = true;
      toast.success(t('common.copied'), { duration: 1500 });
      setTimeout(() => (copied = false), 1500);
    } else {
      toast.error(t('common.copyFailed'));
    }
  }
</script>

{#if enabled}
  <div class="space-y-4">
    <p class="text-sm text-muted-foreground">
      {t('referral.cardBody', { vestingDays })}
    </p>

    {#if referrals.isPending}
      <Skeleton class="h-11 w-full" />
    {:else if shareUrl}
      <div class="flex gap-2">
        <code
          class="min-w-0 flex-1 select-all truncate rounded-md border border-border bg-muted/40 px-3 py-2 font-mono text-xs leading-6"
        >
          {shareUrl}
        </code>
        <Button variant="outline" size="sm" class="min-h-11 shrink-0" onclick={copyLink}>
          {#if copied}
            <Check class="size-3.5" />
          {:else}
            <Copy class="size-3.5" />
          {/if}
          <span class="hidden sm:inline">{t('referral.copyLink')}</span>
        </Button>
      </div>
      <p class="text-xs text-muted-foreground">
        {t('referral.codeLabel')}: <span class="font-mono">{referrals.data?.code}</span>
      </p>
    {/if}

    {#if referrals.data?.stats}
      {@const s = referrals.data.stats}
      <dl class="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div class="rounded-lg border border-border px-3 py-2">
          <dt class="text-[11px] text-muted-foreground">{t('referral.statsInvited')}</dt>
          <dd class="text-lg font-semibold tabular-nums">{s.invited}</dd>
        </div>
        <div class="rounded-lg border border-border px-3 py-2">
          <dt class="text-[11px] text-muted-foreground">{t('referral.statsConverted')}</dt>
          <dd class="text-lg font-semibold tabular-nums">{s.converted}</dd>
        </div>
        <div class="rounded-lg border border-border px-3 py-2">
          <dt class="text-[11px] text-muted-foreground">{t('referral.statsPending')}</dt>
          <dd class="text-lg font-semibold tabular-nums">{s.pending}</dd>
        </div>
        <div class="rounded-lg border border-border px-3 py-2">
          <dt class="text-[11px] text-muted-foreground">{t('referral.statsDays')}</dt>
          <dd class="text-lg font-semibold tabular-nums">{s.bonusDaysEarned}</dd>
        </div>
      </dl>
    {/if}
  </div>
{/if}
