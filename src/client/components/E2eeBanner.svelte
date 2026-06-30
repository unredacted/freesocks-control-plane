<script lang="ts">
  import ShieldCheck from '@lucide/svelte/icons/shield-check';
  import ShieldAlert from '@lucide/svelte/icons/shield-alert';
  import LockIcon from '@lucide/svelte/icons/lock';
  import { t } from '../lib/i18n/index.svelte';
  import E2eeVerifyModal from './E2eeVerifyModal.svelte';

  /**
   * Persistent top-of-app E2EE status indicator (covers member + admin — mounted
   * once in App.svelte above the route chrome). "Configured" is a COMPILE-TIME
   * read of the baked pins (same as api.ts E2EE_ENABLED), so a dark build
   * tree-shakes this branch and never pulls the heavy e2ee chunk. When configured,
   * a one-shot READ-ONLY live attestation downgrades the banner to a warning ONLY
   * if the key endpoint is reachable but its key fails to verify (the meaningful
   * active-CDN tamper signal) — a mere network blip does not alarm. Honest framing:
   * the bar links to the Verify panel where the real off-CDN guarantee lives.
   */
  const enabled =
    !!import.meta.env.VITE_FS_SERVER_HPKE_PK && !!import.meta.env.VITE_FS_SERVER_HPKE_KID;

  let bannerState = $state<'active' | 'warn'>('active'); // optimistic; only downgrades
  let showVerify = $state(false);

  $effect(() => {
    if (!enabled) return;
    void import('../lib/e2ee').then(async (m) => {
      const att = await m.verifyConnection();
      if (att.reachable && !att.attested) bannerState = 'warn';
    });
  });
</script>

{#if enabled}
  <div
    role={bannerState === 'warn' ? 'alert' : undefined}
    class="flex items-center justify-center gap-2 border-b px-3 py-1.5 text-xs {bannerState ===
    'warn'
      ? 'border-destructive/40 bg-destructive/10 text-destructive'
      : 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400'}"
  >
    {#if bannerState === 'warn'}
      <ShieldAlert class="size-4 shrink-0" />
      <span class="font-medium">{t('e2ee.bannerWarn')}</span>
      <span class="hidden text-muted-foreground sm:inline">· {t('e2ee.bannerWarnDetail')}</span>
    {:else}
      <ShieldCheck class="size-4 shrink-0" />
      <span class="font-medium">{t('e2ee.bannerActive')}</span>
      <span class="hidden text-muted-foreground sm:inline">· {t('e2ee.bannerActiveDetail')}</span>
    {/if}
    <button
      type="button"
      class="font-medium underline underline-offset-2 hover:no-underline"
      onclick={() => (showVerify = true)}
    >
      {t('e2ee.verify')}
    </button>
  </div>
  <E2eeVerifyModal bind:open={showVerify} />
{:else}
  <div
    class="flex items-center justify-center gap-2 border-b border-border bg-muted/50 px-3 py-1.5 text-xs text-muted-foreground"
  >
    <LockIcon class="size-3.5 shrink-0" />
    <span>{t('e2ee.bannerOff')}</span>
  </div>
{/if}
