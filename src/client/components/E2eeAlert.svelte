<script lang="ts">
  import ShieldAlert from '@lucide/svelte/icons/shield-alert';
  import { t } from '../lib/i18n/index.svelte';
  import { e2eeSession, openVerify } from '../lib/e2ee-status.svelte';
  import { configQuery } from '../lib/queries';

  // Suppressed along with the badge when the operator hides the E2EE surface.
  const cfg = configQuery();
  const show = $derived(cfg.data?.verification?.showPanel ?? true);

  /**
   * Loud, full-width escalation shown ONLY when the live attestation is reachable
   * but fails to verify (`e2eeSession.attestation === 'warn'`) - the active-CDN
   * tamper tell. The quiet steady-state signal is the header E2eeBadge; this bar
   * exists so "a CDN may be tampering, do NOT enter your account number" is never
   * reduced to a small corner pill. Renders nothing in every other state (including
   * dark builds, where the attestation never leaves 'pending').
   */
</script>

{#if show && e2eeSession.attestation === 'warn'}
  <div
    role="alert"
    class="flex items-center justify-center gap-2 border-b border-destructive/40 bg-destructive/10 px-3 py-1.5 text-xs text-destructive"
  >
    <ShieldAlert class="size-4 shrink-0" />
    <span class="font-medium">{t('e2ee.bannerWarn')}</span>
    <span class="hidden sm:inline">· {t('e2ee.bannerWarnDetail')}</span>
    <button
      type="button"
      class="font-medium underline underline-offset-2 hover:no-underline"
      onclick={openVerify}
    >
      {t('e2ee.verify')}
    </button>
  </div>
{/if}
