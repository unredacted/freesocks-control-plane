<script lang="ts">
  import ShieldCheck from '@lucide/svelte/icons/shield-check';
  import ShieldAlert from '@lucide/svelte/icons/shield-alert';
  import LockIcon from '@lucide/svelte/icons/lock';
  import { t } from '../lib/i18n/index.svelte';
  import { hpkeSession, ensureAttestationChecked, openVerify } from '../lib/hpke-status.svelte';
  import { configQuery } from '../lib/queries';

  /**
   * Compact HPKE status badge for the app chrome (mounted in the member header and
   * the admin sidebar). "Configured" is a COMPILE-TIME read of the baked pins (same
   * as api.ts HPKE_ENABLED), so a dark build tree-shakes the interactive branch and
   * the off pill is all that ships. When configured, a one-shot READ-ONLY live
   * attestation (shared via hpke-status, one fetch per page) turns the badge amber
   * ONLY if the key endpoint is reachable but its key fails to verify (the active-CDN
   * tamper tell); a network blip stays green (the pinned key is still in use). The
   * loud "don't enter your account number" escalation lives in HpkeAlert - this badge
   * is the quiet steady-state signal and the entry point to the Verify panel.
   */
  interface Props {
    /** 'admin' shows deployment-scoped tooltips (admin actions are not in the HPKE layer). */
    context?: 'member' | 'admin';
  }
  let { context = 'member' }: Props = $props();

  // The operator can hide the whole HPKE surface via admin config (default on;
  // undefined while the public config loads → shown, so a normal deployment never
  // flickers the badge away on first paint).
  const cfg = configQuery();
  const show = $derived(cfg.data?.verification?.showPanel ?? true);

  const enabled =
    !!import.meta.env.VITE_FS_SERVER_HPKE_PK && !!import.meta.env.VITE_FS_SERVER_HPKE_KID;

  $effect(() => {
    if (!enabled) return;
    void ensureAttestationChecked();
  });

  // `warn` is the only state that deviates from the green "encrypted" look; pending
  // and unreachable both keep the pinned-key-in-use green (detail is in the panel).
  const warn = $derived(enabled && hpkeSession.attestation === 'warn');

  // Admin tooltips are deployment-scoped ("members' flows are encrypted on this
  // deployment"); member tooltips speak to the current user's own account + key.
  const badgeTitle = $derived(
    context === 'admin'
      ? warn
        ? t('hpke.badgeWarnTitleAdmin')
        : t('hpke.badgeActiveTitleAdmin')
      : warn
        ? t('hpke.badgeWarnTitle')
        : t('hpke.badgeActiveTitle'),
  );
</script>

{#if show}
  {#if enabled}
    <button
      type="button"
      onclick={openVerify}
      title={badgeTitle}
      aria-label={badgeTitle}
      class="inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs font-medium transition-all hover:scale-105 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring {warn
        ? 'border-amber-500/40 bg-amber-500/10 text-amber-600 hover:bg-amber-500/20'
        : 'border-emerald-500/40 bg-emerald-500/10 text-emerald-600 hover:bg-emerald-500/20 dark:text-emerald-400'}"
    >
      {#if warn}
        <ShieldAlert class="size-3.5 shrink-0" />
      {:else}
        <ShieldCheck class="size-3.5 shrink-0" />
      {/if}
      <!-- "HPKE" is a fixed acronym, not localizable text (MT transliterates it),
         so it's hardcoded rather than routed through i18n. -->
      <span>HPKE</span>
    </button>
  {:else}
    <span
      title={t('hpke.badgeOffTitle')}
      class="inline-flex items-center gap-1.5 rounded-md border border-border bg-muted/50 px-2 py-1 text-xs font-medium text-muted-foreground"
    >
      <LockIcon class="size-3.5 shrink-0" />
      <span>{t('hpke.badgeOff')}</span>
    </span>
  {/if}
{/if}
