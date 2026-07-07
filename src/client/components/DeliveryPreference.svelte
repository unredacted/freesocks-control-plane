<script lang="ts">
  import ShieldCheck from '@lucide/svelte/icons/shield-check';
  import Zap from '@lucide/svelte/icons/zap';
  import Check from '@lucide/svelte/icons/check';
  import { t } from '../lib/i18n/index.svelte';

  /**
   * "What matters most to you?" picker — the member-facing connection profile
   * (transport) choice. Both options are always shown; the one the server
   * recommends (country-based) carries a "Recommended" badge.
   *
   * Two modes, driven by `serverBacked`:
   *  - serverBacked=false (no profile squad bound yet, or no subscription): the
   *    choice is a client-side presentation preference only (which delivery panels
   *    lead). Picking calls `onChoose` and the parent persists it locally.
   *  - serverBacked=true: picking a different option re-issues the member's key
   *    into that profile's Remnawave squad (server-authoritative). `onChoose`
   *    opens the parent's confirm dialog; localStorage is only an optimistic hint.
   */
  interface Props {
    /** Highlighted current choice (the parent passes the optimistic-or-server value). */
    selected: 'privacy' | 'evade';
    /** Server's country-based recommendation, badged. */
    suggested?: 'privacy' | 'evade';
    /** True once a profile squad is bound AND the member has a subscription to re-issue. */
    serverBacked?: boolean;
    /** Per-option availability (its squad is bound) — used to disable an unbound
     *  option in server mode. Ignored when serverBacked is false. */
    available?: { evade: boolean; privacy: boolean };
    /** True while a switch is in flight (disables the buttons). */
    busy?: boolean;
    /** Called when the member picks an option other than the current one. */
    onChoose: (mode: 'privacy' | 'evade') => void;
    /** Sign-up context: the pick persists to the account + shapes the first key
     *  (no re-issue yet), so show sign-up-specific copy. */
    signup?: boolean;
    /** Admin-set copy from the public profile catalog. A non-empty title/body
     *  overrides the translated i18n copy verbatim (all locales, by design);
     *  null/absent keeps the i18n default. */
    overrides?: Partial<
      Record<'privacy' | 'evade', { title?: string | null; body?: string | null }>
    >;
  }
  let {
    selected,
    suggested = 'evade',
    serverBacked = false,
    available = { evade: true, privacy: true },
    busy = false,
    onChoose,
    signup = false,
    overrides = {},
  }: Props = $props();

  const OPTIONS = [
    { mode: 'evade', icon: Zap, titleKey: 'delivery.evadeTitle', bodyKey: 'delivery.evadeBody' },
    {
      mode: 'privacy',
      icon: ShieldCheck,
      titleKey: 'delivery.privacyTitle',
      bodyKey: 'delivery.privacyBody',
    },
  ] as const;

  function optTitle(mode: 'privacy' | 'evade', titleKey: Parameters<typeof t>[0]): string {
    const o = overrides[mode]?.title;
    return o?.trim() ? o : t(titleKey);
  }
  function optBody(mode: 'privacy' | 'evade', bodyKey: Parameters<typeof t>[0]): string {
    const o = overrides[mode]?.body;
    return o?.trim() ? o : t(bodyKey);
  }

  // In server mode a not-yet-bound option can't meaningfully be chosen (it would
  // fall back to the same squad); disable it unless it's the current selection.
  function isDisabled(mode: 'privacy' | 'evade'): boolean {
    if (busy) return true;
    if (serverBacked && mode !== selected && !available[mode]) return true;
    return false;
  }

  function choose(mode: 'privacy' | 'evade') {
    if (isDisabled(mode) || mode === selected) return;
    onChoose(mode);
  }
</script>

<section class="space-y-3 rounded-xl border border-border bg-card p-4 sm:p-5">
  <div>
    <h2 class="font-display text-base font-semibold">{t('delivery.title')}</h2>
    <p class="text-sm text-muted-foreground">
      {signup
        ? t('delivery.subtitleSignup')
        : serverBacked
          ? t('delivery.subtitleServer')
          : t('delivery.subtitle')}
    </p>
  </div>
  <div class="grid gap-3 sm:grid-cols-2">
    {#each OPTIONS as opt (opt.mode)}
      {@const disabled = isDisabled(opt.mode)}
      <button
        type="button"
        onclick={() => choose(opt.mode)}
        {disabled}
        aria-pressed={selected === opt.mode}
        title={disabled && serverBacked && opt.mode !== selected && !available[opt.mode]
          ? t('delivery.unavailable')
          : undefined}
        class="relative rounded-lg border p-4 text-start transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-60 {selected ===
        opt.mode
          ? 'border-primary bg-primary/5 ring-1 ring-primary/30'
          : 'border-border hover:border-primary/40'}"
      >
        <div class="flex items-center justify-between gap-2">
          <span class="flex items-center gap-2 text-sm font-semibold">
            <opt.icon class="size-4 shrink-0 text-primary" />
            {optTitle(opt.mode, opt.titleKey)}
          </span>
          {#if suggested === opt.mode}
            <span
              class="rounded-full bg-primary/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-primary"
            >
              {t('delivery.recommended')}
            </span>
          {:else if selected === opt.mode}
            <Check class="size-4 shrink-0 text-primary" />
          {/if}
        </div>
        <p class="mt-1 text-xs text-muted-foreground">{optBody(opt.mode, opt.bodyKey)}</p>
      </button>
    {/each}
  </div>
</section>
