<script lang="ts">
  import ShieldCheck from '@lucide/svelte/icons/shield-check';
  import Zap from '@lucide/svelte/icons/zap';
  import Check from '@lucide/svelte/icons/check';
  import type { Component } from 'svelte';
  import { t, type MessageKey } from '../lib/i18n/index.svelte';

  /**
   * "What matters most to you?" picker — the member-facing connection-mode
   * (transport) choice. DATA-DRIVEN off the public mode catalog (`modes`); the
   * one the server recommends (country-based) carries a "Recommended" badge.
   *
   * Two behaviors, driven by `serverBacked`:
   *  - serverBacked=false (no placement pool bound yet, or no subscription): the
   *    choice is a client-side presentation preference only. Picking calls
   *    `onChoose` and the parent persists it locally.
   *  - serverBacked=true: picking a different mode re-issues the member's key into
   *    that mode's least-loaded node (server-authoritative). `onChoose` opens the
   *    parent's confirm dialog; localStorage is only an optimistic hint.
   *
   * Copy resolves per mode: admin-set catalog label/description (verbatim, all
   * locales) → the built-in i18n key for a known mode → the id as a last resort.
   * So a novel mode with no i18n key just needs an admin-set label.
   */
  interface Mode {
    id: string;
    deliveryStyle: 'url' | 'rawConfig';
    label: string | null;
    description: string | null;
    isDefault: boolean;
    available: boolean;
  }
  interface Props {
    /** The public mode catalog (config.connectionModes). */
    modes: Mode[];
    /** Highlighted current choice (the parent passes the optimistic-or-server id). */
    selected: string;
    /** Server's country-based recommendation id, badged. */
    suggested?: string | null;
    /** True once a placement pool is bound AND the member has a sub to re-issue. */
    serverBacked?: boolean;
    /** True while a switch is in flight (disables the buttons). */
    busy?: boolean;
    /** Called when the member picks a mode other than the current one. */
    onChoose: (modeId: string) => void;
    /** Sign-up context: the pick persists to the account + shapes the first key
     *  (no re-issue yet), so show sign-up-specific copy. */
    signup?: boolean;
  }
  let {
    modes,
    selected,
    suggested = null,
    serverBacked = false,
    busy = false,
    onChoose,
    signup = false,
  }: Props = $props();

  // Built-in copy + icon for the shipped modes, keyed by id. A mode not listed
  // here (a future addition) relies on the admin-set catalog label/description.
  const KNOWN: Record<string, { icon: Component; titleKey: MessageKey; bodyKey: MessageKey }> = {
    evade: { icon: Zap, titleKey: 'delivery.evadeTitle', bodyKey: 'delivery.evadeBody' },
    privacy: {
      icon: ShieldCheck,
      titleKey: 'delivery.privacyTitle',
      bodyKey: 'delivery.privacyBody',
    },
  };

  function modeTitle(m: Mode): string {
    if (m.label?.trim()) return m.label;
    return KNOWN[m.id] ? t(KNOWN[m.id]!.titleKey) : m.id;
  }
  function modeBody(m: Mode): string {
    if (m.description?.trim()) return m.description;
    return KNOWN[m.id] ? t(KNOWN[m.id]!.bodyKey) : '';
  }
  function modeIcon(m: Mode): Component {
    return KNOWN[m.id]?.icon ?? Zap;
  }

  // In server mode an unbound mode can't meaningfully be chosen (it would fall
  // back to the tier squad); disable it unless it's the current selection.
  function isDisabled(m: Mode): boolean {
    if (busy) return true;
    if (serverBacked && m.id !== selected && !m.available) return true;
    return false;
  }

  function choose(m: Mode) {
    if (isDisabled(m) || m.id === selected) return;
    onChoose(m.id);
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
    {#each modes as m (m.id)}
      {@const disabled = isDisabled(m)}
      {@const Icon = modeIcon(m)}
      <button
        type="button"
        onclick={() => choose(m)}
        {disabled}
        aria-pressed={selected === m.id}
        title={disabled && serverBacked && m.id !== selected && !m.available
          ? t('delivery.unavailable')
          : undefined}
        class="relative rounded-lg border p-4 text-start transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-60 {selected ===
        m.id
          ? 'border-primary bg-primary/5 ring-1 ring-primary/30'
          : 'border-border hover:border-primary/40'}"
      >
        <div class="flex items-center justify-between gap-2">
          <span class="flex items-center gap-2 text-sm font-semibold">
            <Icon class="size-4 shrink-0 text-primary" />
            {modeTitle(m)}
          </span>
          {#if suggested === m.id}
            <span
              class="rounded-full bg-primary/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-primary"
            >
              {t('delivery.recommended')}
            </span>
          {:else if selected === m.id}
            <Check class="size-4 shrink-0 text-primary" />
          {/if}
        </div>
        <p class="mt-1 text-xs text-muted-foreground">{modeBody(m)}</p>
      </button>
    {/each}
  </div>
</section>
