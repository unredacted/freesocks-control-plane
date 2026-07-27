<script lang="ts">
  import Check from '@lucide/svelte/icons/check';
  import { t } from '../lib/i18n/index.svelte';
  import {
    FAMILY_COPY,
    familyBody,
    familyIcon,
    familyTitle,
    modeBody,
    modeTitle,
  } from '../lib/connectionModeCopy';
  import {
    familyTargetMode,
    groupModesByFamily,
    withCurrentMode,
    type PickerFamily,
    type PickerMode,
  } from '../lib/connectionModeGroups';

  /**
   * "What matters most to you?" picker - the member-facing connection-mode
   * choice, in TWO levels: a parent FAMILY card (Freedom Mode / Privacy Mode),
   * and inside the selected family a transport SUB-CHOICE (WebSocket / REALITY).
   * A family with a single visible child renders no sub-choice at all, so a
   * one-transport family looks exactly like the old flat card.
   *
   * The hierarchy is presentation only: what `onChoose` emits, and what the
   * server stores, is always a flat LEAF id.
   *
   * Two behaviors, driven by `serverBacked`:
   *  - serverBacked=false (no placement pool bound yet, or no subscription): the
   *    choice is a client-side presentation preference only. Picking calls
   *    `onChoose` and the parent persists it locally.
   *  - serverBacked=true: picking a different mode re-issues the member's key into
   *    that mode's least-loaded node (server-authoritative). `onChoose` opens the
   *    parent's confirm dialog; localStorage is only an optimistic hint.
   *
   * Copy resolves per entry: admin-set catalog label/description (verbatim, all
   * locales) -> the built-in i18n key -> the id as a last resort (see
   * lib/connectionModeCopy).
   */
  // Shapes live with the grouping helpers so the component and its tests agree.
  type Mode = PickerMode;
  type Family = PickerFamily;
  interface Props {
    /** The public LEAF catalog (config.connectionModes). */
    modes: Mode[];
    /** The public FAMILY catalog (config.connectionModeFamilies). */
    families?: Family[];
    /** Highlighted current choice (the parent passes the optimistic-or-server id). */
    selected: string;
    /** Server's country-based recommendation id, badged. */
    suggested?: string | null;
    /** True once a placement pool is bound AND the member has a sub to re-issue. */
    serverBacked?: boolean;
    /** True while a switch is in flight (disables the controls). */
    busy?: boolean;
    /** Called when the member picks a mode other than the current one. */
    onChoose: (modeId: string) => void;
    /** Sign-up context: the pick persists to the account + shapes the first key
     *  (no re-issue yet), so show sign-up-specific copy. */
    signup?: boolean;
    /** Chromeless mode: no card frame - the caller provides the surrounding
     *  surface (avoids card-in-card nesting). */
    flat?: boolean;
  }
  let {
    modes,
    families = [],
    selected,
    suggested = null,
    serverBacked = false,
    busy = false,
    onChoose,
    signup = false,
    flat = false,
  }: Props = $props();

  // Grouping rules live in lib/connectionModeGroups (pure + unit-tested): the
  // synthesized entry for an admin-disabled current mode, family collapsing, and
  // orphan handling are all easy to get subtly wrong by eye.
  let visibleModes = $derived(withCurrentMode(modes, selected));
  let groups = $derived(groupModesByFamily(visibleModes, families));
  let selectedGroupIndex = $derived(
    groups.findIndex((g) => g.children.some((m) => m.id === selected)),
  );

  function isDisabled(m: Mode): boolean {
    if (busy) return true;
    // The current selection stays enabled even when unavailable, so a member is
    // never stranded on a mode they cannot move off.
    if (m.id !== selected && !m.available) return true;
    return false;
  }

  function choose(m: Mode) {
    if (isDisabled(m) || m.id === selected) return;
    onChoose(m.id);
  }

  /** Picking a family selects its default transport (or its only/first available
   *  one), so the parent card alone is a complete choice. */
  function chooseGroup(g: { children: Mode[] }) {
    if (g.children.some((m) => m.id === selected)) return;
    const target = familyTargetMode(g.children);
    if (target) choose(target);
  }

  /** Roving focus for the transport radiogroup (same pattern as the backend
   *  chooser on /get-account). Arrow keys move and select; Home/End jump. */
  function onTransportKeydown(e: KeyboardEvent, children: Mode[]) {
    const keys = ['ArrowRight', 'ArrowLeft', 'ArrowDown', 'ArrowUp', 'Home', 'End'];
    if (!keys.includes(e.key)) return;
    e.preventDefault();
    const usable = children.filter((m) => !isDisabled(m) || m.id === selected);
    if (usable.length < 2) return;
    const at = usable.findIndex((m) => m.id === selected);
    // Logical, not physical: ArrowRight advances in reading order, which the
    // browser already mirrors for RTL, so no dir check is needed here.
    let next = at;
    if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = usable.length - 1;
    else if (e.key === 'ArrowRight' || e.key === 'ArrowDown') next = (at + 1) % usable.length;
    else next = (at - 1 + usable.length) % usable.length;
    const target = usable[next];
    if (target && target.id !== selected) choose(target);
  }
</script>

<section
  class={flat ? 'space-y-3' : 'space-y-3 rounded-xl border border-border bg-card p-4 sm:p-5'}
>
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
    {#each groups as g, gi (g.family?.id ?? g.children[0]!.id)}
      {@const isSelectedGroup = gi === selectedGroupIndex}
      {@const Icon = g.family ? familyIcon(g.family) : undefined}
      {@const title = g.family ? familyTitle(g.family) : modeTitle(g.children[0]!)}
      {@const body = g.family ? familyBody(g.family) : modeBody(g.children[0]!)}
      {@const groupSuggested = g.children.some((m) => m.id === suggested)}
      {@const allDisabled = g.children.every((m) => isDisabled(m))}
      <div
        class="rounded-lg border transition {isSelectedGroup
          ? 'border-primary bg-primary/5 ring-1 ring-primary/30'
          : 'border-border'}"
      >
        <button
          type="button"
          onclick={() => chooseGroup(g)}
          disabled={allDisabled}
          aria-pressed={isSelectedGroup}
          class="w-full rounded-lg p-4 text-start transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-60 {isSelectedGroup
            ? ''
            : 'hover:border-primary/40'}"
        >
          <div class="flex items-center justify-between gap-2">
            <span class="flex items-center gap-2 text-sm font-semibold">
              {#if Icon}<Icon class="size-4 shrink-0 text-primary" />{/if}
              {title}
            </span>
            {#if groupSuggested}
              <span
                class="rounded-full bg-primary/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-primary"
              >
                {t('delivery.recommended')}
              </span>
            {:else if isSelectedGroup}
              <Check class="size-4 shrink-0 text-primary" />
            {/if}
          </div>
          {#if g.family && FAMILY_COPY[g.family.id]}
            <span
              class="mt-1.5 inline-block rounded-full bg-muted px-2 py-0.5 text-[11px] font-medium text-muted-foreground"
            >
              {t(FAMILY_COPY[g.family.id]!.audienceKey)}
            </span>
          {/if}
          <p class="mt-1 text-xs text-muted-foreground">{body}</p>
        </button>

        <!-- Transport sub-choice. Only when the family actually offers a choice:
             a single-child family stays a plain card. -->
        {#if g.children.length > 1}
          <div class="border-t border-border/60 px-4 pb-4 pt-3">
            <p class="mb-2 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
              {t('delivery.transportLabel')}
            </p>
            <div
              role="radiogroup"
              aria-label={`${title} - ${t('delivery.transportLabel')}`}
              class="flex flex-wrap gap-2"
              onkeydown={(e) => onTransportKeydown(e, g.children)}
            >
              {#each g.children as child (child.id)}
                {@const disabled = isDisabled(child)}
                {@const active = selected === child.id}
                <button
                  type="button"
                  role="radio"
                  aria-checked={active}
                  tabindex={active ? 0 : -1}
                  {disabled}
                  onclick={() => choose(child)}
                  title={disabled && !active ? t('delivery.unavailable') : undefined}
                  class="rounded-md border px-2.5 py-1.5 text-xs font-medium transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-60 {active
                    ? 'border-primary bg-primary/10 text-primary'
                    : 'border-border text-muted-foreground hover:border-primary/40'}"
                >
                  {modeTitle(child)}
                </button>
              {/each}
            </div>
            {#each g.children as child (child.id)}
              {#if selected === child.id && modeBody(child)}
                <p class="mt-2 text-xs text-muted-foreground">{modeBody(child)}</p>
              {/if}
            {/each}
          </div>
        {/if}
      </div>
    {/each}
  </div>
</section>
