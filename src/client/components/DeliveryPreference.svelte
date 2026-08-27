<script lang="ts">
  import Check from '@lucide/svelte/icons/check';
  import ChevronDown from '@lucide/svelte/icons/chevron-down';
  import { slide } from 'svelte/transition';
  import { t } from '../lib/i18n/index.svelte';
  import {
    familyAudience,
    familyBody,
    familyTitle,
    modeBody,
    modeTitle,
  } from '../lib/connectionModeCopy';
  import { familyIcon } from '../lib/connectionModeIcons';
  import {
    familyTargetMode,
    groupModesByFamily,
    withCurrentMode,
    type PickerFamily,
    type PickerMode,
  } from '../lib/connectionModeGroups';
  import type { MemberCurrentMode } from '../../shared/contracts/connectionModes';

  /**
   * The connection-mode picker - the member-facing choice, in TWO levels: a
   * parent FAMILY card (Freedom Mode / Privacy Mode), and inside it a
   * transport row (WebSocket / REALITY / ...).
   *
   * Deliberately terse (2026-08 unclutter pass): EVERY card - selected or not -
   * is just icon + name + one audience line, so the choice reads at a glance
   * for non-technical members. The description and the transport chooser sit
   * behind each card's own "More details" disclosure for those who want them.
   * An expanded family always shows its transport row, including one-transport
   * families like Privacy Mode today. With a single transport the row is a
   * static name; it turns into a keyboard-navigable radiogroup on its own as
   * soon as a second transport is enabled, with no change here.
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
    /** The account view's resolved current-mode projection — the synthesized
     *  entry for an admin-disabled current mode carries its REAL deliveryStyle/
     *  label/family instead of a blind guess. */
    currentMode?: MemberCurrentMode | null;
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
    currentMode = null,
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
  let visibleModes = $derived(withCurrentMode(modes, selected, currentMode));
  let groups = $derived(groupModesByFamily(visibleModes, families));
  // Per-card "More details" disclosure state, keyed by the group's stable key
  // (family id, or the orphan leaf's id). Independent of selection: expanding
  // a card is reading, not choosing.
  let detailsOpen = $state<Record<string, boolean>>({});
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

  <!-- items-start: an expanded "More details" on one card must not stretch its
       sibling into an empty-bottomed box. -->
  <div class="grid items-start gap-3 {groups.length === 1 ? '' : 'sm:grid-cols-2'}">
    {#each groups as g, gi (g.family?.id ?? g.children[0]!.id)}
      {@const isSelectedGroup = gi === selectedGroupIndex}
      {@const Icon = g.family ? familyIcon(g.family) : undefined}
      {@const title = g.family ? familyTitle(g.family) : modeTitle(g.children[0]!)}
      {@const body = g.family ? familyBody(g.family) : modeBody(g.children[0]!)}
      {@const groupSuggested = g.children.some((m) => m.id === suggested)}
      {@const allDisabled = g.children.every((m) => isDisabled(m))}
      <!-- The WHOLE card selects the family, not just its head: the transport row
           sits outside the head button (a button cannot contain the transport
           radios), so without this, clicking anywhere below "Connection method"
           did nothing and read as broken. `role="presentation"` because the
           wrapper carries no semantics of its own - the head button below is the
           real control and still provides the keyboard/AT path (its activation
           fires a click that bubbles here, which is why it has no own handler and
           cannot double-fire). The transport radios stopPropagation so picking a
           transport never also re-selects the family. -->
      <div
        role="presentation"
        onclick={() => chooseGroup(g)}
        class="rounded-lg border transition {allDisabled ? '' : 'cursor-pointer'} {isSelectedGroup
          ? 'border-primary bg-primary/5 ring-1 ring-primary/30'
          : 'border-border hover:border-primary/40'}"
      >
        <button
          type="button"
          disabled={allDisabled}
          aria-pressed={isSelectedGroup}
          class="w-full rounded-lg p-4 text-start transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-60"
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
            {:else if isSelectedGroup && g.children.some((m) => m.id === selected && !m.available)}
              <!-- The member's CURRENT mode was disabled/unbound under them:
                   still highlighted (it is where they are), but flagged so the
                   muted styling reads as "unavailable", not "broken". -->
              <span
                class="rounded-full bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-amber-600 dark:text-amber-400"
              >
                {t('delivery.currentUnavailable')}
              </span>
            {:else if isSelectedGroup}
              <Check class="size-4 shrink-0 text-primary" />
            {/if}
          </div>
          {#if g.family && familyAudience(g.family)}
            <!-- The one always-visible line: who this mode is for. -->
            <p class="mt-1 text-xs font-medium text-muted-foreground">
              {familyAudience(g.family)}
            </p>
          {/if}
        </button>

        <!-- "More details" disclosure, identical on EVERY card (selected or not):
             non-technical members get a one-glance choice; the description and
             the transport chooser wait behind the toggle for those who want
             them. stopPropagation so expanding never also selects the family. -->
        {#if body || g.family}
          {@const key = g.family?.id ?? g.children[0]!.id}
          {@const expanded = !!detailsOpen[key]}
          <div class="border-t border-border/60 px-4 pb-3 pt-1.5">
            <button
              type="button"
              aria-expanded={expanded}
              onclick={(e) => {
                e.stopPropagation();
                detailsOpen[key] = !expanded;
              }}
              class="flex min-h-9 w-full items-center justify-between gap-2 rounded-sm text-xs text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              {t('delivery.detailsToggle')}
              <ChevronDown
                class="size-3.5 shrink-0 transition-transform {expanded ? 'rotate-180' : ''}"
                aria-hidden="true"
              />
            </button>

            {#if expanded}
              <div class="space-y-3 pb-1 pt-1.5" transition:slide={{ duration: 150 }}>
                {#if body}
                  <p class="text-xs text-muted-foreground">{body}</p>
                {/if}

                <!-- Transport row. Shown for every family, including one-transport
                     ones like Privacy Mode today: the member should be able to see
                     which method a family uses, and hiding the only transport gives
                     no hint that more can be added. With one option it is a static
                     name rather than a pointless single-item radiogroup; it becomes
                     interactive on its own the moment a second transport is enabled.
                     Skipped for an orphan leaf (family === null), where the card
                     head already IS the mode. -->
                {#if g.family}
                  {@const interactive = g.children.length > 1}
                  {@const activeInGroup = g.children.some((c) => c.id === selected)}
                  <!-- Describe whichever transport the row is highlighting: the
                       single one when static, the selected chip when this family
                       is the selected one, else the family default. -->
                  {@const described = interactive
                    ? (g.children.find((c) => c.id === selected) ?? familyTargetMode(g.children))
                    : g.children[0]}
                  <div>
                    <p
                      class="mb-2 text-[11px] font-medium uppercase tracking-wide text-muted-foreground"
                    >
                      {t('delivery.transportLabel')}
                    </p>
                    {#if interactive}
                      <div
                        role="radiogroup"
                        aria-label={`${title} - ${t('delivery.transportLabel')}`}
                        class="flex flex-wrap gap-2"
                        onkeydown={(e) => onTransportKeydown(e, g.children)}
                      >
                        {#each g.children as child, ci (child.id)}
                          {@const disabled = isDisabled(child)}
                          {@const active = selected === child.id}
                          <button
                            type="button"
                            role="radio"
                            aria-checked={active}
                            tabindex={active || (!activeInGroup && ci === 0) ? 0 : -1}
                            {disabled}
                            onclick={(e) => {
                              // Don't let a transport pick bubble up and re-select
                              // the family (which would snap back to the default).
                              e.stopPropagation();
                              choose(child);
                            }}
                            title={disabled && !active ? t('delivery.unavailable') : undefined}
                            class="rounded-md border px-2.5 py-1.5 text-xs font-medium transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-60 {active
                              ? 'border-primary bg-primary/10 text-primary'
                              : 'border-border text-muted-foreground hover:border-primary/40'}"
                          >
                            {modeTitle(child)}
                          </button>
                        {/each}
                      </div>
                    {:else}
                      <!-- One transport: render the NAME, not a chip. A bordered
                           muted chip was indistinguishable from the disabled state
                           of the interactive chips, so Privacy Mode's REALITY read
                           as greyed out / unsupported when it is simply the only
                           method. -->
                      <p class="text-sm font-medium text-foreground">
                        {modeTitle(g.children[0]!)}
                      </p>
                    {/if}
                    {#if described && modeBody(described)}
                      <p class="mt-2 text-xs text-muted-foreground">{modeBody(described)}</p>
                    {/if}
                  </div>
                {/if}
              </div>
            {/if}
          </div>
        {/if}
      </div>
    {/each}
  </div>
</section>
