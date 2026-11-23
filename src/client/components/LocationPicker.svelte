<script lang="ts">
  /**
   * Node-location picker: lets the member choose WHERE their next config is
   * issued (a `PublicConfig.locations` code), or "Automatic" (the server picks
   * the least-loaded location their plan includes). A radio list so each row
   * can say what it is: the load, "Recommended for you", and "Members" for a
   * location the member's tier is not on (lib/locations.ts). Picking such a
   * row does not select it: it opens a short membership note instead, so a free
   * member sees what membership adds without ever being able to submit a pick
   * the server would refuse. Callers hide this entirely when fewer than two
   * locations exist (there is no choice to make); an offline location stays
   * selectable (the health bit can be a stale probe, and the server fails soft
   * to another location rather than blocking issuance).
   */
  import { t } from '../lib/i18n/index.svelte';
  import { locationOpenTo, type PublicLocation } from '../lib/locations';
  import { Button } from '@client/components/ui/button';
  import MapPin from '@lucide/svelte/icons/map-pin';
  import Lock from '@lucide/svelte/icons/lock';

  function loadText(load: PublicLocation['load']): string {
    if (load === 'quiet') return t('status.loadQuiet');
    if (load === 'busy') return t('status.loadBusy');
    if (load === 'crowded') return t('status.loadCrowded');
    return '';
  }
  interface Props {
    locations: PublicLocation[];
    /** 'auto' or a location code. */
    value: string;
    disabled?: boolean;
    id?: string;
    /** Location codes recommended for the member's country (sign-up), in order. */
    recommended?: readonly string[];
    /** The member's tier slug: locations not open to it read "Members". */
    tierSlug?: string | null;
    /** "See membership" on the membership note; absent = no button (billing off). */
    onSeeMembership?: () => void;
  }
  let {
    locations,
    value = $bindable(),
    disabled = false,
    id = 'location-picker',
    recommended = [],
    tierSlug = null,
    onSeeMembership,
  }: Props = $props();
  let hasRecommended = $derived(recommended.some((code) => locations.some((l) => l.code === code)));
  // The members-only row last tapped: shows the membership note under the list.
  let lockedPick = $state<PublicLocation | null>(null);

  // Compact tiles in a grid (two per row on a phone, three from `sm`), so a
  // short city name never stretches across the whole panel.
  const TILE =
    'flex min-h-14 w-full cursor-pointer flex-col items-start justify-center gap-0.5 rounded-md border px-3 py-2 text-start transition-colors disabled:cursor-not-allowed disabled:opacity-50';
  function tileClass(selected: boolean, locked: boolean): string {
    if (selected) return `${TILE} border-primary bg-primary/10 ring-1 ring-primary`;
    if (locked) return `${TILE} border-dashed border-border hover:bg-accent/40`;
    return `${TILE} border-border hover:bg-accent/40`;
  }
  function pick(next: string) {
    lockedPick = null;
    value = next;
  }
</script>

<div class="space-y-1.5">
  <p
    id="{id}-label"
    class="flex items-center gap-1.5 text-xs uppercase tracking-wider text-muted-foreground font-semibold"
  >
    <MapPin class="size-3.5" aria-hidden="true" />
    {t('location.pickerLabel')}
  </p>
  <div
    role="radiogroup"
    aria-labelledby="{id}-label"
    class="grid grid-cols-2 gap-2 sm:grid-cols-3"
    {id}
  >
    <button
      type="button"
      role="radio"
      aria-checked={value === 'auto'}
      class={tileClass(value === 'auto', false)}
      {disabled}
      onclick={() => pick('auto')}
    >
      <span class="text-sm font-semibold leading-tight">{t('location.autoShort')}</span>
      <span class="text-xs text-muted-foreground">{t('location.autoHint')}</span>
    </button>
    {#each locations as loc (loc.code)}
      {@const open = locationOpenTo(loc, tierSlug)}
      {@const load = open ? loadText(loc.load) : ''}
      <button
        type="button"
        role="radio"
        aria-checked={open && value === loc.code}
        class={tileClass(open && value === loc.code, !open)}
        {disabled}
        onclick={() => (open ? pick(loc.code) : (lockedPick = loc))}
      >
        <span class="text-sm font-semibold leading-tight {open ? '' : 'text-muted-foreground'}">
          {loc.label}
        </span>
        {#if !open}
          <span class="flex items-center gap-1 text-xs font-semibold text-primary">
            <Lock class="size-3" aria-hidden="true" />
            {t('location.membersOnly')}
          </span>
        {:else if !loc.online}
          <span class="text-xs text-muted-foreground">{t('location.offline')}</span>
        {:else if recommended.includes(loc.code)}
          <span class="text-xs text-primary">{t('location.recommended')}</span>
        {:else if load}
          <span class="text-xs text-muted-foreground">{load}</span>
        {/if}
      </button>
    {/each}
  </div>
  {#if lockedPick}
    <div class="space-y-2 rounded-md border border-primary/40 bg-primary/5 p-3" role="status">
      <p class="text-sm font-semibold">
        {t('location.lockedTitle', { location: lockedPick.label })}
      </p>
      <p class="text-sm text-muted-foreground">
        {t('location.lockedBody', { location: lockedPick.label })}
      </p>
      {#if onSeeMembership}
        <Button size="sm" class="min-h-11" onclick={onSeeMembership}>
          {t('location.lockedCta')}
        </Button>
      {/if}
    </div>
  {:else}
    <p class="text-xs text-muted-foreground">
      {hasRecommended ? t('location.pickerHintRecommended') : t('location.pickerHint')}
    </p>
  {/if}
</div>
