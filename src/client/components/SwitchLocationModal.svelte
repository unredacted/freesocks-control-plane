<script lang="ts">
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';
  import { t } from '../lib/i18n/index.svelte';
  import { locationOpenTo, type PublicLocation } from '../lib/locations';
  import Lock from '@lucide/svelte/icons/lock';
  import MapPin from '@lucide/svelte/icons/map-pin';

  /**
   * "Switch location" (`/api/v1/account/switch-location`): move the key to
   * another location, keeping the subscription URL. Two faces, by the
   * member's tier (`user.tier.canSwitchLocation`):
   *  - a tier that may switch: pick a location (the current one marked, any
   *    location the tier is not on shown locked) and confirm;
   *  - a tier that may not (free by default): what membership adds, with
   *    "See membership" and, when the key can move at all, "Switch server
   *    instead" - the free fix for a bad server in the same location.
   * Purely presentational; the mutation lives in the page.
   */
  interface Props {
    open: boolean;
    locations: PublicLocation[];
    tierSlug: string;
    canSwitch: boolean;
    /** The location the key is in now (code + label), when known. */
    currentCode: string | null;
    currentLabel: string | null;
    deviceCount?: number;
    busy: boolean;
    onCancel: () => void;
    onConfirm: (code: string) => void;
    /** "See membership"; absent = billing off (no button). */
    onSeeMembership?: () => void;
    /** "Switch server instead"; absent = the key cannot move. */
    onSwitchServer?: () => void;
  }

  let {
    open = $bindable(),
    locations,
    tierSlug,
    canSwitch,
    currentCode,
    currentLabel,
    deviceCount = 0,
    busy,
    onCancel,
    onConfirm,
    onSeeMembership,
    onSwitchServer,
  }: Props = $props();

  let picked = $state<string | null>(null);
  $effect(() => {
    // A fresh pick each time the dialog opens.
    if (open) picked = null;
  });
  let choices = $derived(locations.filter((l) => l.code !== currentCode));
  let memberOnly = $derived(locations.filter((l) => !locationOpenTo(l, tierSlug)));

  function onOpenChange(next: boolean) {
    if (!next && busy) return;
    open = next;
    if (!next) onCancel();
  }
</script>

<Dialog.Root bind:open {onOpenChange}>
  <Dialog.Content class="sm:max-w-md">
    {#if canSwitch}
      <Dialog.Header>
        <Dialog.Title>{t('switchLocation.title')}</Dialog.Title>
        <Dialog.Description>{t('switchLocation.body')}</Dialog.Description>
      </Dialog.Header>

      {#if currentLabel}
        <p class="flex items-center gap-2 text-sm">
          <MapPin class="size-4 text-primary" aria-hidden="true" />
          <span class="font-semibold">{currentLabel}</span>
          <span class="text-xs text-muted-foreground">{t('switchLocation.current')}</span>
        </p>
      {/if}

      {#if choices.length === 0}
        <p class="text-sm text-muted-foreground">{t('switchLocation.noOther')}</p>
      {:else}
        <fieldset class="space-y-1.5" disabled={busy}>
          <legend class="mb-2 text-sm font-medium">{t('switchLocation.legend')}</legend>
          {#each choices as loc (loc.code)}
            {@const allowed = locationOpenTo(loc, tierSlug)}
            <label
              class="flex min-h-11 items-center gap-3 rounded-md border px-3 py-2 text-sm {allowed
                ? 'cursor-pointer hover:bg-accent/40'
                : 'border-dashed text-muted-foreground'} {picked === loc.code
                ? 'border-primary bg-primary/10'
                : 'border-border'}"
            >
              <input
                type="radio"
                name="switch-location"
                value={loc.code}
                checked={picked === loc.code}
                disabled={!allowed}
                onchange={() => (picked = loc.code)}
                class="size-4 shrink-0 accent-current"
              />
              <span class="flex-1">
                {loc.label}
                {#if !loc.online}
                  <span class="text-xs text-muted-foreground"> ({t('location.offline')})</span>
                {/if}
              </span>
              {#if !allowed}
                <span class="flex items-center gap-1 text-xs font-semibold">
                  <Lock class="size-3.5" aria-hidden="true" />
                  {t('location.membersOnly')}
                </span>
              {/if}
            </label>
          {/each}
        </fieldset>
        <ul class="text-sm text-muted-foreground space-y-1 list-disc ps-5">
          <li>{t('switchLocation.point1')}</li>
          {#if deviceCount > 0}
            <li>{t('switchLocation.point2')}</li>
          {/if}
        </ul>
      {/if}

      <Dialog.Footer>
        <Button variant="ghost" onclick={onCancel} disabled={busy}>{t('common.cancel')}</Button>
        <Button onclick={() => picked && onConfirm(picked)} disabled={busy || picked === null}>
          {busy ? t('switchLocation.working') : t('switchLocation.confirm')}
        </Button>
      </Dialog.Footer>
    {:else}
      <Dialog.Header>
        <Dialog.Title>{t('switchLocation.memberTitle')}</Dialog.Title>
        <Dialog.Description>
          {currentLabel
            ? t('switchLocation.memberBodyFrom', { location: currentLabel })
            : t('switchLocation.memberBody')}
        </Dialog.Description>
      </Dialog.Header>

      {#if memberOnly.length > 0}
        <p class="flex items-start gap-2 text-sm">
          <Lock class="mt-0.5 size-4 shrink-0 text-primary" aria-hidden="true" />
          <span>
            {t('switchLocation.memberLocations', {
              list: memberOnly.map((l) => l.label).join(' · '),
            })}
          </span>
        </p>
      {/if}

      {#if onSeeMembership}
        <Button class="min-h-11 w-full" onclick={onSeeMembership}>
          {t('switchLocation.memberCta')}
        </Button>
      {/if}

      {#if onSwitchServer}
        <div class="space-y-2 border-t border-border/70 pt-4">
          <p class="text-sm text-muted-foreground">{t('switchLocation.serverAlt')}</p>
          <Button variant="outline" class="min-h-11 w-full" onclick={onSwitchServer}>
            {t('switchLocation.serverAltCta')}
          </Button>
        </div>
      {/if}

      <Dialog.Footer>
        <Button variant="ghost" onclick={onCancel}>{t('common.cancel')}</Button>
      </Dialog.Footer>
    {/if}
  </Dialog.Content>
</Dialog.Root>
