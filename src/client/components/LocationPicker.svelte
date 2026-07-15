<script lang="ts">
  /**
   * Node-location picker: lets the member choose WHERE their next config is
   * issued (a `PublicConfig.locations` code), or "Automatic" (the server picks
   * the least-loaded node anywhere). A plain native <select> like the language
   * switcher: keyboard-accessible and tiny. Callers hide this entirely when
   * fewer than two locations exist (there is no choice to make); an offline
   * location stays selectable (the health bit can be a stale probe, and the
   * server fails soft to another location rather than blocking issuance).
   */
  import { t } from '../lib/i18n/index.svelte';
  import MapPin from '@lucide/svelte/icons/map-pin';

  interface LocationEntry {
    code: string;
    label: string;
    online: boolean;
  }
  interface Props {
    locations: LocationEntry[];
    /** 'auto' or a location code. */
    value: string;
    disabled?: boolean;
    id?: string;
  }
  let {
    locations,
    value = $bindable(),
    disabled = false,
    id = 'location-picker',
  }: Props = $props();
</script>

<div class="space-y-1.5">
  <label
    for={id}
    class="flex items-center gap-1.5 text-xs uppercase tracking-wider text-muted-foreground font-semibold"
  >
    <MapPin class="size-3.5" aria-hidden="true" />
    {t('location.pickerLabel')}
  </label>
  <select
    {id}
    bind:value
    {disabled}
    class="w-full min-h-11 cursor-pointer rounded-md border border-border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary disabled:cursor-not-allowed disabled:opacity-50"
  >
    <option value="auto">{t('location.auto')}</option>
    {#each locations as loc (loc.code)}
      <option value={loc.code}>
        {loc.label}{loc.online ? '' : ` (${t('location.offline')})`}
      </option>
    {/each}
  </select>
  <p class="text-xs text-muted-foreground">{t('location.pickerHint')}</p>
</div>
