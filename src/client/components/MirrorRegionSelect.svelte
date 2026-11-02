<script lang="ts">
  import * as Select from '@client/components/ui/select';
  import { t, getLocale } from '../lib/i18n/index.svelte';
  import { COUNTRY_CODES, countryName } from '../lib/countries';

  /**
   * The country a mirror is picked for ("Global" first, then every country by
   * its localized name). Shared by MirrorHelp and MirrorSuggestion. The value
   * only picks a nearby mirror host for one request; it is never stored.
   */
  interface Props {
    id: string;
    /** A COUNTRY_CODES code, or '' for Global. */
    value?: string;
  }
  let { id, value = $bindable('') }: Props = $props();

  const locale = getLocale();
  const regions = COUNTRY_CODES.map((c) => ({ code: c, name: countryName(c, locale) })).sort(
    (a, b) => a.name.localeCompare(b.name, locale),
  );
  const selectedLabel = $derived(
    value ? (regions.find((r) => r.code === value)?.name ?? value) : t('mirror.regionGlobal'),
  );
</script>

<div class="space-y-2">
  <label class="block text-sm text-muted-foreground" for={id}>
    {t('mirror.regionLabel')}
  </label>
  <Select.Root type="single" {value} onValueChange={(v) => (value = v ?? '')}>
    <Select.Trigger {id} class="w-full sm:w-72">{selectedLabel}</Select.Trigger>
    <Select.Content class="max-h-72 overflow-y-auto">
      <Select.Item value="">{t('mirror.regionGlobal')}</Select.Item>
      {#each regions as r (r.code)}
        <Select.Item value={r.code}>{r.name}</Select.Item>
      {/each}
    </Select.Content>
  </Select.Root>
  <p class="text-sm text-muted-foreground/80">{t('mirror.regionNotStored')}</p>
</div>
