<script lang="ts">
  /**
   * What a key's mirror links are set up for (lib/countryQuestion.ts
   * `mirrorCountry`): "Your mirror links are set up for Iran." or "...aren't set
   * up for any country.", with Change (the caller opens the question). Shown
   * only when the key has an answer.
   *
   * Props: country (a listed code, or null for the opt-out), onChange, disabled.
   */
  import { Button } from './ui/button';
  import { countryName } from '../lib/countries';
  import { getLocale, t } from '../lib/i18n/index.svelte';

  interface Props {
    country: string | null;
    onChange: () => void;
    disabled?: boolean;
  }
  let { country, onChange, disabled = false }: Props = $props();
</script>

<p class="text-sm">
  {country
    ? t('mirror.setFor', { country: countryName(country, getLocale()) })
    : t('mirror.setForNone')}
  <Button variant="link" class="h-auto p-0 align-baseline" {disabled} onclick={onChange}>
    {t('region.change')}
  </Button>
</p>
