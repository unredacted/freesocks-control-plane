<script lang="ts">
  /**
   * "Where are you connecting from?" as a required question (sign-up and a
   * mirror, lib/countryQuestion.ts): the countries on the censored-country
   * list, then "Somewhere else, or I'd rather not say" (`ZZ`), never
   * Automatic. A native select (screen readers, RTL, 44px target), as on the
   * account card. Country names come from the browser (`Intl.DisplayNames`)
   * in the page's language, sorted in it; the opt-out stays last.
   *
   * The caller owns the value and saves it (with the first key, or with the
   * mirror request): nothing here talks to the server.
   *
   * Props: id, options (listed codes), value (bindable: '' = nothing picked),
   * help (the line under the label), prefilled (say the value came from the
   * connection), invalid (show the required error), disabled.
   */
  import { countryName } from '../lib/countries';
  import { ELSEWHERE } from '../lib/countryQuestion';
  import { getLocale, t } from '../lib/i18n/index.svelte';

  interface Props {
    id: string;
    options: readonly string[];
    value?: string;
    help: string;
    prefilled?: boolean;
    invalid?: boolean;
    disabled?: boolean;
  }
  let {
    id,
    options,
    value = $bindable(''),
    help,
    prefilled = false,
    invalid = false,
    disabled = false,
  }: Props = $props();

  // Read inside the derivation: a language switch re-renders the names.
  const sorted = $derived.by(() => {
    const locale = getLocale();
    return options
      .map((code) => ({ code, name: countryName(code, locale) }))
      .sort((a, b) => a.name.localeCompare(b.name, locale));
  });
</script>

<div class="space-y-2">
  <label for={id} class="block font-medium">{t('region.title')}</label>
  <p id="{id}-help" class="text-sm text-muted-foreground">{help}</p>
  <select
    {id}
    class="border-input bg-background focus-visible:ring-ring/50 h-11 w-full max-w-xs rounded-md border px-3 text-sm outline-none focus-visible:ring-3 aria-invalid:border-destructive"
    aria-describedby="{id}-help{prefilled && value ? ` ${id}-prefilled` : ''}{invalid
      ? ` ${id}-error`
      : ''}"
    aria-invalid={invalid ? 'true' : undefined}
    aria-required="true"
    {disabled}
    bind:value
  >
    <option value="" disabled>{t('region.choose')}</option>
    {#each sorted as o (o.code)}
      <option value={o.code}>{o.name}</option>
    {/each}
    <option value={ELSEWHERE}>{t('region.elsewhere')}</option>
  </select>
  {#if prefilled && value && value !== ELSEWHERE}
    <p id="{id}-prefilled" class="text-sm text-muted-foreground">{t('region.prefilled')}</p>
  {/if}
  {#if invalid}
    <p id="{id}-error" class="text-sm text-destructive" role="alert">{t('region.required')}</p>
  {/if}
</div>
