<script lang="ts">
  /**
   * Locale picker (P1-15). A plain native <select> — keyboard-accessible, works
   * without JS hydration quirks, and tiny. Persists via setLocale (localStorage
   * + <html lang/dir>). Labels are each language's endonym so a speaker
   * recognizes their own language regardless of the current UI locale.
   */
  import { LOCALES, getLocale, setLocale, t, type LocaleCode } from '../lib/i18n/index.svelte';
  import Globe from '@lucide/svelte/icons/globe';

  let current = $derived(getLocale());
</script>

<label class="inline-flex items-center gap-1.5 text-sm text-muted-foreground">
  <Globe class="size-4" aria-hidden="true" />
  <span class="sr-only">{t('common.language')}</span>
  <select
    class="cursor-pointer rounded-md border border-border bg-background px-2 py-1 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
    value={current}
    onchange={(e) => setLocale((e.currentTarget as HTMLSelectElement).value as LocaleCode)}
  >
    {#each LOCALES as l (l.code)}
      <option value={l.code}>{l.name}</option>
    {/each}
  </select>
</label>
