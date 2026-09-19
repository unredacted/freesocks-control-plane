<script lang="ts">
  /**
   * "Where are you connecting from?" A small control on the account page.
   * Automatic by default. In a few heavily filtered countries, some of the
   * website names a key pretends to visit are blocked; saying where you are
   * makes the key use names known to work there. The answer is the member's own
   * and is the only country the service stores (docs/privacy.md).
   *
   * Country names come from the browser (`Intl.DisplayNames`), in the page's
   * language, so there is nothing per country to translate.
   *
   * Props: disabled?: boolean
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { connectionRegionQuery, queryKeys, setConnectionRegion } from '../lib/queries';
  import { getLocale, t } from '../lib/i18n/index.svelte';

  interface Props {
    disabled?: boolean;
  }
  let { disabled = false }: Props = $props();

  const qc = useQueryClient();
  const region = connectionRegionQuery(() => true);
  let saving = $state(false);

  function countryName(code: string): string {
    try {
      return new Intl.DisplayNames([getLocale()], { type: 'region' }).of(code) ?? code;
    } catch {
      return code;
    }
  }

  async function choose(value: string) {
    saving = true;
    try {
      const next = value === '' ? null : value;
      await setConnectionRegion(next);
      await qc.invalidateQueries({ queryKey: queryKeys.connectionRegion });
      toast.success(t('region.saved'));
    } catch {
      toast.error(t('region.failed'));
    } finally {
      saving = false;
    }
  }
</script>

{#if region.data && region.data.options.length > 0}
  <div class="rounded-lg border p-4">
    <label for="connection-region" class="block font-medium">{t('region.title')}</label>
    <p id="connection-region-help" class="text-muted-foreground mt-1 text-sm">
      {t('region.help')}
    </p>
    <select
      id="connection-region"
      class="border-input bg-background focus-visible:ring-ring/50 mt-3 h-11 w-full max-w-xs rounded-md border px-3 text-sm outline-none focus-visible:ring-3"
      aria-describedby="connection-region-help"
      disabled={disabled || saving}
      value={region.data.region ?? ''}
      onchange={(e) => void choose(e.currentTarget.value)}
    >
      <option value="">{t('region.automatic')}</option>
      {#each region.data.options as code (code)}
        <option value={code}>{countryName(code)}</option>
      {/each}
    </select>
  </div>
{/if}
