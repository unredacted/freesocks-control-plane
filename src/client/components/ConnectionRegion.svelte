<script lang="ts">
  /**
   * "Where are you connecting from?" A small control on the account page, for
   * keys whose connection mode uses a country (the freedom family; hidden
   * otherwise). Automatic by default: with detection on the service may guess
   * the country from the connection and says so ("We think you're connecting
   * from Iran. Change"). The member can pick a listed country, "Somewhere
   * else" (no country, nothing guessed), or Automatic. The answer and the
   * guess travel only sealed (HPKE), so the control is hidden on a build that
   * cannot seal. docs/privacy.md "Where a member connects from".
   *
   * Country names come from the browser (`Intl.DisplayNames`), in the page's
   * language, so there is nothing per country to translate.
   *
   * Props: disabled?: boolean
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { connectionRegionQuery, queryKeys, setConnectionRegion } from '../lib/queries';
  import { countryName } from '../lib/countries';
  import { sealingEnabled } from '../lib/hpke';
  import { getLocale, t } from '../lib/i18n/index.svelte';
  import { Button } from './ui/button';

  interface Props {
    disabled?: boolean;
  }
  let { disabled = false }: Props = $props();

  const ELSEWHERE = 'ZZ';
  const canSeal = sealingEnabled();
  const qc = useQueryClient();
  const region = connectionRegionQuery(() => canSeal);
  let saving = $state(false);
  let changing = $state(false);

  const name = (code: string) => countryName(code, getLocale());
  const view = $derived(region.data);
  const shown = $derived(!!view && view.applies && view.options.length > 0);
  // The select is open by default unless a guess is being shown with its "Change".
  const showSelect = $derived(changing || view?.source !== 'guess');

  async function choose(value: string) {
    saving = true;
    try {
      const next = await setConnectionRegion(value === '' ? null : value);
      qc.setQueryData(queryKeys.connectionRegion, next);
      changing = false;
      toast.success(t('region.saved'));
    } catch {
      toast.error(t('region.failed'));
    } finally {
      saving = false;
    }
  }
</script>

{#if shown && view}
  <div class="panel">
    <label for="connection-region" class="block font-medium">{t('region.title')}</label>
    {#if view.source === 'guess' && view.guess}
      <p class="mt-1 text-sm">
        {t('region.guessed', { country: name(view.guess.country) })}
        {#if !changing}
          <Button
            variant="link"
            class="h-auto p-0 align-baseline"
            disabled={disabled || saving}
            onclick={() => (changing = true)}
          >
            {t('region.change')}
          </Button>
        {/if}
      </p>
    {:else if view.source === 'choice' && view.choice}
      <p class="mt-1 text-sm">
        {view.choice === ELSEWHERE
          ? t('region.chosenElsewhere')
          : t('region.chosen', { country: name(view.choice) })}
      </p>
    {/if}
    <p id="connection-region-help" class="text-muted-foreground mt-1 text-sm">
      {t('region.help')}
      {#if view.detect}
        {t('region.helpDetect', { days: view.stickyDays })}
      {/if}
    </p>
    {#if showSelect}
      <select
        id="connection-region"
        class="border-input bg-background focus-visible:ring-ring/50 mt-3 h-11 w-full max-w-xs rounded-md border px-3 text-sm outline-none focus-visible:ring-3"
        aria-describedby="connection-region-help"
        disabled={disabled || saving}
        value={view.choice ?? ''}
        onchange={(e) => void choose(e.currentTarget.value)}
      >
        <option value="">{t('region.automatic')}</option>
        {#each view.options as code (code)}
          <option value={code}>{name(code)}</option>
        {/each}
        <option value={ELSEWHERE}>{t('region.elsewhere')}</option>
      </select>
    {/if}
  </div>
{/if}
