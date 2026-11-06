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
   * On Automatic, when the member's own country choice has an exit location
   * and their key is elsewhere (`exit`, sealed like the choice), one line
   * offers to move the key there once (POST account/move-to-exit): the link
   * stays the same and the member stays on Automatic. docs/edges.md "Exit
   * location by country".
   *
   * A key with mirror links: those are shaped by this answer too (a mirror
   * cannot see where its reader is), so the card says so, warns that Automatic
   * leaves them with no country, and a saved change says they will update.
   *
   * Props: disabled?: boolean, hasMirrors?: boolean
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { connectionRegionQuery, queryKeys, setConnectionRegion } from '../lib/queries';
  import { countryName } from '../lib/countries';
  import { ApiCallError, apiClient } from '../lib/api';
  import { SwitchServerResponse } from '@shared/contracts/account';
  import { sealingEnabled } from '../lib/hpke';
  import { getLocale, t } from '../lib/i18n/index.svelte';
  import { Button } from './ui/button';

  interface Props {
    disabled?: boolean;
    /** The key has mirror links (they follow this answer). */
    hasMirrors?: boolean;
  }
  let { disabled = false, hasMirrors = false }: Props = $props();

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

  let confirming = $state(false);
  let moving = $state(false);
  async function moveToExit() {
    moving = true;
    try {
      await apiClient.post('/api/v1/account/move-to-exit', { confirm: true }, SwitchServerResponse);
      confirming = false;
      // The key now lives elsewhere: what the page shows of it changes too.
      void qc.invalidateQueries({ queryKey: queryKeys.connectionRegion });
      void qc.invalidateQueries({ queryKey: queryKeys.account });
      // A new key: a new traffic counter and usage history.
      void qc.invalidateQueries({ queryKey: queryKeys.accountUsage });
      void qc.invalidateQueries({ queryKey: queryKeys.subscriptionContent });
      void qc.invalidateQueries({ queryKey: queryKeys.nodeStatus });
      toast.success(t('region.exitMoved'));
    } catch {
      toast.error(t('region.exitFailed'));
    } finally {
      moving = false;
    }
  }

  async function choose(value: string) {
    saving = true;
    try {
      const next = await setConnectionRegion(value === '' ? null : value);
      qc.setQueryData(queryKeys.connectionRegion, next);
      changing = false;
      toast.success(
        t('region.saved'),
        hasMirrors ? { description: t('mirror.willUpdate') } : undefined,
      );
    } catch (err) {
      toast.error(
        err instanceof ApiCallError && err.payload.error.code === 'rate_limit.country_day'
          ? t('region.tooOften')
          : t('region.failed'),
      );
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
    {#if view.exit && view.choice && view.choice !== ELSEWHERE}
      <div class="mt-2 text-sm">
        <p>{t('region.exitFaster', { country: name(view.choice), location: view.exit.label })}</p>
        {#if confirming}
          <p class="text-muted-foreground mt-1">{t('region.exitConfirm')}</p>
          <div class="mt-2 flex gap-2">
            <Button size="sm" disabled={disabled || moving} onclick={() => void moveToExit()}>
              {t('region.exitMoveNow')}
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={moving}
              onclick={() => (confirming = false)}
            >
              {t('common.cancel')}
            </Button>
          </div>
        {:else}
          <Button
            variant="link"
            class="h-auto p-0 align-baseline"
            disabled={disabled || moving}
            onclick={() => (confirming = true)}
          >
            {t('region.exitMove')}
          </Button>
        {/if}
      </div>
    {/if}
    <p id="connection-region-help" class="text-muted-foreground mt-1 text-sm">
      {t('region.help')}
      {#if view.detect}
        {t('region.helpDetect', { days: view.stickyDays })}
      {/if}
    </p>
    {#if hasMirrors}
      <p class="text-muted-foreground mt-1 text-sm">{t('region.alsoMirrors')}</p>
    {/if}
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
      {#if hasMirrors && !view.choice}
        <p class="mt-2 text-sm text-amber-700 dark:text-amber-400">
          {t('region.automaticMirrorWarn')}
        </p>
      {/if}
    {/if}
  </div>
{/if}
