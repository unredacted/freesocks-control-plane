<script lang="ts">
  import { fade } from 'svelte/transition';
  import { Button } from '@client/components/ui/button';
  import GlobeLock from '@lucide/svelte/icons/globe-lock';
  import { apiClient } from '../lib/api';
  import { apiErrorMessage } from '../lib/errors';
  import { t, getLocale } from '../lib/i18n/index.svelte';
  import { COUNTRY_CODES, countryName } from '../lib/countries';
  import { queryKeys } from '../lib/queries';
  import { MIRROR_REQUEST_KEY, withMirror } from '../lib/mirrorSuggestion';
  import { MirrorRequestResponse } from '../../shared/contracts/mirror';
  import type { AccountResponse } from '../../shared/contracts/account';
  import MirrorRegionSelect from './MirrorRegionSelect.svelte';
  import { createMutation, useIsMutating, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';

  /**
   * Onboarding (/get-account step 3): the CDN places this visitor in a country
   * on the censored-country list (the server's `geoCountryCensored` verdict), so
   * the main link may be blocked where they are. Offers ONE mirror link through
   * the same `POST /api/v1/mirror/request` as MirrorHelp, its country prefilled
   * from the CDN geo (transient, never stored, overridable). Opt-in: nothing is
   * created until the member clicks.
   *
   * Once the key has a mirror both links are listed and the member picks the
   * one their app gets (the mirror is the recommendation). The pick is page
   * state only: `onPick` hands it to the parent, which feeds the pass (copy,
   * download, QR) and the app list (import buttons); `link` is what it resolved.
   * A mirror serves one fixed format, so sing-box and Clash apps keep importing
   * the main link (ConnectClient `linkListUrl`), and the copy says so.
   */
  interface Props {
    /** The key's mirror links (lib/mirrorSuggestion `mirrorLinks`). */
    mirrors: string[];
    /** The CDN country of this request (never null here: no country, no suggestion). */
    geoCountry: string;
    /** The key's main link. */
    subscriptionUrl: string;
    /** The link the app gets now (lib/mirrorSuggestion `chosenLink`). */
    link: string;
    onPick: (url: string) => void;
  }
  let { mirrors, geoCountry, subscriptionUrl, link, onPick }: Props = $props();

  const qc = useQueryClient();
  const locale = getLocale();

  // svelte-ignore state_referenced_locally -- a one-time snapshot: the picker
  // starts on the geo and the member may change it.
  let selected = $state<string>(COUNTRY_CODES.includes(geoCountry) ? geoCountry : '');
  const place = $derived(countryName(geoCountry, locale));

  let status = $state<MirrorRequestResponse['status'] | 'idle'>('idle');

  const request = createMutation(() => ({
    mutationKey: MIRROR_REQUEST_KEY,
    mutationFn: () =>
      apiClient.post(
        '/api/v1/mirror/request',
        { countryCode: selected || null },
        MirrorRequestResponse,
      ),
    onSuccess: (res) => {
      if (res.status === 'ok' && res.publicUrl) {
        const added = { provider: res.provider ?? '', publicUrl: res.publicUrl };
        qc.setQueryData<AccountResponse>(queryKeys.account, (old) => withMirror(old, added));
        onPick(res.publicUrl);
        status = 'idle';
        void qc.invalidateQueries({ queryKey: queryKeys.account });
      } else {
        status = res.status === 'ok' ? 'error' : res.status;
      }
    },
    onError: (err) => {
      status = 'error';
      toast.error(t('mirror.errorToast'), { description: apiErrorMessage(err) });
    },
  }));

  // MirrorHelp's request holds this button too (one request per key at a time).
  const requesting = useIsMutating({ mutationKey: MIRROR_REQUEST_KEY });
  const busy = $derived(request.isPending || requesting.current > 0);

  const options = $derived([
    ...mirrors.map((url) => ({ url, mirror: true })),
    { url: subscriptionUrl, mirror: false },
  ]);
</script>

<section
  class="space-y-4 rounded-lg border border-amber-500/40 bg-card p-[clamp(20px,2.4vw,28px)] text-card-foreground"
  aria-labelledby="mirror-suggest-title"
>
  <div class="space-y-1.5">
    <h2
      id="mirror-suggest-title"
      class="flex items-start gap-2 text-xl font-bold leading-tight tracking-[-0.01em] rtl:tracking-normal"
    >
      <GlobeLock class="mt-0.5 size-5 shrink-0 text-amber-600 dark:text-amber-400" />
      {t('mirrorSuggest.title', { country: place })}
    </h2>
    <p class="text-[15px] text-muted-foreground">{t('mirrorSuggest.body', { country: place })}</p>
    <p class="text-[15px] font-bold text-foreground">{t('mirrorSuggest.recommend')}</p>
  </div>

  {#if mirrors.length === 0}
    <MirrorRegionSelect id="mirror-suggest-region" bind:value={selected} />
    <Button onclick={() => request.mutate()} disabled={busy} class="min-h-11">
      {busy ? t('mirror.working') : t('mirrorSuggest.create')}
    </Button>
    {#if status === 'capped'}
      <p class="text-sm text-amber-600" transition:fade={{ duration: 150 }}>
        {t('mirror.capped')}
      </p>
    {:else if status === 'exhausted'}
      <p class="text-sm text-amber-600" transition:fade={{ duration: 150 }}>
        {t('mirror.exhausted')}
      </p>
    {:else if status === 'no_subscription'}
      <p class="text-sm text-muted-foreground" transition:fade={{ duration: 150 }}>
        {t('mirror.noSubscription')}
      </p>
    {:else if status === 'error'}
      <p class="text-sm text-amber-600" role="status" transition:fade={{ duration: 150 }}>
        {t('mirror.failed')}
      </p>
    {/if}
  {:else}
    <fieldset class="space-y-2">
      <legend class="mb-2 text-sm font-bold text-foreground">
        {t('mirrorSuggest.chooseLabel')}
      </legend>
      {#each options as o (o.url)}
        {@const active = link === o.url}
        <label
          class="flex cursor-pointer items-start gap-3 rounded-sm border-2 p-3 transition-colors focus-within:ring-2 focus-within:ring-ring focus-within:ring-offset-2 focus-within:ring-offset-background {active
            ? 'border-primary bg-background'
            : 'border-border/70 hover:border-primary/50'}"
        >
          <input
            type="radio"
            name="mirror-suggest-link"
            value={o.url}
            checked={active}
            onchange={() => onPick(o.url)}
            class="mt-1 size-4 shrink-0 accent-primary focus:outline-none"
          />
          <span class="min-w-0 flex-1 space-y-0.5">
            <span class="block font-bold text-foreground">
              {o.mirror ? t('mirrorSuggest.optionMirror') : t('mirrorSuggest.optionMain')}
              {#if o.mirror}
                <span class="font-bold text-primary">
                  <span aria-hidden="true">{' · '}</span>{t('mirrorSuggest.recommended')}
                </span>
              {/if}
            </span>
            <span class="block text-sm text-muted-foreground">
              {o.mirror ? t('mirrorSuggest.optionMirrorHint') : t('mirrorSuggest.optionMainHint')}
            </span>
            <code dir="ltr" class="block break-all font-mono text-sm text-foreground">{o.url}</code>
          </span>
        </label>
      {/each}
    </fieldset>
    <p class="text-sm text-muted-foreground">{t('mirrorSuggest.chooseHint')}</p>
  {/if}
</section>
