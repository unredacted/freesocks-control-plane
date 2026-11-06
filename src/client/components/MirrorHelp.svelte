<script lang="ts">
  import { slide, fade } from 'svelte/transition';
  import { Button } from '@client/components/ui/button';
  import Copy from '@lucide/svelte/icons/copy';
  import Check from '@lucide/svelte/icons/check';
  import LifeBuoy from '@lucide/svelte/icons/life-buoy';
  import ChevronDown from '@lucide/svelte/icons/chevron-down';
  import RefreshCw from '@lucide/svelte/icons/refresh-cw';
  import MapPin from '@lucide/svelte/icons/map-pin';
  import Flag from '@lucide/svelte/icons/flag';
  import { ApiCallError, apiClient } from '../lib/api';
  import { apiErrorMessage } from '../lib/errors';
  import { t } from '../lib/i18n/index.svelte';
  import { COUNTRY_CODES } from '../lib/countries';
  import MirrorRegionSelect from './MirrorRegionSelect.svelte';
  import { MirrorRequestResponse, MirrorClearResponse } from '../../shared/contracts/mirror';
  import type { AccountResponse } from '../../shared/contracts/account';
  import { connectionRegionQuery, queryKeys, setConnectionRegion } from '../lib/queries';
  import { sealingEnabled } from '../lib/hpke';
  import { asksCountry, isAnswer, mirrorCountry, prefillAnswer } from '../lib/countryQuestion';
  import CountryQuestion from './CountryQuestion.svelte';
  import MirrorSetFor from './MirrorSetFor.svelte';
  import { MIRROR_REQUEST_KEY, withoutMirrors } from '../lib/mirrorSuggestion';
  import { copyText } from '../lib/utils';
  import { createMutation, useIsMutating, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';

  /**
   * Opt-in "trouble connecting?" affordance. Understated by design - the normal
   * subscription URL stays primary. A member who can't connect provisions one
   * country-tiered mirror at a time (capped server-side); each is an extra
   * subscription URL they add in their app. The country picker is prefilled from
   * the CDN geo (transient, NEVER stored) and is overridable.
   *
   * Renders in ALL deployments (the availability is member-visible state, not a
   * reason to hide): `available=false` (no active mirror provider configured)
   * shows a quiet "not available here" note instead of the picker.
   *
   * With the country question on (`askCountry`, lib/countryQuestion.ts), a
   * mirror is shaped for the key's own answer to "Where are you connecting
   * from?" (it cannot see where its reader is): a key with an answer says what
   * its mirrors are set up for (Change asks again); a key without one asks,
   * required, prefilled from the guess or the CDN geo. The answer travels sealed
   * with the mirror request (saved to the key first) or, for mirrors the key
   * already has, with Save (the account card's route): the server rewrites them
   * at the same URLs. Off, or for a key whose mode holds no country, the old
   * transient region picker stays.
   */
  interface Props {
    mirrors: { provider: string; publicUrl: string }[];
    geoCountry?: string | null;
    subscriptionUrl: string;
    /** Whether the deployment has any active mirror provider (publicConfig
     *  mirrorsEnabled). */
    available?: boolean;
    /** Quick fix #1: open the "move me to a different server" flow (same
     *  handler as the pass's node line). Omitted = the action isn't offered
     *  here (no key to move / backend can't move one / caller has no modal). */
    onSwitchServer?: () => void;
    /** Quick fix #2: open the new-key flow with the location picker (the
     *  regenerate modal). Omitted = not offered (single-location deploys). */
    onPickLocation?: () => void;
    /** Open the report-issue dialog. The one place a member reports from (the
     *  pass has no report button): a member stuck here is exactly who should
     *  tell us why. */
    onReportIssue?: () => void;
    /** The deployment asks where the member connects from (publicConfig.countryQuestion). */
    askCountry?: boolean;
  }
  let {
    mirrors,
    geoCountry = null,
    subscriptionUrl,
    available = true,
    onSwitchServer = undefined,
    onPickLocation = undefined,
    onReportIssue = undefined,
    askCountry = false,
  }: Props = $props();

  const qc = useQueryClient();

  const canSeal = sealingEnabled();
  const region = connectionRegionQuery(() => canSeal && askCountry);
  const asking = $derived(asksCountry({ countryQuestion: askCountry, canSeal, view: region.data }));
  const setFor = $derived(mirrorCountry(region.data));
  let changing = $state(false);
  const needsAnswer = $derived(asking && (setFor.kind === 'unset' || changing));
  let answer = $state('');
  let answerInvalid = $state(false);
  let savingAnswer = $state(false);
  $effect(() => {
    if (!needsAnswer || answer) return;
    answer = prefillAnswer(region.data?.options ?? [], region.data?.guess?.country, geoCountry);
  });
  $effect(() => {
    if (answer) answerInvalid = false;
  });
  const answerOk = () => isAnswer(answer, region.data?.options ?? []);

  /** The request body: the answer (sealed), nothing (the stored answer picks the host), or a host hint. */
  function requestBody(): Record<string, string | null> {
    if (needsAnswer) return { region: answer };
    if (asking) return {};
    return { countryCode: selected || null };
  }
  function getMirror() {
    if (needsAnswer && !answerOk()) {
      answerInvalid = true;
      return;
    }
    request.mutate();
  }
  /** Mirrors the key already has: save the answer only; the server rewrites them. */
  async function saveAnswer() {
    if (!answerOk()) {
      answerInvalid = true;
      return;
    }
    savingAnswer = true;
    try {
      qc.setQueryData(queryKeys.connectionRegion, await setConnectionRegion(answer));
      changing = false;
      toast.success(t('region.saved'), { description: t('mirror.willUpdate') });
    } catch (err) {
      toast.error(
        err instanceof ApiCallError && err.payload.error.code === 'rate_limit.country_day'
          ? t('region.tooOften')
          : t('region.failed'),
      );
    } finally {
      savingAnswer = false;
    }
  }

  let open = $state(false);

  // One-time snapshot of the geo prop into local state (the IIFE breaks the
  // compiler's "captures initial value of prop" analysis - same idiom as the
  // editors).
  const init = ((g: Props['geoCountry']) => ({
    selected: g && COUNTRY_CODES.includes(g) ? g : '',
  }))(geoCountry);

  let status = $state<MirrorRequestResponse['status'] | 'idle'>('idle');
  let copiedUrl = $state<string | null>(null);

  // The list follows the server (the `mirrors` prop): a mirror withdrawn with
  // its provider, or one whose last refresh failed, leaves it at the parent's
  // next refetch instead of staying on screen until a reload. Two local
  // overlays bridge the moment before that refetch lands: a mirror just added
  // (`pending`) and the ones just removed (`removed`). Each entry goes once the
  // server agrees, so a later withdrawal never brings a pending one back.
  let pending = $state<{ provider: string; publicUrl: string }[]>([]);
  let removed = $state<string[]>([]);
  const fromServer = $derived(
    mirrors.filter((x) => x.publicUrl && x.publicUrl !== subscriptionUrl),
  );
  const added = $derived([
    ...fromServer.filter((m) => !removed.includes(m.publicUrl)),
    ...pending.filter((p) => !fromServer.some((m) => m.publicUrl === p.publicUrl)),
  ]);
  $effect(() => {
    const listed = new Set(fromServer.map((m) => m.publicUrl));
    if (pending.some((p) => listed.has(p.publicUrl)))
      pending = pending.filter((p) => !listed.has(p.publicUrl));
    if (removed.some((u) => !listed.has(u))) removed = removed.filter((u) => listed.has(u));
  });

  // A NEW key (regenerate/switch) retires every mirror minted against the old
  // one: the overlays describe the old key, so they go with it.
  // svelte-ignore state_referenced_locally -- intentionally a "last seen" tracker,
  // compared against the live prop in the $effect below.
  let lastSubUrl = $state(subscriptionUrl);
  $effect(() => {
    if (subscriptionUrl !== lastSubUrl) {
      lastSubUrl = subscriptionUrl;
      pending = [];
      removed = [];
    }
  });

  let selected = $state<string>(init.selected);

  async function copy(url: string) {
    if (await copyText(url)) {
      copiedUrl = url;
      setTimeout(() => (copiedUrl = null), 1500);
    } else {
      toast.error(t('common.copyFailed'));
    }
  }

  const request = createMutation(() => ({
    mutationKey: MIRROR_REQUEST_KEY,
    mutationFn: () =>
      apiClient.post('/api/v1/mirror/request', requestBody(), MirrorRequestResponse),
    onSuccess: (res) => {
      // An answer sent with the request is the key's answer now.
      if (needsAnswer) {
        changing = false;
        void qc.invalidateQueries({ queryKey: queryKeys.connectionRegion });
      }
      if (res.status === 'ok' && res.publicUrl) {
        if (!added.some((m) => m.publicUrl === res.publicUrl)) {
          pending = [...pending, { provider: res.provider ?? '', publicUrl: res.publicUrl }];
        }
        status = res.remaining > 0 ? 'idle' : 'capped';
        void qc.invalidateQueries({ queryKey: queryKeys.account });
      } else {
        status = res.status === 'ok' ? 'idle' : res.status;
      }
    },
    onError: (err) => {
      status = 'error';
      toast.error(t('mirror.errorToast'), { description: apiErrorMessage(err) });
    },
  }));

  const clear = createMutation(() => ({
    mutationFn: () => apiClient.delete('/api/v1/mirror', MirrorClearResponse),
    onSuccess: () => {
      removed = fromServer.map((m) => m.publicUrl);
      // The shared view too: a link picked from these (the onboarding choice)
      // stops reaching the pass and the app buttons now, not at the refetch.
      qc.setQueryData<AccountResponse>(queryKeys.account, (old) => withoutMirrors(old));
      pending = [];
      status = 'idle';
      void qc.invalidateQueries({ queryKey: queryKeys.account });
      toast.success(t('mirror.removedToast'));
    },
    onError: (err) => toast.error(t('mirror.errorToast'), { description: apiErrorMessage(err) }),
  }));

  const exhausted = $derived(status === 'capped' || status === 'exhausted');
  // A request from either mirror button (this one or the onboarding
  // suggestion) holds both, and the remove, until it settles.
  const requesting = useIsMutating({ mutationKey: MIRROR_REQUEST_KEY });
  const busy = $derived(request.isPending || requesting.current > 0);
</script>

<div class="rounded-lg border border-border/70 bg-card">
  <button
    type="button"
    class="flex min-h-14 w-full items-center justify-between gap-2 rounded-lg px-5 py-3 text-start font-bold text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
    onclick={() => (open = !open)}
    aria-expanded={open}
  >
    <span class="flex items-center gap-2 text-muted-foreground">
      <LifeBuoy class="size-4 shrink-0" />
      {t('mirror.disclosure')}
    </span>
    <ChevronDown class="size-4 shrink-0 transition-transform {open ? 'rotate-180' : ''}" />
  </button>

  {#if open}
    <div class="space-y-4 px-5 pb-5 text-sm" transition:slide={{ duration: 180 }}>
      <!-- Quick fixes first: a blocked/overloaded server is the most common
           cause, and moving the key (same handlers as the pass) fixes it
           without any new URLs to import. Mirrors follow as the deeper tool. -->
      {#if onSwitchServer || onPickLocation || onReportIssue}
        <div class="space-y-2">
          <p class="text-sm font-bold text-foreground">
            {t('mirror.quickLabel')}
          </p>
          <p class="text-muted-foreground">{t('mirror.quickHint')}</p>
          <div class="flex flex-wrap gap-2">
            {#if onSwitchServer}
              <Button variant="outline" size="sm" class="min-h-11" onclick={onSwitchServer}>
                <RefreshCw class="size-4" />
                {t('switchServer.action')}
              </Button>
            {/if}
            {#if onPickLocation}
              <Button variant="outline" size="sm" class="min-h-11" onclick={onPickLocation}>
                <MapPin class="size-4" />
                {t('mirror.pickLocation')}
              </Button>
            {/if}
            {#if onReportIssue}
              <Button
                variant="outline"
                size="sm"
                class="min-h-11 border-destructive/40 text-destructive hover:bg-destructive/10 hover:text-destructive"
                onclick={onReportIssue}
              >
                <Flag class="size-4" />
                {t('report.action')}
              </Button>
            {/if}
          </div>
        </div>
        <div class="border-t border-border/60"></div>
      {/if}

      <p class="text-muted-foreground">{t('mirror.explainer')}</p>

      {#if !available}
        <!-- Availability is member-visible: no mirror provider is configured on
             this deployment, so the fallback simply doesn't exist here. -->
        <p class="text-muted-foreground/80 text-sm">{t('mirror.unavailable')}</p>
      {:else}
        {#if added.length > 0}
          <div class="space-y-2">
            <p class="text-sm font-bold text-foreground">
              {t('mirror.addedLabel')}
            </p>
            {#each added as m (m.publicUrl)}
              <div class="flex gap-2">
                <code
                  class="min-w-0 flex-1 select-all break-all rounded-sm border border-border bg-well px-3 py-2 font-mono text-sm text-foreground"
                >
                  {m.publicUrl}
                </code>
                <Button
                  variant="outline"
                  size="sm"
                  class="min-h-11"
                  onclick={() => copy(m.publicUrl)}
                >
                  {#if copiedUrl === m.publicUrl}
                    <Check class="size-3.5" />
                  {:else}
                    <Copy class="size-3.5" />
                  {/if}
                </Button>
              </div>
            {/each}
            <p class="text-sm text-muted-foreground/80">{t('mirror.addToAppHint')}</p>
          </div>
        {/if}

        {#if asking && !needsAnswer}
          <MirrorSetFor
            country={setFor.kind === 'country' ? setFor.country : null}
            onChange={() => (changing = true)}
            disabled={busy || savingAnswer}
          />
        {/if}

        {#if needsAnswer && added.length > 0}
          <!-- Mirrors made before the question (or a change of answer): save it,
               and the server rewrites the mirrors the key has at the same URLs. -->
          <div class="space-y-3">
            {#if setFor.kind === 'unset'}
              <p class="font-bold text-foreground">{t('mirror.notSetPrompt')}</p>
            {/if}
            <CountryQuestion
              id="mirror-country"
              options={region.data?.options ?? []}
              bind:value={answer}
              help={t('mirror.countryHelp')}
              invalid={answerInvalid}
              disabled={busy || savingAnswer}
            />
            <Button
              variant="outline"
              onclick={() => void saveAnswer()}
              disabled={busy || savingAnswer}
              class="min-h-11"
            >
              {savingAnswer ? t('mirror.working') : t('mirror.saveCountry')}
            </Button>
          </div>
        {/if}

        {#if !exhausted}
          {#if needsAnswer && added.length === 0}
            <CountryQuestion
              id="mirror-country"
              options={region.data?.options ?? []}
              bind:value={answer}
              help={t('mirror.countryHelp')}
              invalid={answerInvalid}
              disabled={busy}
            />
          {:else if !asking}
            <MirrorRegionSelect id="mirror-region" bind:value={selected} />
          {/if}

          <Button onclick={getMirror} disabled={busy || savingAnswer} class="min-h-11">
            {busy
              ? t('mirror.working')
              : added.length === 0
                ? t('mirror.getButton')
                : t('mirror.tryAnother')}
          </Button>
        {/if}

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
          <!-- The server answered but could not add one (a transient upload or
               backend failure, or the key moved meanwhile): say so, or the
               button looks like it did nothing. -->
          <p class="text-sm text-amber-600" role="status" transition:fade={{ duration: 150 }}>
            {t('mirror.failed')}
          </p>
        {/if}

        {#if added.length > 0}
          <button
            type="button"
            class="rounded-sm text-sm text-muted-foreground underline underline-offset-2 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            onclick={() => clear.mutate()}
            disabled={clear.isPending || busy}
          >
            {clear.isPending ? t('mirror.working') : t('mirror.removeAll')}
          </button>
        {/if}
      {/if}
    </div>
  {/if}
</div>
