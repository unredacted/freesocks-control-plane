<script lang="ts">
  import { slide, fade } from 'svelte/transition';
  import { Button } from '@client/components/ui/button';
  import * as Select from '@client/components/ui/select';
  import Copy from '@lucide/svelte/icons/copy';
  import Check from '@lucide/svelte/icons/check';
  import LifeBuoy from '@lucide/svelte/icons/life-buoy';
  import ChevronDown from '@lucide/svelte/icons/chevron-down';
  import { apiClient } from '../lib/api';
  import { apiErrorMessage } from '../lib/errors';
  import { t, getLocale } from '../lib/i18n/index.svelte';
  import { COUNTRY_CODES, countryName } from '../lib/countries';
  import { MirrorRequestResponse, MirrorClearResponse } from '../../shared/contracts/mirror';
  import { queryKeys } from '../lib/queries';
  import { copyText } from '../lib/utils';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';

  /**
   * Opt-in "trouble connecting?" affordance. Understated by design — the normal
   * subscription URL stays primary. A member who can't connect provisions one
   * country-tiered mirror at a time (capped server-side); each is an extra
   * subscription URL they add in their app. The country picker is prefilled from
   * the CDN geo (transient, NEVER stored) and is overridable.
   */
  interface Props {
    mirrors: { provider: string; publicUrl: string }[];
    geoCountry?: string | null;
    subscriptionUrl: string;
  }
  let { mirrors, geoCountry = null, subscriptionUrl }: Props = $props();

  const qc = useQueryClient();
  const locale = getLocale();

  let open = $state(false);

  // One-time snapshot of the props into local state (the IIFE breaks the
  // compiler's "captures initial value of prop" analysis — same idiom as the
  // editors). `added` is seeded from props so it updates immediately on provision
  // without waiting for the parent to re-fetch.
  const init = ((m: Props['mirrors'], g: Props['geoCountry'], sub: string) => ({
    added: m.filter((x) => x.publicUrl && x.publicUrl !== sub),
    selected: g && COUNTRY_CODES.includes(g) ? g : '',
  }))(mirrors, geoCountry, subscriptionUrl);

  let added = $state<{ provider: string; publicUrl: string }[]>(init.added);
  let status = $state<MirrorRequestResponse['status'] | 'idle'>('idle');
  let copiedUrl = $state<string | null>(null);

  // Region options: localized names (Intl.DisplayNames), sorted; "Global" first.
  const regions = COUNTRY_CODES.map((c) => ({ code: c, name: countryName(c, locale) })).sort(
    (a, b) => a.name.localeCompare(b.name, locale),
  );
  let selected = $state<string>(init.selected);
  const selectedLabel = $derived(
    selected
      ? (regions.find((r) => r.code === selected)?.name ?? selected)
      : t('mirror.regionGlobal'),
  );

  async function copy(url: string) {
    if (await copyText(url)) {
      copiedUrl = url;
      setTimeout(() => (copiedUrl = null), 1500);
    } else {
      toast.error(t('common.copyFailed'));
    }
  }

  const request = createMutation(() => ({
    mutationFn: () =>
      apiClient.post(
        '/api/v1/mirror/request',
        { countryCode: selected || null },
        MirrorRequestResponse,
      ),
    onSuccess: (res) => {
      if (res.status === 'ok' && res.publicUrl) {
        if (!added.some((m) => m.publicUrl === res.publicUrl)) {
          added = [...added, { provider: res.provider ?? '', publicUrl: res.publicUrl }];
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
      added = [];
      status = 'idle';
      void qc.invalidateQueries({ queryKey: queryKeys.account });
      toast.success(t('mirror.removedToast'));
    },
    onError: (err) => toast.error(t('mirror.errorToast'), { description: apiErrorMessage(err) }),
  }));

  const exhausted = $derived(status === 'capped' || status === 'exhausted');
</script>

<div class="rounded-xl border border-border/60 bg-muted/30">
  <button
    type="button"
    class="flex w-full items-center justify-between gap-2 rounded-xl px-4 py-3 text-start text-sm font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
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
    <div class="space-y-4 px-4 pb-4 text-sm" transition:slide={{ duration: 180 }}>
      <p class="text-muted-foreground">{t('mirror.explainer')}</p>

      {#if added.length > 0}
        <div class="space-y-2">
          <p class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            {t('mirror.addedLabel')}
          </p>
          {#each added as m (m.publicUrl)}
            <div class="flex gap-2">
              <code
                class="min-w-0 flex-1 select-all break-all rounded-md bg-muted px-3 py-2 font-mono text-xs text-muted-foreground"
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
          <p class="text-xs text-muted-foreground/80">{t('mirror.addToAppHint')}</p>
        </div>
      {/if}

      {#if !exhausted}
        <div class="space-y-2">
          <label class="block text-xs text-muted-foreground" for="mirror-region">
            {t('mirror.regionLabel')}
          </label>
          <Select.Root type="single" value={selected} onValueChange={(v) => (selected = v ?? '')}>
            <Select.Trigger id="mirror-region" class="w-full sm:w-72"
              >{selectedLabel}</Select.Trigger
            >
            <Select.Content class="max-h-72 overflow-y-auto">
              <Select.Item value="">{t('mirror.regionGlobal')}</Select.Item>
              {#each regions as r (r.code)}
                <Select.Item value={r.code}>{r.name}</Select.Item>
              {/each}
            </Select.Content>
          </Select.Root>
          <p class="text-xs text-muted-foreground/80">{t('mirror.regionNotStored')}</p>
        </div>

        <Button onclick={() => request.mutate()} disabled={request.isPending} class="min-h-11">
          {request.isPending
            ? t('mirror.working')
            : added.length === 0
              ? t('mirror.getButton')
              : t('mirror.tryAnother')}
        </Button>
      {/if}

      {#if status === 'capped'}
        <p class="text-xs text-amber-600" transition:fade={{ duration: 150 }}>
          {t('mirror.capped')}
        </p>
      {:else if status === 'exhausted'}
        <p class="text-xs text-amber-600" transition:fade={{ duration: 150 }}>
          {t('mirror.exhausted')}
        </p>
      {:else if status === 'no_subscription'}
        <p class="text-xs text-muted-foreground" transition:fade={{ duration: 150 }}>
          {t('mirror.noSubscription')}
        </p>
      {/if}

      {#if added.length > 0}
        <button
          type="button"
          class="rounded-sm text-xs text-muted-foreground underline underline-offset-2 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          onclick={() => clear.mutate()}
          disabled={clear.isPending}
        >
          {clear.isPending ? t('mirror.working') : t('mirror.removeAll')}
        </button>
      {/if}
    </div>
  {/if}
</div>
