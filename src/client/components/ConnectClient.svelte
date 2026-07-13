<script lang="ts">
  /**
   * The single, catalog-driven "set up your app" section - the merge of the old
   * SetupGuidance (per-platform recommended apps + 3-step guide) and the old
   * SubscriptionHero import chips (per-client deep-link QR). The client list is
   * DB-driven (publicConfig.clients, CMS-managed); the per-app import scheme comes
   * from a code builder keyed by the catalog's `schemeId` (buildImportLink).
   *
   * Per platform, each recommended app shows: an Install link, a device-limit tag,
   * and - when we have a subscription URL (evade, non-privacy) and the app has an
   * import scheme - a one-tap "Open in <app>" button + a scannable per-app QR that
   * lands straight in the app (a plain https QR would just open a browser). Privacy
   * mode hides the URL, so those apps import the raw config below (manual).
   *
   * App names are proper nouns (not translated); the structural copy is i18n'd.
   */
  import { t, type MessageKey } from '../lib/i18n/index.svelte';
  import Smartphone from '@lucide/svelte/icons/smartphone';
  import ExternalLink from '@lucide/svelte/icons/external-link';
  import QrCodeIcon from '@lucide/svelte/icons/qr-code';
  import QrCode from './QrCode.svelte';
  import { configQuery } from '../lib/queries';
  import { buildImportLink, IMPORT_PROFILE_NAME } from '../lib/appLinks';

  interface Props {
    backend?: 'remnawave' | 'outline';
    /** The FCP-fronted subscription URL. Absent in rawConfig mode / before a key
     *  exists → we show install + manual-import guidance, no deep-link buttons. */
    subscriptionUrl?: string;
    /** A rawConfig-delivery mode hides the auto-updating link → deliver the raw
     *  config below, so step 2 says "enter the configuration below" instead of
     *  "paste your link". */
    rawConfigFirst?: boolean;
    /** True when the member's plan enforces a device limit (tier opts in AND the
     *  global toggle is on). Only then do we split apps by HWID support + show
     *  the HWID note; otherwise the device-limit concept is irrelevant and hidden. */
    deviceLimited?: boolean;
  }
  let {
    backend = 'remnawave',
    subscriptionUrl,
    rawConfigFirst = false,
    deviceLimited = false,
  }: Props = $props();

  const config = configQuery();

  type PlatformKey = 'android' | 'ios' | 'windows' | 'desktop';
  const PLATFORMS: { key: PlatformKey; labelKey: MessageKey }[] = [
    { key: 'android', labelKey: 'setup.android' },
    { key: 'ios', labelKey: 'setup.ios' },
    { key: 'windows', labelKey: 'setup.windows' },
    { key: 'desktop', labelKey: 'setup.desktop' },
  ];
  let active = $state<PlatformKey>('android');

  // Catalog for this backend (already enabled + priority-sorted server-side).
  let clients = $derived((config.data?.clients ?? []).filter((c) => c.backends.includes(backend)));
  let currentClients = $derived(clients.filter((c) => c.platforms.includes(active)));
  // On a device-limited plan, HWID-capable apps honor the limit; others each
  // consume a slot per launch (or, with panel enforcement on, fail to connect),
  // so we surface them separately. `gateDevices` is true only when it matters.
  let gateDevices = $derived(deviceLimited && backend !== 'outline');
  let compatClients = $derived(currentClients.filter((c) => c.hwid));
  let incompatClients = $derived(currentClients.filter((c) => !c.hwid));

  // A one-tap import link is possible only with a (non-rawConfig) subscription
  // URL and an app that has an import scheme.
  let canImport = $derived(!rawConfigFirst && !!subscriptionUrl);
  function importLink(schemeId: string | null): string | null {
    return canImport && subscriptionUrl
      ? buildImportLink(schemeId, subscriptionUrl, IMPORT_PROFILE_NAME)
      : null;
  }

  // Per-card QR toggle (one open at a time), keyed by client name.
  let qrFor = $state<string | null>(null);

  // WAI-ARIA tabs roving focus (same pattern as the old SetupGuidance).
  function tabKeydown(e: KeyboardEvent) {
    const forward = ['ArrowRight', 'ArrowDown'].includes(e.key);
    const backward = ['ArrowLeft', 'ArrowUp'].includes(e.key);
    if (!forward && !backward) return;
    e.preventDefault();
    const idx = PLATFORMS.findIndex((p) => p.key === active);
    const next = (idx + (forward ? 1 : -1) + PLATFORMS.length) % PLATFORMS.length;
    active = PLATFORMS[next]!.key;
    qrFor = null;
    (e.currentTarget as HTMLElement).parentElement
      ?.querySelector<HTMLElement>('[aria-selected="true"]')
      ?.focus();
  }
</script>

<section class="rounded-xl border border-border bg-card p-5 sm:p-6">
  <h2 class="flex items-center gap-2 text-lg font-display font-semibold">
    <Smartphone class="size-4 text-muted-foreground" aria-hidden="true" />
    {t('setup.title')}
  </h2>
  <p class="mt-1 text-sm text-muted-foreground">{t('setup.intro')}</p>

  <div class="mt-4 flex flex-wrap gap-1.5" role="tablist" aria-label={t('setup.title')}>
    {#each PLATFORMS as p (p.key)}
      <button
        type="button"
        role="tab"
        id="connect-tab-{p.key}"
        aria-selected={active === p.key}
        aria-controls="connect-panel-{p.key}"
        tabindex={active === p.key ? 0 : -1}
        onclick={() => {
          active = p.key;
          qrFor = null;
        }}
        onkeydown={tabKeydown}
        class="min-h-9 rounded-md px-3 py-1.5 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background {active ===
        p.key
          ? 'bg-primary text-primary-foreground'
          : 'bg-muted text-muted-foreground hover:text-foreground'}"
      >
        {t(p.labelKey)}
      </button>
    {/each}
  </div>

  <div
    role="tabpanel"
    id="connect-panel-{active}"
    aria-labelledby="connect-tab-{active}"
    class="mt-4"
  >
    {#snippet clientCard(c: (typeof currentClients)[number])}
      {@const link = importLink(c.schemeId)}
      <li class="rounded-lg border border-border bg-background/40 p-3">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <div class="min-w-0">
            <span class="text-sm font-semibold">{c.name}</span>
            {#if c.openSource}
              <span
                class="ms-2 inline-flex items-center rounded-full bg-primary/10 px-2 py-0.5 text-[11px] font-medium text-primary"
              >
                {t('setup.openSource')}
              </span>
            {:else}
              <span
                class="ms-2 inline-flex items-center rounded-full bg-muted px-2 py-0.5 text-[11px] font-medium text-muted-foreground"
              >
                {t('setup.proprietary')}
              </span>
            {/if}
            <!-- Ease-of-use badge: only the poles ('moderate' would just be noise). -->
            {#if c.easeOfUse === 'easy'}
              <span
                class="ms-2 inline-flex items-center rounded-full bg-emerald-500/10 px-2 py-0.5 text-[11px] font-medium text-emerald-600 dark:text-emerald-400"
              >
                {t('setup.easeEasy')}
              </span>
            {:else if c.easeOfUse === 'advanced'}
              <span
                class="ms-2 inline-flex items-center rounded-full bg-muted px-2 py-0.5 text-[11px] font-medium text-muted-foreground"
              >
                {t('setup.easeAdvanced')}
              </span>
            {/if}
            {#if c.sourceUrl}
              <a
                href={c.sourceUrl}
                target="_blank"
                rel="noopener noreferrer"
                class="ms-2 text-xs text-muted-foreground underline hover:text-foreground"
              >
                {t('setup.viewSource')}
              </a>
            {/if}
          </div>
          <div class="flex flex-wrap items-center gap-2">
            <a
              href={c.homepageUrl}
              target="_blank"
              rel="noopener noreferrer"
              class="inline-flex min-h-9 items-center gap-1.5 rounded-md border border-border px-3 py-1 text-sm font-medium hover:bg-muted"
            >
              <ExternalLink class="size-3.5" />
              {t('setup.install')}
            </a>
            {#if link}
              <a
                href={link}
                class="inline-flex min-h-9 items-center gap-1.5 rounded-md bg-primary px-3 py-1 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
              >
                <Smartphone class="size-3.5" />
                {t('hero.importOpen', { app: c.name })}
              </a>
              <button
                type="button"
                onclick={() => (qrFor = qrFor === c.name ? null : c.name)}
                aria-expanded={qrFor === c.name}
                aria-label={t('hero.importScan', { app: c.name })}
                class="inline-flex min-h-9 items-center rounded-md border border-border px-2 py-1 hover:bg-muted"
              >
                <QrCodeIcon class="size-4" />
              </button>
            {/if}
          </div>
        </div>
        {#if link && qrFor === c.name}
          <div class="mt-3 flex flex-col items-center">
            <QrCode text={link} size={168} />
            <p class="mt-2 text-xs text-muted-foreground">
              {t('hero.importScan', { app: c.name })}
            </p>
          </div>
        {/if}
      </li>
    {/snippet}

    <!-- Recommended apps for this platform (CMS-managed catalog). On a
         device-limited plan, split by HWID support so members pick an app that
         actually honors the limit; otherwise a single flat list. -->
    {#if gateDevices}
      <p class="text-xs font-medium text-muted-foreground">{t('setup.deviceCompatibleTitle')}</p>
      <ul class="mt-2 space-y-2">
        {#each compatClients as c (c.name)}
          {@render clientCard(c)}
        {/each}
      </ul>
      {#if incompatClients.length > 0}
        <p class="mt-4 text-xs font-medium text-muted-foreground">
          {t('setup.deviceIncompatibleTitle')}
        </p>
        <p class="mt-1 text-xs text-muted-foreground">{t('setup.deviceIncompatibleNote')}</p>
        <ul class="mt-2 space-y-2 opacity-75">
          {#each incompatClients as c (c.name)}
            {@render clientCard(c)}
          {/each}
        </ul>
      {/if}
    {:else}
      <ul class="space-y-2">
        {#each currentClients as c (c.name)}
          {@render clientCard(c)}
        {/each}
      </ul>
    {/if}

    <!-- The same three steps as before (install → import → connect). -->
    <ol class="mt-4 space-y-3 text-sm">
      <li class="flex gap-3">
        <span
          class="flex size-6 shrink-0 items-center justify-center rounded-full bg-primary/10 text-xs font-semibold text-primary tabular-nums"
          >1</span
        >
        <span>{t('setup.step.install')}</span>
      </li>
      <li class="flex gap-3">
        <span
          class="flex size-6 shrink-0 items-center justify-center rounded-full bg-primary/10 text-xs font-semibold text-primary tabular-nums"
          >2</span
        >
        <span>{rawConfigFirst ? t('setup.step.importConfig') : t('setup.step.import')}</span>
      </li>
      <li class="flex gap-3">
        <span
          class="flex size-6 shrink-0 items-center justify-center rounded-full bg-primary/10 text-xs font-semibold text-primary tabular-nums"
          >3</span
        >
        <span>{t('setup.step.connect')}</span>
      </li>
    </ol>
    {#if gateDevices}
      <p class="mt-3 text-xs text-muted-foreground">{t('setup.hwidNote')}</p>
    {/if}
  </div>
</section>
