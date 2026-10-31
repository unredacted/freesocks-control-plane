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
  import { getLocale, t, type MessageKey } from '../lib/i18n/index.svelte';
  import Smartphone from '@lucide/svelte/icons/smartphone';
  import ExternalLink from '@lucide/svelte/icons/external-link';
  import QrCodeIcon from '@lucide/svelte/icons/qr-code';
  import QrCode from './QrCode.svelte';
  import { configQuery } from '../lib/queries';
  import { backendEntry } from '../lib/backends';
  import { buildImportLink, IMPORT_PROFILE_NAME } from '../lib/appLinks';
  import { installKind, type InstallKind } from '../lib/installKind';
  import { detectClientPlatform, type PlatformKey } from '../lib/platform';

  interface Props {
    backend?: string;
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

  const PLATFORMS: { key: PlatformKey; labelKey: MessageKey }[] = [
    { key: 'android', labelKey: 'setup.android' },
    { key: 'ios', labelKey: 'setup.ios' },
    { key: 'windows', labelKey: 'setup.windows' },
    { key: 'desktop', labelKey: 'setup.desktop' },
  ];
  // Preselect the visitor's own platform (UA-detected) so nobody lands on the
  // wrong instructions; tabs remain free to change.
  let active = $state<PlatformKey>(detectClientPlatform());

  // Catalog for this backend (already enabled + priority-sorted server-side).
  let clients = $derived(
    (config.data?.clients ?? []).filter((c) => (c.backends as string[]).includes(backend)),
  );
  let currentClients = $derived(clients.filter((c) => c.platforms.includes(active)));
  // On a device-limited plan, HWID-capable apps honor the limit; others each
  // consume a slot per launch (or, with backend enforcement on, fail to connect),
  // so we surface them separately. `gateDevices` is true only when it matters —
  // the backend's DEVICE capability comes from publicConfig, not an id literal.
  let gateDevices = $derived(
    deviceLimited &&
      (backendEntry(config.data?.backends, backend)?.capabilities.devices ?? backend !== 'outline'),
  );
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

  // Where the Install button actually goes (Play Store / App Store / GitHub /
  // direct APK / website) - derived from the URL, labeled on the button.
  const KIND_KEYS: Record<InstallKind, MessageKey> = {
    play: 'setup.linkKind.play',
    appStore: 'setup.linkKind.appStore',
    github: 'setup.linkKind.github',
    apk: 'setup.linkKind.apk',
    website: 'setup.linkKind.website',
  };

  // Per-client blurb ("why choose this app"): an admin-set catalog description
  // overrides the translated copy verbatim (all locales); else the built-in i18n
  // for known default apps, else nothing. Same pattern as connection-mode labels.
  const DESC_KEYS: Partial<Record<string, MessageKey>> = {
    Hiddify: 'setup.clientDesc.hiddify',
    Karing: 'setup.clientDesc.karing',
    Anywhere: 'setup.clientDesc.anywhere',
    'sing-box': 'setup.clientDesc.singBox',
    v2rayNG: 'setup.clientDesc.v2rayng',
    v2rayN: 'setup.clientDesc.v2rayn',
    Clash: 'setup.clientDesc.clash',
    FlClash: 'setup.clientDesc.flclash',
    'Mihomo Party': 'setup.clientDesc.mihomoParty',
    Throne: 'setup.clientDesc.throne',
    Shadowrocket: 'setup.clientDesc.shadowrocket',
    Outline: 'setup.clientDesc.outline',
  };
  function clientDesc(c: { name: string; description?: string }): string | null {
    if (c.description?.trim()) return c.description;
    const key = DESC_KEYS[c.name];
    return key ? t(key) : null;
  }

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

  // Step numbers in the member's own digits (Persian and Arabic included).
  const stepNumber = $derived(new Intl.NumberFormat(getLocale()));
</script>

<section class="@container panel">
  <h2 class="text-xl font-bold leading-tight">{t('setup.title')}</h2>
  <p class="mt-1.5 text-[15px] text-muted-foreground">{t('setup.intro')}</p>

  <!-- Platform picker: one segmented row (the active platform inverted). -->
  <div class="mt-4 flex flex-wrap" role="tablist" aria-label={t('setup.title')}>
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
        class="relative -ms-px min-h-11 border px-3.5 text-[15px] transition-colors first:ms-0 first:rounded-s-sm last:rounded-e-sm focus-visible:z-10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring {active ===
        p.key
          ? 'z-[1] border-foreground bg-foreground font-bold text-background'
          : 'border-border text-body hover:text-foreground'}"
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
    {#snippet clientCard(c: (typeof currentClients)[number], recommended = false)}
      {@const link = importLink(c.schemeId)}
      {@const desc = clientDesc(c)}
      <!-- Facts as one quiet line, not a row of badges: recommended (the first
           entry, already sorted OSS-first then easiest), license, the two
           poles of ease-of-use ('moderate' would be noise), VERIFIED IPv6
           support only, and the source link. -->
      {@const facts = [
        c.openSource ? t('setup.openSource') : t('setup.proprietary'),
        c.easeOfUse === 'easy'
          ? t('setup.easeEasy')
          : c.easeOfUse === 'advanced'
            ? t('setup.easeAdvanced')
            : null,
        c.ipv6 === true ? t('setup.ipv6Works') : c.ipv6 === false ? t('setup.ipv4Only') : null,
      ].filter(Boolean)}
      <li class="border-t border-border/70 py-4 first:border-t-0 first:pt-1">
        <!-- Buttons beside the name once the panel is wide enough, below it otherwise. -->
        <div class="flex flex-col gap-2 @xl:flex-row @xl:items-start @xl:justify-between @xl:gap-4">
          <div class="min-w-0 flex-1">
            <p class="font-bold text-foreground">{c.name}</p>
            <p class="text-sm text-muted-foreground">
              {#if recommended}
                <span class="font-bold text-primary">{t('setup.recommended')}</span>
                <span aria-hidden="true">{' · '}</span>
              {/if}{facts.join(' · ')}{#if c.sourceUrl}
                <span aria-hidden="true">{' · '}</span>
                <a
                  href={c.sourceUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  class="link-brand text-muted-foreground">{t('setup.viewSource')}</a
                >
              {/if}
            </p>
          </div>
          <div class="flex shrink-0 flex-wrap items-center gap-2">
            <a
              href={c.homepageUrl}
              target="_blank"
              rel="noopener noreferrer"
              class="inline-flex min-h-10 items-center gap-1.5 rounded-sm border-2 border-border px-3 text-sm font-semibold transition-colors hover:bg-muted"
            >
              <ExternalLink class="size-3.5" />
              {t('setup.install')}
              <span class="text-xs font-normal text-muted-foreground">
                · {t(KIND_KEYS[installKind(c.homepageUrl)])}
              </span>
            </a>
            {#if link}
              <a
                href={link}
                class="inline-flex min-h-10 items-center gap-1.5 rounded-sm border-2 border-transparent bg-primary px-3 text-sm font-semibold text-primary-foreground transition-colors hover:bg-primary/90"
              >
                <Smartphone class="size-3.5" />
                {t('hero.importOpen', { app: c.name })}
              </a>
              <button
                type="button"
                onclick={() => (qrFor = qrFor === c.name ? null : c.name)}
                aria-expanded={qrFor === c.name}
                aria-label={t('hero.importScan', { app: c.name })}
                class="inline-flex min-h-10 items-center rounded-sm border-2 border-border px-2 hover:bg-muted"
              >
                <QrCodeIcon class="size-4" />
              </button>
            {/if}
          </div>
        </div>
        {#if desc}
          <p class="mt-1.5 text-[15px] leading-relaxed text-body">{desc}</p>
        {/if}
        {#if link && qrFor === c.name}
          <div class="mt-3 flex flex-col items-center">
            <QrCode text={link} size={168} />
            <p class="mt-2 text-sm text-muted-foreground">
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
      <p class="text-sm font-bold text-foreground">{t('setup.deviceCompatibleTitle')}</p>
      <ul class="mt-2">
        {#each compatClients as c (c.name)}
          {@render clientCard(c)}
        {/each}
      </ul>
      {#if incompatClients.length > 0}
        <p class="mt-4 text-sm font-bold text-foreground">
          {t('setup.deviceIncompatibleTitle')}
        </p>
        <p class="mt-1 text-sm text-muted-foreground">{t('setup.deviceIncompatibleNote')}</p>
        <ul class="mt-2 opacity-75">
          {#each incompatClients as c (c.name)}
            {@render clientCard(c)}
          {/each}
        </ul>
      {/if}
    {:else}
      <!-- The full catalog, all visible: the first entry (already sorted
           OSS-first-then-easiest server-side) carries the Recommended badge,
           so the choice is guided without hiding the alternatives. -->
      <ul>
        {#each currentClients as c, i (c.name)}
          {@render clientCard(c, i === 0)}
        {/each}
      </ul>
    {/if}

    <!-- A partially-populated catalog (or a platform with nothing for this
         backend) should say so, not render a silent gap above the steps. -->
    {#if currentClients.length === 0}
      <p
        class="rounded-sm border border-dashed border-border px-3 py-2 text-sm text-muted-foreground"
      >
        {t('setup.noApps')}
      </p>
    {/if}

    <!-- The same three steps as before (install → import → connect). -->
    <ol class="mt-5 grid gap-3 border-t border-border/70 pt-5">
      {#each [t('setup.step.install'), rawConfigFirst ? t('setup.step.importConfig') : t('setup.step.import'), t('setup.step.connect')] as step, i (i)}
        <li class="grid grid-cols-[1.75rem_minmax(0,1fr)] gap-2">
          <span class="font-display font-bold text-primary tabular-nums"
            >{stepNumber.format(i + 1)}</span
          >
          <span class="text-foreground">{step}</span>
        </li>
      {/each}
    </ol>
    {#if gateDevices}
      <p class="mt-3 text-sm text-muted-foreground">{t('setup.hwidNote')}</p>
    {/if}
  </div>
</section>
