<script lang="ts">
  /**
   * P1-14: per-platform setup guidance. After we hand the user a subscription
   * link, non-technical users in censored regions still need to know WHICH app
   * to install and HOW to import the link. A compact tabbed list of
   * recommended, free, open-source clients per OS + the same three steps
   * (install → import → connect). Backend-aware: an Outline access key uses the
   * official Outline client; an Xray subscription works with the v2ray-family
   * apps.
   *
   * App names are proper nouns (not translated); the structural copy is i18n'd.
   * Links open the app's own site — the user chooses whether to follow them.
   */
  import { t, type MessageKey } from '../lib/i18n/index.svelte';
  import Smartphone from '@lucide/svelte/icons/smartphone';

  interface Props {
    backend?: 'remnawave' | 'outline';
  }
  let { backend = 'remnawave' }: Props = $props();

  type App = { name: string; url: string };
  type Platform = {
    key: 'android' | 'ios' | 'windows' | 'desktop';
    labelKey: MessageKey;
    apps: App[];
  };

  // Recommended free/open-source clients. Outline keys → the Outline client;
  // Xray (Remnawave) subscriptions → the v2ray-family apps.
  const XRAY: Record<Platform['key'], App[]> = {
    android: [
      { name: 'v2rayNG', url: 'https://github.com/2dust/v2rayNG' },
      { name: 'Hiddify', url: 'https://hiddify.com' },
    ],
    ios: [
      { name: 'Streisand', url: 'https://apps.apple.com/app/streisand/id6450534064' },
      { name: 'Hiddify', url: 'https://hiddify.com' },
    ],
    windows: [
      { name: 'Hiddify', url: 'https://hiddify.com' },
      { name: 'NekoRay', url: 'https://github.com/MatsuriDayo/nekoray' },
    ],
    desktop: [
      { name: 'Hiddify', url: 'https://hiddify.com' },
      { name: 'NekoRay', url: 'https://github.com/MatsuriDayo/nekoray' },
    ],
  };
  const OUTLINE: App[] = [{ name: 'Outline', url: 'https://getoutline.org/get-started/#step-3' }];

  const PLATFORMS: Platform[] = [
    { key: 'android', labelKey: 'setup.android', apps: [] },
    { key: 'ios', labelKey: 'setup.ios', apps: [] },
    { key: 'windows', labelKey: 'setup.windows', apps: [] },
    { key: 'desktop', labelKey: 'setup.desktop', apps: [] },
  ].map((p) => ({
    ...p,
    apps: backend === 'outline' ? OUTLINE : XRAY[p.key as Platform['key']],
  })) as Platform[];

  let active = $state<Platform['key']>('android');
  // `active` is always one of the defined keys, so find() always hits.
  let currentApps = $derived(PLATFORMS.find((p) => p.key === active)?.apps ?? []);
</script>

<section class="rounded-xl border border-border bg-card p-5 sm:p-6">
  <h2 class="flex items-center gap-2 text-lg font-display font-semibold">
    <Smartphone class="size-4 text-muted-foreground" aria-hidden="true" />
    {t('setup.title')}
  </h2>
  <p class="mt-1 text-sm text-muted-foreground">{t('setup.intro')}</p>

  <div class="mt-4 flex flex-wrap gap-1.5" role="tablist">
    {#each PLATFORMS as p (p.key)}
      <button
        type="button"
        role="tab"
        aria-selected={active === p.key}
        onclick={() => (active = p.key)}
        class="min-h-9 rounded-md px-3 py-1.5 text-sm font-medium transition-colors {active ===
        p.key
          ? 'bg-primary text-primary-foreground'
          : 'bg-muted text-muted-foreground hover:text-foreground'}"
      >
        {t(p.labelKey)}
      </button>
    {/each}
  </div>

  <ol class="mt-4 space-y-3 text-sm">
    <li class="flex gap-3">
      <span
        class="flex size-6 shrink-0 items-center justify-center rounded-full bg-primary/10 text-xs font-semibold text-primary tabular-nums"
        >1</span
      >
      <span>
        {t('setup.step.install')}:
        {#each currentApps as app, i (app.name)}{i > 0 ? ' · ' : ' '}<a
            href={app.url}
            target="_blank"
            rel="noopener noreferrer"
            class="text-primary underline">{app.name}</a
          >{/each}
      </span>
    </li>
    <li class="flex gap-3">
      <span
        class="flex size-6 shrink-0 items-center justify-center rounded-full bg-primary/10 text-xs font-semibold text-primary tabular-nums"
        >2</span
      >
      <span>{t('setup.step.import')}</span>
    </li>
    <li class="flex gap-3">
      <span
        class="flex size-6 shrink-0 items-center justify-center rounded-full bg-primary/10 text-xs font-semibold text-primary tabular-nums"
        >3</span
      >
      <span>{t('setup.step.connect')}</span>
    </li>
  </ol>
</section>
