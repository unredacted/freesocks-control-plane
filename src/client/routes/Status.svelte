<script lang="ts">
  /**
   * Public network-status page (/status): per-location health + coarse load,
   * the operator-curated censorship-availability matrix, and published
   * incidents. "Verify, don't trust" as a page — everything here is public-safe
   * by construction (bands, never raw user counts). Polled at 60s; the server
   * data is cron-quantized to 10 min. Deep-linkable: a location card anchors
   * as #loc-<code> (the member account page links here with the key's own
   * location pre-scrolled).
   */
  import { networkStatusQuery, configQuery } from '../lib/queries';
  import { t, type MessageKey } from '../lib/i18n/index.svelte';
  import { modeTitle } from '../lib/connectionModeCopy';
  import { Skeleton } from '@client/components/ui/skeleton';
  import type { StatusIncident } from '../../shared/contracts/status';

  const status = networkStatusQuery();
  const config = configQuery();

  const supportEmail = $derived(config.data?.site?.supportEmail || '');

  function flag(code: string): string {
    return String.fromCodePoint(...[...code].map((c) => 127397 + c.charCodeAt(0)));
  }

  function fmtTime(isoOrMs: string | number): string {
    const d = new Date(isoOrMs);
    return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  }

  // Overall banner: a major incident or >half of locations offline reads
  // "major"; any open incident or any offline location reads "partial".
  const overall = $derived.by(() => {
    const d = status.data;
    if (!d) return 'ok';
    const open = d.incidents.filter((i) => !i.resolvedAt);
    const offline = d.locations.filter((l) => !l.online).length;
    if (
      open.some((i) => i.severity === 'outage') ||
      (d.locations.length > 0 && offline > d.locations.length / 2)
    ) {
      return 'major';
    }
    if (open.length > 0 || offline > 0) return 'partial';
    return 'ok';
  });

  const openIncidents = $derived((status.data?.incidents ?? []).filter((i) => !i.resolvedAt));
  const pastIncidents = $derived((status.data?.incidents ?? []).filter((i) => i.resolvedAt));

  // Deep-link scroll: /status#loc-<code> scrolls the card into view (the member
  // account page links its key's location here).
  $effect(() => {
    const d = status.data;
    if (!d || typeof window === 'undefined') return;
    const hash = window.location.hash;
    if (!hash.startsWith('#loc-')) return;
    document.getElementById(hash.slice(1))?.scrollIntoView({ block: 'center' });
  });

  const LOAD_BADGE: Record<string, { key: MessageKey; cls: string }> = {
    quiet: { key: 'status.loadQuiet', cls: 'text-primary' },
    busy: { key: 'status.loadBusy', cls: 'text-amber-700 dark:text-amber-400' },
    crowded: { key: 'status.loadCrowded', cls: 'text-destructive' },
    unknown: { key: 'status.loadUnknown', cls: 'text-muted-foreground' },
  };

  const CELL_STYLE: Record<string, { key: MessageKey; dot: string }> = {
    available: { key: 'status.matrixAvailable', dot: 'bg-primary' },
    partial: { key: 'status.matrixPartial', dot: 'bg-amber-500' },
    blocked: { key: 'status.matrixBlocked', dot: 'bg-destructive' },
  };

  function incidentLocationText(i: StatusIncident): string {
    return i.locationCodes.length > 0 ? i.locationCodes.join(', ') : t('status.incidentsGlobal');
  }
</script>

{#snippet sectionTitle(id: string, text: string)}
  <h2 {id} class="text-2xl font-bold leading-tight tracking-[-0.01em] rtl:tracking-normal">
    {text}
  </h2>
{/snippet}

<div class="mx-auto max-w-3xl space-y-12">
  <header class="space-y-3">
    <h1
      class="text-[clamp(34px,4vw,46px)] font-bold leading-[1.05] tracking-[-0.03em] rtl:tracking-normal"
    >
      {t('status.title')}
    </h1>
    {#if status.data}
      <p
        class="flex items-center gap-2.5 text-lg font-bold {overall === 'ok'
          ? 'text-foreground'
          : overall === 'partial'
            ? 'text-amber-700 dark:text-amber-400'
            : 'text-destructive'}"
      >
        <span
          class="status-pulse size-[11px] shrink-0 {overall === 'ok'
            ? 'bg-primary'
            : overall === 'partial'
              ? 'bg-amber-500'
              : 'bg-destructive'}"
          aria-hidden="true"
        ></span>
        {overall === 'ok'
          ? t('status.overallOk')
          : overall === 'partial'
            ? t('status.overallPartial')
            : t('status.overallMajor')}
      </p>
      <p class="text-sm text-muted-foreground">
        {t('status.updated', { time: fmtTime(status.data.generatedAt) })}
      </p>
    {:else}
      <Skeleton class="h-8 w-64" />
    {/if}
  </header>

  <!-- Locations: one ruled row each (status, name and code, then load). -->
  <section class="space-y-4" aria-labelledby="status-locations">
    {@render sectionTitle('status-locations', t('status.locationsTitle'))}
    {#if status.isPending}
      <Skeleton class="h-16 w-full rounded-sm" />
    {:else if status.data && status.data.locations.length > 0}
      <ul>
        {#each status.data.locations as loc (loc.code)}
          {@const badge = LOAD_BADGE[loc.load] ?? LOAD_BADGE.unknown!}
          <li
            id="loc-{loc.code}"
            class="flex scroll-mt-24 flex-wrap items-center justify-between gap-x-6 gap-y-1 border-t border-border/70 py-4 last:border-b"
          >
            <div class="flex min-w-0 items-center gap-3">
              <span
                class="size-[11px] shrink-0 {loc.online
                  ? 'status-pulse bg-primary'
                  : 'bg-destructive'}"
                aria-hidden="true"
              ></span>
              <span class="sr-only"
                >{loc.online ? t('status.srOnline') : t('status.srOffline')}</span
              >
              <span class="font-bold text-foreground">{loc.label}</span>
              <span class="font-mono text-sm text-muted-foreground" dir="ltr">{loc.code}</span>
            </div>
            <p class="flex items-center gap-2.5 text-[15px]">
              <span class={loc.online ? 'text-foreground' : 'text-destructive'}>
                {loc.online ? t('status.online') : t('status.offline')}
              </span>
              <span class="text-muted-foreground" aria-hidden="true">·</span>
              <span class="font-bold {badge.cls}">{t(badge.key)}</span>
            </p>
          </li>
        {/each}
      </ul>
    {/if}
  </section>

  <!-- Censorship matrix -->
  {#if status.data && status.data.censorship.modes.length > 0}
    <section class="space-y-4" aria-labelledby="status-matrix">
      {@render sectionTitle('status-matrix', t('status.matrixTitle'))}
      <p class="text-body">{t('status.matrixBody')}</p>
      {#if status.data.censorship.rows.length === 0}
        <p
          class="rounded-sm border border-dashed border-border p-4 text-[15px] text-muted-foreground"
        >
          {t('status.matrixEmpty')}
        </p>
      {:else}
        <div class="overflow-x-auto rounded-lg border border-border/70">
          <table class="w-full min-w-96 text-[15px]">
            <thead>
              <tr class="border-b border-border/70 bg-card">
                <th class="px-4 py-3 text-start font-bold"></th>
                {#each status.data.censorship.modes as m (m.id)}
                  <th class="px-4 py-3 text-center font-bold">
                    <!-- Through the copy layer: admin label verbatim, else the
                         built-in translated title, else a humanized slug — the
                         raw id never renders (it used to, for every built-in
                         with no admin label). -->
                    {modeTitle(m)}
                  </th>
                {/each}
              </tr>
            </thead>
            <tbody>
              {#each status.data.censorship.rows as row (row.countryCode)}
                <tr class="border-b border-border/70 last:border-0">
                  <th class="px-4 py-3 text-start font-bold">
                    <span class="me-2" aria-hidden="true">{flag(row.countryCode)}</span>
                    {row.label ?? row.countryCode}
                  </th>
                  {#each status.data.censorship.modes as m (m.id)}
                    {@const cell = row.cells[m.id]}
                    <td class="px-4 py-3 text-center">
                      {#if cell && CELL_STYLE[cell]}
                        <span class="inline-flex items-center gap-2">
                          <span
                            class="size-[9px] shrink-0 {CELL_STYLE[cell].dot}"
                            aria-hidden="true"
                          ></span>
                          {t(CELL_STYLE[cell].key)}
                        </span>
                      {:else}
                        <span class="text-muted-foreground">-</span>
                      {/if}
                    </td>
                  {/each}
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>
  {/if}

  <!-- Incidents -->
  <section class="space-y-4" aria-labelledby="status-incidents">
    {@render sectionTitle('status-incidents', t('status.incidentsTitle'))}
    {#if status.isPending}
      <Skeleton class="h-20 w-full rounded-sm" />
    {:else if status.data}
      {#if status.data.incidents.length === 0}
        <p class="text-body">{t('status.incidentsNone')}</p>
      {:else}
        {#if openIncidents.length > 0}
          <ul class="space-y-3">
            {#each openIncidents as i (i.id)}
              <li class="rounded-sm border border-amber-500/40 bg-amber-500/10 p-4">
                <div class="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <span class="font-bold text-foreground">{i.title}</span>
                  <span class="text-sm text-muted-foreground">{incidentLocationText(i)}</span>
                  <span class="ms-auto text-sm font-bold text-amber-700 dark:text-amber-400">
                    {t('status.incidentsOngoing')}
                  </span>
                </div>
                {#if i.body}<p class="mt-1.5 text-body">{i.body}</p>{/if}
                <p class="mt-1.5 text-sm text-muted-foreground">
                  {t('status.incidentsStarted', { time: fmtTime(i.startedAt) })}
                </p>
              </li>
            {/each}
          </ul>
        {/if}
        {#if pastIncidents.length > 0}
          <details class="group rounded-lg border border-border/70 bg-card">
            <summary
              class="flex min-h-14 cursor-pointer list-none items-center px-5 font-bold text-foreground select-none"
            >
              {t('status.incidentsPast')} ({pastIncidents.length})
            </summary>
            <ul class="divide-y divide-border/70 border-t border-border/70">
              {#each pastIncidents as i (i.id)}
                <li class="px-5 py-4">
                  <div class="flex flex-wrap items-center gap-x-3 gap-y-1">
                    <span class="font-bold text-foreground">{i.title}</span>
                    <span class="text-sm text-muted-foreground">{incidentLocationText(i)}</span>
                    <span class="ms-auto text-sm text-muted-foreground">
                      {t('status.incidentsResolved', { time: fmtTime(i.resolvedAt!) })}
                    </span>
                  </div>
                  {#if i.body}<p class="mt-1 text-body">{i.body}</p>{/if}
                  <p class="mt-1 text-sm text-muted-foreground">
                    {t('status.incidentsStarted', { time: fmtTime(i.startedAt) })}
                  </p>
                </li>
              {/each}
            </ul>
          </details>
        {/if}
      {/if}
    {/if}
  </section>

  {#if supportEmail}
    <p>
      <a class="link-brand text-foreground" href="mailto:{supportEmail}">
        {t('status.report')}
      </a>
    </p>
  {/if}
</div>
