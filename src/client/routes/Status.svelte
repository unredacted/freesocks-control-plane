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
  import { Skeleton } from '@client/components/ui/skeleton';
  import Link from '../components/Link.svelte';
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
    quiet: { key: 'status.loadQuiet', cls: 'bg-primary/10 text-primary' },
    busy: {
      key: 'status.loadBusy',
      cls: 'bg-amber-500/10 text-amber-600 dark:text-amber-400',
    },
    crowded: { key: 'status.loadCrowded', cls: 'bg-destructive/10 text-destructive' },
    unknown: { key: 'status.loadUnknown', cls: 'bg-muted text-muted-foreground' },
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

<div class="mx-auto max-w-3xl space-y-10 py-6 md:py-10">
  <header class="space-y-3">
    <h1 class="font-display text-3xl font-bold tracking-tight md:text-4xl">
      {t('status.title')}
    </h1>
    {#if status.data}
      <p
        class="inline-flex items-center gap-2 rounded-full px-3 py-1 text-sm font-medium {overall ===
        'ok'
          ? 'bg-primary/10 text-primary'
          : overall === 'partial'
            ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400'
            : 'bg-destructive/10 text-destructive'}"
      >
        <span
          class="size-2 rounded-full {overall === 'ok'
            ? 'bg-primary status-pulse'
            : overall === 'partial'
              ? 'bg-amber-500 status-pulse'
              : 'bg-destructive status-pulse'}"
          aria-hidden="true"
        ></span>
        {overall === 'ok'
          ? t('status.overallOk')
          : overall === 'partial'
            ? t('status.overallPartial')
            : t('status.overallMajor')}
      </p>
      <p class="text-xs text-muted-foreground">
        {t('status.updated', { time: fmtTime(status.data.generatedAt) })}
      </p>
    {:else}
      <Skeleton class="h-8 w-64" />
    {/if}
  </header>

  <!-- Locations -->
  <section class="space-y-3" aria-labelledby="status-locations">
    <h2
      id="status-locations"
      class="font-mono text-xs font-medium uppercase tracking-[0.18em] text-muted-foreground"
    >
      {t('status.locationsTitle')}
    </h2>
    {#if status.isPending}
      <div class="grid gap-3 sm:grid-cols-2">
        {#each Array(2) as _, i (i)}<Skeleton class="h-24 w-full rounded-xl" />{/each}
      </div>
    {:else if status.data && status.data.locations.length > 0}
      <div class="grid gap-3 sm:grid-cols-2">
        {#each status.data.locations as loc (loc.code)}
          {@const badge = LOAD_BADGE[loc.load] ?? LOAD_BADGE.unknown!}
          <div id="loc-{loc.code}" class="scroll-mt-24 rounded-xl border border-border bg-card p-4">
            <div class="flex items-center gap-2">
              <span
                class="size-2.5 shrink-0 rounded-full {loc.online
                  ? 'bg-primary status-pulse'
                  : 'bg-destructive'}"
                aria-hidden="true"
              ></span>
              <span class="sr-only"
                >{loc.online ? t('status.srOnline') : t('status.srOffline')}</span
              >
              <span class="font-mono text-xs uppercase text-muted-foreground">{loc.code}</span>
              <span class="ms-auto rounded-full px-2 py-0.5 text-xs font-medium {badge.cls}">
                {t(badge.key)}
              </span>
            </div>
            <p class="mt-2 font-medium">{loc.label}</p>
            <p class="mt-0.5 text-sm text-muted-foreground">
              {loc.online ? t('status.online') : t('status.offline')}
              {#if loc.nodesOnline !== null && loc.nodesTotal !== null}
                · {t('status.nodesUp', { online: loc.nodesOnline, total: loc.nodesTotal })}
              {/if}
            </p>
          </div>
        {/each}
      </div>
    {/if}
  </section>

  <!-- Censorship matrix -->
  {#if status.data && status.data.censorship.modes.length > 0}
    <section class="space-y-3" aria-labelledby="status-matrix">
      <h2
        id="status-matrix"
        class="font-mono text-xs font-medium uppercase tracking-[0.18em] text-muted-foreground"
      >
        {t('status.matrixTitle')}
      </h2>
      <p class="text-sm text-muted-foreground">{t('status.matrixBody')}</p>
      {#if status.data.censorship.rows.length === 0}
        <p class="rounded-lg border border-dashed border-border p-4 text-sm text-muted-foreground">
          {t('status.matrixEmpty')}
        </p>
      {:else}
        <div class="overflow-x-auto rounded-xl border border-border">
          <table class="w-full min-w-96 text-sm">
            <thead>
              <tr class="border-b border-border bg-muted/40">
                <th class="px-4 py-2.5 text-start font-medium"></th>
                {#each status.data.censorship.modes as m (m.id)}
                  <th class="px-4 py-2.5 text-center font-medium">
                    {m.label ?? m.id}
                  </th>
                {/each}
              </tr>
            </thead>
            <tbody>
              {#each status.data.censorship.rows as row (row.countryCode)}
                <tr class="border-b border-border last:border-0">
                  <th class="px-4 py-2.5 text-start font-medium">
                    <span class="me-2" aria-hidden="true">{flag(row.countryCode)}</span>
                    {row.label ?? row.countryCode}
                  </th>
                  {#each status.data.censorship.modes as m (m.id)}
                    {@const cell = row.cells[m.id]}
                    <td class="px-4 py-2.5 text-center">
                      {#if cell && CELL_STYLE[cell]}
                        <span class="inline-flex items-center gap-1.5">
                          <span
                            class="size-2 rounded-full {CELL_STYLE[cell].dot}"
                            aria-hidden="true"
                          ></span>
                          <span class="text-xs">{t(CELL_STYLE[cell].key)}</span>
                        </span>
                      {:else}
                        <span class="text-xs text-muted-foreground">—</span>
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
  <section class="space-y-3" aria-labelledby="status-incidents">
    <h2
      id="status-incidents"
      class="font-mono text-xs font-medium uppercase tracking-[0.18em] text-muted-foreground"
    >
      {t('status.incidentsTitle')}
    </h2>
    {#if status.isPending}
      <Skeleton class="h-20 w-full rounded-xl" />
    {:else if status.data}
      {#if status.data.incidents.length === 0}
        <p class="rounded-lg border border-dashed border-border p-4 text-sm text-muted-foreground">
          {t('status.incidentsNone')}
        </p>
      {:else}
        {#if openIncidents.length > 0}
          <ul class="space-y-2">
            {#each openIncidents as i (i.id)}
              <li class="rounded-xl border border-amber-500/40 bg-amber-500/5 p-4">
                <div class="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <span class="font-medium">{i.title}</span>
                  <span class="text-xs text-muted-foreground">{incidentLocationText(i)}</span>
                  <span
                    class="ms-auto rounded-full bg-amber-500/10 px-2 py-0.5 text-xs font-medium text-amber-600 dark:text-amber-400"
                  >
                    {t('status.incidentsOngoing')}
                  </span>
                </div>
                {#if i.body}<p class="mt-1.5 text-sm text-muted-foreground">{i.body}</p>{/if}
                <p class="mt-1.5 text-xs text-muted-foreground">
                  {t('status.incidentsStarted', { time: fmtTime(i.startedAt) })}
                </p>
              </li>
            {/each}
          </ul>
        {/if}
        {#if pastIncidents.length > 0}
          <details class="group rounded-xl border border-border">
            <summary
              class="cursor-pointer list-none px-4 py-3 text-sm font-medium text-muted-foreground select-none"
            >
              {t('status.incidentsPast')} ({pastIncidents.length})
            </summary>
            <ul class="divide-y divide-border border-t border-border">
              {#each pastIncidents as i (i.id)}
                <li class="px-4 py-3">
                  <div class="flex flex-wrap items-center gap-x-3 gap-y-1">
                    <span class="font-medium">{i.title}</span>
                    <span class="text-xs text-muted-foreground">{incidentLocationText(i)}</span>
                    <span class="ms-auto text-xs text-muted-foreground">
                      {t('status.incidentsResolved', { time: fmtTime(i.resolvedAt!) })}
                    </span>
                  </div>
                  {#if i.body}<p class="mt-1 text-sm text-muted-foreground">{i.body}</p>{/if}
                  <p class="mt-1 text-xs text-muted-foreground">
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
    <p class="text-sm">
      <a class="text-primary underline underline-offset-4" href="mailto:{supportEmail}">
        {t('status.report')}
      </a>
    </p>
  {/if}

  <p class="text-sm">
    <Link href="/" class="text-muted-foreground">← FreeSocks</Link>
  </p>
</div>
