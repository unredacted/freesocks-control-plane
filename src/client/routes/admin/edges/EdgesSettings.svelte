<script lang="ts">
  /**
   * Settings (`/admin/servers/settings`): every knob for edges and the backend
   * panels on one page, in groups (settings/groups.ts), with a search.
   * URL state:
   *   ?group=<id>      one group (default: all of them); the old `?section=`
   *                    addresses are rewritten to it (servers/lib/legacyRoutes.ts)
   *   ?q=<words>       search over label, helper, key and keywords, in every group
   *   ?changed=1       only what differs from its default
   *   ?field=<path>    scroll to one setting and mark it (a deep link)
   * What shows is decided by settings/search.ts (pure); the knobs, their copy and
   * their group live in settings/fields.ts, bounds and defaults come from the
   * server view. Each group saves only its own changed keys (flat patch). A
   * value with an unsaved edit never hides under the search, and the group
   * column marks the groups holding unsaved edits.
   */
  import { tick, untrack } from 'svelte';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import { Badge } from '@client/components/ui/badge';
  import { Button } from '@client/components/ui/button';
  import { Checkbox } from '@client/components/ui/checkbox';
  import * as Select from '@client/components/ui/select';
  import { cn } from '@client/lib/utils';
  import { searchParam } from '@client/lib/urlState.svelte';
  import { edgeConfigQuery, freedomDeliveryQuery, maintenanceQuery } from '@client/lib/edgesApi';
  import { serverSummaryQuery } from '@client/lib/serversApi';
  import { drainWarningCodes } from '@shared/contracts/edgeCodes';
  import AdminListState from '../AdminListState.svelte';
  import SectionHeader from './components/SectionHeader.svelte';
  import Link from '@client/components/Link.svelte';
  import { edgesPaths } from './lib/routes';
  import CodeNote from './components/CodeNote.svelte';
  import ConfigField from './settings/ConfigField.svelte';
  import SettingsSectionCard, { type ExtraChanges } from './settings/SettingsSectionCard.svelte';
  import RenderRules from './settings/RenderRules.svelte';
  import DeliveryBindingsCard from './settings/DeliveryBindingsCard.svelte';
  import MaintenanceCard from './settings/MaintenanceCard.svelte';
  import FreedomDeliveryCard from './settings/FreedomDeliveryCard.svelte';
  import ClientCheckCard from './settings/ClientCheckCard.svelte';
  import PanelSwitchesCard from './settings/PanelSwitchesCard.svelte';
  import CountryBudgets from './settings/CountryBudgets.svelte';
  import TrustCounts from './settings/TrustCounts.svelte';
  import { ConfigForm } from './settings/form.svelte';
  import { pathCovers } from './settings/configDiff';
  import {
    ALL_GROUPS,
    SETTINGS_GROUPS,
    groupLabel,
    parseGroup,
    type GroupChoice,
    type SettingsGroupId,
  } from './settings/groups';
  import {
    AUTO_PROVISION,
    BASIC_NUMBERS,
    BASIC_SWITCHES,
    COUNTRY_FIELDS,
    DETECTOR_FIELDS,
    ENTRY_IDS as E,
    L7_FIELDS,
    LIST_FIELDS,
    NAMES_FIELDS,
    NAME_ZONES_PATH,
    PROBE_FIELDS,
    PROBE_SOURCE_FIELDS,
    RENDER_GLOBAL_FIELDS,
    REPLACEMENT_FIELDS,
    TRUST_FIELDS,
    groupPaths,
    settingEntries,
    type Field,
    type SettingEntry,
  } from './settings/fields';
  import { changedFromDefault, fieldDomId, settingsView } from './settings/search';

  const config = edgeConfigQuery();
  const form = new ConfigForm(() => config.data);
  // The switches outside the edge config, for "Changed" (both default to off).
  const freedom = freedomDeliveryQuery();
  const servers = serverSummaryQuery();
  // Paused new work is off its normal state too: "changed only" keeps the card and its Resume.
  const maintenance = maintenanceQuery();

  const families = $derived(config.data?.families ?? []);
  const entries = $derived(settingEntries(families));
  const entryById = $derived(new Map(entries.map((e) => [e.id, e])));

  // A country's own replacement budget: one number per listed country, blank = the fleet's.
  const censoredCountries = $derived(config.data?.censoredCountries ?? []);

  // --- URL state ----------------------------------------------------------------
  const groupParam = searchParam('group', ALL_GROUPS);
  const group = $derived(parseGroup(groupParam.value));
  const changedParam = searchParam('changed', '');
  const changedOnly = $derived(changedParam.value === '1');
  const fieldParam = searchParam('field', '');
  const qParam = searchParam('q', '');
  // The box keeps its own text (so typing never waits on the URL) and follows
  // the URL when it changes elsewhere (back, forward, a link).
  let query = $state(untrack(() => qParam.value));
  $effect(() => {
    const fromUrl = qParam.value;
    untrack(() => {
      if (fromUrl !== query) query = fromUrl;
    });
  });
  function setQuery(v: string) {
    query = v;
    qParam.value = v;
  }
  const pickGroup = (g: GroupChoice) => {
    groupParam.value = g;
  };
  const searching = $derived(query.trim() !== '');

  // --- what shows ---------------------------------------------------------------
  const current = $derived({ ...form.base, ...form.edits });
  const defaults = $derived(config.data?.defaults ?? {});
  function isChanged(e: SettingEntry): boolean {
    if (e.id === E.freedom) return freedom.data?.on === true;
    if (e.id === E.panelRead) return servers.data?.config['manage.observe'] === true;
    if (e.id === E.panelChanges) return servers.data?.config['manage.enabled'] === true;
    if (e.id === E.pause) return maintenance.data?.frozen === true;
    // The stored value or the one typed: neither drops out while it is edited.
    return (
      changedFromDefault(current, defaults, e.paths) ||
      changedFromDefault(form.base, defaults, e.paths)
    );
  }

  // Write-only probe credentials: the stored value is never shown, only whether one exists.
  let globalpingToken = $state('');
  let ripeAtlasKey = $state('');

  const editedPath = (p: string) =>
    p in form.edits || Object.keys(form.invalid).some((k) => pathCovers(p, k));
  const pinned = $derived(
    new Set([
      ...entries.filter((e) => e.paths.some(editedPath)).map((e) => e.id),
      ...(globalpingToken.trim() ? [E.globalpingToken] : []),
      ...(ripeAtlasKey.trim() ? [E.ripeAtlasKey] : []),
    ]),
  );
  const view = $derived(settingsView(entries, { group, query, changedOnly, isChanged, pinned }));
  const show = (id: string) => view.shown.has(id);
  const anyShown = (fields: readonly Field[]) => fields.some((f) => show(f.path));

  // Groups holding an unsaved edit or a value that cannot be saved.
  const unsaved = $derived(
    new Set(
      SETTINGS_GROUPS.map((g) => g.id).filter((g) => {
        const paths = groupPaths(g, families);
        if (g === 'probes' && (globalpingToken.trim() || ripeAtlasKey.trim())) return true;
        return form.changes(paths).length > 0 || form.hasInvalid(paths);
      }),
    ),
  );
  const unsavedHidden = $derived([...unsaved].filter((g) => !view.groups.includes(g)));

  const choices = $derived([
    { id: ALL_GROUPS as GroupChoice, label: 'All', count: view.total },
    ...SETTINGS_GROUPS.map((g) => ({
      id: g.id as GroupChoice,
      label: g.label,
      count: view.counts[g.id],
    })),
  ]);

  // --- a deep link to one setting (`?field=`) ----------------------------------
  let flash = $state<string | null>(null);
  let handledField: string | null = null;
  $effect(() => {
    const raw = fieldParam.value;
    if (!config.data || !raw || handledField === raw) return;
    handledField = raw;
    const entry = untrack(() => entryById.get(raw.replace(/^edge\./, '')));
    if (!entry) return;
    // Make sure nothing hides it: its group open (from All too), no other search,
    // not "changed only".
    untrack(() => {
      if (group !== entry.group) groupParam.value = entry.group;
      if (query) setQuery('');
      if (changedOnly) changedParam.value = '';
    });
    const smooth = !window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    void tick().then(() => {
      document
        .getElementById(fieldDomId(entry.id))
        ?.scrollIntoView({ block: 'center', behavior: smooth ? 'smooth' : 'auto' });
      flash = entry.id;
      setTimeout(() => {
        if (flash === entry.id) flash = null;
      }, 2500);
    });
  });
  const rowClass = (id: string) =>
    cn(
      'scroll-mt-24 rounded-md transition-shadow duration-300 motion-reduce:transition-none',
      flash === id && 'ring-ring/60 ring-offset-card ring-2 ring-offset-4',
    );

  // --- group details --------------------------------------------------------------
  // Drains members' apps cannot outlive at the refresh interval, judged on the
  // values as typed (the save answers with the same rule as warnings).
  const drainCodes = $derived.by(() => {
    const values = {
      drainMinutes: form.num('drainMinutes'),
      burnedDrainMinutes: form.num('burnedDrainMinutes'),
      updateIntervalHours: form.num('updateIntervalHours'),
    };
    return Object.values(values).every(Number.isFinite) ? drainWarningCodes(values) : [];
  });

  // What one Globalping run costs, as typed (lib/edgeConfig `globalpingTestsPerRun` on the server).
  const controlCount = $derived(
    form
      .str('country.controlCountries')
      .split(/[\s,]+/)
      .filter(
        (c) => /^[A-Za-z]{2}$/.test(c) && !form.list('probe.countries').includes(c.toUpperCase()),
      ).length,
  );
  const globalpingTestsPerRun = $derived(
    form.list('probe.countries').length *
      Math.max(1, Math.min(form.num('probe.perCountryLimit') || 1, 10)) +
      (form.bool('country.enabled') ? controlCount : 0),
  );

  // Address hostnames: the zones of every DNS account, ticked when eligible.
  const nameZones = $derived(config.data?.nameZones ?? []);
  const toggleZone = (id: string, on: boolean) => {
    const now = form.list(NAME_ZONES_PATH).filter((z) => z !== id);
    form.set(NAME_ZONES_PATH, on ? [...now, id] : now);
  };

  function secretChanges(): ExtraChanges | null {
    const secrets: Record<string, string> = {};
    const lines: string[] = [];
    if (globalpingToken.trim()) {
      secrets.globalpingToken = globalpingToken.trim();
      lines.push('Globalping token: a new value will be stored');
    }
    if (ripeAtlasKey.trim()) {
      secrets.ripeAtlasKey = ripeAtlasKey.trim();
      lines.push('RIPE Atlas key: a new value will be stored');
    }
    return lines.length > 0 ? { patch: { secrets }, lines } : null;
  }
  function clearSecrets() {
    globalpingToken = '';
    ripeAtlasKey = '';
  }

  const descriptionOf = (g: SettingsGroupId) =>
    SETTINGS_GROUPS.find((x) => x.id === g)?.description ?? '';
  const NAV_ITEM =
    'focus-visible:ring-ring/50 flex min-h-9 w-full items-center gap-2 rounded-md px-3 text-start text-sm outline-none focus-visible:ring-3';
</script>

{#snippet row(field: Field)}
  {#if show(field.path)}
    <div id={fieldDomId(field.path)} class={rowClass(field.path)}>
      <ConfigField {field} {form} />
    </div>
  {/if}
{/snippet}

{#snippet grid(fields: readonly Field[], cls = '')}
  {#if anyShown(fields)}
    <div class={cn('grid gap-5 sm:grid-cols-2', cls)}>
      {#each fields as field (field.path)}
        {@render row(field)}
      {/each}
    </div>
  {/if}
{/snippet}

{#snippet subhead(title: string, first = false)}
  <h3 class={cn('mb-2 text-sm font-medium', !first && 'mt-6')}>{title}</h3>
{/snippet}

{#snippet card(
  g: SettingsGroupId,
  body: import('svelte').Snippet,
  extra?: Partial<{
    note: string;
    extra: () => ExtraChanges | null;
    onSaved: () => void;
  }>,
)}
  <SettingsSectionCard
    id={g}
    title={groupLabel(g)}
    description={descriptionOf(g)}
    {form}
    paths={groupPaths(g, families)}
    note={extra?.note}
    extra={extra?.extra}
    onSaved={extra?.onSaved}
  >
    {@render body()}
  </SettingsSectionCard>
{/snippet}

{#snippet automatic()}
  {#if anyShown(BASIC_SWITCHES)}
    <div class="space-y-5">
      {#each BASIC_SWITCHES as field (field.path)}
        {@render row(field)}
      {/each}
    </div>
  {/if}
  {@render grid(BASIC_NUMBERS, anyShown(BASIC_SWITCHES) ? 'mt-6' : '')}
  {#if drainCodes.includes('drain_below_refresh') && show('drainMinutes')}
    <CodeNote issue={{ code: 'drain_below_refresh' }} tone="warning" class="mt-4" />
  {/if}
  {#if show(AUTO_PROVISION.path)}
    <div
      id={fieldDomId(AUTO_PROVISION.path)}
      class={cn(
        rowClass(AUTO_PROVISION.path),
        'rounded-lg border border-amber-500/40 bg-amber-500/5 p-3',
        (anyShown(BASIC_SWITCHES) || anyShown(BASIC_NUMBERS)) && 'mt-6',
      )}
    >
      <ConfigField field={AUTO_PROVISION} {form} />
    </div>
  {/if}
{/snippet}

{#snippet replacement()}
  {@render grid(REPLACEMENT_FIELDS)}
  {#if show(E.countryBudgets)}
    <div id={fieldDomId(E.countryBudgets)} class={rowClass(E.countryBudgets)}>
      <CountryBudgets codes={censoredCountries} {form} />
    </div>
  {/if}
  {#each drainCodes as code (code)}
    <CodeNote issue={{ code }} tone="warning" class="mt-4" />
  {/each}
{/snippet}

{#snippet trust()}
  {@render grid(TRUST_FIELDS)}
  {#if show(E.trustCounts)}
    <div id={fieldDomId(E.trustCounts)} class={rowClass(E.trustCounts)}>
      <TrustCounts />
    </div>
  {/if}
{/snippet}

{#snippet detection()}
  {@render grid(DETECTOR_FIELDS)}
{/snippet}

{#snippet probes()}
  {@const secrets = config.data!.secrets}
  {@const credentials = show(E.globalpingToken) || show(E.ripeAtlasKey)}
  {@const coverage = show(E.probeCountries) || anyShown(PROBE_FIELDS)}
  {#if !form.bool('probe.enabled')}
    <p class="text-muted-foreground mb-4 text-sm">
      Probes are switched off in Automatic work. These settings apply once they are on.
    </p>
  {/if}
  {#if anyShown(PROBE_SOURCE_FIELDS)}
    {@render subhead('Sources', true)}
    {@render grid(PROBE_SOURCE_FIELDS)}
  {/if}

  {#if credentials}
    {@render subhead('Credentials', !anyShown(PROBE_SOURCE_FIELDS))}
    <div class="grid gap-5 sm:grid-cols-2">
      {#if show(E.globalpingToken)}
        <div
          id={fieldDomId(E.globalpingToken)}
          class={cn('space-y-1.5', rowClass(E.globalpingToken))}
        >
          <div class="flex items-center gap-2">
            <Label for="edge-secret-globalping">Globalping token</Label>
            <Badge variant={secrets.globalpingToken ? 'success' : 'muted'}>
              {secrets.globalpingToken ? 'Set' : 'Not set'}
            </Badge>
          </div>
          <Input
            id="edge-secret-globalping"
            type="password"
            autocomplete="off"
            placeholder={secrets.globalpingToken
              ? 'Enter a new token to replace it'
              : 'Paste the token'}
            bind:value={globalpingToken}
          />
          <p class="text-muted-foreground text-xs">
            Write only. Leave empty to keep the stored token.
          </p>
        </div>
      {/if}
      {#if show(E.ripeAtlasKey)}
        <div id={fieldDomId(E.ripeAtlasKey)} class={cn('space-y-1.5', rowClass(E.ripeAtlasKey))}>
          <div class="flex items-center gap-2">
            <Label for="edge-secret-ripeatlas">RIPE Atlas key</Label>
            <Badge variant={secrets.ripeAtlasKey ? 'success' : 'muted'}>
              {secrets.ripeAtlasKey ? 'Set' : 'Not set'}
            </Badge>
          </div>
          <Input
            id="edge-secret-ripeatlas"
            type="password"
            autocomplete="off"
            placeholder={secrets.ripeAtlasKey ? 'Enter a new key to replace it' : 'Paste the key'}
            bind:value={ripeAtlasKey}
          />
          <p class="text-muted-foreground text-xs">
            Write only. Leave empty to keep the stored key.
          </p>
        </div>
      {/if}
    </div>
  {/if}

  {#if coverage}
    {@render subhead('Coverage and budget', !anyShown(PROBE_SOURCE_FIELDS) && !credentials)}
    {#if show(E.probeCountries)}
      <div
        id={fieldDomId(E.probeCountries)}
        class={cn('space-y-1 text-sm', rowClass(E.probeCountries))}
      >
        <p class="font-medium">Countries to probe from</p>
        <p class="text-muted-foreground">
          {form.list('probe.countries').length > 0
            ? `${form.list('probe.countries').join(', ')}.`
            : 'None.'}
          The censored countries with "Check edges from here" on.
          <Link href="/admin/settings" class="underline underline-offset-2">
            Change them in Settings, Censored countries.
          </Link>
        </p>
      </div>
    {/if}
    {@render grid(PROBE_FIELDS, show(E.probeCountries) ? 'mt-5' : '')}
  {/if}
{/snippet}

{#snippet countryChecks()}
  {#if show(E.runCost)}
    <p
      id={fieldDomId(E.runCost)}
      class={cn('text-muted-foreground mb-4 text-sm', rowClass(E.runCost))}
    >
      One Globalping run of an IPv4 edge asks {globalpingTestsPerRun} vantage points ({form.list(
        'probe.countries',
      ).length} countries, {form.num('probe.perCountryLimit')} each{form.bool('country.enabled')
        ? `, plus ${controlCount} controls`
        : ''}). A failing source gives no evidence and never reads as a block.
    </p>
  {/if}
  {@render grid(COUNTRY_FIELDS)}
{/snippet}

{#snippet subscriptions()}
  {@render grid(RENDER_GLOBAL_FIELDS)}
  {#if show(E.clientRules)}
    <div id={fieldDomId(E.clientRules)} class={rowClass(E.clientRules)}>
      {@render subhead('Client families', !anyShown(RENDER_GLOBAL_FIELDS))}
      <RenderRules {form} families={config.data?.families ?? []} />
    </div>
  {/if}
{/snippet}

{#snippet cdnFronts()}
  {@render grid(L7_FIELDS)}
{/snippet}

{#snippet hostnames()}
  <p class="text-muted-foreground mb-4 text-sm">
    A censor can see and fake DNS answers, and blocking a zone stops every hostname in it. Addresses
    are spread over the zones you pick, and apps with an Auto group keep the IP as a fallback. Older
    addresses keep their IPs until you open one and press Give it a hostname.
  </p>
  {@render grid(NAMES_FIELDS)}
  {#if show(E.nameZones)}
    <div id={fieldDomId(E.nameZones)} class={rowClass(E.nameZones)}>
      {@render subhead('Zones for hostnames', !anyShown(NAMES_FIELDS))}
      {#if nameZones.length === 0}
        <p class="text-muted-foreground text-sm">
          No DNS account has a zone yet. Add one under Providers, DNS providers.
        </p>
      {:else}
        <ul class="space-y-2">
          {#each nameZones as z (z.id)}
            <li class="flex items-center gap-2 text-sm">
              <Checkbox
                id={`name-zone-${z.id}`}
                checked={form.list(NAME_ZONES_PATH).includes(z.id)}
                onCheckedChange={(v) => toggleZone(z.id, v === true)}
              />
              <Label for={`name-zone-${z.id}`} class="font-normal">
                {z.zone} <span class="text-muted-foreground">({z.account})</span>
              </Label>
            </li>
          {/each}
        </ul>
        <p class="text-muted-foreground mt-2 text-xs">
          Use two or more zones kept for nothing else, so a blocked zone takes out only part of a
          node's addresses.
        </p>
      {/if}
    </div>
  {/if}
{/snippet}

{#snippet countryLists()}
  <p class="text-muted-foreground mb-4 text-sm">
    The lists themselves are under
    <Link href={edgesPaths.lists()} class="underline underline-offset-2">Countries, Lists</Link>. A
    version that looks wrong waits for you there.
  </p>
  {@render grid(LIST_FIELDS)}
{/snippet}

{#snippet group_(g: SettingsGroupId)}
  {#if g === 'automatic'}
    {@render card(g, automatic)}
  {:else if g === 'replacement'}
    {@render card(g, replacement)}
  {:else if g === 'trust'}
    {@render card(g, trust)}
  {:else if g === 'detection'}
    {@render card(g, detection)}
  {:else if g === 'probes'}
    {@render card(g, probes, { extra: secretChanges, onSaved: clearSecrets })}
  {:else if g === 'country-checks'}
    {@render card(g, countryChecks)}
  {:else if g === 'subscriptions'}
    {@render card(g, subscriptions, {
      note: 'A change here alters what every member gets. Cached subscriptions renew and stored mirrors are rebuilt once.',
    })}
  {:else if g === 'cdn-fronts'}
    {@render card(g, cdnFronts)}
  {:else if g === 'address-hostnames'}
    {@render card(g, hostnames)}
  {:else if g === 'country-lists'}
    {@render card(g, countryLists)}
  {:else if g === 'delivery'}
    {#if show(E.freedom)}
      <div id={fieldDomId(E.freedom)} class={rowClass(E.freedom)}><FreedomDeliveryCard /></div>
    {/if}
    {#if show(E.deliveryPlaces)}
      <div id={fieldDomId(E.deliveryPlaces)} class={rowClass(E.deliveryPlaces)}>
        <DeliveryBindingsCard />
      </div>
    {/if}
  {:else if g === 'client-check'}
    <div id={fieldDomId(E.clientCheck)} class={rowClass(E.clientCheck)}><ClientCheckCard /></div>
  {:else if g === 'maintenance'}
    {#if show(E.pause)}
      <div id={fieldDomId(E.pause)} class={rowClass(E.pause)}><MaintenanceCard /></div>
    {/if}
    {#if show(E.panelRead) || show(E.panelChanges)}
      <PanelSwitchesCard
        readId={fieldDomId(E.panelRead)}
        changesId={fieldDomId(E.panelChanges)}
        showRead={show(E.panelRead)}
        showChanges={show(E.panelChanges)}
        {rowClass}
      />
    {/if}
  {/if}
{/snippet}

<SectionHeader
  title="Settings"
  description="Every knob for edges and the backend panels, in groups. Search finds a setting by its name, its words or its key."
/>

{#if config.isPending}
  <div class="space-y-4">
    <Skeleton class="h-10 max-w-md" />
    <Skeleton class="h-64" />
    <Skeleton class="h-16" />
  </div>
{:else if config.isError}
  <AdminListState error={config.error} onRetry={() => config.refetch()} />
{:else if config.data}
  <div class="grid gap-6 md:grid-cols-[13rem_minmax(0,1fr)]">
    <nav aria-label="Setting groups" class="hidden md:block">
      <ul class="sticky top-20 space-y-0.5">
        {#each choices as c (c.id)}
          {@const on = group === c.id && !searching}
          <li>
            <button
              type="button"
              aria-current={on ? 'true' : undefined}
              class={cn(
                NAV_ITEM,
                on
                  ? 'bg-accent text-accent-foreground font-medium'
                  : 'text-muted-foreground hover:bg-accent/50 hover:text-foreground',
              )}
              onclick={() => pickGroup(c.id)}
            >
              <span class="min-w-0 flex-1 truncate">{c.label}</span>
              {#if c.id !== ALL_GROUPS && unsaved.has(c.id as SettingsGroupId)}
                <span class="size-2 shrink-0 rounded-full bg-amber-500" aria-hidden="true"></span>
                <span class="sr-only">(unsaved changes)</span>
              {/if}
              <span class="text-muted-foreground shrink-0 text-xs tabular-nums">{c.count}</span>
            </button>
          </li>
        {/each}
      </ul>
    </nav>

    <div class="min-w-0 space-y-4">
      <div class="space-y-1.5 md:hidden">
        <Label for="settings-group">Group</Label>
        <Select.Root type="single" bind:value={() => group, (v) => pickGroup(parseGroup(v))}>
          <Select.Trigger id="settings-group" class="w-full">
            {choices.find((c) => c.id === group)?.label ?? 'All'}
          </Select.Trigger>
          <Select.Content>
            {#each choices as c (c.id)}
              <Select.Item value={c.id} label={c.label}>
                {c.label}{c.id !== ALL_GROUPS && unsaved.has(c.id as SettingsGroupId)
                  ? ' (unsaved)'
                  : ''}
              </Select.Item>
            {/each}
          </Select.Content>
        </Select.Root>
      </div>

      <div class="flex flex-wrap items-center gap-x-6 gap-y-3">
        <div class="w-full max-w-md">
          <Label for="settings-search" class="sr-only">Search settings</Label>
          <Input
            id="settings-search"
            type="search"
            autocomplete="off"
            placeholder="Search settings: drain, IPv6, Globalping, strike, pause"
            value={query}
            oninput={(e) => setQuery(e.currentTarget.value)}
          />
        </div>
        <div class="flex items-center gap-2">
          <Checkbox
            id="settings-changed"
            checked={changedOnly}
            onCheckedChange={(v) => (changedParam.value = v === true ? '1' : '')}
          />
          <Label for="settings-changed" class="font-normal">Show changed only</Label>
        </div>
      </div>

      {#if searching || changedOnly}
        <p class="text-muted-foreground text-sm" role="status">
          {view.total === 0
            ? 'No setting matches.'
            : `${view.total} ${view.total === 1 ? 'setting matches' : 'settings match'}${searching ? ', in every group' : ''}.`}
        </p>
      {/if}

      {#if unsavedHidden.length > 0}
        <div
          class="rounded-md border border-amber-500/40 bg-amber-500/5 px-3 py-2 text-sm"
          role="status"
        >
          Unsaved changes in
          {#each unsavedHidden as g, i (g)}
            {i > 0 ? (i === unsavedHidden.length - 1 ? ' and ' : ', ') : ''}<button
              type="button"
              class="underline underline-offset-2"
              onclick={() => {
                setQuery('');
                changedParam.value = '';
                pickGroup(g);
              }}>{groupLabel(g)}</button
            >
          {/each}.
        </div>
      {/if}

      {#each view.groups as g (g)}
        {@render group_(g)}
      {/each}

      {#if view.groups.length === 0}
        <div class="text-muted-foreground rounded-lg border border-dashed p-6 text-center text-sm">
          <p>
            {changedOnly && !searching
              ? 'Every setting here is at its default.'
              : 'No setting matches. Try another word.'}
          </p>
          <Button
            variant="outline"
            size="sm"
            class="mt-3"
            onclick={() => {
              setQuery('');
              changedParam.value = '';
            }}
          >
            Show every setting
          </Button>
        </div>
      {/if}
    </div>
  </div>
{/if}
