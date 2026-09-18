<script lang="ts">
  /**
   * Edge settings (`/admin/edges/settings`).
   * URL state: `?section` = basics | rotation | rendering | detector | probes | l7 | maintenance.
   * Basics and Maintenance are always open; `?section` opens ONE advanced card and
   * scrolls to it. Each section saves only its own changed keys (flat patch); the
   * knobs, their copy and their section live in settings/fields.ts, bounds and
   * defaults come from the server view.
   */
  import { tick } from 'svelte';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import { Badge } from '@client/components/ui/badge';
  import { searchParam } from '@client/lib/urlState.svelte';
  import { edgeConfigQuery } from '@client/lib/edgesApi';
  import AdminListState from '../AdminListState.svelte';
  import SectionHeader from './components/SectionHeader.svelte';
  import CountryPicker from './components/CountryPicker.svelte';
  import ConfigField from './settings/ConfigField.svelte';
  import SettingsSectionCard, { type ExtraChanges } from './settings/SettingsSectionCard.svelte';
  import RenderRules from './settings/RenderRules.svelte';
  import MaintenanceCard from './settings/MaintenanceCard.svelte';
  import { ConfigForm } from './settings/form.svelte';
  import {
    AUTO_PROVISION,
    BASIC_NUMBERS,
    BASIC_SWITCHES,
    DETECTOR_FIELDS,
    L7_FIELDS,
    PROBE_COUNTRIES_PATH,
    PROBE_FIELDS,
    PROBE_SOURCE_FIELDS,
    RENDER_GLOBAL_FIELDS,
    ROTATION_FIELDS,
    SECTION_PATHS,
    parseSection,
    rulePath,
    type SettingsSection,
  } from './settings/fields';

  const config = edgeConfigQuery();
  const form = new ConfigForm(() => config.data);

  const sectionParam = searchParam('section', 'basics');
  const section = $derived(parseSection(sectionParam.value));
  const toggle = (id: SettingsSection) => (open: boolean) => {
    sectionParam.value = open ? id : 'basics';
  };

  // Bring the addressed section into view once the cards exist (deep links from attention items).
  let scrolledFor = $state<string | null>(null);
  $effect(() => {
    const target = section;
    if (!config.data || scrolledFor === target) return;
    scrolledFor = target;
    if (target === 'basics') return;
    void tick().then(() =>
      document.getElementById(`settings-${target}`)?.scrollIntoView({ block: 'start' }),
    );
  });

  const renderingPaths = $derived([
    ...SECTION_PATHS.rendering,
    ...(config.data?.families ?? []).map(rulePath),
  ]);

  // Write-only probe credentials: the stored value is never shown, only whether one exists.
  let globalpingToken = $state('');
  let ripeAtlasKey = $state('');
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
</script>

<SectionHeader
  title="Edge settings"
  description="Fleet defaults, rotation limits, rendering, the detector, probes and the maintenance switch."
/>

{#if config.isPending}
  <div class="space-y-4">
    <Skeleton class="h-64" />
    <Skeleton class="h-16" />
    <Skeleton class="h-16" />
  </div>
{:else if config.isError}
  <AdminListState error={config.error} onRetry={() => config.refetch()} />
{:else if config.data}
  {@const view = config.data}
  <div class="space-y-4">
    <SettingsSectionCard
      id="basics"
      title="Basics"
      description="The switches that decide whether edges act on their own, and the pool defaults."
      {form}
      paths={SECTION_PATHS.basics}
    >
      <div class="space-y-5">
        {#each BASIC_SWITCHES as field (field.path)}
          <ConfigField {field} {form} />
        {/each}
      </div>
      <div class="mt-6 grid gap-5 sm:grid-cols-2">
        {#each BASIC_NUMBERS as field (field.path)}
          <ConfigField {field} {form} />
        {/each}
      </div>
      <div class="mt-6 rounded-lg border border-amber-500/40 bg-amber-500/5 p-3">
        <ConfigField field={AUTO_PROVISION} {form} />
      </div>
    </SettingsSectionCard>

    <SettingsSectionCard
      id="rotation"
      title="Rotation"
      description="Timing and attempt limits of the provision, publish and replace runs."
      {form}
      paths={SECTION_PATHS.rotation}
      collapsible
      open={section === 'rotation'}
      onToggle={toggle('rotation')}
    >
      <div class="grid gap-5 sm:grid-cols-2">
        {#each ROTATION_FIELDS as field (field.path)}
          <ConfigField {field} {form} />
        {/each}
      </div>
    </SettingsSectionCard>

    <SettingsSectionCard
      id="rendering"
      title="Rendering"
      description="How edge addresses appear in a member's subscription, per client family."
      {form}
      paths={renderingPaths}
      collapsible
      open={section === 'rendering'}
      onToggle={toggle('rendering')}
      note="A rendering change alters what every member receives: cached subscriptions are renewed and stored mirrors are rebuilt once."
    >
      <div class="grid gap-5 sm:grid-cols-2">
        {#each RENDER_GLOBAL_FIELDS as field (field.path)}
          <ConfigField {field} {form} />
        {/each}
      </div>
      <h3 class="mt-6 mb-2 text-sm font-medium">Client families</h3>
      <RenderRules {form} families={view.families} />
    </SettingsSectionCard>

    <SettingsSectionCard
      id="detector"
      title="Detector"
      description="When member reports, load and probes add up to a suspected block."
      {form}
      paths={SECTION_PATHS.detector}
      collapsible
      open={section === 'detector'}
      onToggle={toggle('detector')}
    >
      <div class="grid gap-5 sm:grid-cols-2">
        {#each DETECTOR_FIELDS as field (field.path)}
          <ConfigField {field} {form} />
        {/each}
      </div>
    </SettingsSectionCard>

    <SettingsSectionCard
      id="probes"
      title="Probes"
      description="Where reachability is measured from, how often, and within what budget."
      {form}
      paths={SECTION_PATHS.probes}
      collapsible
      open={section === 'probes'}
      onToggle={toggle('probes')}
      extra={secretChanges}
      onSaved={clearSecrets}
    >
      {#if !form.bool('probe.enabled')}
        <p class="text-muted-foreground mb-4 text-sm">
          Probes are switched off in Basics. These settings apply once they are on.
        </p>
      {/if}
      <h3 class="mb-2 text-sm font-medium">Sources</h3>
      <div class="grid gap-5 sm:grid-cols-2">
        {#each PROBE_SOURCE_FIELDS as field (field.path)}
          <ConfigField {field} {form} />
        {/each}
      </div>

      <h3 class="mt-6 mb-2 text-sm font-medium">Credentials</h3>
      <div class="grid gap-5 sm:grid-cols-2">
        <div class="space-y-1.5">
          <div class="flex items-center gap-2">
            <Label for="edge-secret-globalping">Globalping token</Label>
            <Badge variant={view.secrets.globalpingToken ? 'success' : 'muted'}>
              {view.secrets.globalpingToken ? 'Set' : 'Not set'}
            </Badge>
          </div>
          <Input
            id="edge-secret-globalping"
            type="password"
            autocomplete="off"
            placeholder={view.secrets.globalpingToken
              ? 'Enter a new token to replace it'
              : 'Paste the token'}
            bind:value={globalpingToken}
          />
          <p class="text-muted-foreground text-xs">
            Write only. The stored token is never shown; leave this empty to keep it.
          </p>
        </div>
        <div class="space-y-1.5">
          <div class="flex items-center gap-2">
            <Label for="edge-secret-ripeatlas">RIPE Atlas key</Label>
            <Badge variant={view.secrets.ripeAtlasKey ? 'success' : 'muted'}>
              {view.secrets.ripeAtlasKey ? 'Set' : 'Not set'}
            </Badge>
          </div>
          <Input
            id="edge-secret-ripeatlas"
            type="password"
            autocomplete="off"
            placeholder={view.secrets.ripeAtlasKey
              ? 'Enter a new key to replace it'
              : 'Paste the key'}
            bind:value={ripeAtlasKey}
          />
          <p class="text-muted-foreground text-xs">
            Write only. The stored key is never shown; leave this empty to keep it.
          </p>
        </div>
      </div>

      <h3 class="mt-6 mb-2 text-sm font-medium">Coverage and budget</h3>
      <CountryPicker
        label="Countries to probe from"
        helper="Each published edge is checked from vantage points in these countries. Up to 40."
        max={40}
        bind:value={() => form.list(PROBE_COUNTRIES_PATH), (v) => form.set(PROBE_COUNTRIES_PATH, v)}
      />
      <div class="mt-5 grid gap-5 sm:grid-cols-2">
        {#each PROBE_FIELDS as field (field.path)}
          <ConfigField {field} {form} />
        {/each}
      </div>
    </SettingsSectionCard>

    <SettingsSectionCard
      id="l7"
      title="CDN fronts (L7)"
      description="Limits and proof lifetimes of hostname fronts. Whether automation may pick them is in Basics."
      {form}
      paths={SECTION_PATHS.l7}
      collapsible
      open={section === 'l7'}
      onToggle={toggle('l7')}
    >
      <div class="grid gap-5 sm:grid-cols-2">
        {#each L7_FIELDS as field (field.path)}
          <ConfigField {field} {form} />
        {/each}
      </div>
    </SettingsSectionCard>

    <MaintenanceCard />
  </div>
{/if}
