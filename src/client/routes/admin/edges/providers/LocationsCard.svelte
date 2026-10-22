<script lang="ts">
  /**
   * An account's locations: where its edges are created. One row per
   * location with its trust, its addresses, its plan (a load balancer's size,
   * with what one address there costs: `PlanDialog` changes it, Refresh prices
   * reads them again) and its cost note; actions to add
   * one (`LocationPicker`), trust or untrust one (trust is per location: a
   * new region is trusted by its first tested address), switch one off, make
   * one the default the pickers preselect, or remove one nothing uses. A CDN
   * account's locations are DNS zones (a front's: the DNS account's zone and
   * its TLS configuration), each checked with the provider: what the check
   * saw (the zone's encryption mode, WebSockets) and a refusal show here,
   * with "Check again".
   *
   * Props:
   *   account: EdgeProviderAccountAdmin
   *   accountNames?: Record<string, string>   account id -> name (a front's DNS account)
   */
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Badge } from '@client/components/ui/badge';
  import { Button } from '@client/components/ui/button';
  import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
  } from '@client/components/ui/card';
  import * as Dialog from '@client/components/ui/dialog';
  import InlineError from '@client/components/InlineError.svelte';
  import type {
    EdgeLocationAdmin,
    EdgeProviderAccountAdmin,
  } from '../../../../../shared/contracts/edges';
  import {
    checkProviderLocation,
    deleteProviderLocation,
    invalidateProviders,
    providersQuery,
    qualifyProviderLocation,
    refreshLocationPlans,
    removeSharedCertificate,
    updateProviderLocation,
  } from '../../../../lib/edgesApi';
  import PlanDialog from './PlanDialog.svelte';
  import { costWords, sourceWords, trafficWords } from '../lib/planWords';
  import { EDGE_PROVIDER_META } from '../../../../lib/edgeProviderMeta';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { relativeTime } from '../lib/time';
  import LocationPicker from '../forms/LocationPicker.svelte';
  import { hasLocations } from '../forms/providerFields';
  import QualifyDialog from './QualifyDialog.svelte';
  import { locationTrustWords, sharedCertificateWords } from './accountWords';

  interface Props {
    account: EdgeProviderAccountAdmin;
    accountNames?: Record<string, string>;
  }
  let { account, accountNames = {} }: Props = $props();

  const qc = useQueryClient();
  const places = $derived(hasLocations(account.provider));
  /** A CDN account's places are its DNS zones. */
  const zones = $derived(EDGE_PROVIDER_META[account.provider].layer === 'l7');

  const check = createMutation(() => ({
    mutationFn: (id: string) => checkProviderLocation(account.id, id),
    onSuccess: (r) => {
      invalidateProviders(qc);
      if (r.ok) toast.success('The zone checks out');
      else toast.error(`The zone was refused (${r.code ?? 'error'})`);
    },
    onError: (err: unknown) => toast.error(edgeErrorMessage(err)),
  }));

  // A zone's wildcard FCP ordered that no live front uses any more can be
  // removed at the provider (and must be before the account is deleted): FCP
  // never removes it by itself, and never removes one it only found there.
  // `ambiguous` counts when FCP ordered it (another authority than the account's now).
  const REMOVABLE = ['pending', 'processing', 'issued', 'renewing', 'failed', 'ambiguous'];
  function sharedRemovable(l: EdgeLocationAdmin): boolean {
    const sc = l.sharedCertificate;
    return !!sc && sc.orderedByFcp && sc.edges === 0 && REMOVABLE.includes(sc.state);
  }
  let removeSharedOpen = $state(false);
  let removingShared = $state<EdgeLocationAdmin | null>(null);

  /** What a zone check saw, in words (never typed by the operator). */
  function zoneFacts(l: EdgeLocationAdmin): string {
    const o = l.observed ?? {};
    const parts: string[] = [];
    if (o.zoneSslMode) parts.push(`encryption mode ${o.zoneSslMode}`);
    else if (EDGE_PROVIDER_META[account.provider].providesDns)
      parts.push('encryption mode not read');
    if (o.websockets) parts.push(`WebSockets ${o.websockets}`);
    if (o.zoneStatus && o.zoneStatus !== 'active') parts.push(`zone ${o.zoneStatus}`);
    // What a fronting DNS account's zone check also read (lib/edges/providers/cloudflare.ts).
    if (o.edgeCertificate)
      parts.push(
        o.edgeCertificate === 'active'
          ? 'certificate for its names active'
          : o.edgeCertificate === 'pending'
            ? 'certificate for its names on its way'
            : o.edgeCertificate === 'none'
              ? 'no certificate for its names'
              : 'certificate not read',
      );
    if (o.minTlsVersion) parts.push(`lowest TLS version ${o.minTlsVersion}`);
    if (o.pseudoIpv4 && o.pseudoIpv4 !== 'off')
      parts.push("Pseudo IPv4 on (the member's address reaches the node in CF-Connecting-IPv6)");
    if (o.ipGeolocation === 'on')
      parts.push("IP geolocation on (the member's country reaches the node in CF-IPCountry)");
    return parts.length > 0 ? `${parts.join(', ')}.` : '';
  }
  /** The DNS account a front location writes through, by name. */
  function dnsAccountOf(l: EdgeLocationAdmin): string | null {
    const id = l.placement.dnsAccountId;
    return typeof id === 'string' ? (accountNames[id] ?? id) : null;
  }
  // The provider's size field (`from: 'flavors'`): what a location's plan is chosen in.
  const providers = providersQuery();
  const sizeKey = $derived(
    providers.data?.optionSchemas[account.provider]?.fields.find((f) => f.from === 'flavors')
      ?.key ?? null,
  );
  let planFor = $state<EdgeLocationAdmin | null>(null);
  let planOpen = $state(false);
  const prices = createMutation(() => ({
    mutationFn: (id: string) => refreshLocationPlans(account.id, id),
    onSuccess: (r) => {
      invalidateProviders(qc);
      if (r.error) toast.error(`The prices could not be read (${r.error})`);
      else toast.success(r.refreshed ? 'Prices read again' : 'Prices were just read');
    },
    onError: (err: unknown) => toast.error(edgeErrorMessage(err)),
  }));

  let adding = $state(false);
  let trusting = $state<EdgeLocationAdmin | null>(null);
  let trustOpen = $state(false);
  let removing = $state<EdgeLocationAdmin | null>(null);
  let removeOpen = $state(false);

  const patch = createMutation(() => ({
    mutationFn: (a: { id: string; patch: Parameters<typeof updateProviderLocation>[2] }) =>
      updateProviderLocation(account.id, a.id, a.patch),
    onSuccess: () => invalidateProviders(qc),
    onError: (err: unknown) => toast.error(edgeErrorMessage(err)),
  }));

  async function qualify(id: string, qualified: boolean): Promise<void> {
    await qualifyProviderLocation(account.id, id, qualified);
    invalidateProviders(qc);
    toast.success(qualified ? 'Location trusted' : 'Trust removed');
  }

  function capacity(l: EdgeLocationAdmin): string {
    return l.maxLiveEdges === null
      ? `${l.liveEdges} address${l.liveEdges === 1 ? '' : 'es'}`
      : `${l.liveEdges} of ${l.maxLiveEdges} addresses`;
  }
</script>

<Card>
  <CardHeader>
    <CardTitle class="text-base">Locations</CardTitle>
    <CardDescription>
      {#if zones}
        The DNS zones this account fronts in. Pick one, or any other zone the account reaches, when
        you protect a node or add an address; each address stays in the zone it was created in.
        Trust is per zone: a new one is trusted by its first proven front.
      {:else}
        Where this account's edges are created. Pick one when you protect a node or add an address;
        each address stays in the location it was created in. Trust is per location: a new one is
        trusted by its first tested address.
      {/if}
    </CardDescription>
  </CardHeader>
  <CardContent class="space-y-3">
    {#if account.locations.length === 0}
      <p class="text-muted-foreground text-sm">
        {zones
          ? 'No zone yet. Add one here, or pick one when you protect a node.'
          : 'No location yet. Add one: nothing can be created in this account until it has one.'}
      </p>
    {/if}
    <ul class="divide-y rounded-md border">
      {#each account.locations as l (l.id)}
        {@const trust = locationTrustWords(l)}
        <li class="flex flex-wrap items-start justify-between gap-3 p-3">
          <div class="min-w-0 space-y-1">
            <p class="flex flex-wrap items-center gap-2 font-medium">
              {l.label}
              {#if l.isDefault && account.locations.length > 1}<Badge variant="info">Default</Badge
                >{/if}
              {#if !l.enabled}<Badge variant="muted">Off</Badge>{/if}
              <Badge variant={trust.tone}>{trust.label}</Badge>
            </p>
            <p class="text-muted-foreground text-xs">
              {trust.detail}
              {capacity(l)}.
              {#if l.inventoryAt}Inventory {relativeTime(l.inventoryAt)}.{/if}
            </p>
            {#if zones}
              <p class="text-muted-foreground text-xs">
                {#if dnsAccountOf(l)}Records in {dnsAccountOf(l)}.{/if}
                {#if typeof l.placement.tlsConfigurationId === 'string'}TLS configuration
                  <span class="font-mono">{l.placement.tlsConfigurationId}</span>.{/if}
                {zoneFacts(l)}
                {#if l.observedAt}Checked {relativeTime(l.observedAt)}.{/if}
              </p>
              {#if l.sharedCertificate}
                {@const shared = sharedCertificateWords(l.sharedCertificate)}
                <p class="flex flex-wrap items-center gap-2 text-xs">
                  <span class="font-mono">{l.sharedCertificate.name}</span>
                  <Badge variant={shared.tone}>{shared.label}</Badge>
                  <span class="text-muted-foreground">{shared.detail}</span>
                  {#if sharedRemovable(l)}
                    <Button
                      size="sm"
                      variant="outline"
                      onclick={() => {
                        removingShared = l;
                        removeSharedOpen = true;
                      }}
                    >
                      Remove shared certificate
                    </Button>
                  {/if}
                </p>
                {#if !l.sharedCertificate.orderedByFcp}
                  <p class="text-muted-foreground text-xs">
                    FCP found this certificate at the provider and reuses it. It removes only
                    certificates its own fronts ordered.
                  </p>
                {/if}
              {/if}
              {#if l.checkError}
                <p class="text-destructive text-xs" role="alert">
                  The last check refused this zone ({l.checkError}). No new address is created here
                  until a check passes.
                </p>
              {/if}
            {/if}
            {#if !zones && l.pricing}
              {@const pr = l.pricing}
              <p class="text-xs">
                Plan {pr.plan?.label ?? pr.size ?? 'not set'}: {costWords(pr.cost)}.
                {#if pr.plan}<span class="text-muted-foreground"
                    >{trafficWords(pr.plan.traffic)}. {sourceWords(pr.plan)}.</span
                  >{:else if pr.plans.length === 0}<span class="text-muted-foreground"
                    >{pr.plansAt
                      ? 'The provider listed no plans here.'
                      : 'Prices not read yet.'}</span
                  >{/if}
              </p>
              {#if pr.plansError}
                <p class="text-muted-foreground text-xs">
                  The last price read failed ({pr.plansError}); the prices shown are the ones read
                  before.
                </p>
              {/if}
            {:else if zones && l.pricing}
              <p class="text-xs">{costWords(l.pricing.cost)}.</p>
            {/if}
            {#if l.costNote}<p class="text-xs">{l.costNote}</p>{/if}
            {#if Object.keys(l.regionalParams).length > 0}
              <p class="text-muted-foreground font-mono text-xs">
                {Object.entries(l.regionalParams)
                  .map(([k, v]) => `${k}: ${v}`)
                  .join(', ')}
              </p>
            {/if}
          </div>
          <div class="flex flex-wrap gap-2">
            <Button
              size="sm"
              variant="outline"
              class="h-11 sm:h-8"
              onclick={() => {
                trusting = l;
                trustOpen = true;
              }}
            >
              {l.qualified ? 'Remove trust' : 'Trust override'}
            </Button>
            {#if zones}
              <Button
                size="sm"
                variant="outline"
                class="h-11 sm:h-8"
                disabled={check.isPending}
                onclick={() => check.mutate(l.id)}
              >
                {check.isPending && check.variables === l.id ? 'Checking' : 'Check again'}
              </Button>
            {/if}
            {#if !zones && sizeKey}
              <Button
                size="sm"
                variant="outline"
                class="h-11 sm:h-8"
                onclick={() => {
                  planFor = l;
                  planOpen = true;
                }}
              >
                Change plan
              </Button>
              <Button
                size="sm"
                variant="ghost"
                class="h-11 sm:h-8"
                disabled={prices.isPending}
                onclick={() => prices.mutate(l.id)}
              >
                {prices.isPending && prices.variables === l.id
                  ? 'Reading prices'
                  : 'Refresh prices'}
              </Button>
            {/if}
            {#if places}
              <Button
                size="sm"
                variant="outline"
                class="h-11 sm:h-8"
                disabled={patch.isPending}
                onclick={() => patch.mutate({ id: l.id, patch: { enabled: !l.enabled } })}
              >
                {l.enabled ? 'Switch off' : 'Switch on'}
              </Button>
              {#if !l.isDefault}
                <Button
                  size="sm"
                  variant="ghost"
                  class="h-11 sm:h-8"
                  disabled={patch.isPending}
                  onclick={() => patch.mutate({ id: l.id, patch: { makeDefault: true } })}
                >
                  Make default
                </Button>
              {/if}
              <Button
                size="sm"
                variant="ghost"
                class="text-destructive h-11 sm:h-8"
                disabled={l.liveEdges > 0}
                title={l.liveEdges > 0 ? 'Addresses still live here' : undefined}
                onclick={() => {
                  removing = l;
                  removeOpen = true;
                }}
              >
                Remove
              </Button>
            {/if}
          </div>
        </li>
      {/each}
    </ul>
    {#if places}
      <Button size="sm" class="h-11 sm:h-8" onclick={() => (adding = true)}>
        {zones ? 'Add a zone' : 'Add location'}
      </Button>
    {/if}
  </CardContent>
</Card>

<Dialog.Root bind:open={adding}>
  <Dialog.Content class="sm:max-w-2xl">
    <Dialog.Header>
      <Dialog.Title>Add a {zones ? 'zone' : 'location'} to {account.name}</Dialog.Title>
      <Dialog.Description>
        {zones
          ? 'A DNS zone this account can front in. The provider is asked about it before it is added.'
          : 'A region or zone this account can create addresses in. The provider lists what these credentials can use.'}
      </Dialog.Description>
    </Dialog.Header>
    {#if adding}
      <LocationPicker
        accountId={account.id}
        provider={account.provider}
        onCreated={() => (adding = false)}
        onCancel={() => (adding = false)}
      />
    {/if}
  </Dialog.Content>
</Dialog.Root>

<PlanDialog bind:open={planOpen} {account} location={planFor} {sizeKey} />

<QualifyDialog
  bind:open={trustOpen}
  account={trusting
    ? { id: trusting.id, name: `${account.name}, ${trusting.label}`, qualified: trusting.qualified }
    : null}
  tested={!!account.lastTestOkAt && !account.lastTestError}
  onQualify={qualify}
/>

<ConfirmDialog
  bind:open={removeOpen}
  title={`Remove the location ${removing?.label ?? ''}?`}
  body="Nothing at the provider is touched. FCP refuses while an address still lives here or a protected node uses this location."
  confirmLabel="Remove location"
  danger
  onConfirm={async () => {
    if (!removing) return;
    await deleteProviderLocation(account.id, removing.id);
    invalidateProviders(qc);
    toast.success('Location removed');
  }}
/>

<ConfirmDialog
  bind:open={removeSharedOpen}
  title="Remove the shared certificate?"
  body="The zone's wildcard certificate is deleted at the provider, with the validation record FCP wrote for it. No live front uses it now; a later front in this zone on the wildcard orders a new one and waits for it to be issued."
  confirmLabel="Remove certificate"
  onConfirm={async () => {
    if (!removingShared) return;
    await removeSharedCertificate(account.id, removingShared.id);
    invalidateProviders(qc);
    toast.success('Shared certificate removed');
  }}
/>

{#if patch.error}<InlineError message={edgeErrorMessage(patch.error)} />{/if}
