<script lang="ts">
  /**
   * One node (`/admin/servers/nodes/:uuid?instance=<slug>`): its status in a
   * sentence, the inbounds it serves with the addresses members get for each,
   * and every action on the node in the header. Nothing on this page changes a
   * panel unless changes are allowed and the node role has handed it over.
   *
   * Wording lives in ./lib/words.ts (pure, unit-tested).
   */
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import Link from '@client/components/Link.svelte';
  import { serverSummaryQuery, serverTreeQuery } from '@client/lib/serversApi';
  import { router } from '@client/stores/router.svelte';
  import type { PanelHostView, PanelInboundView } from '../../../../shared/contracts/servers';
  import SectionHeader from '../edges/components/SectionHeader.svelte';
  import StatusDot from '../edges/simple/StatusDot.svelte';
  import HostDialog from './components/HostDialog.svelte';
  import NamesDialog from './components/NamesDialog.svelte';
  import NodeActions from './components/NodeActions.svelte';
  import { codeOf } from './lib/run';
  import { pickInstance, serversPaths } from './lib/routes';
  import {
    countryLabel,
    inboundSummary,
    nodeNotes,
    nodeWords,
    serverErrorWords,
    serverNamesLabel,
  } from './lib/words';

  let { uuid }: { uuid: string } = $props();
  const summary = serverSummaryQuery();
  let slug = $derived(pickInstance(router.search, summary.data?.instances ?? []));
  const tree = serverTreeQuery(() => slug);
  let instance = $derived(summary.data?.instances.find((i) => i.slug === slug) ?? null);
  let node = $derived(tree.data?.nodes.find((n) => n.nodeUuid === uuid) ?? null);
  let manageOn = $derived(summary.data?.config['manage.enabled'] ?? false);
  let canWrite = $derived(manageOn && !!instance?.writable && !!instance?.handoffCurrent);
  let back = $derived({
    href: serversPaths.home({ instance: slug ?? undefined }),
    label: 'Servers',
  });

  let hostOpen = $state(false);
  let hostFor = $state<{ inbound: PanelInboundView; host: PanelHostView | null } | null>(null);
  let namesOpen = $state(false);
  let namesFor = $state<{ profileUuid: string; inbound: PanelInboundView } | null>(null);
  const editHost = (inbound: PanelInboundView, host: PanelHostView | null) => {
    hostFor = { inbound, host };
    hostOpen = true;
  };
</script>

{#if summary.isPending || tree.isPending}
  <SectionHeader title="Node" {back} />
  <div class="space-y-3"><Skeleton class="h-6 w-72" /><Skeleton class="h-32 w-full" /></div>
{:else if tree.isError}
  <SectionHeader title="Node" {back} />
  <p class="text-destructive text-sm">{serverErrorWords(codeOf(tree.error))}</p>
{:else if !node || !slug}
  <SectionHeader title="Node not found" {back} />
  <p class="text-muted-foreground text-sm">
    There is no node with this id on the panel any more, or the link is old.
  </p>
{:else}
  {@const w = nodeWords(node)}
  {@const country = countryLabel(node.countryCode)}
  {@const notes = nodeNotes(node)}
  <SectionHeader
    title={node.name}
    description={[country, node.address].filter(Boolean).join(' · ') || undefined}
    {back}
  >
    {#snippet actions()}
      {#if canWrite}
        <NodeActions {slug} {node} />
      {/if}
    {/snippet}
  </SectionHeader>

  <div class="space-y-8">
    <div>
      <p class="flex items-center gap-2 text-lg font-medium" role="status">
        <StatusDot dot={w.dot} class="size-3" />
        {w.sentence}
      </p>
      {#if node.profile}
        <p class="text-muted-foreground mt-1 text-sm">Runs the profile {node.profile.name}.</p>
      {/if}
      {#if notes.length > 0}
        <ul class="text-muted-foreground mt-1 space-y-1 text-sm" aria-label="Notes">
          {#each notes as n (n)}
            <li>{n}</li>
          {/each}
        </ul>
      {/if}
    </div>

    <section aria-labelledby="inbounds">
      <h2 id="inbounds" class="mb-3 text-base font-semibold">Inbounds</h2>
      {#if node.inbounds.length === 0}
        <p class="text-muted-foreground text-sm">This node serves no inbound.</p>
      {:else}
        <ul class="space-y-3">
          {#each node.inbounds as inbound (inbound.inboundUuid)}
            {@const names = serverNamesLabel(inbound)}
            <li class="rounded-lg border p-3 text-sm">
              <p class="font-medium break-all">
                {inbound.tag}
                <span class="text-muted-foreground font-normal">{inboundSummary(inbound)}</span>
              </p>

              {#if names}
                <div class="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1">
                  <details class="min-w-0">
                    <summary class="text-muted-foreground cursor-pointer">
                      {names}{inbound.realityTarget ? `, from ${inbound.realityTarget}` : ''}
                    </summary>
                    <ul class="mt-1 columns-1 gap-x-6 sm:columns-2">
                      {#each inbound.serverNames ?? [] as name (name)}
                        <li class="break-all">{name}</li>
                      {/each}
                    </ul>
                  </details>
                  {#if canWrite && node.profile}
                    <Button
                      variant="ghost"
                      size="sm"
                      class="-my-1"
                      onclick={() => {
                        namesFor = { profileUuid: node.profile!.profileUuid, inbound };
                        namesOpen = true;
                      }}
                    >
                      Edit
                    </Button>
                  {/if}
                </div>
              {/if}

              <div class="mt-3">
                <h3 class="text-muted-foreground text-xs font-medium uppercase">
                  Addresses members get
                </h3>
                {#if inbound.hosts.length === 0}
                  <p class="text-muted-foreground">None yet.</p>
                {:else}
                  <ul class="mt-1 space-y-0.5">
                    {#each inbound.hosts as host (host.hostUuid)}
                      <li class={host.isDisabled ? 'text-muted-foreground line-through' : ''}>
                        {#if canWrite}
                          <button
                            type="button"
                            class="hover:text-foreground focus-visible:ring-ring/50 rounded text-start underline-offset-2 outline-none hover:underline focus-visible:ring-3"
                            onclick={() => editHost(inbound, host)}
                          >
                            <span class="break-all">{host.remark}</span>
                          </button>
                        {:else}
                          <span class="break-all">{host.remark}</span>
                        {/if}
                        <span class="text-muted-foreground break-all">
                          {host.address}:{host.port}{host.sni ? ` · ${host.sni}` : ''}
                        </span>
                      </li>
                    {/each}
                  </ul>
                {/if}
                {#if canWrite}
                  <Button
                    variant="ghost"
                    size="sm"
                    class="-ms-2 mt-1"
                    onclick={() => editHost(inbound, null)}
                  >
                    Add an address
                  </Button>
                {/if}
              </div>

              <p class="text-muted-foreground mt-2">
                {#if inbound.squads.length === 0}
                  In no squad.
                {:else}
                  Squads: {inbound.squads.map((s) => s.name).join(', ')}
                {/if}
              </p>
            </li>
          {/each}
        </ul>
      {/if}
    </section>

    {#if !canWrite}
      <p class="text-muted-foreground border-t pt-4 text-sm">
        {#if !manageOn}
          Changes from here are off. Turn them on from the
          <Link href={back.href} class="underline underline-offset-4">Servers page</Link>.
        {:else if instance && !instance.handoffCurrent}
          Changes are refused until the node role has handed this panel over.
        {/if}
      </p>
    {/if}
  </div>

  {#if hostFor}
    <HostDialog
      bind:open={hostOpen}
      {slug}
      inboundUuid={hostFor.inbound.inboundUuid}
      inboundTag={hostFor.inbound.tag}
      host={hostFor.host}
    />
  {/if}
  {#if namesFor}
    <NamesDialog
      bind:open={namesOpen}
      {slug}
      profileUuid={namesFor.profileUuid}
      inbound={namesFor.inbound}
    />
  {/if}
{/if}
