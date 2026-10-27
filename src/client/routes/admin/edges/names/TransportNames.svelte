<script lang="ts">
  /**
   * A REALITY transport's server names on a node's page (docs/edges.md "A
   * transport's names"), the way the node's edges show theirs: one status line
   * (what this node's members get, what waits) and ONE next step at a time,
   * worded by ./lib/transportWords.ts:
   *
   *   Manage these names with FCP -> (checked) -> Add suggestions -> Send to
   *   the node -> Test one name -> members get them.
   *
   * A step a switch holds back says which switch, with a link to it. The rest
   * (the name list, looking for more names, stopping, editing by hand when FCP
   * does not manage them) sits in "More". The names the port lists now are one
   * click away.
   *
   * Props:
   *   backendSlug, nodeUuid           the page's backend and node
   *   transport                       its row of `GET sni/transports` (undefined while loading)
   *   switches                        that read's switches
   *   names                           the names the port lists now (Servers' read)
   *   onEditByHand?                   offered while FCP does not manage the names
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import ChevronDown from '@lucide/svelte/icons/chevron-down';
  import { Button } from '@client/components/ui/button';
  import * as DropdownMenu from '@client/components/ui/dropdown-menu';
  import { Skeleton } from '@client/components/ui/skeleton';
  import Link from '@client/components/Link.svelte';
  import { ApiCallError } from '@client/lib/api';
  import { invalidateSni, lookUpCt, readTargetCert, unbindFamily } from '@client/lib/sniApi';
  import { invalidateServers } from '@client/lib/serversApi';
  import { router } from '@client/stores/router.svelte';
  import type { SniTransport, SniTransportsView } from '../../../../../shared/contracts/sni';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import { edgesPaths } from '../lib/routes';
  import StatusDot from '../simple/StatusDot.svelte';
  import AddSuggestionsDialog from './AddSuggestionsDialog.svelte';
  import ManageNamesDialog from './ManageNamesDialog.svelte';
  import SendNamesDialog from './SendNamesDialog.svelte';
  import TestNameDialog from './TestNameDialog.svelte';
  import {
    lookedWords,
    namesStatus,
    namesStep,
    STEP_BUTTON,
    stepWords,
  } from './lib/transportWords';
  import { CHECK_WORDS, sniErrorWords } from './lib/words';

  let {
    backendSlug,
    nodeUuid,
    transport,
    switches,
    names,
    serversHref,
    onEditByHand,
  }: {
    backendSlug: string;
    nodeUuid: string | null;
    transport: SniTransport | undefined;
    switches: SniTransportsView['switches'] | undefined;
    names: readonly string[];
    /** Where the backend-changes switch is (the Servers page). */
    serversHref: string;
    onEditByHand?: () => void;
  } = $props();
  const qc = useQueryClient();
  const codeOf = (e: unknown) => (e instanceof ApiCallError ? e.payload.error.code : null);

  let step = $derived(transport && switches ? namesStep(transport, switches, nodeUuid) : null);
  let status = $derived(transport ? namesStatus(transport, nodeUuid) : null);
  let button = $derived(step ? (STEP_BUTTON[step.kind] ?? null) : null);

  // Once the backend is seen to hold a send, the port's names as Servers reads
  // them change too: read them again, so this card never shows two lists.
  let lastPhase: string | null = null;
  $effect(() => {
    const phase = transport?.send?.phase ?? null;
    if (lastPhase === 'writing' && phase !== 'writing') invalidateServers(qc);
    lastPhase = phase;
  });

  let manageOpen = $state(false);
  let addOpen = $state(false);
  let sendOpen = $state(false);
  let testOpen = $state(false);
  let stopOpen = $state(false);
  function next() {
    if (!step) return;
    if (step.kind === 'manage') manageOpen = true;
    else if (step.kind === 'add_suggestions') addOpen = true;
    else if (step.kind === 'send' || step.kind === 'send_again') sendOpen = true;
    else if (step.kind === 'test') testOpen = true;
  }

  let busy = $state(false);
  async function lookForMore() {
    const t = transport;
    if (!t?.list) return;
    busy = true;
    try {
      const r = await readTargetCert(t.list.slug);
      const host = (t.coverSite ?? '').replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
      // Certificate logs are kept per site name, never for an address.
      const ct =
        /^[\d.]+$/.test(host) || host.includes(':')
          ? null
          : await lookUpCt([host], { family: t.list.slug });
      if (r.ok) toast.success(lookedWords(r, ct));
      else toast.error(CHECK_WORDS[r.code ?? ''] ?? 'The cover site could not be read.');
    } catch (e) {
      toast.error(sniErrorWords(codeOf(e)));
    } finally {
      busy = false;
      invalidateSni(qc);
    }
  }
  async function stop() {
    const t = transport;
    if (!t?.list) return;
    try {
      await unbindFamily(t.list.bindingId);
      stopOpen = false;
      toast.success('FCP no longer manages these names. They stay as they are.');
    } finally {
      invalidateSni(qc);
    }
  }
</script>

<div class="mt-3 border-t pt-3" aria-label="Server names">
  {#if !transport || !switches || !step || !status}
    <Skeleton class="h-5 w-64" />
  {:else}
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div class="min-w-0 flex-1 space-y-1">
        <p class="flex flex-wrap items-center gap-2 font-medium" role="status">
          <StatusDot dot={status.dot} />
          Server names: {status.text}
        </p>
        <p class="text-muted-foreground">
          {stepWords(step, transport)}
          {#if step.kind === 'names_off'}
            <Link href={edgesPaths.names()} class="text-primary underline underline-offset-4">
              Turn them on
            </Link>
          {:else if step.kind === 'send_blocked' && step.why === 'backend_changes_off'}
            <Link href={serversHref} class="text-primary underline underline-offset-4">
              Turn them on under Servers
            </Link>
          {:else if step.kind === 'send_blocked'}
            <Link href={serversHref} class="text-primary underline underline-offset-4">
              Set it up under Servers
            </Link>
          {:else if step.kind === 'list_off' && transport.list}
            <Link
              href={edgesPaths.family(transport.list.slug)}
              class="text-primary underline underline-offset-4"
            >
              Open the name list
            </Link>
          {/if}
        </p>
        {#if transport.coverSite}
          <p class="text-muted-foreground">
            Cover site <span class="font-mono break-all">{transport.coverSite}</span>
          </p>
        {/if}
      </div>
      <div class="flex shrink-0 flex-wrap items-center gap-2">
        {#if button}
          <Button disabled={busy} onclick={next}>{button}</Button>
        {/if}
        {#if transport.list || onEditByHand}
          <DropdownMenu.Root>
            <DropdownMenu.Trigger>
              {#snippet child({ props })}
                <Button {...props} variant="outline" aria-label="More name actions">
                  More <ChevronDown aria-hidden="true" />
                </Button>
              {/snippet}
            </DropdownMenu.Trigger>
            <DropdownMenu.Content align="end" class="w-64">
              {#if transport.list}
                {@const list = transport.list}
                <DropdownMenu.Item onSelect={() => router.navigate(edgesPaths.family(list.slug))}>
                  Open the name list
                </DropdownMenu.Item>
                <DropdownMenu.Item
                  disabled={busy || !switches.findNames}
                  onSelect={() => void lookForMore()}
                >
                  {switches.findNames
                    ? 'Look for more names'
                    : 'Look for more names (finding names is off)'}
                </DropdownMenu.Item>
                {#if list.suggestions > 0 && step.kind !== 'add_suggestions'}
                  <DropdownMenu.Item onSelect={() => (addOpen = true)}>
                    Add suggestions ({list.suggestions})
                  </DropdownMenu.Item>
                {/if}
                <DropdownMenu.Separator />
                <DropdownMenu.Item variant="destructive" onSelect={() => (stopOpen = true)}>
                  Stop managing
                </DropdownMenu.Item>
              {:else if onEditByHand}
                <DropdownMenu.Item onSelect={onEditByHand}>Edit names by hand</DropdownMenu.Item>
              {/if}
            </DropdownMenu.Content>
          </DropdownMenu.Root>
        {/if}
      </div>
    </div>
    {#if names.length > 0}
      <details class="mt-2 min-w-0">
        <summary class="text-muted-foreground cursor-pointer">
          The {names.length === 1 ? 'name' : `${names.length} names`} this port lists now
        </summary>
        <ul class="mt-1 columns-1 gap-x-6 sm:columns-2">
          {#each names as name (name)}
            <li class="break-all">{name}</li>
          {/each}
        </ul>
      </details>
    {/if}

    <ManageNamesDialog bind:open={manageOpen} {backendSlug} {transport} {nodeUuid} />
    {#if transport.list}
      <AddSuggestionsDialog
        bind:open={addOpen}
        family={transport.list.slug}
        label={transport.list.label}
      />
      <SendNamesDialog bind:open={sendOpen} {transport} />
    {/if}
    {#if step.kind === 'test' && transport.send}
      <TestNameDialog bind:open={testOpen} send={transport.send} node={step.node} />
    {/if}
    <ConfirmDialog
      bind:open={stopOpen}
      title="Stop managing these names?"
      body="The names stay on the node and with members. FCP stops checking them and sending new ones, and they can be edited by hand again. The name list itself is kept."
      confirmLabel="Stop managing"
      danger
      onConfirm={stop}
    />
  {/if}
</div>
