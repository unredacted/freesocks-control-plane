<script lang="ts">
  /**
   * "Set up this panel" (docs/servers.md "Setting up a panel"): the profile
   * name, the two REALITY decoys with their names, the squad names, and the
   * account whose zone front nodes get their origin names in. One press;
   * the sheet then shows the run as it goes. A panel that already has nodes
   * needs the typed takeover first.
   *
   * Props: open (bindable), slug, setup (the current view), accounts
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import * as Sheet from '@client/components/ui/sheet';
  import { Switch } from '@client/components/ui/switch';
  import { invalidateServers, startSetup, takeoverPanel } from '@client/lib/serversApi';
  import type { PanelSetupView } from '../../../../../shared/contracts/servers';
  import ConfirmDialog from '../../edges/components/ConfirmDialog.svelte';
  import StatusDot from '../../edges/simple/StatusDot.svelte';
  import { codeOf } from '../lib/run';
  import { serverErrorWords, setupWords } from '../lib/words';

  interface Props {
    open: boolean;
    slug: string;
    setup: PanelSetupView | null;
    accounts: { id: string; name: string; zoneName: string }[];
  }
  let { open = $bindable(false), slug, setup, accounts }: Props = $props();
  const qc = useQueryClient();
  const uid = $props.id();

  let profileName = $state('FreeSocks-Config');
  let realityTarget = $state('');
  let realityNames = $state('');
  let relayTarget = $state('');
  let relayNames = $state('');
  let acceptProxyProtocol = $state(false);
  let squadFronted = $state('FreeSocks-Fronted');
  let squadReality = $state('FreeSocks-Reality');
  let squadRelay = $state('FreeSocks-Relay');
  let originAccountId = $state('');
  let busy = $state(false);
  let takeoverOpen = $state(false);

  const parseTarget = (s: string) => {
    const m = /^([^:\s]+)(?::(\d{1,5}))?$/.exec(s.trim());
    return m ? { address: m[1]!, port: m[2] ? Number(m[2]) : 443 } : null;
  };
  const parseNames = (s: string) =>
    s
      .split(/[\s,]+/)
      .map((n) => n.trim())
      .filter(Boolean);

  async function submit() {
    const reality = parseTarget(realityTarget);
    const relay = parseTarget(relayTarget);
    if (!reality || !relay) {
      toast.error('Each decoy is a host, or host:port.');
      return;
    }
    busy = true;
    try {
      await startSetup(slug, {
        profileName: profileName.trim(),
        cdn: { path: '/ws', port: 8443 },
        reality: { target: reality, serverNames: parseNames(realityNames) },
        relay: { target: relay, serverNames: parseNames(relayNames), acceptProxyProtocol },
        squads: {
          fronted: squadFronted.trim(),
          reality: squadReality.trim(),
          relay: squadRelay.trim(),
        },
        originDns: originAccountId ? { accountId: originAccountId } : null,
      });
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
    } finally {
      busy = false;
      invalidateServers(qc);
    }
  }

  async function takeover() {
    takeoverOpen = false;
    busy = true;
    try {
      await takeoverPanel(slug);
      await submit();
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
    } finally {
      busy = false;
      invalidateServers(qc);
    }
  }

  let running = $derived(setup?.running ?? false);
  let status = $derived(setup ? setupWords(setup) : null);
</script>

<Sheet.Root bind:open>
  <Sheet.Content side="right" class="gap-0 overflow-y-auto sm:max-w-xl">
    <Sheet.Header class="border-b">
      <Sheet.Title>Set up this panel</Sheet.Title>
      <Sheet.Description>
        The profile and its three inbounds, the squads and the connection modes they feed, and the
        subscription templates. Nothing here is a secret: keys are made on the way and kept nowhere.
      </Sheet.Description>
    </Sheet.Header>

    <div class="space-y-6 p-4">
      {#if setup?.exists}
        <p class="flex items-center gap-2 text-sm" role="status">
          <StatusDot
            dot={setup.state === 'ready' ? 'green' : setup.state === 'failed' ? 'red' : 'amber'}
          />
          {status ?? 'The panel is set up.'}
          {#if setup.step && running}<span class="text-muted-foreground">({setup.step})</span>{/if}
        </p>
        {#if setup.state === 'ready' && setup.inbounds}
          <ul class="text-muted-foreground space-y-1 text-sm">
            <li>
              Profile {setup.profile?.name}: {setup.inbounds.cdn.tag}, {setup.inbounds.reality.tag}, {setup
                .inbounds.relay.tag}.
            </li>
            <li>
              Squads: {setup.squads.map((s) => s.name).join(', ')}. Modes bound:
              {setup.placements.filter((p) => p.state === 'bound').length} of {setup.placements
                .length}.
            </li>
            {#if setup.originDns}<li>Origin names under {setup.originDns.zoneName}.</li>{/if}
          </ul>
        {/if}
      {/if}

      {#if !setup?.exists || setup.state !== 'ready'}
        <form
          class="space-y-4"
          onsubmit={(e) => {
            e.preventDefault();
            if (setup?.state === 'needs_takeover') takeoverOpen = true;
            else void submit();
          }}
        >
          <div class="space-y-1.5">
            <Label for={`${uid}-profile`}>Profile name</Label>
            <Input id={`${uid}-profile`} bind:value={profileName} autocomplete="off" />
          </div>
          <fieldset class="space-y-3">
            <legend class="text-sm font-medium">Direct nodes (REALITY)</legend>
            <div class="space-y-1.5">
              <Label for={`${uid}-rt`}>Decoy site (host or host:port)</Label>
              <Input
                id={`${uid}-rt`}
                bind:value={realityTarget}
                placeholder="decoy.example"
                autocomplete="off"
                spellcheck={false}
              />
            </div>
            <div class="space-y-1.5">
              <Label for={`${uid}-rn`}>Server names the decoy serves</Label>
              <Input
                id={`${uid}-rn`}
                bind:value={realityNames}
                placeholder="decoy.example, www.decoy.example"
                autocomplete="off"
                spellcheck={false}
              />
            </div>
          </fieldset>
          <fieldset class="space-y-3">
            <legend class="text-sm font-medium">Relay nodes (REALITY behind an edge)</legend>
            <div class="space-y-1.5">
              <Label for={`${uid}-lt`}>Decoy site</Label>
              <Input
                id={`${uid}-lt`}
                bind:value={relayTarget}
                placeholder="relay-decoy.example"
                autocomplete="off"
                spellcheck={false}
              />
            </div>
            <div class="space-y-1.5">
              <Label for={`${uid}-ln`}>Server names the decoy serves</Label>
              <Input
                id={`${uid}-ln`}
                bind:value={relayNames}
                autocomplete="off"
                spellcheck={false}
              />
            </div>
            <div class="flex items-center gap-3">
              <Switch id={`${uid}-pp`} bind:checked={acceptProxyProtocol} />
              <Label for={`${uid}-pp`} class="font-normal">The edges send PROXY protocol</Label>
            </div>
          </fieldset>
          <fieldset class="space-y-3">
            <legend class="text-sm font-medium">Squads</legend>
            <div class="grid grid-cols-3 gap-3">
              <Input bind:value={squadFronted} aria-label="Fronted squad" autocomplete="off" />
              <Input bind:value={squadReality} aria-label="Direct squad" autocomplete="off" />
              <Input bind:value={squadRelay} aria-label="Relay squad" autocomplete="off" />
            </div>
            <p class="text-muted-foreground text-xs">
              Fronted feeds Freedom (WebSocket), direct feeds Privacy (REALITY), relay feeds Freedom
              (REALITY).
            </p>
          </fieldset>
          <div class="space-y-1.5">
            <Label for={`${uid}-dns`}>Origin names for front nodes</Label>
            <select
              id={`${uid}-dns`}
              class="bg-background w-full rounded-md border px-3 py-2 text-sm"
              bind:value={originAccountId}
            >
              <option value="">The role gives each front node its hostname</option>
              {#each accounts as a (a.id)}
                <option value={a.id}>{a.name} ({a.zoneName})</option>
              {/each}
            </select>
          </div>
          <Sheet.Footer>
            <Button type="button" variant="outline" onclick={() => (open = false)}>Close</Button>
            <Button type="submit" disabled={busy || running}>
              {setup?.state === 'needs_takeover' ? 'Take over and set up' : 'Set up'}
            </Button>
          </Sheet.Footer>
        </form>
      {:else}
        <Sheet.Footer>
          <Button type="button" variant="outline" onclick={() => (open = false)}>Close</Button>
        </Sheet.Footer>
      {/if}
    </div>
  </Sheet.Content>
</Sheet.Root>

<ConfirmDialog
  bind:open={takeoverOpen}
  title="Take over this panel?"
  body="No node role must still write to this panel. From now on FCP is its only writer; the old role would fight it."
  typed={slug}
  confirmLabel="Take over"
  danger
  onConfirm={takeover}
/>
