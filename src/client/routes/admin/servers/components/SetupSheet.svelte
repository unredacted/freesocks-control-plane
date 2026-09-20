<script lang="ts">
  /**
   * "Set up this backend" (docs/servers.md "Setting up a backend"): the profile
   * name, the modes the backend serves (a table, pre-filled with the four
   * defaults: each a connection mode, a group name, a shape and, for REALITY,
   * the server-name family whose target and names its transport carries), and
   * the account whose zone WebSocket nodes get their origin names in. One
   * press; the sheet then shows the run as it goes. A backend that already
   * has nodes or addresses is adopted after a typed confirmation. Nothing here
   * is a secret: keys are made on the way and kept nowhere.
   *
   * Props: open (bindable), slug, setup (the current view), accounts
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import Trash2 from '@lucide/svelte/icons/trash-2';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import * as Sheet from '@client/components/ui/sheet';
  import { Switch } from '@client/components/ui/switch';
  import { adminConnectionModesQuery } from '@client/lib/queries';
  import { invalidateServers, startSetup } from '@client/lib/serversApi';
  import { familiesQuery } from '@client/lib/sniApi';
  import {
    DEFAULT_MODE_SETUP,
    MODE_SHAPES,
    type ModeSetupInput,
    type PanelSetupView,
  } from '../../../../../shared/contracts/servers';
  import ConfirmDialog from '../../edges/components/ConfirmDialog.svelte';
  import StatusDot from '../../edges/simple/StatusDot.svelte';
  import { codeOf } from '../lib/run';
  import { serverErrorWords, setupWords, shapeWords } from '../lib/words';

  interface Props {
    open: boolean;
    slug: string;
    setup: PanelSetupView | null;
    accounts: { id: string; name: string; zoneName: string }[];
  }
  let { open = $bindable(false), slug, setup, accounts }: Props = $props();
  const qc = useQueryClient();
  const uid = $props.id();
  const catalog = adminConnectionModesQuery();
  const families = familiesQuery();

  type Row = ModeSetupInput & { key: number };
  let seq = 0;
  const rowOf = (m: ModeSetupInput): Row => ({
    ...m,
    ws: m.ws ? { ...m.ws } : undefined,
    key: seq++,
  });

  let profileName = $state('FreeSocks-Config');
  let rows = $state<Row[]>(DEFAULT_MODE_SETUP.map(rowOf));
  let originAccountId = $state('');
  let busy = $state(false);
  let adoptOpen = $state(false);

  const shapeKey = (s: { transport: string; fronting: string }) => `${s.transport}/${s.fronting}`;
  const isReality = (r: Row) => r.shape.transport !== 'ws';
  const knownModes = $derived(catalog.data?.modes ?? []);
  const familyRows = $derived((families.data?.families ?? []).filter((f) => f.enabled));

  function setShape(r: Row, key: string) {
    const s = MODE_SHAPES.find((m) => shapeKey(m) === key);
    if (!s) return;
    r.shape = { ...s };
    if (s.transport === 'ws') {
      r.familySlug = undefined;
      r.ws ??= { path: '/ws', port: 8443 };
    } else r.ws = undefined;
  }
  function addRow() {
    rows = [
      ...rows,
      rowOf({
        slug: '',
        name: '',
        shape: { transport: 'reality', fronting: 'edge-l4' },
        acceptProxyProtocol: false,
      }),
    ];
  }
  const removeRow = (key: number) => (rows = rows.filter((r) => r.key !== key));

  function input(adopt: boolean) {
    return {
      profileName: profileName.trim(),
      modes: rows.map(({ key: _k, ...m }) => ({
        ...m,
        slug: m.slug.trim(),
        name: m.name.trim(),
        familySlug: isReality(m as Row) ? m.familySlug || undefined : undefined,
        ws: m.shape.transport === 'ws' ? m.ws : undefined,
      })),
      originDns: originAccountId ? { accountId: originAccountId } : null,
      adopt,
    };
  }

  async function submit(adopt = false) {
    if (rows.length === 0) {
      toast.error('Keep at least one mode.');
      return;
    }
    for (const r of rows)
      if (isReality(r) && !r.familySlug) {
        toast.error(`Pick a server-name family for ${r.name || r.slug || 'each REALITY mode'}.`);
        return;
      }
    busy = true;
    try {
      await startSetup(slug, input(adopt));
    } catch (e) {
      const code = codeOf(e);
      if (code === 'servers.adopt_required' && !adopt) adoptOpen = true;
      else toast.error(serverErrorWords(code));
    } finally {
      busy = false;
      invalidateServers(qc);
    }
  }

  let running = $derived(setup?.running ?? false);
  let status = $derived(setup ? setupWords(setup) : null);
  const familyState: Record<string, string> = {
    none: '',
    bound: 'family bound',
    unbound: 'family not bound yet',
    target_mismatch: 'family target differs',
  };
</script>

<Sheet.Root bind:open>
  <Sheet.Content side="right" class="gap-0 overflow-y-auto sm:max-w-2xl">
    <Sheet.Header class="border-b">
      <Sheet.Title>Set up this backend</Sheet.Title>
      <Sheet.Description>
        The modes this backend serves, each with its transport, its group and (REALITY) the family
        of server names it borrows. Nothing here is a secret: keys are made on the way and kept
        nowhere.
      </Sheet.Description>
    </Sheet.Header>

    <div class="space-y-6 p-4">
      {#if setup?.exists}
        <p class="flex items-center gap-2 text-sm" role="status">
          <StatusDot
            dot={setup.state === 'ready' ? 'green' : setup.state === 'failed' ? 'red' : 'amber'}
          />
          {status ??
            (setup.adopted ? 'The backend is adopted and set up.' : 'The backend is set up.')}
          {#if setup.step && running}<span class="text-muted-foreground">({setup.step})</span>{/if}
        </p>
        {#if setup.modes.length > 0}
          <ul class="text-muted-foreground space-y-1 text-sm">
            {#each setup.modes as m (m.slug)}
              <li>
                <span class="text-foreground font-medium">{m.name}</span>: {shapeWords(m.shape)}
                {#if m.transport}, port {m.transport.port}{/if}
                {#if m.familySlug}, names from {m.familySlug}{/if}
                {#if m.placement !== 'bound'}, <span class="text-amber-700 dark:text-amber-300"
                    >mode not bound</span
                  >{/if}
                {#if m.family === 'unbound' || m.family === 'target_mismatch'}, <span
                    class="text-amber-700 dark:text-amber-300">{familyState[m.family]}</span
                  >{/if}
                {#if m.group.renamedFrom}, renamed from {m.group.renamedFrom}{/if}
              </li>
            {/each}
            {#if setup.originDns}<li>Origin names under {setup.originDns.zoneName}.</li>{/if}
          </ul>
        {/if}
      {/if}

      {#if !setup?.exists || setup.state !== 'ready'}
        <form
          class="space-y-4"
          onsubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          <div class="space-y-1.5">
            <Label for={`${uid}-profile`}>Profile name</Label>
            <Input id={`${uid}-profile`} bind:value={profileName} autocomplete="off" />
          </div>

          <fieldset class="space-y-3">
            <legend class="text-sm font-medium">Modes</legend>
            <p class="text-muted-foreground text-xs">
              One transport per mode. A node serves one mode; members reach a direct node at its own
              address and a fronted one through an edge. REALITY modes take their site and server
              names from a family (Edges, Server names).
            </p>
            <div class="space-y-3">
              {#each rows as r (r.key)}
                <div class="bg-card space-y-2 rounded-md border p-3">
                  <div class="grid grid-cols-1 gap-2 sm:grid-cols-3">
                    <div class="space-y-1">
                      <Label for={`${uid}-slug-${r.key}`} class="text-xs">Connection mode</Label>
                      <select
                        id={`${uid}-slug-${r.key}`}
                        class="bg-background w-full rounded-md border px-2 py-1.5 text-sm"
                        bind:value={r.slug}
                      >
                        <option value="">Pick a mode</option>
                        {#each knownModes as m (m.id)}
                          <option value={m.id}>{m.label ?? m.id}{m.enabled ? '' : ' (off)'}</option>
                        {/each}
                      </select>
                    </div>
                    <div class="space-y-1">
                      <Label for={`${uid}-name-${r.key}`} class="text-xs"
                        >Group name on the backend</Label
                      >
                      <Input
                        id={`${uid}-name-${r.key}`}
                        bind:value={r.name}
                        autocomplete="off"
                        spellcheck={false}
                      />
                    </div>
                    <div class="space-y-1">
                      <Label for={`${uid}-shape-${r.key}`} class="text-xs">Shape</Label>
                      <select
                        id={`${uid}-shape-${r.key}`}
                        class="bg-background w-full rounded-md border px-2 py-1.5 text-sm"
                        value={shapeKey(r.shape)}
                        onchange={(e) => setShape(r, (e.currentTarget as HTMLSelectElement).value)}
                      >
                        {#each MODE_SHAPES as s (shapeKey(s))}
                          <option value={shapeKey(s)}>{shapeWords(s)}</option>
                        {/each}
                      </select>
                    </div>
                  </div>
                  <div class="grid grid-cols-1 gap-2 sm:grid-cols-3">
                    {#if isReality(r)}
                      <div class="space-y-1 sm:col-span-2">
                        <Label for={`${uid}-fam-${r.key}`} class="text-xs">Server-name family</Label
                        >
                        <select
                          id={`${uid}-fam-${r.key}`}
                          class="bg-background w-full rounded-md border px-2 py-1.5 text-sm"
                          bind:value={r.familySlug}
                        >
                          <option value={undefined}>Pick a family</option>
                          {#each familyRows as f (f.slug)}
                            <option value={f.slug}
                              >{f.label} ({f.target.address}, {f.counts.ready} usable)</option
                            >
                          {/each}
                        </select>
                        {#if familyRows.length === 0}
                          <p class="text-xs text-amber-700 dark:text-amber-300">
                            No family yet. Add one under Edges, Server names, and let its names
                            qualify.
                          </p>
                        {/if}
                      </div>
                      {#if r.shape.fronting === 'edge-l4'}
                        <div class="flex items-center gap-2 self-end pb-1.5">
                          <Switch id={`${uid}-pp-${r.key}`} bind:checked={r.acceptProxyProtocol} />
                          <Label for={`${uid}-pp-${r.key}`} class="text-xs font-normal"
                            >Edges send PROXY protocol</Label
                          >
                        </div>
                      {/if}
                    {:else if r.ws}
                      <div class="space-y-1">
                        <Label for={`${uid}-path-${r.key}`} class="text-xs">Path</Label>
                        <Input
                          id={`${uid}-path-${r.key}`}
                          bind:value={r.ws.path}
                          autocomplete="off"
                        />
                      </div>
                      <div class="space-y-1">
                        <Label for={`${uid}-port-${r.key}`} class="text-xs">Loopback port</Label>
                        <Input
                          id={`${uid}-port-${r.key}`}
                          type="number"
                          bind:value={r.ws.port}
                          autocomplete="off"
                        />
                      </div>
                    {/if}
                    <div class="flex justify-end self-end">
                      <Button
                        type="button"
                        size="sm"
                        variant="ghost"
                        class="text-destructive"
                        aria-label={`Remove ${r.name || 'this mode'}`}
                        onclick={() => removeRow(r.key)}><Trash2 class="size-4" /></Button
                      >
                    </div>
                  </div>
                </div>
              {/each}
            </div>
            <Button type="button" size="sm" variant="outline" onclick={addRow}>Add a mode</Button>
          </fieldset>

          <div class="space-y-1.5">
            <Label for={`${uid}-dns`}>Origin names for WebSocket nodes</Label>
            <select
              id={`${uid}-dns`}
              class="bg-background w-full rounded-md border px-3 py-2 text-sm"
              bind:value={originAccountId}
            >
              <option value="">No managed zone: set each node's hostname in its settings</option>
              {#each accounts as a (a.id)}
                <option value={a.id}>{a.name} ({a.zoneName})</option>
              {/each}
            </select>
          </div>
          <Sheet.Footer>
            <Button type="button" variant="outline" onclick={() => (open = false)}>Close</Button>
            <Button type="submit" disabled={busy || running}>Set up</Button>
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
  bind:open={adoptOpen}
  title="Adopt this backend?"
  body="It already has nodes or addresses. FCP becomes its writer: the profile is adopted as it is (keys untouched), groups an earlier setup named are renamed in place, and nothing a member holds changes."
  typed={slug}
  confirmLabel="Adopt"
  danger
  onConfirm={() => {
    adoptOpen = false;
    void submit(true);
  }}
/>
