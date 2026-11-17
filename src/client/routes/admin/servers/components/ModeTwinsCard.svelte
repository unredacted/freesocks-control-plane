<script lang="ts">
  /**
   * The encrypted twin of each WebSocket mode behind a CDN, on one backend
   * (docs/servers.md "A mode's encrypted twin"). A CDN that fronts such a mode
   * holds the connection in the clear; the twin is the mode's transport a
   * second time, encrypted inside, on another loopback port and path.
   *
   * Three steps, in order: add an encrypted WebSocket transport (the button
   * opens "Add a transport" filled in), make it the mode's twin (its mode
   * group then carries both), and turn it on per node from the node's page.
   * Taking it away is refused while a node still serves it.
   *
   * Shown only for a backend with such a mode.
   *
   * Props: slug, canWrite
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Label } from '@client/components/ui/label';
  import {
    intentsQuery,
    invalidateServers,
    modeTwinAction,
    setupQuery,
  } from '@client/lib/serversApi';
  import { transportName } from '@client/lib/transportName';
  import type { ModeSetupView } from '../../../../../shared/contracts/servers';
  import ConfirmDialog from '../../edges/components/ConfirmDialog.svelte';
  import StatusDot from '../../edges/simple/StatusDot.svelte';
  import { codeOf } from '../lib/run';
  import { modeTwinWords, opTitle, opWords, serverErrorWords } from '../lib/words';
  import AddTransportDialog from './AddTransportDialog.svelte';

  let { slug, canWrite }: { slug: string; canWrite: boolean } = $props();
  const qc = useQueryClient();
  const uid = $props.id();
  const setup = setupQuery(() => slug);
  const intents = intentsQuery(() => slug);

  let busy = $state(false);
  let pick = $state<Record<string, string>>({});
  let addFor = $state<ModeSetupView | null>(null);
  let addOpen = $state(false);
  let removeFor = $state<ModeSetupView | null>(null);
  let removeOpen = $state(false);

  // Only a WebSocket mode behind a CDN takes a twin (a REALITY mode is end to end already).
  let modes = $derived(
    (setup.data?.modes ?? []).filter(
      (m) => m.shape.transport === 'ws' && m.shape.fronting === 'edge-l7' && !!m.transport,
    ),
  );
  let profile = $derived(setup.data?.profile ?? null);

  const nodesOf = (mode: string) => {
    const own = (intents.data?.intents ?? []).filter((i) => i.mode.slug === mode && !i.retirement);
    return { total: own.length, serving: own.filter((i) => i.twin?.state === 'serving').length };
  };

  /** What "Add a transport" opens with: the mode's own tag, port and path, one step on. */
  const presetFor = (m: ModeSetupView) => ({
    tag: `${m.tag}_E`.slice(0, 40),
    port: (m.transport?.port ?? 8443) + 1,
    path: `${(m.transport?.path ?? '/ws').replace(/\/$/, '')}e`,
  });

  async function act(
    m: ModeSetupView,
    body: Parameters<typeof modeTwinAction>[2],
    nothing: string,
  ) {
    if (busy) return;
    busy = true;
    try {
      const { op } = await modeTwinAction(slug, m.slug, body);
      if (!op) toast.message(nothing);
      else {
        const w = opWords(op);
        const line = `${opTitle(op)}: ${w.sentence}`;
        if (w.dot === 'green') toast.success(line);
        else if (w.dot === 'red') toast.error(line);
        else toast.message(line);
      }
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
    } finally {
      busy = false;
      invalidateServers(qc);
    }
  }
</script>

{#if modes.length > 0}
  <section aria-labelledby={`${uid}-title`} class="space-y-3">
    <h2 id={`${uid}-title`} class="text-base font-semibold">Encryption behind a CDN</h2>
    {#each modes as m (m.slug)}
      {@const w = modeTwinWords(m, nodesOf(m.slug))}
      {@const chosen = pick[m.slug] ?? m.twinCandidates[0]?.tag ?? ''}
      <div class="space-y-2 rounded-md border p-3 text-sm">
        <p class="font-medium break-all">{m.name}</p>
        <p class="flex items-start gap-2" role="status">
          <StatusDot dot={w.dot} class="mt-1.5" />
          <span class="break-all">{w.sentence}</span>
        </p>
        {#if canWrite}
          {#if m.twin && !m.twin.detaching}
            <Button
              size="sm"
              variant="ghost"
              class="text-destructive"
              disabled={busy}
              onclick={() => {
                removeFor = m;
                removeOpen = true;
              }}
            >
              Take it away
            </Button>
          {:else if m.twin}
            <Button
              size="sm"
              variant="outline"
              disabled={busy}
              onclick={() => act(m, { action: 'detach' }, 'Taken away.')}
            >
              Look again
            </Button>
          {:else if m.twinCandidates.length > 0}
            <div class="flex flex-wrap items-end gap-2">
              <div class="space-y-1">
                <Label for={`${uid}-${m.slug}`} class="text-xs">Encrypted transport</Label>
                <select
                  id={`${uid}-${m.slug}`}
                  class="bg-background rounded-md border px-2 py-1.5 text-sm"
                  value={chosen}
                  onchange={(e) => (pick = { ...pick, [m.slug]: e.currentTarget.value })}
                >
                  {#each m.twinCandidates as c (c.tag)}
                    <option value={c.tag}>
                      {transportName(c.tag)} (port {c.port}, path {c.path})
                    </option>
                  {/each}
                </select>
              </div>
              <Button
                size="sm"
                disabled={busy || !chosen}
                onclick={() =>
                  act(m, { action: 'attach', transportTag: chosen }, 'It is already the twin.')}
              >
                Make it the twin
              </Button>
            </div>
            <p class="text-muted-foreground text-xs">
              Members get nothing new yet. Each node is turned on from its own page and checked
              through its fronts first.
            </p>
          {:else if profile?.uuid}
            <Button
              size="sm"
              variant="outline"
              disabled={busy}
              onclick={() => {
                addFor = m;
                addOpen = true;
              }}
            >
              Add an encrypted transport
            </Button>
            <p class="text-muted-foreground text-xs">
              Adding a transport restarts the connections of every node on this backend once.
            </p>
          {/if}
        {/if}
      </div>
    {/each}
  </section>

  {#if profile?.uuid && addFor}
    <AddTransportDialog
      bind:open={addOpen}
      {slug}
      profileUuid={profile.uuid}
      profileName={profile.name}
      preset={presetFor(addFor)}
    />
  {/if}
  <ConfirmDialog
    bind:open={removeOpen}
    title="Take the encrypted twin away?"
    body="The mode's group goes back to its own transport. The encrypted transport stays on the backend. Refused while a node still serves the twin."
    confirmLabel="Take it away"
    danger
    {busy}
    onConfirm={async () => {
      const m = removeFor;
      removeOpen = false;
      if (m) await act(m, { action: 'detach' }, 'It has no twin.');
    }}
  />
{/if}
