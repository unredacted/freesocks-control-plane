<script lang="ts">
  /**
   * Recent changes to one panel. A change is sent once and then looked at until
   * it is seen; one whose outcome is unknown stays in the way of anything else
   * on the same item until it is seen or settled by hand (docs/servers.md).
   *
   * Props: slug (the backend server)
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Card, CardContent, CardHeader, CardTitle } from '@client/components/ui/card';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { Label } from '@client/components/ui/label';
  import { invalidateServers, observeOp, opsQuery, recoverOp } from '@client/lib/serversApi';
  import type { PanelOpView } from '../../../../../shared/contracts/servers';
  import ConfirmDialog from '../../edges/components/ConfirmDialog.svelte';
  import { codeOf } from '../lib/run';
  import { ago, opTitle, opWords, serverErrorWords, type Dot } from '../lib/words';

  let { slug }: { slug: string } = $props();
  const qc = useQueryClient();
  const ops = opsQuery(
    () => slug,
    () => true,
  );

  const DOT: Record<Dot, string> = {
    green: 'bg-emerald-500',
    amber: 'bg-amber-500',
    red: 'bg-destructive',
    grey: 'bg-muted-foreground/50',
  };

  let looking = $state<string | null>(null);
  let settling = $state<PanelOpView | null>(null);
  let settleOpen = $state(false);
  let revoked = $state(false);
  let noWorker = $state(false);
  let drained = $state(false);

  async function look(op: PanelOpView) {
    looking = op.id;
    try {
      const next = await observeOp(slug, op.id);
      toast.message(`${opTitle(next)}: ${opWords(next).sentence}`);
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
    } finally {
      looking = null;
      invalidateServers(qc);
    }
  }

  function startSettle(op: PanelOpView) {
    settling = op;
    revoked = noWorker = drained = false;
    settleOpen = true;
  }

  async function settle() {
    if (!settling) return;
    try {
      await recoverOp(slug, settling.id, {
        credentialsRevoked: revoked,
        noInFlightExecutor: noWorker,
        queueDrained: drained,
      });
    } catch (e) {
      // The dialog stays open on a rejection; the words go in a toast.
      toast.error(serverErrorWords(codeOf(e)));
      throw e;
    } finally {
      invalidateServers(qc);
    }
  }
</script>

<Card class="mt-6">
  <CardHeader>
    <CardTitle class="text-base">Recent changes</CardTitle>
  </CardHeader>
  <CardContent class="text-sm">
    {#if ops.isPending}
      <p class="text-muted-foreground">Loading…</p>
    {:else if (ops.data?.ops.length ?? 0) === 0}
      <p class="text-muted-foreground">Nothing has been changed from here yet.</p>
    {:else}
      <ul class="divide-y" aria-live="polite">
        {#each ops.data?.ops ?? [] as op (op.id)}
          {@const w = opWords(op)}
          <li class="flex flex-wrap items-start gap-3 py-2">
            <span
              class={`mt-1.5 inline-block size-2.5 shrink-0 rounded-full ${DOT[w.dot]}`}
              aria-hidden="true"
            ></span>
            <span class="min-w-0 flex-1">
              <span class="block font-medium break-all">{opTitle(op)}</span>
              <span class="text-muted-foreground block">{w.sentence}</span>
            </span>
            <span class="text-muted-foreground">{ago(Date.now() - Date.parse(op.createdAt))}</span>
            {#if op.open}
              <span class="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={looking === op.id}
                  onclick={() => look(op)}
                >
                  Look again
                </Button>
                {#if op.state === 'outcome_unknown'}
                  <Button variant="outline" size="sm" onclick={() => startSettle(op)}>
                    Settle by hand
                  </Button>
                {/if}
              </span>
            {/if}
          </li>
        {/each}
      </ul>
    {/if}
  </CardContent>
</Card>

<ConfirmDialog
  bind:open={settleOpen}
  title="Settle this change by hand"
  body="Only do this when the change can no longer happen late. A change that lands after being settled can overwrite whatever you do next."
  confirmLabel="Settle"
  danger
  onConfirm={settle}
>
  <p class="mb-3 font-medium break-all">{settling ? opTitle(settling) : ''}</p>
  <div class="space-y-3">
    <div class="flex items-start gap-2">
      <Checkbox id="settle-revoked" bind:checked={revoked} />
      <Label for="settle-revoked" class="leading-snug font-normal">
        The API token this was sent with has been revoked on the panel, and I checked that the panel
        now rejects it.
      </Label>
    </div>
    <div class="flex items-start gap-2">
      <Checkbox id="settle-worker" bind:checked={noWorker} />
      <Label for="settle-worker" class="leading-snug font-normal">
        Nothing is still carrying this request: no proxy, no gateway, no panel worker.
      </Label>
    </div>
    <div class="flex items-start gap-2">
      <Checkbox id="settle-queue" bind:checked={drained} />
      <Label for="settle-queue" class="leading-snug font-normal">
        I looked at the panel's job queues, and every job from this change has finished or been
        cancelled. Restarting the panel does not count: its queues survive a restart.
      </Label>
    </div>
  </div>
  <p class="text-muted-foreground mt-3">
    The panel is read again as part of settling, and what it shows becomes the recorded outcome.
  </p>
</ConfirmDialog>
