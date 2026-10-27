<script lang="ts">
  /**
   * "Send to the node" (docs/edges.md "Rollout and acceptance"): what the next
   * write puts on the backend, read first (the plan), then the write through
   * the operations ledger. Every node on the profile restarts Xray once; no
   * member gets a new name until a test on a node proves it accepts them.
   *
   * Props: open (bindable), transport (managed: it has a name list).
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { ApiCallError } from '@client/lib/api';
  import { invalidateSni, planRollout, startRollout } from '@client/lib/sniApi';
  import type { SniRolloutPlan, SniTransport } from '../../../../../shared/contracts/sni';
  import { DIALOG_FIT, STICKY_FOOTER } from '../lib/dialogLayout';
  import { sendPlanWords } from './lib/transportWords';
  import { sniErrorWords } from './lib/words';

  let { open = $bindable(false), transport }: { open: boolean; transport: SniTransport } = $props();
  const qc = useQueryClient();
  const codeOf = (e: unknown) => (e instanceof ApiCallError ? e.payload.error.code : null);

  let plan = $state<SniRolloutPlan | null>(null);
  let planError = $state<string | null>(null);
  let busy = $state(false);
  $effect(() => {
    if (!open || !transport.list) return;
    plan = null;
    planError = null;
    planRollout(transport.list.bindingId)
      .then((p) => (plan = p))
      .catch((e) => (planError = sniErrorWords(codeOf(e))));
  });

  async function send() {
    if (!transport.list) return;
    busy = true;
    try {
      const r = await startRollout(transport.list.bindingId);
      open = false;
      toast.success(
        r.rolloutId
          ? 'Sent. Once the backend has the names, test one on the node.'
          : 'The backend already had exactly these names.',
      );
    } catch (e) {
      toast.error(sniErrorWords(codeOf(e)));
    } finally {
      busy = false;
      invalidateSni(qc);
    }
  }
</script>

<Dialog.Root bind:open>
  <Dialog.Content class={`${DIALOG_FIT} sm:max-w-lg`}>
    <Dialog.Header>
      <Dialog.Title>Send to the node</Dialog.Title>
      <Dialog.Description>{transport.tag} on the profile {transport.profileName}</Dialog.Description
      >
    </Dialog.Header>
    <div class="space-y-3 text-sm" aria-live="polite">
      {#if planError}
        <p class="text-destructive">{planError}</p>
      {:else if !plan}
        <Skeleton class="h-16 w-full" />
      {:else}
        {#each sendPlanWords(plan, transport) as line (line)}
          <p>{line}</p>
        {/each}
        {#if plan.added.length + plan.removed.length > 0}
          <details>
            <summary class="text-muted-foreground cursor-pointer">The names</summary>
            {#each plan.added as n (n)}
              <p class="break-all text-emerald-700 dark:text-emerald-400">+ {n}</p>
            {/each}
            {#each plan.removed as n (n)}
              <p class="text-destructive break-all">- {n}</p>
            {/each}
          </details>
        {/if}
      {/if}
    </div>
    <Dialog.Footer class={STICKY_FOOTER}>
      <Button variant="outline" onclick={() => (open = false)}>Cancel</Button>
      <Button disabled={busy || !plan?.changed} onclick={send}>
        {busy ? 'Sending…' : 'Send to the node'}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
