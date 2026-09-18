<script lang="ts">
  /**
   * Step 6, qualification. The operator proves the edge carries a real session,
   * then marks the ACCOUNT qualified. A CDN front (L7) also needs FCP's own
   * authenticated end-to-end proof: mint the credential, then qualify the edge.
   *
   * Props: StepBodyProps
   */
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button, buttonVariants } from '@client/components/ui/button';
  import Link from '@client/components/Link.svelte';
  import {
    invalidateEdge,
    invalidateProviders,
    invalidateRelay,
    mintQualificationCredential,
    qualifyEdge,
    qualifyProvider,
  } from '@client/lib/edgesApi';
  import CodeNote from '../components/CodeNote.svelte';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import { assertEdgeOk, edgeErrorIssue, edgeErrorMessage } from '../lib/edgeErrors';
  import { edgesPaths } from '../lib/routes';
  import { shortId } from '../lib/time';
  import StepIssues from './StepIssues.svelte';
  import { factString, type StepBodyProps } from './types';

  let { step, status, relay, linkCtx }: StepBodyProps = $props();

  const qc = useQueryClient();
  const accountId = $derived(factString(step.facts, 'accountId'));
  const accountName = $derived(factString(step.facts, 'accountName'));
  const isL7 = $derived(factString(step.facts, 'layer') === 'l7');
  const edgeId = $derived(status.context.edgeId);
  const has = (code: string) => step.blockers.some((b) => b.code === code);
  const accountNeedsMark = $derived(has('account_unqualified') || has('qualification_stale'));
  const credentialMissing = $derived(has('qualification_credential_missing'));
  const frontPending = $derived(has('front_unqualified') || has('front_failed'));

  const CHECKLIST = [
    'Import the subscription of a test member whose key lives on this relay, or wire a client by hand to the edge address shown on the relay page.',
    'Open a real session through the edge and load a few pages.',
    'Leave the session idle for a few minutes, then use it again. Some providers drop idle connections.',
    'Open the edge on the relay page and pull its live view: the provider should report the origin as a healthy member.',
  ];

  let confirmOpen = $state(false);
  const mark = () =>
    qualifyProvider(accountId!, true).then((r) => {
      assertEdgeOk(r);
      invalidateProviders(qc);
      if (relay) invalidateRelay(qc, relay.slug);
      toast.success('Account marked qualified');
    });

  const mint = createMutation(() => ({
    mutationFn: () => mintQualificationCredential(relay!.id).then(assertEdgeOk),
    onSuccess: () => {
      invalidateRelay(qc, relay!.slug);
      toast.success('Qualification credential minted');
    },
  }));
  let frontResult = $state<{ ok: boolean; code: string | null } | null>(null);
  const qualify = createMutation(() => ({
    mutationFn: () => qualifyEdge(edgeId!),
    onSuccess: (r) => {
      frontResult = { ok: r.ok, code: r.code ?? null };
      invalidateEdge(qc, edgeId!);
      if (relay) invalidateRelay(qc, relay.slug);
      if (r.ok) toast.success('The front carried an authenticated session');
      else toast.error('The front did not pass');
    },
  }));
  const mintIssue = $derived(mint.error ? edgeErrorIssue(mint.error) : null);
  const qualifyIssue = $derived(qualify.error ? edgeErrorIssue(qualify.error) : null);
</script>

<div class="space-y-4">
  <StepIssues
    {step}
    ctx={{ ...linkCtx, accountId: accountId ?? linkCtx.accountId }}
    hide={['no_edge']}
  />

  {#if !edgeId}
    <p class="text-muted-foreground text-sm">
      There is no edge to qualify yet. Provision or import one first (step 5).
    </p>
  {:else}
    <section class="space-y-2">
      <h4 class="text-sm font-semibold">
        Prove that edge {shortId(edgeId)} carries traffic
      </h4>
      <ol class="list-decimal space-y-1 ps-5 text-sm">
        {#each CHECKLIST as item (item)}<li>{item}</li>{/each}
      </ol>
      {#if relay}
        <Link
          href={edgesPaths.relay(relay.slug, { tab: 'edges', edge: edgeId })}
          class={buttonVariants({ size: 'sm', variant: 'outline' })}
        >
          Open the edge
        </Link>
      {/if}
    </section>

    {#if accountId}
      <section class="space-y-2 rounded-lg border p-3">
        <h4 class="text-sm font-semibold">Account {accountName ?? ''}</h4>
        {#if accountNeedsMark}
          <p class="text-sm">
            Marking the account qualified lets ordinary provisioning, standbys and automatic
            rotation create edges from it. Do it only after the checks above passed.
          </p>
          <Button onclick={() => (confirmOpen = true)}>Mark qualified</Button>
        {:else}
          <p class="text-sm">This account is qualified for its current template.</p>
        {/if}
      </section>
    {:else}
      <p class="text-muted-foreground text-sm">
        This edge was imported by address, so no account needs to be qualified for it.
      </p>
    {/if}

    {#if isL7 && relay}
      <section class="space-y-2 rounded-lg border p-3">
        <h4 class="text-sm font-semibold">CDN front: end-to-end proof</h4>
        <p class="text-sm">
          Before a CDN front is published, FCP opens one authenticated session through it with a
          credential minted only for this purpose. The proof expires and is renewed automatically
          while the edge is published.
        </p>
        <div class="flex flex-wrap gap-2">
          <Button
            variant={credentialMissing ? 'default' : 'outline'}
            disabled={mint.isPending || (!credentialMissing && relay.qualificationCredential)}
            onclick={() => mint.mutate()}
          >
            {relay.qualificationCredential && !credentialMissing
              ? 'Credential minted'
              : mint.isPending
                ? 'Minting'
                : 'Mint credential'}
          </Button>
          <Button
            variant={frontPending && !credentialMissing ? 'default' : 'outline'}
            disabled={qualify.isPending || credentialMissing}
            onclick={() => qualify.mutate()}
          >
            {qualify.isPending ? 'Qualifying, this can take a minute' : 'Qualify now'}
          </Button>
        </div>
        {#if mintIssue}
          <CodeNote issue={mintIssue} />
        {:else if mint.error}
          <p class="text-destructive text-sm" role="alert">{edgeErrorMessage(mint.error)}</p>
        {/if}
        {#if qualifyIssue}
          <CodeNote issue={qualifyIssue} />
        {:else if qualify.error}
          <p class="text-destructive text-sm" role="alert">{edgeErrorMessage(qualify.error)}</p>
        {:else if frontResult && !frontResult.ok}
          <CodeNote
            issue={{ code: frontResult.code ?? 'front_failed', subject: `edge ${shortId(edgeId)}` }}
          />
        {:else if frontResult?.ok}
          <p class="text-sm text-emerald-700 dark:text-emerald-300">
            The front carried an authenticated session end to end.
          </p>
        {/if}
      </section>
    {/if}
  {/if}
</div>

<ConfirmDialog
  bind:open={confirmOpen}
  title={`Mark ${accountName ?? 'the account'} qualified?`}
  body="You confirm that a real session worked through an edge of this account, stayed up while idle, and that the provider reports the origin as healthy. Editing the account's credentials, settings or template clears this again."
  confirmLabel="Mark qualified"
  onConfirm={mark}
/>
