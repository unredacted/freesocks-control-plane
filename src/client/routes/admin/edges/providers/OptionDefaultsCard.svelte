<script lang="ts">
  /**
   * An account's defaults for its provider's CERTIFICATE options (who issues
   * the certificate, one wildcard or one per front). They prefill a node's
   * options when it is protected; a node keeps what it was protected with, and
   * an edge keeps what it was built with. Tuning options live in templates.
   *
   * Props:
   *   account: EdgeProviderAccountAdmin
   *   fields: EdgeTemplateField[]          the provider's certificate options (`optionSchemas`)
   */
  import { untrack, type Snippet } from 'svelte';
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
  } from '@client/components/ui/card';
  import type {
    EdgeProviderAccountAdmin,
    EdgeTemplateField,
  } from '../../../../../shared/contracts/edges';
  import { invalidateProviders, updateProvider } from '../../../../lib/edgesApi';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { optionSummary } from '../lib/options';
  import OptionFields from '../templates/OptionFields.svelte';
  import { asParams, deepEqual, setPath, type Params } from '../templates/params';

  interface Props {
    account: EdgeProviderAccountAdmin;
    fields: EdgeTemplateField[];
    /** Extra content under the fields (the shared certificate's state). */
    children?: Snippet;
  }
  let { account, fields, children }: Props = $props();

  const qc = useQueryClient();
  const declared = $derived.by(() => {
    let out: Params = {};
    for (const f of fields) if (f.default !== undefined) out = setPath(out, f.key, f.default);
    return out;
  });
  const seed = untrack(() => asParams(account.optionDefaults));
  let values = $state<Params>(seed);
  const dirty = $derived(!deepEqual(values, seed));
  let confirmOpen = $state(false);
  let saving = $state(false);
  const changes = $derived(optionSummary(fields, values));

  async function save() {
    saving = true;
    try {
      await updateProvider(account.id, { optionDefaults: $state.snapshot(values) });
      invalidateProviders(qc);
      toast.success('Defaults saved');
    } catch (err) {
      toast.error(edgeErrorMessage(err));
    } finally {
      saving = false;
    }
  }
</script>

<Card>
  <CardHeader>
    <CardTitle class="text-base">Certificates</CardTitle>
    <CardDescription>
      What a node protected from this account gets by default. Each node can choose its own when it
      is protected; nodes already protected keep theirs.
    </CardDescription>
  </CardHeader>
  <CardContent class="space-y-4">
    <OptionFields {fields} {values} base={declared} onchange={(next) => (values = next)} />
    {#if changes.length > 0 && !dirty}
      <p class="text-xs text-muted-foreground">Now: {changes.join(', ')}.</p>
    {/if}
    <div class="flex gap-2">
      <Button disabled={!dirty || saving} onclick={() => (confirmOpen = true)}>Save defaults</Button
      >
      {#if dirty}
        <Button variant="ghost" disabled={saving} onclick={() => (values = seed)}>Undo</Button>
      {/if}
    </div>
    {@render children?.()}
  </CardContent>
</Card>

<ConfirmDialog
  bind:open={confirmOpen}
  title="Change this account's certificate defaults?"
  body="Nodes protected from now on start from these; nodes and fronts that exist keep theirs. Like a settings change, the account loses its trust: test it again, and its next proven front trusts it."
  confirmLabel="Save defaults"
  onConfirm={save}
/>
