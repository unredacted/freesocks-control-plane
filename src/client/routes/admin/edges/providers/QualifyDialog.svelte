<script lang="ts">
  /**
   * Mark an account qualified, or remove its qualification, with the checklist
   * in words. Qualification is the operator's statement that edges from this
   * account carry real sessions; FCP cannot verify it on its own.
   *
   * Props:
   *   open: boolean (bindable)
   *   account: { id, name, qualified } | null
   *   tested: boolean                    the last credential test passed
   *   onQualify(id, qualified): Promise  (useAccountActions().qualify)
   */
  import ConfirmDialog from '../components/ConfirmDialog.svelte';

  interface Props {
    open: boolean;
    account: { id: string; name: string; qualified: boolean } | null;
    tested: boolean;
    onQualify: (id: string, qualified: boolean) => Promise<void>;
  }
  let { open = $bindable(false), account, tested, onQualify }: Props = $props();

  const removing = $derived(account?.qualified === true);
  const CHECKLIST = [
    'The credential test passed with the credentials stored now.',
    'A test edge was provisioned in this account and became healthy.',
    'A real client session through that edge connected and survived sitting idle.',
    'The live view of the edge shows the listeners, origin and addresses you expect.',
  ];
</script>

<ConfirmDialog
  bind:open
  title={removing
    ? `Remove the qualification of "${account?.name ?? ''}"?`
    : `Mark "${account?.name ?? ''}" qualified?`}
  body={removing
    ? 'Ordinary provisioning and rotation will skip this account until it is qualified again. Edges that already exist stay as they are.'
    : 'Qualified accounts are used automatically when FCP provisions, rotates or replaces an edge. Confirm each point before you continue:'}
  confirmLabel={removing ? 'Remove qualification' : 'Mark qualified'}
  danger={removing}
  onConfirm={() => (account ? onQualify(account.id, !account.qualified) : undefined)}
>
  {#if !removing}
    <ul class="list-disc space-y-1 ps-5">
      {#each CHECKLIST as item (item)}<li>{item}</li>{/each}
    </ul>
    {#if !tested}
      <p class="mt-2 text-amber-700 dark:text-amber-300">
        The credentials of this account have not passed a test yet. Run Test credentials first.
      </p>
    {/if}
    <p class="mt-2 text-muted-foreground">
      Changing the credentials, the settings or the effective template clears the qualification.
      Rotating credentials keeps it.
    </p>
  {/if}
</ConfirmDialog>
