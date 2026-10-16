<script lang="ts">
  /**
   * The first edge of an origin that is not a backend node (a manual address,
   * a whole Outline server): what replaced the step-by-step wizard for them.
   * Shown on Origin details while the origin has no edge. Two ways in:
   * provision one (ProvisionDialog: a named, tested account is allowed even
   * before it is trusted, and the edge waits unpublished until it is tried), or
   * import a front that already forwards here (ImportFrontDialog). A backend
   * node is protected with Autopilot (Protect a node), never from here.
   *
   * Props: relay; listeners; accounts; onStarted(rotationId); onImported(edgeId)
   */
  import type {
    EdgeProviderAccountAdmin,
    OriginAdmin,
    RelayListenerAdmin,
  } from '@shared/contracts/edges';
  import * as Card from '@client/components/ui/card';
  import { Button } from '@client/components/ui/button';
  import Link from '@client/components/Link.svelte';
  import { edgesPaths } from '../lib/routes';
  import ImportFrontDialog from './ImportFrontDialog.svelte';
  import ProvisionDialog from './ProvisionDialog.svelte';

  interface Props {
    relay: OriginAdmin;
    listeners: RelayListenerAdmin[];
    accounts: EdgeProviderAccountAdmin[];
    onStarted: (rotationId: string) => void;
    onImported: (edgeId: string) => void;
  }
  let { relay, listeners, accounts, onStarted, onImported }: Props = $props();

  let provisionOpen = $state(false);
  let importOpen = $state(false);
  const usable = $derived(listeners.filter((l) => !l.retired && l.enabled && l.deployed));
  const tested = $derived(accounts.filter((a) => a.enabled && a.lastTestOkAt !== null));
</script>

<Card.Root>
  <Card.Header>
    <Card.Title>Give it its first edge</Card.Title>
    <Card.Description>
      Members of this origin are only ever given an edge's address. Provision one at a provider (any
      tested account; it waits unpublished so you can try it first, then publish it from the Edges
      tab), or import a front that already forwards here.
    </Card.Description>
  </Card.Header>
  <Card.Content class="space-y-3">
    {#if usable.length === 0}
      <p class="text-muted-foreground text-sm">
        It has no deployed, enabled listener yet: add one on the Listeners tab first.
      </p>
    {/if}
    {#if tested.length === 0}
      <p class="text-muted-foreground text-sm">
        No provider account has passed a credential test yet:
        <Link href={edgesPaths.providers()} class="text-primary underline underline-offset-4"
          >add or test one</Link
        >.
      </p>
    {/if}
    <div class="flex flex-wrap gap-2">
      <Button
        class="min-h-11 sm:min-h-9"
        disabled={relay.deleting || usable.length === 0}
        onclick={() => (provisionOpen = true)}
      >
        Provision the first edge
      </Button>
      <Button
        variant="outline"
        class="min-h-11 sm:min-h-9"
        disabled={relay.deleting || usable.length === 0}
        onclick={() => (importOpen = true)}
      >
        Import an existing front
      </Button>
    </div>
  </Card.Content>
</Card.Root>

<ProvisionDialog
  bind:open={provisionOpen}
  {relay}
  {listeners}
  accountId={tested.length === 1 ? tested[0]!.id : null}
  {onStarted}
/>
<ImportFrontDialog bind:open={importOpen} {relay} {listeners} {accounts} {onImported} />
