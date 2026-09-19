<script lang="ts">
  /**
   * Whether panels may be changed from here at all, and whether this panel's
   * node role has handed it over. Both must hold before a change is accepted;
   * the server enforces it, this card explains it.
   *
   * Props: slug, manageOn, handoffCurrent
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Button } from '@client/components/ui/button';
  import { Card, CardContent, CardHeader, CardTitle } from '@client/components/ui/card';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { Label } from '@client/components/ui/label';
  import { Switch } from '@client/components/ui/switch';
  import {
    invalidateServers,
    patchServerConfig,
    recoverReservation,
    refreshServer,
    reservationsQuery,
  } from '@client/lib/serversApi';
  import type { ReservationList } from '../../../../../shared/contracts/servers';
  import ConfirmDialog from '../../edges/components/ConfirmDialog.svelte';
  import { codeOf } from '../lib/run';
  import { ago, serverErrorWords } from '../lib/words';

  interface Props {
    slug: string;
    manageOn: boolean;
    handoffCurrent: boolean;
  }
  let { slug, manageOn, handoffCurrent }: Props = $props();
  const qc = useQueryClient();
  const reservations = reservationsQuery(
    () => slug,
    () => manageOn,
  );
  let saving = $state(false);

  // Releasing a reservation whose run never answered: the same three attested
  // conditions as a change with an unknown outcome, after a FRESH read of the
  // panel (an object that did show up is adopted by that read, and the
  // reservation then clears by itself instead).
  type Reservation = ReservationList['reservations'][number];
  let releasing = $state<Reservation | null>(null);
  let releaseOpen = $state(false);
  let revoked = $state(false);
  let noWorker = $state(false);
  let drained = $state(false);

  function startRelease(r: Reservation) {
    releasing = r;
    revoked = noWorker = drained = false;
    releaseOpen = true;
  }

  async function release() {
    if (!releasing) return;
    const r = releasing;
    try {
      // The fresh read comes first and is part of the attestation; a panel that
      // cannot be read right now cannot have this released.
      await refreshServer(slug);
      await recoverReservation(slug, r.roleOpId, {
        credentialsRevoked: revoked,
        noInFlightExecutor: noWorker,
        queueDrained: drained,
        freshReadAt: Date.now(),
      });
      toast.success(`Released the reservation of ${r.kind} ${r.label}.`);
    } catch (e) {
      // `not_found` here means the fresh read adopted it: it is settled either way.
      toast.error(serverErrorWords(codeOf(e)));
      throw e;
    } finally {
      invalidateServers(qc);
    }
  }

  async function setManage(on: boolean) {
    saving = true;
    try {
      await patchServerConfig({ 'manage.enabled': on });
      toast.success(on ? 'Panels can now be changed from here.' : 'Changing panels is off.');
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
    } finally {
      saving = false;
      invalidateServers(qc);
    }
  }
</script>

<Card class="mt-6">
  <CardHeader>
    <CardTitle class="text-base">Changing panels from here</CardTitle>
  </CardHeader>
  <CardContent class="space-y-3 text-sm">
    <div class="flex items-start gap-3">
      <Switch
        id="servers-manage"
        class="mt-0.5"
        disabled={saving}
        aria-describedby="servers-manage-help"
        bind:checked={() => manageOn, (v) => void setManage(v)}
      />
      <div>
        <label for="servers-manage" class="font-medium">Allow changes</label>
        <p id="servers-manage-help" class="text-muted-foreground">
          Off, this page only shows what is there. On, each change is sent to the panel once and
          then watched until it is seen there.
        </p>
      </div>
    </div>

    {#if manageOn && !handoffCurrent}
      <p class="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2">
        The node role has not handed this panel over yet, so changes are refused. Run the role with
        fcp_managed set. Until then both would be writing the same things.
      </p>
    {/if}

    {#if (reservations.data?.reservations.length ?? 0) > 0}
      <div>
        <h3 class="font-medium">Reserved by the node role</h3>
        <p class="text-muted-foreground">
          A role run said it is about to create these and has not said how that ended. Each clears
          by itself once it shows up on the panel. One that never shows up, and whose run is known
          to be gone, is released by hand under the same conditions as a change with an unknown
          outcome.
        </p>
        <ul class="mt-1 space-y-1">
          {#each reservations.data?.reservations ?? [] as r (r.roleOpId)}
            <li class="flex flex-wrap items-center gap-3">
              <span class="min-w-0 flex-1 break-all">
                {r.kind}
                {r.label}
                <span class="text-muted-foreground">· {ago(Date.now() - r.at)}</span>
              </span>
              <Button variant="outline" size="sm" onclick={() => startRelease(r)}>
                Release by hand
              </Button>
            </li>
          {/each}
        </ul>
      </div>
    {/if}
  </CardContent>
</Card>

<ConfirmDialog
  bind:open={releaseOpen}
  title="Release this reservation by hand"
  body="Only do this when the role run that reserved it can no longer create it late. A create that lands after the release would be a second copy of whatever is made next under this name."
  confirmLabel="Release"
  danger
  onConfirm={release}
>
  <p class="mb-3 font-medium break-all">
    {releasing ? `${releasing.kind} ${releasing.label}` : ''}
  </p>
  <div class="space-y-3">
    <div class="flex items-start gap-2">
      <Checkbox id="release-revoked" bind:checked={revoked} />
      <Label for="release-revoked" class="leading-snug font-normal">
        The token that run used has been revoked, and I checked that the panel now rejects it.
      </Label>
    </div>
    <div class="flex items-start gap-2">
      <Checkbox id="release-worker" bind:checked={noWorker} />
      <Label for="release-worker" class="leading-snug font-normal">
        Nothing is still carrying that run's request: no proxy, no gateway, no role process.
      </Label>
    </div>
    <div class="flex items-start gap-2">
      <Checkbox id="release-queue" bind:checked={drained} />
      <Label for="release-queue" class="leading-snug font-normal">
        I looked at the panel's job queues, and nothing from that run is still waiting.
      </Label>
    </div>
  </div>
  <p class="text-muted-foreground mt-3">
    The panel is read again first. If the object shows up in that read, it is adopted and the
    reservation clears by itself; nothing is released.
  </p>
</ConfirmDialog>
