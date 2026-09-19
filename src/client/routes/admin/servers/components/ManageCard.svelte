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
  import { Card, CardContent, CardHeader, CardTitle } from '@client/components/ui/card';
  import { Switch } from '@client/components/ui/switch';
  import { invalidateServers, patchServerConfig, reservationsQuery } from '@client/lib/serversApi';
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
          by itself once it shows up on the panel.
        </p>
        <ul class="mt-1">
          {#each reservations.data?.reservations ?? [] as r (r.roleOpId)}
            <li class="break-all">
              {r.kind}
              {r.label}
              <span class="text-muted-foreground">· {ago(Date.now() - r.at)}</span>
            </li>
          {/each}
        </ul>
      </div>
    {/if}
  </CardContent>
</Card>
