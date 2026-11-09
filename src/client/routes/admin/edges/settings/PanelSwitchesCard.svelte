<script lang="ts">
  /**
   * The two backend panel switches (`servers.manage.observe` and
   * `servers.manage.enabled`, docs/servers.md "Switches"): global, both off by
   * default. The same calls as the Nodes page footer: `PATCH config`, then the
   * Servers and SNI caches are read again (a send to a backend is held back
   * by the second switch, so the SNI pages say so at once).
   *
   * Props:
   *   readId?: string      element id of the first switch's row (`?field=` scrolls to it)
   *   changesId?: string   element id of the second switch's row
   *   showRead?: boolean   default true (a search can hide one switch)
   *   showChanges?: boolean
   *   rowClass?: (id: 'manage.observe' | 'manage.enabled') => string
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { Switch } from '@client/components/ui/switch';
  import { Label } from '@client/components/ui/label';
  import { invalidateServers, patchServerConfig, serverSummaryQuery } from '@client/lib/serversApi';
  import { invalidateSni } from '@client/lib/sniApi';
  import AdminListState from '../../AdminListState.svelte';
  import { codeOf } from '../../servers/lib/run';
  import { serverErrorWords } from '../../servers/lib/words';

  type Key = 'manage.observe' | 'manage.enabled';
  interface Props {
    readId?: string;
    changesId?: string;
    showRead?: boolean;
    showChanges?: boolean;
    rowClass?: (id: Key) => string;
  }
  let {
    readId,
    changesId,
    showRead = true,
    showChanges = true,
    rowClass = () => '',
  }: Props = $props();

  const qc = useQueryClient();
  const summary = serverSummaryQuery();
  const uid = $props.id();
  let saving = $state(false);

  const observable = $derived((summary.data?.instances ?? []).some((i) => i.observable));
  const writable = $derived((summary.data?.instances ?? []).some((i) => i.writable));

  async function setConfig(key: Key, on: boolean) {
    saving = true;
    try {
      await patchServerConfig({ [key]: on });
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
    } finally {
      saving = false;
      invalidateServers(qc);
      invalidateSni(qc);
    }
  }
</script>

<section
  id="settings-panels"
  class="bg-card ring-foreground/15 scroll-mt-20 rounded-xl ring-1"
  aria-labelledby={`${uid}-title`}
>
  <header class="px-4 py-3">
    <h2 id={`${uid}-title`} class="font-medium">Backend panels</h2>
    <p class="text-muted-foreground mt-0.5 text-sm">
      Whether FCP reads the backend panels, and whether it may change them. They apply to every
      backend.
    </p>
  </header>
  <div class="space-y-5 border-t px-4 py-4">
    {#if summary.isPending}
      <Skeleton class="h-16" />
    {:else if summary.isError}
      <AdminListState error={summary.error} onRetry={() => summary.refetch()} />
    {:else if summary.data}
      {@const config = summary.data.config}
      {#if showRead}
        <div id={readId} class={rowClass('manage.observe')}>
          <div class="flex items-start gap-3">
            <Switch
              id={`${uid}-observe`}
              class="mt-0.5"
              checked={config['manage.observe']}
              disabled={saving}
              aria-describedby={`${uid}-observe-help`}
              onCheckedChange={(v) => void setConfig('manage.observe', v)}
            />
            <div class="min-w-0 flex-1">
              <Label for={`${uid}-observe`}>Read panels every ten minutes</Label>
              <p id={`${uid}-observe-help`} class="text-muted-foreground mt-1 text-xs">
                On: each backend panel is read with the health check, so node status stays current.
                Off: FCP makes no extra call to the panels.
                {#if !observable}No backend here can be read yet.{/if}
              </p>
            </div>
          </div>
        </div>
      {/if}
      {#if showChanges}
        <div id={changesId} class={rowClass('manage.enabled')}>
          <div class="flex items-start gap-3">
            <Switch
              id={`${uid}-manage`}
              class="mt-0.5"
              checked={config['manage.enabled']}
              disabled={saving}
              aria-describedby={`${uid}-manage-help`}
              onCheckedChange={(v) => void setConfig('manage.enabled', v)}
            />
            <div class="min-w-0 flex-1">
              <Label for={`${uid}-manage`}>Changes from here</Label>
              <p id={`${uid}-manage-help`} class="text-muted-foreground mt-1 text-xs">
                On: FCP may change nodes, Hosts and mode groups on the backend panels. Off: every
                change from here is refused, and Servers only shows them.
                {#if !writable}No backend here can be changed yet.{/if}
              </p>
            </div>
          </div>
        </div>
      {/if}
    {/if}
  </div>
</section>
