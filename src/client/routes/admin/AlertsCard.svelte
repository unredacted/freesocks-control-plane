<script lang="ts">
  /**
   * Operator alerts (Settings): an opt-in webhook that receives new
   * alert-worthy edge attention items once, as ntfy-compatible JSON. The
   * server never sends the stored topic or token back (only whether each is
   * set) and shows only the webhook's origin, so the fields start empty: a
   * blank field keeps what is stored, "Clear" removes it.
   */
  import {
    Card,
    CardHeader,
    CardTitle,
    CardDescription,
    CardContent,
  } from '@client/components/ui/card';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { apiClient } from '../../lib/api';
  import { apiErrorMessage } from '../../lib/errors';
  import { adminAlertsQuery, queryKeys } from '../../lib/queries';
  import {
    AdminAlertsConfig,
    AdminAlertsTestResult,
    type AdminAlertsPatch,
  } from '../../../shared/contracts/admin';

  const qc = useQueryClient();
  const alerts = adminAlertsQuery();
  const view = $derived(alerts.data ?? null);

  let enabled = $state(false);
  let url = $state('');
  let topic = $state('');
  let token = $state('');
  let init = $state(false);
  $effect(() => {
    if (view && !init) {
      enabled = view.enabled;
      init = true;
    }
  });

  const save = createMutation(() => ({
    mutationFn: (patch: AdminAlertsPatch) =>
      apiClient.patch('/api/v1/admin/alerts', patch, AdminAlertsConfig),
    onSuccess: (updated) => {
      enabled = updated.enabled;
      url = '';
      topic = '';
      token = '';
      void qc.invalidateQueries({ queryKey: queryKeys.adminAlerts });
      toast.success('Alert settings saved');
    },
    onError: (err) => {
      toast.error('Could not save alert settings', { description: apiErrorMessage(err) });
    },
  }));

  const test = createMutation(() => ({
    mutationFn: () => apiClient.post('/api/v1/admin/alerts/test', {}, AdminAlertsTestResult),
    onSuccess: (r) => {
      if (r.ok) toast.success('Test alert sent');
      else toast.error('The test alert was not delivered', { description: errorWords(r.error) });
    },
    onError: (err) => {
      toast.error('Could not send a test alert', { description: apiErrorMessage(err) });
    },
  }));

  function submit() {
    const patch: AdminAlertsPatch = { enabled };
    if (url.trim()) patch.url = url.trim();
    if (topic.trim()) patch.topic = topic.trim();
    if (token.trim()) patch.token = token.trim();
    save.mutate(patch);
  }

  function errorWords(code: string | null): string {
    if (!code) return 'No answer from the webhook.';
    if (code === 'no_url') return 'Save a webhook URL first.';
    if (code === 'timeout') return 'The webhook did not answer in time.';
    if (code === 'network') return 'The webhook could not be reached.';
    return `The webhook answered ${code}.`;
  }

  const when = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : 'never');
</script>

<Card>
  <CardHeader>
    <CardTitle class="text-base">Operator alerts</CardTitle>
    <CardDescription>
      FCP posts each new edge problem you have to act on (a node paused for safety, members getting
      nothing, a provider that stopped answering, a node waiting to be protected or approved, an
      address that looks blocked while automatic replacement is held back) once, to a webhook that
      takes ntfy JSON. Alerts carry kinds and counts only: never a member, an address, a node name,
      a provider or a region. Off by default.
    </CardDescription>
  </CardHeader>
  <CardContent class="space-y-3 text-sm">
    <label class="flex items-center gap-3">
      <Checkbox checked={enabled} onCheckedChange={(v) => (enabled = v === true)} />
      <span>Send alerts</span>
    </label>
    <div class="grid gap-3 sm:grid-cols-3">
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="alerts-url">
          Webhook URL (https)
        </label>
        <Input
          id="alerts-url"
          placeholder={view?.urlSet ? `Stored: ${view.urlOrigin}` : 'https://ntfy.example.org'}
          bind:value={url}
        />
      </div>
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="alerts-topic">
          Topic (ntfy)
        </label>
        <Input
          id="alerts-topic"
          placeholder={view?.topicSet ? 'Stored (hidden)' : 'Optional'}
          bind:value={topic}
          autocomplete="off"
        />
      </div>
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="alerts-token">
          Access token
        </label>
        <Input
          id="alerts-token"
          type="password"
          placeholder={view?.tokenSet ? 'Stored (hidden)' : 'Optional'}
          bind:value={token}
          autocomplete="off"
        />
      </div>
    </div>
    <p class="text-xs text-muted-foreground">
      A blank field keeps what is stored. The topic and the token are never shown again once saved.
      To poll instead, read the attention list with a read-only token (see docs/edges.md).
    </p>
    {#if view}
      <p class="text-xs text-muted-foreground">
        Last sent: {when(view.lastSentAt)}.
        {#if view.lastError}
          Last attempt failed: {errorWords(view.lastError)}
        {/if}
        {view.openAlerts > 0 ? `${view.openAlerts} sent alerts are still open.` : ''}
      </p>
    {/if}
    <div class="flex flex-wrap justify-end gap-2">
      {#if view?.topicSet || view?.tokenSet}
        <Button
          variant="outline"
          onclick={() => save.mutate({ topic: '', token: '' })}
          disabled={save.isPending}
        >
          Clear topic and token
        </Button>
      {/if}
      <Button
        variant="outline"
        onclick={() => test.mutate()}
        disabled={test.isPending || !view?.urlSet}
      >
        {test.isPending ? 'Sending…' : 'Send a test alert'}
      </Button>
      <Button onclick={submit} disabled={save.isPending || !init}>
        {save.isPending ? 'Saving…' : 'Save alert settings'}
      </Button>
    </div>
  </CardContent>
</Card>
