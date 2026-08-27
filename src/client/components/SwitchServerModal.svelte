<script lang="ts">
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';
  import TelemetryConsent from './TelemetryConsent.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import {
    SWITCH_SERVER_REASONS,
    type SwitchServerReason,
  } from '@shared/contracts/switchServerReasons';
  import type { TelemetryContextResponse, TelemetryPayload } from '@shared/contracts/telemetry';

  /**
   * Confirm dialog for `/api/v1/account/switch-server` - move this key to a
   * different server without changing the connection mode. The member must pick a
   * reason from a fixed list before confirming: it is what tells the operator
   * WHICH nodes people are leaving, and a closed set keeps user-authored text out
   * of the audit log. Purely presentational; the mutation lives in the page.
   */
  interface Props {
    open: boolean;
    /** Name/location of the server they're on now, when known - so the dialog can
     *  say what they are leaving rather than talking about "a server". */
    currentServer?: string | null;
    /** Registered HWID devices. Drives the re-registration caveat, which only
     *  matters to someone who HAS devices registered. */
    deviceCount?: number;
    reason: SwitchServerReason | null;
    /** From telemetryContextQuery; drives the optional consent block. */
    telemetryContext?: TelemetryContextResponse | undefined;
    onCancel: () => void;
    /** `telemetry` is the consent block's outcome (null = declined/unavailable). */
    onConfirm: (telemetry: TelemetryPayload | null) => void;
    busy: boolean;
  }

  let {
    open = $bindable(),
    currentServer = null,
    deviceCount = 0,
    reason = $bindable(),
    telemetryContext = undefined,
    onCancel,
    onConfirm,
    busy,
  }: Props = $props();

  let consent = $state<ReturnType<typeof TelemetryConsent>>();

  const REASON_LABELS: Record<SwitchServerReason, () => string> = {
    slow: () => t('switchServer.reasonSlow'),
    blocked: () => t('switchServer.reasonBlocked'),
    disconnects: () => t('switchServer.reasonDisconnects'),
    other: () => t('switchServer.reasonOther'),
  };

  function onOpenChange(next: boolean) {
    // Don't allow Escape / outside-click mid-flight: a close during the request
    // leaves the member unsure whether their key moved.
    if (!next && busy) return;
    open = next;
    if (!next) onCancel();
  }
</script>

<Dialog.Root bind:open {onOpenChange}>
  <Dialog.Content class="sm:max-w-md">
    <Dialog.Header>
      <Dialog.Title>{t('switchServer.title')}</Dialog.Title>
      <Dialog.Description>
        {currentServer
          ? t('switchServer.bodyWithServer', { server: currentServer })
          : t('switchServer.body')}
      </Dialog.Description>
    </Dialog.Header>

    <fieldset class="space-y-1" disabled={busy}>
      <legend class="mb-2 text-sm font-medium">{t('switchServer.reasonLegend')}</legend>
      {#each SWITCH_SERVER_REASONS as value (value)}
        <label
          class="flex items-center gap-3 rounded-md px-2 py-2 min-h-[44px] cursor-pointer hover:bg-accent/50"
        >
          <input
            type="radio"
            name="switch-server-reason"
            {value}
            checked={reason === value}
            onchange={() => (reason = value)}
            class="size-4 shrink-0 accent-current"
          />
          <span class="text-sm">{REASON_LABELS[value]()}</span>
        </label>
      {/each}
    </fieldset>

    <ul class="text-sm text-muted-foreground space-y-1 list-disc ps-5">
      <li>{t('switchServer.point1')}</li>
      <li>{t('switchServer.point2')}</li>
      <!-- Only shown when it can actually apply: the server may have to re-issue
           the key on another panel, which cannot carry HWID registrations over.
           Members with no registered devices never see the caveat. -->
      {#if deviceCount > 0}
        <li>{t('switchServer.point3')}</li>
      {/if}
    </ul>

    <TelemetryConsent bind:this={consent} context={telemetryContext} {busy} />

    <!-- The other tool, for the other problem: when the URL itself is the issue,
         switching servers won't help - point at "Create a new key" so members
         pick the right action instead of trying this one repeatedly. -->
    <p class="text-xs text-muted-foreground">{t('switchServer.vsNewKey')}</p>

    <Dialog.Footer>
      <Button variant="ghost" onclick={onCancel} disabled={busy}>{t('common.cancel')}</Button>
      <Button
        onclick={() => onConfirm(consent?.payload() ?? null)}
        disabled={busy || reason === null}
        variant="default"
      >
        {busy ? t('switchServer.working') : t('switchServer.confirm')}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
