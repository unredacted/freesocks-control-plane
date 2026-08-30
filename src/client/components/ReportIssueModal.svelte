<script lang="ts">
  import { Button } from '@client/components/ui/button';
  import * as Dialog from '@client/components/ui/dialog';
  import TelemetryConsent from './TelemetryConsent.svelte';
  import { t } from '../lib/i18n/index.svelte';
  import { REPORT_ISSUE_REASONS, type ReportIssueReason } from '@shared/contracts/issueReasons';
  import type { TelemetryContextResponse, TelemetryPayload } from '@shared/contracts/telemetry';

  /**
   * "Report issue": tell the operator what is going wrong, without touching the
   * key. The member must pick a reason from a fixed list (audited scalars only;
   * also the aggregation buckets on Admin → Telemetry); picking "something
   * else" opens a free-text box (stored only on the unlinked telemetry row);
   * the optional consent block attaches editable network context. Purely
   * presentational; the mutation lives in the page.
   */
  interface Props {
    open: boolean;
    reason: ReportIssueReason | null;
    telemetryContext: TelemetryContextResponse | undefined;
    onCancel: () => void;
    onConfirm: (telemetry: TelemetryPayload | null, detail: string | null) => void;
    busy: boolean;
  }

  let {
    open = $bindable(),
    reason = $bindable(),
    telemetryContext,
    onCancel,
    onConfirm,
    busy,
  }: Props = $props();

  let consent = $state<ReturnType<typeof TelemetryConsent>>();
  // Free text for "something else" — server caps at 500 too (sanitizeDetail).
  const DETAIL_MAX = 500;
  let detail = $state('');

  const REASON_LABELS: Record<ReportIssueReason, () => string> = {
    'cant-connect': () => t('report.reasonCantConnect'),
    slow: () => t('report.reasonSlow'),
    disconnects: () => t('report.reasonDisconnects'),
    'blocked-site': () => t('report.reasonBlockedSite'),
    'app-problem': () => t('report.reasonAppProblem'),
    other: () => t('report.reasonOther'),
  };

  function onOpenChange(next: boolean) {
    if (!next && busy) return;
    open = next;
    if (!next) {
      detail = '';
      onCancel();
    }
  }
</script>

<Dialog.Root bind:open {onOpenChange}>
  <Dialog.Content class="sm:max-w-md">
    <Dialog.Header>
      <Dialog.Title>{t('report.title')}</Dialog.Title>
      <Dialog.Description>{t('report.body')}</Dialog.Description>
    </Dialog.Header>

    <fieldset class="space-y-1" disabled={busy}>
      <legend class="mb-2 text-sm font-medium">{t('report.reasonLegend')}</legend>
      {#each REPORT_ISSUE_REASONS as value (value)}
        <label
          class="flex items-center gap-3 rounded-md px-2 py-2 min-h-[44px] cursor-pointer hover:bg-accent/50"
        >
          <input
            type="radio"
            name="report-issue-reason"
            {value}
            checked={reason === value}
            onchange={() => (reason = value)}
            class="size-4 shrink-0 accent-current"
          />
          <span class="text-sm">{REASON_LABELS[value]()}</span>
        </label>
      {/each}
    </fieldset>

    {#if reason === 'other'}
      <div class="space-y-1.5">
        <label for="report-issue-detail" class="text-sm font-medium">
          {t('report.detailLabel')}
        </label>
        <textarea
          id="report-issue-detail"
          bind:value={detail}
          rows="3"
          maxlength={DETAIL_MAX}
          disabled={busy}
          placeholder={t('report.detailPlaceholder')}
          class="w-full resize-y rounded-md border border-input bg-background px-3 py-2 text-sm disabled:cursor-not-allowed disabled:opacity-50"
        ></textarea>
        <p class="text-xs text-muted-foreground">{t('report.detailHint')}</p>
      </div>
    {/if}

    <TelemetryConsent bind:this={consent} context={telemetryContext} {busy} />

    <p class="text-xs text-muted-foreground">{t('report.nothingChanges')}</p>

    <Dialog.Footer>
      <Button variant="ghost" onclick={onCancel} disabled={busy}>{t('common.cancel')}</Button>
      <Button
        onclick={() =>
          onConfirm(consent?.payload() ?? null, reason === 'other' ? detail.trim() || null : null)}
        disabled={busy || reason === null}
      >
        {busy ? t('report.working') : t('report.confirm')}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
