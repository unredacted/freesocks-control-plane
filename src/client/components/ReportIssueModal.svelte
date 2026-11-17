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
   * also the aggregation buckets on Admin → Telemetry). There is deliberately
   * NO free-text box: a member who needs to say more is pointed at the
   * operator's support email (`site.supportEmail`, admin-set; the line is
   * absent when none is configured). The optional consent block attaches
   * editable network context. When the key sits behind origin edges the member
   * may also say which connection they were using (the labels the pass shows;
   * optional, feeds edge attribution). Purely presentational; the mutation lives in
   * the page.
   */
  interface Props {
    open: boolean;
    reason: ReportIssueReason | null;
    /** The connection names the pass shows; empty = the question is not asked. */
    connections?: Array<{
      label: string;
      base?: string;
      role: 'primary' | 'backup';
      /** Where the app holds this address twice: its encrypted entry or the plain one. */
      entry?: 'encrypted' | 'plain';
    }>;
    /** The member's answer; null = not answered (the question is optional). */
    connection?: 'primary' | 'backup' | 'unsure' | null;
    /** With it, which of an address's two entries (null where it has one, or not answered). */
    connectionEntry?: 'encrypted' | 'plain' | null;
    telemetryContext: TelemetryContextResponse | undefined;
    /** The member's chosen country (ConnectionRegion), prefilled in the consent block. */
    ownCountry?: string | null;
    /** Operator support address from publicConfig.site; empty/null = no pointer. */
    supportEmail?: string | null;
    /** The member's NON-SECRET support ID, prefilled into the mailto subject. */
    supportId?: string | null;
    onCancel: () => void;
    onConfirm: (telemetry: TelemetryPayload | null) => void;
    busy: boolean;
  }

  let {
    open = $bindable(),
    reason = $bindable(),
    connections = [],
    connection = $bindable(null),
    connectionEntry = $bindable(null),
    telemetryContext,
    ownCountry = null,
    supportEmail = null,
    supportId = null,
    onCancel,
    onConfirm,
    busy,
  }: Props = $props();

  let consent = $state<ReturnType<typeof TelemetryConsent>>();

  // Subject carries the support ID only (never the account number), matching
  // the support card on /account.
  const mailto = $derived(
    supportEmail
      ? `mailto:${supportEmail}${
          supportId ? `?subject=${encodeURIComponent(`FreeSocks support - ID ${supportId}`)}` : ''
        }`
      : null,
  );

  type Option = {
    role: 'primary' | 'backup' | 'unsure';
    entry: 'encrypted' | 'plain' | null;
    label: string;
  };
  // One option per role, named after its address (a role carries one entry per
  // form of its address: `· Domain`, `· IPv4`, `· IPv6` share one base name).
  // Where the app holds an address twice (an encrypted entry and a plain one
  // marked for old apps), each is its own option: which of them failed says
  // whether the address is at fault or the app.
  const connectionOptions = $derived(
    (['primary', 'backup'] as const).flatMap((role): Option[] => {
      const own = connections.filter((c) => c.role === role);
      const named = (entry: 'encrypted' | 'plain' | undefined) =>
        [...new Set(own.filter((c) => c.entry === entry).map((c) => c.base ?? c.label))].join(
          ' / ',
        );
      const twice = own.some((c) => c.entry === 'plain');
      const options: Option[] = twice
        ? [
            { role, entry: 'encrypted', label: named('encrypted') },
            { role, entry: 'plain', label: named('plain') },
          ]
        : [
            {
              role,
              entry: null,
              label: [...new Set(own.map((c) => c.base ?? c.label))].join(' / '),
            },
          ];
      return options.filter((o) => o.label !== '');
    }),
  );
  const twoEntries = $derived(connectionOptions.some((o) => o.entry === 'plain'));

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
    if (!next) onCancel();
  }
</script>

<Dialog.Root bind:open {onOpenChange}>
  <Dialog.Content class="max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-md">
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

    {#if connectionOptions.length > 0}
      <fieldset class="space-y-1" disabled={busy}>
        <legend class="mb-2 text-sm font-medium">{t('report.connectionLegend')}</legend>
        {#each [...connectionOptions, { role: 'unsure' as const, entry: null, label: t('report.connectionUnsure') }] as o (`${o.role}:${o.entry ?? ''}`)}
          <label
            class="flex items-center gap-3 rounded-md px-2 py-2 min-h-[44px] cursor-pointer hover:bg-accent/50"
          >
            <input
              type="radio"
              name="report-issue-connection"
              value={`${o.role}:${o.entry ?? ''}`}
              checked={connection === o.role && connectionEntry === o.entry}
              onchange={() => {
                connection = o.role;
                connectionEntry = o.entry;
              }}
              class="size-4 shrink-0 accent-current"
            />
            <span class="text-sm">{o.label}</span>
          </label>
        {/each}
        {#if twoEntries}
          <p class="px-2 text-sm text-muted-foreground">{t('report.connectionOldAppsHint')}</p>
        {/if}
      </fieldset>
    {/if}

    {#if mailto}
      <p class="text-sm text-muted-foreground">
        {t('report.tellUsMore')}
        <a class="text-primary underline" href={mailto}>{supportEmail}</a>
      </p>
    {/if}

    <TelemetryConsent bind:this={consent} context={telemetryContext} {ownCountry} {busy} />

    <p class="text-xs text-muted-foreground">{t('report.nothingChanges')}</p>

    <Dialog.Footer>
      <Button variant="ghost" onclick={onCancel} disabled={busy}>{t('common.cancel')}</Button>
      <Button
        onclick={() => onConfirm(consent?.payload() ?? null)}
        disabled={busy || reason === null}
      >
        {busy ? t('report.working') : t('report.confirm')}
      </Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>
