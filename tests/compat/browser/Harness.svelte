<script lang="ts">
  import ReportIssueModal from '../../../src/client/components/ReportIssueModal.svelte';
  import { apiClient } from '../../../src/client/lib/api';
  import {
    ReportIssueResponse,
    type TelemetryPayload,
  } from '../../../src/shared/contracts/telemetry';
  import type { ReportIssueReason } from '../../../src/shared/contracts/issueReasons';
  let open = $state(false);
  let reason = $state<ReportIssueReason | null>(null);
  let busy = $state(false);
  let result = $state('');
  const context = {
    enabled: true,
    fields: { country: true, city: true, asn: true },
    detected: { country: 'US', city: 'Chicago', asn: 64512 },
  };
  async function submit(telemetry: TelemetryPayload | null, detail: string | null) {
    busy = true;
    try {
      await apiClient.post(
        '/api/v1/account/report-issue',
        { reason, ...(telemetry ? { telemetry } : {}), ...(detail ? { detail } : {}) },
        ReportIssueResponse,
      );
      result = 'Report sent';
      open = false;
      reason = null;
    } catch (error) {
      result = error instanceof Error ? error.message : 'Report failed';
    } finally {
      busy = false;
    }
  }
</script>

<button
  onclick={() => {
    result = '';
    open = true;
  }}>Open report</button
>
<p role="status">{result}</p>
<ReportIssueModal
  bind:open
  bind:reason
  telemetryContext={context}
  {busy}
  onCancel={() => {
    open = false;
    reason = null;
  }}
  onConfirm={submit}
/>
