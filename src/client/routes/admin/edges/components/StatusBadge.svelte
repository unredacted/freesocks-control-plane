<script lang="ts" module>
  /** Which vocabulary `value` belongs to (each has its labels + tones in lib/edgeCodes.ts). */
  export type StatusKind =
    | 'status'
    | 'health'
    | 'publication'
    | 'phase'
    | 'readiness'
    | 'host'
    | 'setup'
    | 'severity';
</script>

<script lang="ts">
  /**
   * A status chip in words with a tone.
   *
   * Props:
   *   kind: StatusKind        'status' (edge status) | 'health' | 'publication' | 'phase' (rotation)
   *                           | 'readiness' (dns/certificate/front) | 'host' (panel Host state)
   *                           | 'setup' (setup step status) | 'severity' (attention)
   *   value: string           the raw server value
   *   label?: string          override the words
   *   tone?: Tone             override the tone
   *   dot?: boolean           leading status dot (default true)
   *   class?: string
   */
  import { Badge } from '@client/components/ui/badge';
  import { cn } from '@client/lib/utils';
  import {
    EDGE_HEALTH_LABELS,
    HOST_STATE_LABELS,
    READINESS_LABELS,
    SETUP_STATUS_LABELS,
    edgeStatusLabel,
    edgeStatusTone,
    healthTone,
    hostStateTone,
    humanizeCode,
    phaseLabel,
    phaseTone,
    publicationLabel,
    publicationTone,
    readinessTone,
    setupStatusTone,
    severityTone,
    type Tone,
  } from '@client/lib/edgeCodes';
  import type { AttentionSeverity, SetupStepStatus } from '@shared/contracts/edgeCodes';

  interface Props {
    kind: StatusKind;
    value: string;
    label?: string;
    tone?: Tone;
    dot?: boolean;
    class?: string;
  }
  let { kind, value, label, tone, dot = true, class: className }: Props = $props();

  const SEVERITY_LABELS: Record<string, string> = {
    critical: 'Critical',
    warning: 'Warning',
    info: 'Info',
  };

  const resolved = $derived.by((): { label: string; tone: Tone } => {
    switch (kind) {
      case 'status':
        return { label: edgeStatusLabel(value), tone: edgeStatusTone(value) };
      case 'health':
        return { label: EDGE_HEALTH_LABELS[value] ?? humanizeCode(value), tone: healthTone(value) };
      case 'publication':
        return { label: publicationLabel(value), tone: publicationTone(value) };
      case 'phase':
        return { label: phaseLabel(value), tone: phaseTone(value) };
      case 'readiness':
        return {
          label: READINESS_LABELS[value] ?? humanizeCode(value),
          tone: readinessTone(value),
        };
      case 'host':
        return {
          label: HOST_STATE_LABELS[value] ?? humanizeCode(value),
          tone: hostStateTone(value),
        };
      case 'setup':
        return {
          label: SETUP_STATUS_LABELS[value as SetupStepStatus] ?? humanizeCode(value),
          tone: setupStatusTone(value as SetupStepStatus),
        };
      case 'severity':
        return {
          label: SEVERITY_LABELS[value] ?? humanizeCode(value),
          tone: severityTone(value as AttentionSeverity),
        };
    }
  });
</script>

<Badge variant={tone ?? resolved.tone} class={cn(className)}>
  {#if dot}
    <span class="size-1.5 rounded-full bg-current opacity-70" aria-hidden="true"></span>
  {/if}
  {label ?? resolved.label}
</Badge>
