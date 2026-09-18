<script lang="ts">
  /**
   * What a listener speaks, e.g. "VLESS · raw · REALITY".
   *
   * Props:
   *   protocol: ListenerProtocolId
   *   streamTransport: ListenerStreamTransport
   *   security: ListenerSecurity
   *   compact?: boolean       protocol + security only ("VLESS · REALITY")
   *   class?: string
   * Any object with those three fields spreads straight in: <ProtocolBadge {...listener} />
   * is NOT safe (extra props); pass the three fields explicitly.
   */
  import type {
    ListenerProtocolId,
    ListenerSecurity,
    ListenerStreamTransport,
  } from '@shared/contracts/edges';
  import { Badge } from '@client/components/ui/badge';
  import { PROTOCOL_LABELS, SECURITY_LABELS, protocolLine } from '../lib/format';

  interface Props {
    protocol: ListenerProtocolId;
    streamTransport: ListenerStreamTransport;
    security: ListenerSecurity;
    compact?: boolean;
    class?: string;
  }
  let { protocol, streamTransport, security, compact = false, class: className }: Props = $props();

  const full = $derived(protocolLine({ protocol, streamTransport, security }));
  const text = $derived(
    compact ? `${PROTOCOL_LABELS[protocol]} · ${SECURITY_LABELS[security]}` : full,
  );
</script>

<Badge variant="outline" class={className} title={compact ? full : undefined}>{text}</Badge>
