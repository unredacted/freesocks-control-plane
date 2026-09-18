<script lang="ts">
  /**
   * "L4" / "L7" chip with the meaning in a tooltip (and as the accessible name).
   *
   * Props:
   *   layer: EdgeLayer ('l4' | 'l7')
   *   class?: string
   */
  import type { EdgeLayer } from '@shared/contracts/edges';
  import { Badge } from '@client/components/ui/badge';
  import * as Tooltip from '@client/components/ui/tooltip';
  import { LAYER_HINTS, LAYER_LABELS } from '../lib/format';

  interface Props {
    layer: EdgeLayer;
    class?: string;
  }
  let { layer, class: className }: Props = $props();
</script>

<Tooltip.Root>
  <Tooltip.Trigger
    class="focus-visible:ring-ring/50 rounded-md outline-none focus-visible:ring-3"
    aria-label={LAYER_HINTS[layer]}
  >
    <Badge variant={layer === 'l7' ? 'info' : 'neutral'} class={className}>
      {LAYER_LABELS[layer]}
    </Badge>
  </Tooltip.Trigger>
  <Tooltip.Content>{LAYER_HINTS[layer]}</Tooltip.Content>
</Tooltip.Root>
