<script lang="ts">
  /**
   * One on/off setting with its consequence in a line. The switch shows the
   * SERVER's value; a click calls `onToggle(next)` and stays busy until it settles.
   *
   * Props:
   *   label: string
   *   consequence: string                  one line: what turning it on does
   *   checked: boolean                     the server's value
   *   disabled?: boolean
   *   disabledReason?: string              shown instead of the consequence when disabled
   *   onToggle: (next: boolean) => Promise<unknown>
   */
  import { toast } from 'svelte-sonner';
  import { Switch } from '@client/components/ui/switch';
  import { Label } from '@client/components/ui/label';
  import { edgeErrorMessage } from '../lib/edgeErrors';

  interface Props {
    label: string;
    consequence: string;
    checked: boolean;
    disabled?: boolean;
    disabledReason?: string;
    onToggle: (next: boolean) => Promise<unknown>;
  }
  let { label, consequence, checked, disabled = false, disabledReason, onToggle }: Props = $props();

  const uid = $props.id();
  let busy = $state(false);

  async function toggle(next: boolean) {
    busy = true;
    try {
      await onToggle(next);
    } catch (err) {
      toast.error(`Could not change "${label}"`, { description: edgeErrorMessage(err) });
    } finally {
      busy = false;
    }
  }
</script>

<div class="flex items-start justify-between gap-4 py-3">
  <div class="min-w-0">
    <Label for={uid}>{label}</Label>
    <p class="text-muted-foreground text-xs" id={`${uid}-help`}>
      {disabled && disabledReason ? disabledReason : consequence}
    </p>
  </div>
  <Switch
    id={uid}
    aria-describedby={`${uid}-help`}
    bind:checked={() => checked, (v) => void toggle(v)}
    disabled={disabled || busy}
  />
</div>
