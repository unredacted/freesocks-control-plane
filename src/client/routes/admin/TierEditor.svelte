<script lang="ts">
  import { z } from 'zod';
  import { Card, CardHeader, CardTitle, CardContent } from '@client/components/ui/card';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import * as Select from '@client/components/ui/select';
  import { TierAdmin } from '../../../shared/contracts/admin';

  interface Props {
    tier: z.infer<typeof TierAdmin>;
    onCancel: () => void;
    onSave: (t: z.infer<typeof TierAdmin>) => void;
  }
  let { tier, onCancel, onSave }: Props = $props();

  // Spread once at init from the prop. We intentionally don't track tier
  // changes after mount: once an editor is open, the dialog has its own
  // editable copy and prop changes shouldn't blow it away mid-edit. Wrapping
  // in an IIFE silences `state_referenced_locally` since the snapshot lives
  // in a separate scope, breaking the "captures initial value of prop"
  // analysis the compiler does.
  let draft = $state(((t: typeof tier) => ({ ...$state.snapshot(t) }))(tier));

  // Compare against the original to disable Save when nothing has changed;
  // gives the operator a clear signal that they haven't unsaved edits and
  // prevents accidental tier-propagation jobs from no-op saves.
  let isPristine = $derived(JSON.stringify(draft) === JSON.stringify(tier));
</script>

<div class="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
  <Card class="w-full max-w-lg">
    <CardHeader>
      <CardTitle>Edit tier · {tier.name}</CardTitle>
    </CardHeader>
    <CardContent class="space-y-3">
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="tier-name">Display name</label>
        <Input id="tier-name" bind:value={draft.name} />
      </div>
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="tier-backend">Backend</label>
        <Select.Root
          type="single"
          value={draft.backend}
          onValueChange={(v) => (draft = { ...draft, backend: v as 'remnawave' | 'outline' })}
        >
          <Select.Trigger id="tier-backend" class="w-48">
            {draft.backend === 'outline' ? 'Outline' : 'Xray'}
          </Select.Trigger>
          <Select.Content>
            <!--
              Backend ids are the internal discriminator (`remnawave` /
              `outline`), kept for backwards compatibility with existing
              DB rows. The labels shown to admins say "Xray" because that's
              what's surfaced to end users; "Remnawave" is the management
              panel implementation detail we don't advertise.
            -->
            <Select.Item value="remnawave">Xray</Select.Item>
            <Select.Item value="outline">Outline</Select.Item>
          </Select.Content>
        </Select.Root>
        {#if draft.backend !== tier.backend}
          <p class="text-xs text-amber-600 dark:text-amber-400 mt-1 leading-snug">
            Changing backend does not migrate existing users on this tier. They keep their current
            backend until they regenerate or switch explicitly.
          </p>
        {/if}
      </div>
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="tier-traffic">
          Monthly traffic (GB, 0 = unlimited)
        </label>
        <Input id="tier-traffic" type="number" min={0} bind:value={draft.monthlyTrafficGb} />
      </div>
      <div>
        <label class="text-xs text-muted-foreground mb-1 block" for="tier-devices">
          Device limit
        </label>
        <Input id="tier-devices" type="number" min={0} bind:value={draft.deviceLimit} />
      </div>
      {#if draft.backend === 'remnawave'}
        <div>
          <label class="text-xs text-muted-foreground mb-1 block" for="tier-hwid">HWID limit</label>
          <Input id="tier-hwid" type="number" min={0} bind:value={draft.hwidLimit} />
          <p class="text-xs text-muted-foreground/80 mt-1 leading-snug">
            Xray-only. Number of distinct device fingerprints allowed per subscription.
          </p>
        </div>
      {/if}
      <div class="flex gap-2 justify-end pt-2">
        <Button variant="ghost" onclick={onCancel}>Cancel</Button>
        <Button onclick={() => onSave(draft)} disabled={isPristine}>
          {isPristine ? 'No changes' : 'Save'}
        </Button>
      </div>
    </CardContent>
  </Card>
</div>
