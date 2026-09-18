<script lang="ts">
  /**
   * Per client family rendering rules (`render.clients.<family>`). A rule is one
   * object on the server, so an edit to any field sends the whole rule; "Reset to
   * default" puts the compiled default rule back (saved with the section).
   *
   * Props:
   *   form: ConfigForm
   *   families: string[]          EdgeConfigView.families
   */
  import RotateCcw from '@lucide/svelte/icons/rotate-ccw';
  import { Switch } from '@client/components/ui/switch';
  import { Label } from '@client/components/ui/label';
  import { Input } from '@client/components/ui/input';
  import { Button } from '@client/components/ui/button';
  import { Badge } from '@client/components/ui/badge';
  import * as Select from '@client/components/ui/select';
  import NumberField from '../components/NumberField.svelte';
  import { sameValue } from './configDiff';
  import { RULE_FIELDS, familyLabel, rulePath } from './fields';
  import type { ConfigForm } from './form.svelte';

  interface Props {
    form: ConfigForm;
    families: string[];
  }
  let { form, families }: Props = $props();

  const uid = $props.id();
  const MAX_ENTRIES_BOUNDS = 'render.clients.maxEntries';
</script>

<div class="space-y-2">
  {#each families as family (family)}
    {@const path = rulePath(family)}
    {@const rule = form.rule(path)}
    {@const dflt = form.defaultOf(path)}
    {@const edited = path in form.edits}
    {@const offDefault = dflt !== undefined && !sameValue(dflt, rule)}
    <details class="rounded-lg border" open={edited}>
      <summary
        class="focus-visible:ring-ring/50 flex cursor-pointer flex-wrap items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium outline-none focus-visible:ring-3"
      >
        {familyLabel(family)}
        {#if rule.enabled === false}<Badge variant="muted">Not rendered</Badge>{/if}
        {#if offDefault}<Badge variant="neutral">Customised</Badge>{/if}
        {#if edited}<Badge variant="warning">Unsaved</Badge>{/if}
      </summary>
      <div class="space-y-4 border-t px-3 py-3">
        <div class="grid gap-4 sm:grid-cols-2">
          {#each RULE_FIELDS as f (f.key)}
            {@const fid = `${uid}-${family}-${f.key}`}
            {#if f.kind === 'switch'}
              <div class="flex items-start gap-3">
                <Switch
                  id={fid}
                  class="mt-0.5"
                  bind:checked={
                    () => rule[f.key] === true, (v) => form.setRuleField(path, f.key, v)
                  }
                />
                <div class="min-w-0">
                  <Label for={fid}>{f.label}</Label>
                  <p class="text-muted-foreground mt-1 text-xs">{f.helper}</p>
                </div>
              </div>
            {:else if f.kind === 'number'}
              <NumberField
                label={f.label}
                unit={f.unit}
                helper={f.helper}
                bounds={form.bounds(MAX_ENTRIES_BOUNDS)}
                bind:value={
                  () => (typeof rule[f.key] === 'number' ? (rule[f.key] as number) : Number.NaN),
                  (v) => form.setRuleField(path, f.key, v)
                }
                bind:invalid={
                  () => form.invalid[`${path}.${f.key}`] ?? false,
                  (v) => form.setInvalid(`${path}.${f.key}`, v)
                }
              />
            {:else if f.kind === 'select'}
              {@const current = typeof rule[f.key] === 'string' ? (rule[f.key] as string) : ''}
              <div class="space-y-1.5">
                <Label for={fid}>{f.label}</Label>
                <Select.Root
                  type="single"
                  bind:value={() => current, (v) => form.setRuleField(path, f.key, v)}
                >
                  <Select.Trigger id={fid} class="w-full">
                    {f.options.find((o) => o.value === current)?.label ?? 'Choose'}
                  </Select.Trigger>
                  <Select.Content>
                    {#each f.options as o (o.value)}
                      <Select.Item value={o.value} label={o.label}>{o.label}</Select.Item>
                    {/each}
                  </Select.Content>
                </Select.Root>
                <p class="text-muted-foreground text-xs">{f.helper}</p>
              </div>
            {:else}
              <div class="space-y-1.5">
                <Label for={fid}>{f.label}</Label>
                <Input
                  id={fid}
                  maxlength={f.maxLength}
                  value={typeof rule[f.key] === 'string' ? (rule[f.key] as string) : ''}
                  oninput={(e) => form.setRuleField(path, f.key, e.currentTarget.value)}
                />
                <p class="text-muted-foreground text-xs">{f.helper}</p>
              </div>
            {/if}
          {/each}
        </div>
        <Button
          variant="outline"
          size="sm"
          disabled={!offDefault}
          onclick={() => form.set(path, dflt)}
        >
          <RotateCcw aria-hidden="true" />
          Reset to default
        </Button>
      </div>
    </details>
  {/each}
</div>
