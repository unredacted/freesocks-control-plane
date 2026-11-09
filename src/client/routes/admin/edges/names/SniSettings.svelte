<script lang="ts">
  /**
   * SNIs -> More settings (`/admin/servers/snis/settings`; docs/edges.md "The
   * page"): the numeric `edge.sni.*` knobs that have no place on the other
   * views, one card per block of `PATCH sni/config` (checking SNIs on lists,
   * finding SNIs, checks from inside countries). Each field says its default
   * and its range; a card saves only what changed in it, and "Use the
   * defaults" fills its fields (saved with Save, like any edit). The server
   * clamps every value to the same bounds. The switches stay on the views they
   * belong to.
   *
   * The catalog and its checks live in ./lib/sniKnobs.ts (pure, unit-tested).
   */
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Badge } from '@client/components/ui/badge';
  import { Button } from '@client/components/ui/button';
  import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
  } from '@client/components/ui/card';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import { ApiCallError } from '@client/lib/api';
  import { invalidateSni, patchSniConfig, sniConfigQuery } from '@client/lib/sniApi';
  import SectionHeader from '../components/SectionHeader.svelte';
  import {
    KNOB_GROUPS,
    changedFromDefault,
    groupErrors,
    groupPatch,
    knobRange,
    knobValue,
    knobsOf,
    type KnobGroup,
  } from './lib/sniKnobs';
  import { sniErrorWords } from './lib/words';

  const qc = useQueryClient();
  const uid = $props.id();
  const config = sniConfigQuery();
  const codeOf = (e: unknown) => (e instanceof ApiCallError ? e.payload.error.code : null);

  // Typed values by knob id; a field not here shows its value now.
  let edits = $state<Record<string, string>>({});
  let saving = $state<KnobGroup | null>(null);

  function valuesOf(group: KnobGroup): Record<string, string> {
    const view = config.data;
    const out: Record<string, string> = {};
    for (const k of knobsOf(group))
      out[k.id] = edits[k.id] ?? (view ? String(knobValue(view, k)) : '');
    return out;
  }
  function clear(group: KnobGroup) {
    const next = { ...edits };
    for (const k of knobsOf(group)) delete next[k.id];
    edits = next;
  }
  function useDefaults(group: KnobGroup) {
    const next = { ...edits };
    for (const k of knobsOf(group)) next[k.id] = String(k.default);
    edits = next;
  }
  async function save(group: KnobGroup) {
    const view = config.data;
    if (!view) return;
    const patch = groupPatch(group, edits, view);
    if (!patch) return;
    saving = group;
    try {
      await patchSniConfig(patch);
      clear(group);
      toast.success('Saved.');
    } catch (e) {
      toast.error(sniErrorWords(codeOf(e)));
    } finally {
      saving = null;
      invalidateSni(qc);
    }
  }
</script>

<SectionHeader
  title="More settings"
  description="The numbers behind SNI lists, finding SNIs and the checks from inside countries. The defaults suit most setups. The switches are on the other views."
/>

{#if config.isPending}
  <p class="text-muted-foreground text-sm">Loading…</p>
{:else if config.isError}
  <p class="text-destructive text-sm">{sniErrorWords(codeOf(config.error))}</p>
{:else if config.data}
  {@const view = config.data}
  <div class="space-y-6">
    {#each KNOB_GROUPS as g (g.id)}
      {@const values = valuesOf(g.id)}
      {@const errors = groupErrors(g.id, values)}
      {@const patch = groupPatch(g.id, edits, view)}
      {@const changed = changedFromDefault(g.id, view)}
      <Card>
        <CardHeader>
          <CardTitle class="flex flex-wrap items-center gap-2 text-base">
            <h2 id={`${uid}-${g.id}`}>{g.title}</h2>
            {#if changed > 0}
              <Badge variant="secondary">
                {changed} changed from default
              </Badge>
            {/if}
          </CardTitle>
          <CardDescription>{g.description}</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            class="space-y-4 text-sm"
            aria-labelledby={`${uid}-${g.id}`}
            novalidate
            onsubmit={(e) => {
              e.preventDefault();
              void save(g.id);
            }}
          >
            <div class="grid gap-4 sm:grid-cols-2">
              {#each knobsOf(g.id) as k (k.id)}
                {@const id = `${uid}-${k.id.replace('.', '-')}`}
                {@const error = errors[k.id]}
                <div class="space-y-1.5">
                  <Label for={id}>{k.label}</Label>
                  <div class="flex items-center gap-2">
                    <Input
                      {id}
                      class="w-36"
                      inputmode="numeric"
                      autocomplete="off"
                      value={values[k.id]}
                      aria-invalid={error ? true : undefined}
                      aria-describedby={`${id}-help`}
                      oninput={(e) => (edits = { ...edits, [k.id]: e.currentTarget.value })}
                    />
                    <span class="text-muted-foreground">{k.unit}</span>
                  </div>
                  <p id={`${id}-help`} class="text-muted-foreground">
                    {#if error}
                      <span class="text-destructive block">{error}</span>
                    {/if}
                    {k.help}
                    {knobRange(k)}
                  </p>
                </div>
              {/each}
            </div>
            <div class="flex flex-wrap items-center gap-2">
              <Button type="submit" size="sm" disabled={!patch || saving !== null}>
                {saving === g.id ? 'Saving…' : 'Save'}
              </Button>
              <Button
                type="button"
                size="sm"
                variant="outline"
                disabled={saving !== null}
                onclick={() => useDefaults(g.id)}
              >
                Use the defaults
              </Button>
              {#if knobsOf(g.id).some((k) => edits[k.id] !== undefined)}
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  disabled={saving !== null}
                  onclick={() => clear(g.id)}
                >
                  Undo changes
                </Button>
              {/if}
            </div>
          </form>
        </CardContent>
      </Card>
    {/each}
  </div>
{/if}
