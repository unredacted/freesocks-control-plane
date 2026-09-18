<script lang="ts">
  /**
   * Create a relay: its origin, a slug, and (optionally) its first listeners.
   * The node role can register the listeners instead, so none is required here.
   *
   * Props:
   *   open: boolean (bindable)
   *   draft?: RelayPrefill | null      prefill (the guided setup's draft: origin + listener forms)
   *   onCreated: (slug: string) => void
   */
  import { untrack } from 'svelte';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import Plus from '@lucide/svelte/icons/plus';
  import Trash2 from '@lucide/svelte/icons/trash-2';
  import * as Dialog from '@client/components/ui/dialog';
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { Label } from '@client/components/ui/label';
  import InlineError from '@client/components/InlineError.svelte';
  import { createRelay, invalidateRelay } from '@client/lib/edgesApi';
  import CodeNote from '../components/CodeNote.svelte';
  import { edgeErrorIssue, edgeErrorMessage } from '../lib/edgeErrors';
  import OriginPicker from './OriginPicker.svelte';
  import ListenerFields from './ListenerFields.svelte';
  import {
    emptyOrigin,
    originIssue,
    suggestSlug,
    toCreateOrigin,
    type OriginDraft,
  } from './origin';
  import {
    emptyListenerForm,
    formCombo,
    listenerFormIssues,
    toListenerSpec,
    type ListenerForm,
  } from './listenerForm';
  import { relaySlugIssue, suggestListenerKey, type RelayPrefill } from './prefill';

  interface Props {
    open: boolean;
    draft?: RelayPrefill | null;
    onCreated: (slug: string) => void;
  }
  let { open = $bindable(false), draft = null, onCreated }: Props = $props();

  const uid = $props.id();
  const qc = useQueryClient();

  let origin = $state<OriginDraft>(emptyOrigin());
  let slug = $state('');
  let slugTouched = $state(false);
  let label = $state('');
  let locationCode = $state('');
  let listeners = $state<ListenerForm[]>([]);
  let submitted = $state(false);

  function withKeys(forms: readonly ListenerForm[]): ListenerForm[] {
    const taken: string[] = [];
    return forms.map((f) => {
      const key = f.listenerKey || suggestListenerKey(f, taken);
      taken.push(key);
      return { ...f, listenerKey: key };
    });
  }

  let seeded = false;
  $effect(() => {
    if (!open) {
      seeded = false;
      return;
    }
    if (seeded) return;
    seeded = true;
    origin = draft?.origin ? { ...draft.origin } : emptyOrigin();
    listeners = withKeys(draft?.listeners ?? []);
    slug = suggestSlug(origin);
    slugTouched = false;
    label = '';
    locationCode = '';
    submitted = false;
    untrack(() => create.reset());
  });

  function onOriginChange(next: OriginDraft) {
    if (!slugTouched) slug = suggestSlug(next);
  }
  function addListener() {
    const f = emptyListenerForm(origin.kind);
    f.listenerKey = suggestListenerKey(
      f,
      listeners.map((l) => l.listenerKey),
    );
    listeners = [...listeners, f];
  }
  function removeListener(i: number) {
    listeners = listeners.filter((_, idx) => idx !== i);
  }

  const originProblem = $derived(originIssue(origin));
  const slugProblem = $derived(relaySlugIssue(slug));
  const listenerProblems = $derived(listeners.map((l) => listenerFormIssues(l, origin.kind)));
  const duplicateKey = $derived.by(() => {
    const seen = new Set<string>();
    for (const l of listeners) {
      if (seen.has(l.listenerKey)) return l.listenerKey;
      seen.add(l.listenerKey);
    }
    return null;
  });
  const valid = $derived(
    originProblem === null &&
      slugProblem === null &&
      duplicateKey === null &&
      listenerProblems.every((p) => p.length === 0),
  );

  const create = createMutation(() => ({
    mutationFn: () =>
      createRelay({
        slug: slug.trim(),
        origin: toCreateOrigin(origin),
        originAddress: origin.address.trim(),
        ...(label.trim() ? { label: label.trim() } : {}),
        ...(locationCode.trim() ? { locationCode: locationCode.trim().toUpperCase() } : {}),
        ...(listeners.length > 0
          ? { listeners: listeners.map((l) => toListenerSpec(l, origin.kind)) }
          : {}),
      }),
    onSuccess: () => {
      const created = slug.trim();
      invalidateRelay(qc, created);
      toast.success(`Relay ${created} created`);
      open = false;
      onCreated(created);
    },
  }));
  const refusal = $derived(create.error ? edgeErrorIssue(create.error) : null);

  function submit(e: Event) {
    e.preventDefault();
    submitted = true;
    if (!valid) return;
    create.mutate();
  }
</script>

<Dialog.Root bind:open>
  <Dialog.Content class="max-h-[90vh] overflow-y-auto sm:max-w-3xl">
    <Dialog.Header>
      <Dialog.Title>New relay</Dialog.Title>
      <Dialog.Description>
        A relay is one origin that sits behind edges. Members covered by it are served through a
        published edge, never the origin itself.
      </Dialog.Description>
    </Dialog.Header>
    <form class="space-y-6" onsubmit={submit}>
      <section class="space-y-4">
        <h3 class="text-sm font-semibold">Origin</h3>
        <OriginPicker bind:value={origin} disabled={create.isPending} onchange={onOriginChange} />
        {#if submitted && originProblem}
          <p class="text-destructive text-sm" role="alert">{originProblem}</p>
        {/if}
      </section>

      <section class="grid gap-4 sm:grid-cols-3">
        <div class="space-y-1.5">
          <Label for={`${uid}-slug`}>Slug</Label>
          <Input
            id={`${uid}-slug`}
            class="font-mono"
            placeholder="node1"
            bind:value={slug}
            oninput={() => (slugTouched = true)}
            disabled={create.isPending}
            aria-invalid={submitted && slugProblem !== null}
          />
          <p
            class={submitted && slugProblem
              ? 'text-destructive text-xs'
              : 'text-muted-foreground text-xs'}
          >
            {submitted && slugProblem
              ? slugProblem
              : 'The stable name of the relay. The node role registers under the same slug.'}
          </p>
        </div>
        <div class="space-y-1.5">
          <Label for={`${uid}-label`}>Label (optional)</Label>
          <Input id={`${uid}-label`} bind:value={label} disabled={create.isPending} />
        </div>
        <div class="space-y-1.5">
          <Label for={`${uid}-loc`}>Location code (optional)</Label>
          <Input
            id={`${uid}-loc`}
            class="font-mono uppercase"
            placeholder="XXX"
            maxlength={16}
            bind:value={locationCode}
            disabled={create.isPending}
          />
        </div>
      </section>

      <section class="space-y-3">
        <div class="flex items-center justify-between gap-2">
          <div>
            <h3 class="text-sm font-semibold">Listeners</h3>
            <p class="text-muted-foreground text-xs">
              Optional here: the node role can register them. Without a deployed listener no edge
              can be provisioned.
            </p>
          </div>
          <Button type="button" size="sm" variant="outline" onclick={addListener}>
            <Plus class="size-4" aria-hidden="true" /> Add listener
          </Button>
        </div>
        {#each listeners as _, i (i)}
          <div class="space-y-3 rounded-lg border p-3">
            <div class="flex items-center justify-between gap-2">
              <p class="text-sm font-medium">
                {listeners[i]!.listenerKey || 'New listener'}
                <span class="text-muted-foreground font-normal"
                  >{formCombo(listeners[i]!).label}</span
                >
              </p>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                aria-label={`Remove listener ${listeners[i]!.listenerKey}`}
                onclick={() => removeListener(i)}
              >
                <Trash2 class="size-4" aria-hidden="true" />
              </Button>
            </div>
            <ListenerFields
              bind:form={listeners[i]!}
              originKind={origin.kind}
              disabled={create.isPending}
            />
            {#if submitted && (listenerProblems[i]?.length ?? 0) > 0}
              <ul class="text-destructive list-disc space-y-0.5 ps-5 text-sm" role="alert">
                {#each listenerProblems[i] ?? [] as p (p)}<li>{p}</li>{/each}
              </ul>
            {/if}
          </div>
        {/each}
        {#if submitted && duplicateKey}
          <p class="text-destructive text-sm" role="alert">
            Two listeners share the key "{duplicateKey}". Give each its own key.
          </p>
        {/if}
      </section>

      {#if refusal}
        <CodeNote issue={refusal} />
      {:else if create.error}
        <InlineError message={edgeErrorMessage(create.error)} />
      {/if}

      <Dialog.Footer>
        <Button type="button" variant="outline" onclick={() => (open = false)}>Cancel</Button>
        <Button type="submit" disabled={create.isPending}>
          {create.isPending ? 'Creating' : 'Create relay'}
        </Button>
      </Dialog.Footer>
    </form>
  </Dialog.Content>
</Dialog.Root>
