<script lang="ts">
  /**
   * Free-text tag entry (server names, country codes, remarks). Enter, comma,
   * space or Tab-away adds; Backspace in the empty field removes the last tag;
   * a paste is split. Each tag has its own labelled remove button.
   *
   * Props:
   *   value: string[] (bindable)
   *   label: string                         visible label (also names the group)
   *   normalize?: (raw: string) => string | null
   *       normalise or reject one tag; see normalizeHostname / normalizeCountry in lib/tags.ts
   *   placeholder?: string
   *   helper?: string                       muted helper text under the field
   *   invalidText?: string                  shown when a tag was rejected (default 'Not a valid value')
   *   max?: number
   *   disabled?: boolean
   *   mono?: boolean                        monospace tags
   *   onchange?: (next: string[]) => void
   *   class?: string
   */
  import X from '@lucide/svelte/icons/x';
  import { Label } from '@client/components/ui/label';
  import { cn } from '@client/lib/utils';
  import { addTags } from '../lib/tags';

  interface Props {
    value: string[];
    label: string;
    normalize?: (raw: string) => string | null;
    placeholder?: string;
    helper?: string;
    invalidText?: string;
    max?: number;
    disabled?: boolean;
    mono?: boolean;
    onchange?: (next: string[]) => void;
    class?: string;
  }
  let {
    value = $bindable([]),
    label,
    normalize,
    placeholder = 'Type and press Enter',
    helper,
    invalidText = 'Not a valid value',
    max,
    disabled = false,
    mono = false,
    onchange,
    class: className,
  }: Props = $props();

  const uid = $props.id();
  let draft = $state('');
  let rejected = $state<string[]>([]);
  let inputEl = $state<HTMLInputElement | null>(null);

  function commit(raw: string) {
    if (raw.trim() === '') return;
    const result = addTags(value, raw, { normalize, max });
    rejected = result.rejected;
    draft = result.rejected.join(' ');
    if (result.next.length !== value.length) {
      value = result.next;
      onchange?.(value);
    }
  }

  function remove(tag: string) {
    value = value.filter((t) => t !== tag);
    onchange?.(value);
    inputEl?.focus();
  }

  function onkeydown(e: KeyboardEvent) {
    if (e.key === 'Enter' || e.key === ',' || e.key === ' ') {
      if (draft.trim() !== '' || e.key !== ' ') e.preventDefault();
      commit(draft);
    } else if (e.key === 'Backspace' && draft === '' && value.length > 0) {
      remove(value[value.length - 1]!);
    }
  }
</script>

<div class={cn('space-y-1.5', className)}>
  <Label for={`${uid}-input`}>{label}</Label>
  <div
    class={cn(
      'border-input dark:bg-input/30 focus-within:border-ring focus-within:ring-ring/50 flex min-h-9 flex-wrap items-center gap-1 rounded-lg border bg-transparent px-1.5 py-1 text-sm focus-within:ring-3',
      disabled && 'cursor-not-allowed opacity-50',
    )}
    role="group"
    aria-label={label}
  >
    {#each value as tag (tag)}
      <span
        class={cn(
          'bg-secondary text-secondary-foreground inline-flex items-center gap-0.5 rounded-md py-0.5 ps-1.5 pe-0.5 text-xs',
          mono && 'font-mono',
        )}
      >
        {tag}
        <button
          type="button"
          class="hover:bg-foreground/10 focus-visible:ring-ring/60 rounded-sm p-0.5 outline-none focus-visible:ring-2"
          aria-label={`Remove ${tag}`}
          {disabled}
          onclick={() => remove(tag)}
        >
          <X class="size-3" aria-hidden="true" />
        </button>
      </span>
    {/each}
    <input
      bind:this={inputEl}
      id={`${uid}-input`}
      class="placeholder:text-muted-foreground min-w-24 flex-1 bg-transparent px-1 py-0.5 outline-none"
      bind:value={draft}
      placeholder={value.length === 0 ? placeholder : ''}
      autocomplete="off"
      autocapitalize="off"
      spellcheck={false}
      {disabled}
      aria-invalid={rejected.length > 0 ? 'true' : undefined}
      aria-describedby={`${uid}-help`}
      {onkeydown}
      oninput={() => (rejected = [])}
      onblur={() => commit(draft)}
      onpaste={(e) => {
        const text = e.clipboardData?.getData('text') ?? '';
        if (/[\s,;]/.test(text.trim())) {
          e.preventDefault();
          commit(`${draft} ${text}`);
        }
      }}
    />
  </div>
  <p id={`${uid}-help`} class="text-xs">
    {#if rejected.length > 0}
      <span class="text-destructive" role="alert">
        {max !== undefined && value.length >= max
          ? `At most ${max} values.`
          : `${invalidText}: ${rejected.join(', ')}`}
      </span>
    {:else if helper}
      <span class="text-muted-foreground">{helper}</span>
    {/if}
  </p>
</div>
