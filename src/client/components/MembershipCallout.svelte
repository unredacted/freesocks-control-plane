<script lang="ts" module>
  export type CalloutTone = 'info' | 'warn' | 'error';
</script>

<script lang="ts">
  import { Button } from '@client/components/ui/button';

  interface Props {
    tone: CalloutTone;
    title: string;
    body: string;
    ctaUrl?: string;
    /** Optional: omit (with no ctaUrl) for a callout whose only action is the secondary snippet. */
    ctaLabel?: string;
    secondaryAction?: import('svelte').Snippet;
  }

  let { tone, title, body, ctaUrl, ctaLabel, secondaryAction }: Props = $props();

  const TONE_CLASSES: Record<CalloutTone, string> = {
    info: 'bg-blue-500/10 border-blue-500/40',
    warn: 'bg-amber-500/10 border-amber-500/40',
    error: 'bg-destructive/10 border-destructive/40',
  };
</script>

<div class="rounded-md border {TONE_CLASSES[tone]} px-3 py-3 text-sm space-y-2">
  <p class="font-semibold">{title}</p>
  <p class="text-muted-foreground">{body}</p>
  <div class="flex flex-wrap items-center gap-3 pt-1">
    {#if ctaUrl && ctaLabel}
      <a href={ctaUrl} target="_blank" rel="noopener noreferrer">
        <Button size="sm">{ctaLabel}</Button>
      </a>
    {/if}
    {#if secondaryAction}{@render secondaryAction()}{/if}
  </div>
</div>
