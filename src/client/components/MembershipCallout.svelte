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
    /** In-app action, an alternative to ctaUrl - renders a button, not an external
     *  link. Takes precedence over ctaUrl when both are set. */
    onCta?: () => void;
    /** Optional: omit (with no ctaUrl/onCta) for a callout whose only action is the secondary snippet. */
    ctaLabel?: string;
    secondaryAction?: import('svelte').Snippet;
  }

  let { tone, title, body, ctaUrl, onCta, ctaLabel, secondaryAction }: Props = $props();

  const TONE_CLASSES: Record<CalloutTone, string> = {
    info: 'bg-blue-500/10 border-blue-500/40',
    warn: 'bg-amber-500/10 border-amber-500/40',
    error: 'bg-destructive/10 border-destructive/40',
  };
</script>

<div class="space-y-2 rounded-sm border {TONE_CLASSES[tone]} px-4 py-3.5 text-[15px]">
  <p class="font-bold text-foreground">{title}</p>
  <p class="text-body">{body}</p>
  <div class="flex flex-wrap items-center gap-3 pt-1">
    {#if onCta && ctaLabel}
      <Button size="lg" class="text-[15px]" onclick={onCta}>{ctaLabel}</Button>
    {:else if ctaUrl && ctaLabel}
      <a href={ctaUrl} target="_blank" rel="noopener noreferrer">
        <Button size="lg" class="text-[15px]">{ctaLabel}</Button>
      </a>
    {/if}
    {#if secondaryAction}{@render secondaryAction()}{/if}
  </div>
</div>
