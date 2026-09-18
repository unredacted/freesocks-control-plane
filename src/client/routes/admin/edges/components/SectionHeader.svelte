<script lang="ts">
  /**
   * Page / section heading for the Edges pages.
   *
   * Props:
   *   title: string
   *   description?: string
   *   back?: { href: string; label: string }    a "back to ..." link above the title
   *   level?: 1 | 2                             h1 (page, default) or h2 (section inside a page)
   *   badges?: Snippet                          rendered inline after the title (status chips)
   *   actions?: Snippet                         right-aligned buttons
   *   class?: string
   */
  import type { Snippet } from 'svelte';
  import ArrowLeft from '@lucide/svelte/icons/arrow-left';
  import Link from '../../../../components/Link.svelte';
  import { cn } from '../../../../lib/utils';

  interface Props {
    title: string;
    description?: string;
    back?: { href: string; label: string };
    level?: 1 | 2;
    badges?: Snippet;
    actions?: Snippet;
    class?: string;
  }
  let { title, description, back, level = 1, badges, actions, class: className }: Props = $props();
</script>

<div class={cn(level === 1 ? 'mb-6' : 'mb-3', className)}>
  {#if back}
    <Link
      href={back.href}
      class="text-muted-foreground hover:text-foreground focus-visible:ring-ring/50 mb-2 inline-flex items-center gap-1 rounded-sm text-sm outline-none focus-visible:ring-3"
    >
      <ArrowLeft class="size-3.5 rtl:rotate-180" aria-hidden="true" />
      {back.label}
    </Link>
  {/if}
  <div class="flex flex-wrap items-start justify-between gap-3">
    <div class="min-w-0">
      <div class="flex flex-wrap items-center gap-2">
        {#if level === 1}
          <h1 class="text-2xl font-semibold tracking-tight">{title}</h1>
        {:else}
          <h2 class="text-lg font-semibold tracking-tight">{title}</h2>
        {/if}
        {#if badges}{@render badges()}{/if}
      </div>
      {#if description}
        <p class="text-muted-foreground mt-1 max-w-prose text-sm">{description}</p>
      {/if}
    </div>
    {#if actions}
      <div class="flex shrink-0 flex-wrap items-center gap-2">{@render actions()}</div>
    {/if}
  </div>
</div>
