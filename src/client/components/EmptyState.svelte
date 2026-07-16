<script lang="ts">
  import type { Component, Snippet } from 'svelte';
  import DitherField from './DitherField.svelte';

  /**
   * The single empty-state pattern: dashed border (the one place a dashed frame
   * means "nothing here yet"), centered, flat, calm. Art is either a neutral
   * icon or - for brand moments - the `dither` disc (a small dissolving mass
   * in the signature texture). Use for no-key / no-codes / no-data.
   */
  interface Props {
    icon?: Component;
    /** Brand-art variant: a small dithered disc instead of the icon chip.
     *  Used sparingly (the no-key state on /account). */
    dither?: boolean;
    title: string;
    body?: string;
    children?: Snippet;
  }
  let { icon: Icon, dither = false, title, body, children }: Props = $props();
</script>

<div class="rounded-xl border border-dashed border-border p-8 text-center space-y-3">
  {#if dither}
    <div class="relative mx-auto size-14 overflow-hidden rounded-full border border-border">
      <DitherField
        class="absolute inset-0"
        anchor={{ x: 0.5, y: 0.5 }}
        radius={0.95}
        alphaLight={0.5}
        alphaDark={0.65}
        cell={2}
      />
    </div>
  {:else if Icon}
    <div
      class="mx-auto flex size-10 items-center justify-center rounded-full bg-muted text-muted-foreground"
    >
      <Icon class="size-5" aria-hidden="true" />
    </div>
  {/if}
  <h3 class="text-lg font-semibold">{title}</h3>
  {#if body}
    <p class="text-sm text-muted-foreground max-w-sm mx-auto">{body}</p>
  {/if}
  {#if children}
    <div class="pt-1">
      {@render children()}
    </div>
  {/if}
</div>
