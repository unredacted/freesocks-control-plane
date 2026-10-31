<script lang="ts">
  /**
   * Consistent section header: a display title and a one-line description.
   * `divider` draws the hairline that separates this section from the one
   * above it.
   */
  interface Props {
    title: string;
    description?: string;
    divider?: boolean;
  }
  let { title, description, divider = false }: Props = $props();
</script>

<div class="space-y-1.5 {divider ? 'border-t border-border pt-6' : ''}">
  <h2 class="text-2xl font-bold leading-tight tracking-[-0.01em] rtl:tracking-normal">{title}</h2>
  {#if description}
    <p class="text-body">{description}</p>
  {/if}
</div>
