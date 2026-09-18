<script lang="ts">
  /**
   * What the provider answered on a failed call, folded away by default. The
   * server has already replaced addresses and the credential, and capped it.
   *
   * Props:
   *   detail: string | null | undefined   renders nothing when empty
   */
  interface Props {
    detail: string | null | undefined;
  }
  let { detail }: Props = $props();
</script>

{#if detail}
  <details class="text-sm">
    <summary class="text-muted-foreground hover:text-foreground cursor-pointer select-none">
      Show the provider's answer
    </summary>
    <pre
      class="bg-muted mt-2 max-h-48 overflow-auto rounded-md p-3 text-xs break-words whitespace-pre-wrap">{detail}</pre>
    <p class="text-muted-foreground mt-1 text-xs">
      Addresses and the credential are replaced before this is shown.
    </p>
  </details>
{/if}
