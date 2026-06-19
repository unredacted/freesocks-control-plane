<script lang="ts">
  /**
   * The canonical inline error box. This `bg-destructive/10` recipe was
   * copy-pasted across Login / GetAccount / Account / CapWidget / QrCode, and a
   * couple of spots rendered errors as bare red text (easy to miss on a flaky,
   * censored network). Centralizing it keeps every inline failure consistent.
   */
  interface Props {
    message: string;
    /** Extra classes (e.g. width/centering for an empty-state error). */
    class?: string;
  }
  let { message, class: cls = '' }: Props = $props();
</script>

<div
  class="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive {cls}"
  role="alert"
>
  {message}
</div>
