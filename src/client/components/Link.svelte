<script lang="ts">
  import { router } from '../stores/router.svelte';

  interface Props {
    href: string;
    class?: string;
    children?: import('svelte').Snippet;
    onclick?: (e: MouseEvent) => void;
    [key: string]: unknown;
  }

  let { href, class: cls, children, onclick: onClickProp, ...rest }: Props = $props();

  function handle(e: MouseEvent) {
    // Run the caller's own onclick first (e.g. closing the mobile nav drawer).
    // It MUST be pulled out of `...rest`, otherwise a caller-supplied onclick
    // would overwrite this handler in the spread and we'd lose SPA navigation.
    onClickProp?.(e);
    if (e.defaultPrevented) return;
    // Allow ⌘/ctrl-click and middle-click to open in new tab as expected.
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return;
    e.preventDefault();
    router.navigate(href);
  }
</script>

<a {href} class={cls} {...rest} onclick={handle}>
  {#if children}{@render children()}{/if}
</a>
