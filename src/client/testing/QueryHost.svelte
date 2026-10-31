<script lang="ts" generics="P extends Record<string, unknown>">
  /**
   * Component tests: what `mountWithQuery` mounts, one component under a query
   * client as App.svelte does for the app.
   */
  import { QueryClientProvider, type QueryClient } from '@tanstack/svelte-query';
  import type { Component } from 'svelte';

  let {
    client,
    component: Mounted,
    props,
  }: { client: QueryClient; component: Component<P>; props: P } = $props();
</script>

<QueryClientProvider {client}>
  <Mounted {...props} />
</QueryClientProvider>
