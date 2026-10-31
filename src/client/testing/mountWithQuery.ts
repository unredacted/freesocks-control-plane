import type { QueryClient } from '@tanstack/svelte-query';
import { mount, type Component } from 'svelte';
import QueryHost from './QueryHost.svelte';

/**
 * Component tests (`*.svelte.test.ts`): mounts `component` into the document
 * under `client`. `props` may be a `$state` object: the test changes a prop by
 * assigning to it. Unmount what this returns after the test.
 */
export function mountWithQuery<P extends Record<string, unknown>>(
  client: QueryClient,
  component: Component<P>,
  props: P,
) {
  const host: Component<{ client: QueryClient; component: Component<P>; props: P }> = QueryHost;
  return mount(host, { target: document.body, props: { client, component, props } });
}
