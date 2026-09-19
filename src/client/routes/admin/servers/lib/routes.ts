/**
 * Admin -> Servers paths. The only place the section's paths are spelled.
 *
 *   /admin/servers[?instance=<slug>]    the nodes of one instance
 */
export const SERVERS_ROOT = '/admin/servers';

export const serversPaths = {
  /** The nodes page; `instance` selects a backend server by slug. */
  home: (opts: { instance?: string } = {}) =>
    opts.instance ? `${SERVERS_ROOT}?instance=${encodeURIComponent(opts.instance)}` : SERVERS_ROOT,
};

/** The instance a URL selects, else the first observable one, else the first. */
export function pickInstance(
  search: string,
  instances: readonly { slug: string; observable: boolean }[],
): string | null {
  const wanted = new URLSearchParams(search).get('instance');
  if (wanted && instances.some((i) => i.slug === wanted)) return wanted;
  return (instances.find((i) => i.observable) ?? instances[0])?.slug ?? null;
}
