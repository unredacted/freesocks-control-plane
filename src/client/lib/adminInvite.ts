export function adminInviteUrl(origin: string, token: string): string {
  const url = new URL('/admin/register', origin);
  url.hash = new URLSearchParams({ invite: token }).toString();
  return url.href;
}

/** A token in the query may already have been logged. Only a fragment can authorize enrollment. */
export function readAdminInvite(href: string): { token: string; cleanPath: string } {
  const url = new URL(href);
  const fragment = new URLSearchParams(url.hash.slice(1));
  const token = url.searchParams.has('invite') ? '' : (fragment.get('invite') ?? '');
  url.searchParams.delete('invite');
  return { token, cleanPath: url.pathname + url.search };
}
