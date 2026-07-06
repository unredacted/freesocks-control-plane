import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// shadcn-svelte component prop helpers: the generated UI components import
// these to strip the `child` / `children` snippet props from delegated
// HTMLAttributes so consumers can spread the rest onto the root element
// without TS complaining about unrecognized JSX-ish attributes.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type WithoutChild<T> = T extends { child?: any } ? Omit<T, 'child'> : T;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type WithoutChildren<T> = T extends { children?: any } ? Omit<T, 'children'> : T;
export type WithoutChildrenOrChild<T> = WithoutChildren<WithoutChild<T>>;
export type WithElementRef<T, U extends HTMLElement = HTMLElement> = T & { ref?: U | null };

/**
 * The member-facing subscription URL. When the subscription carries an FCP
 * `subToken`, build the FCP-fronted URL from the CURRENT origin — the SPA and the
 * `/api` surface share one public origin, so `<origin>/api/v1/sub/<token>` is
 * same-origin and routes to Convex, which serves the config (cached) and hides the
 * backend panel URL. Building it here (not server-side) needs no deployment-origin
 * env var and fronts every UI surface uniformly. The token arrives HPKE-sealed in
 * the account reveal-leg; only the proxy client's later fetch of this URL is
 * necessarily unsealed (a dumb client can't decrypt). Falls back to the raw backend
 * URL for legacy subscriptions issued before the token existed.
 */
export function subscriptionDisplayUrl(
  subToken: string | null | undefined,
  backendUrl: string,
): string {
  if (subToken && typeof location !== 'undefined') {
    return `${location.origin}/api/v1/sub/${subToken}`;
  }
  return backendUrl;
}

export function formatBytes(bytes: number, decimals = 1): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(decimals))} ${sizes[i]}`;
}

/**
 * Whole days from now until `when` (rounded up; negative = in the past). Returns
 * null when `when` is absent or unparseable. Single source for the "N days
 * left / resets in N days" hints (previously inlined in SubscriptionHero + Account).
 */
export function daysUntil(when: string | number | Date | null | undefined): number | null {
  if (when == null) return null;
  const ms = when instanceof Date ? when.getTime() : new Date(when).getTime();
  if (Number.isNaN(ms)) return null;
  return Math.ceil((ms - Date.now()) / 86_400_000);
}
