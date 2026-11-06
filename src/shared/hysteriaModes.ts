/**
 * Modes whose entries are Hysteria 2 (the built-in `privacy-hysteria`). The
 * entry's certificate is self-signed and trusted by pin alone, so an app that
 * drops the pin either fails to connect or, worse, connects to whoever answers
 * and hands over the member's password. The client catalog's `hysteria2` flag
 * is therefore an allowlist, unlike `xhttp`: only apps marked `true` (recorded
 * evidence, docs/client-compatibility.md § "Hysteria in the client catalog")
 * are offered on these modes; untested ones are left out too. The setup page,
 * the app notice and mode availability (convex/lib/placement.ts) read it.
 * Zod-free: Convex imports it.
 */
import { isXhttpMode } from './xhttpModes';

export const HYSTERIA_MODE_IDS: ReadonlySet<string> = new Set(['privacy-hysteria']);

export function isHysteriaMode(modeId: string | null | undefined): boolean {
  return !!modeId && HYSTERIA_MODE_IDS.has(modeId);
}

/** The catalog flags a mode's app filter reads. */
export interface ModeAppFlags {
  xhttp?: boolean | null;
  hysteria2?: boolean | null;
}

/**
 * Whether a catalog app may be offered to a member on this mode: on an XHTTP
 * mode, anything but `xhttp: false`; on a Hysteria mode, only `hysteria2: true`;
 * on any other mode, every app.
 */
export function appFitsMode(app: ModeAppFlags, modeId: string | null | undefined): boolean {
  if (isXhttpMode(modeId) && app.xhttp === false) return false;
  if (isHysteriaMode(modeId) && app.hysteria2 !== true) return false;
  return true;
}
