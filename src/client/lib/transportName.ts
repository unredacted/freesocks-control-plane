/**
 * The name to show for a backend transport (pure; unit-tested). A transport's
 * tag is its mode's group name upper-cased with `-` as `_`
 * (convex/lib/backend/profileTemplate.ts `transportTagOf`): `Freedom-Reality`
 * becomes `FREEDOM_REALITY`. So the mode's own name is shown when it is at
 * hand, and otherwise the tag read as words ("Freedom REALITY"). A tag that is
 * not one (lower case, a role's listener key) is shown as it is.
 */

/** A name's transport tag, as the backend setup makes it. */
export function tagOfName(name: string): string {
  return name
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, '_');
}

/** Words the tag spells in capitals but people write their own way. */
const WORD: Record<string, string> = {
  WEBSOCKET: 'WebSocket',
  WS: 'WebSocket',
  XHTTP: 'XHTTP',
  REALITY: 'REALITY',
  GRPC: 'gRPC',
  HTTPUPGRADE: 'HTTPUpgrade',
  TCP: 'TCP',
  UDP: 'UDP',
  TLS: 'TLS',
  VLESS: 'VLESS',
  VMESS: 'VMess',
  QUIC: 'QUIC',
};

/**
 * `tag` as people read it: the first of `names` (mode or group names) whose
 * tag it is, else its words ("FREEDOM_WEBSOCKET" -> "Freedom WebSocket").
 */
export function transportName(
  tag: string | null | undefined,
  names: readonly (string | null | undefined)[] = [],
): string {
  const t = (tag ?? '').trim();
  if (!t) return 'a transport';
  const named = names.find((n) => n && n.trim() && tagOfName(n) === t);
  if (named) return named.trim();
  if (!/^[A-Z0-9_]+$/.test(t) || !/[A-Z]/.test(t)) return t;
  return t
    .split('_')
    .filter(Boolean)
    .map((w) => WORD[w] ?? w.charAt(0) + w.slice(1).toLowerCase())
    .join(' ');
}
