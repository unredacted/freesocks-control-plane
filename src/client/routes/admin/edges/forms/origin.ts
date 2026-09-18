/**
 * The origin of a relay as the forms hold it (pure; unit-tested).
 *
 * One flat draft covers the three origin kinds so a segmented control can
 * switch kind without losing what was typed. The admin create call names the
 * backend by ID, the guided-setup draft names it by SLUG: both projections
 * live here so no form builds either shape by hand.
 *
 * Exports:
 *   OriginDraft, emptyOrigin()
 *   addressIssue(raw)                 null when the address is a public IP literal or DNS name
 *   originIssue(o)                    the first thing still missing, in words (null = complete)
 *   toCreateOrigin(o) / toWireOrigin(o)
 *   suggestSlug(o)                    a slug proposal from the node / backend name
 */
import type { z } from 'zod';
import type { RelayWireOrigin } from '@shared/contracts/edges';
import type { CreateRelayOrigin } from '@client/lib/edgesApi';
import { normalizeHostname } from '../lib/tags';

export type OriginKind = 'panel-node' | 'backend-server' | 'manual';

export interface OriginDraft {
  kind: OriginKind;
  backendServerId: string;
  backendSlug: string;
  nodeName: string;
  nodeUuid: string | null;
  /** What edges dial. Never shown to members. */
  address: string;
}

export const emptyOrigin = (kind: OriginKind = 'panel-node'): OriginDraft => ({
  kind,
  backendServerId: '',
  backendSlug: '',
  nodeName: '',
  nodeUuid: null,
  address: '',
});

function ipv4Octets(s: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  return o.every((n) => n <= 255) ? o : null;
}

function privateV4(o: number[]): boolean {
  const [a = 0, b = 0] = o;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a >= 224
  );
}

function privateV6(s: string): boolean {
  const a = s.toLowerCase();
  return (
    a === '::' ||
    a === '::1' ||
    a.startsWith('fe8') ||
    a.startsWith('fe9') ||
    a.startsWith('fea') ||
    a.startsWith('feb') ||
    a.startsWith('fc') ||
    a.startsWith('fd') ||
    a.startsWith('ff')
  );
}

/** Why `raw` cannot be an origin address, in words; null when it can. */
export function addressIssue(raw: string): string | null {
  const s = raw.trim();
  if (s === '') return 'Enter the address edges should dial.';
  if (/[\s/]/.test(s) || s.includes('://'))
    return 'Enter a bare IP address or DNS name, without a scheme, a path or a port.';
  const v4 = ipv4Octets(s);
  if (v4) return privateV4(v4) ? 'This is a private or reserved address. Use a public one.' : null;
  if (/^\d+(\.\d+)*$/.test(s)) return 'This is not a valid IPv4 address.';
  if (s.includes(':')) {
    if (!/^[0-9a-f:]+$/i.test(s) || s.length < 3) return 'This is not a valid IPv6 address.';
    return privateV6(s) ? 'This is a private or reserved address. Use a public one.' : null;
  }
  const name = normalizeHostname(s);
  if (!name) return 'This is not a valid DNS name.';
  if (name === 'localhost' || /\.(local|localhost|internal|lan|home\.arpa)$/.test(name))
    return 'This name only resolves on a private network. Use a public one.';
  return null;
}

export function originIssue(o: OriginDraft): string | null {
  if (o.kind === 'panel-node') {
    if (!o.backendServerId) return 'Choose the panel the node belongs to.';
    if (!o.nodeName) return 'Choose the node.';
  } else if (o.kind === 'backend-server') {
    if (!o.backendServerId) return 'Choose the backend server.';
  }
  return addressIssue(o.address);
}

export function toCreateOrigin(o: OriginDraft): CreateRelayOrigin {
  if (o.kind === 'panel-node')
    return {
      kind: 'panel-node',
      backendServerId: o.backendServerId,
      nodeName: o.nodeName,
      ...(o.nodeUuid ? { nodeUuid: o.nodeUuid } : {}),
    };
  if (o.kind === 'backend-server')
    return { kind: 'backend-server', backendServerId: o.backendServerId };
  return { kind: 'manual' };
}

/** The draft's origin for `POST setup-status`; null until enough is chosen to judge it. */
export function toWireOrigin(o: OriginDraft | null): z.infer<typeof RelayWireOrigin> | null {
  if (!o) return null;
  if (o.kind === 'manual') return { kind: 'manual' };
  if (!o.backendSlug) return null;
  if (o.kind === 'backend-server') return { kind: 'backend-server', backendSlug: o.backendSlug };
  if (!o.nodeName) return null;
  return {
    kind: 'panel-node',
    backendSlug: o.backendSlug,
    nodeName: o.nodeName,
    ...(o.nodeUuid ? { nodeUuid: o.nodeUuid } : {}),
  };
}

export function slugify(raw: string): string {
  return raw
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48);
}

export function suggestSlug(o: OriginDraft): string {
  if (o.kind === 'panel-node') return slugify(o.nodeName);
  if (o.kind === 'backend-server') return slugify(o.backendSlug);
  return '';
}
