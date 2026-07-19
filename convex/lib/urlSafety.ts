/**
 * Outbound-URL safety for operator-registered infrastructure (backend panels,
 * S3 mirror providers). The control plane fetches these URLs on a schedule
 * (healthchecks), at issuance, and on admin test-connection, so a registered
 * URL is a DURABLE SSRF primitive — notably because `admin:servers:write` /
 * `admin:settings:write` automation tokens (not just a full admin cookie) can
 * register them. (Review D-M4.)
 *
 * WHATWG URL canonicalizes IPv4 hosts (hex/octal/short forms → dotted quad),
 * so checking the parsed hostname covers the encoding tricks. Panels and
 * buckets legitimately live on private RFC1918 addresses, so private space is
 * ALLOWED; the denylist is loopback, link-local (incl. the cloud metadata
 * address 169.254.169.254), the unspecified address, and obvious metadata
 * hostnames — none of which is ever a legitimate panel/bucket on this
 * deployment shape. Set ALLOW_INTERNAL_BACKENDS=true to lift the deny (dev
 * panels on the same host).
 *
 * This is prefix filtering, not DNS pinning: a hostname that RESOLVES to a
 * denied address still passes (no DNS in mutations). It raises the bar from
 * "anything" to "no literal internal addresses"; full DNS-rebinding protection
 * would need egress policy outside the app.
 */

/** Lowercased, bracket-stripped hostname → true when it must not be fetched. */
function isDeniedHost(hostname: string): boolean {
  let h = hostname.toLowerCase();
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);

  // Hostname denylist (exact or suffix): localhost + cloud metadata names.
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (h === 'metadata.google.internal' || h === 'metadata') return true;

  // IPv6: loopback, unspecified, link-local.
  if (h === '::1' || h === '::' || h === '0:0:0:0:0:0:0:1' || h === '0:0:0:0:0:0:0:0') return true;
  if (h.includes(':')) {
    // fe80::/10 → first hextet 0xfe80..0xfebf.
    const first = parseInt(h.split(':')[0] || '0', 16);
    if (first >= 0xfe80 && first <= 0xfebf) return true;
    return false; // other IPv6 (incl. ULA fc00::/7 — legitimately private)
  }

  // IPv4 (already canonicalized by WHATWG URL): 127/8 loopback, 169.254/16
  // link-local (cloud metadata), 0.0.0.0.
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = Number(m[1]);
    const b = Number(m[2]);
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 0) return true;
  }
  return false;
}

export interface UrlSafetyResult {
  ok: boolean;
  reason?: string;
}

/**
 * Validate an operator-supplied infra URL: http(s) shape + the SSRF denylist
 * above. Returns a reason string when rejected (safe to show the operator).
 */
export function checkInfraUrl(raw: string): UrlSafetyResult {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return { ok: false, reason: 'not a valid URL' };
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    return { ok: false, reason: 'must be an http(s) URL' };
  }
  if (process.env.ALLOW_INTERNAL_BACKENDS === 'true') return { ok: true };
  if (isDeniedHost(u.hostname)) {
    return {
      ok: false,
      reason:
        'points at a loopback/link-local/metadata address, which is not allowed for a backend ' +
        '(set ALLOW_INTERNAL_BACKENDS=true to override for local development)',
    };
  }
  return { ok: true };
}
