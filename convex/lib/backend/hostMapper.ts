/**
 * A backend Host's per-client rewrites (Remnawave 3.x `mapper`), and the ones
 * FCP writes on a Hysteria 2 address (pure).
 *
 * The backend's Mihomo and sing-box generators turn a pinned self-signed
 * certificate into "skip verification" (`skip-cert-verify: true`,
 * `tls.insecure: true`) with no pin. A Hysteria password is the member's VLESS
 * id, so FCP's Hysteria Host rewrites every format to verify by pin only:
 *
 *   base64   `pinSHA256` set, `insecure` and the Xray-only `fm` removed
 *   mihomo   `fingerprint` set to the certificate pin, `skip-cert-verify` removed
 *   singbox  `tls.certificate_public_key_sha256` set to the public-key pin,
 *            `tls.insecure` removed
 *   xrayJson nothing: the backend keeps `pinnedPeerCertSha256` there itself
 *
 * The delivery guard (lib/hysteriaGuard.ts) checks every body anyway; these
 * rewrites are what makes the guard never have anything to drop.
 */
import type { HostMapper } from '../backends/types';
import { canonicalJson } from './digest';

/**
 * A Host mapper as canonical JSON, or null when it carries no operation (the
 * backend answers an empty `{}` or lists for a Host that never had one).
 */
export function hostMapperJson(mapper: unknown): string | null {
  if (!mapper || typeof mapper !== 'object' || Array.isArray(mapper)) return null;
  const m = mapper as Record<string, unknown>;
  const kept = Object.fromEntries(
    ['base64', 'mihomo', 'singbox', 'xrayJson']
      .filter((k) => Array.isArray(m[k]) && (m[k] as unknown[]).length > 0)
      .map((k) => [k, m[k]]),
  );
  return Object.keys(kept).length > 0 ? canonicalJson(kept) : null;
}

/** The rewrites of a Hysteria Host: every format verifies the node by pin, never by a CA or not at all. */
export function hysteriaHostMapper(pins: { pinHex: string; spkiB64: string }): HostMapper {
  return {
    base64: [
      { op: 'set', to: 'pinSHA256', value: pins.pinHex },
      { op: 'unset', to: 'insecure' },
      { op: 'unset', to: 'fm' },
    ],
    mihomo: [
      { op: 'set', to: 'fingerprint', value: pins.pinHex },
      { op: 'unset', to: 'skip-cert-verify' },
    ],
    singbox: [
      { op: 'unset', to: 'tls.insecure' },
      { op: 'set', to: 'tls.certificate_public_key_sha256', value: [pins.spkiB64] },
    ],
  };
}
