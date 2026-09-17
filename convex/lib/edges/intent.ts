/**
 * The FROZEN provisioning intent of an L7 (CDN) edge, and the binding a front
 * qualification is valid for.
 *
 * An L7 edge depends on things that live OUTSIDE its own row: the account's
 * zone, the referenced DNS account, a TLS configuration, a certificate
 * authority, the slot's origin transport, the rendered template. All of them
 * may be edited while the edge exists. If a later step, a discovery, a describe
 * or a destroy re-read them, an operator's edit mid-rotation would make FCP
 * create one resource and then look for (or delete) a different one.
 *
 * So the intent is computed ONCE, when the edge is planned, stored as JSON on
 * the edge, and read by everything afterwards. Account settings and templates
 * are read only when planning a NEW edge. L4 edges have no intent (their whole
 * configuration is the listener list, which is already frozen on the row).
 *
 * The same reasoning gives the qualification BINDING: an authenticated test
 * session proves one exact configuration, so the publishing mutation re-derives
 * the binding from the current slot/profile/intent and refuses a qualification
 * that no longer describes what would be published.
 */
import { canonicalJson } from './providers/template';
import { edgeHostnameFor } from './hostname';
import { edgeLayerOf, zoneModeGovernsOrigin } from './providers/capabilities';
import type { SlotProtocol } from './protocols';
import { zoneModeCarriesOrigin, type OriginTransport } from './layers';

/** FNV-1a 64-bit as 16 hex chars (isolate-safe, no WebCrypto; same function the template hash uses). */
export function intentFnv1a64Hex(input: string): string {
  let h = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  for (let i = 0; i < input.length; i++) {
    h ^= BigInt(input.charCodeAt(i));
    h = (h * prime) & 0xffffffffffffffffn;
  }
  return h.toString(16).padStart(16, '0');
}

/** The intent's own copy of the slot's declaration (mutable: it crosses the action boundary). */
export interface FrozenOriginTransport {
  scheme: 'http' | 'https';
  certPublic: boolean;
  certNames: string[];
  acceptsHostHeader: 'any' | 'names';
}

export interface ProvisionIntent {
  /** The public hostname members connect to; every provider call and discovery uses it. */
  hostname: string;
  zoneId: string;
  zoneName: string;
  /** The Cloudflare account whose credentials write this edge's DNS (Fastly edges). */
  dnsAccountId?: string;
  tlsConfigurationId?: string;
  certificateAuthority?: string;
  originTransport: FrozenOriginTransport;
  originPort: number;
  /**
   * The zone's encryption mode at plan time; a live change is surfaced, never
   * followed. Present only for a provider that is the zone's own proxy
   * (`providesDns`); for any other L7 front the mode does not describe the
   * origin leg and is deliberately absent.
   */
  zoneSslMode?: string;
  templateHash: string;
  /** The EFFECTIVE rendered template values, so no step ever needs the template row again. */
  templateParams: Record<string, unknown>;
}

export interface IntentAccountLike {
  id: string;
  provider: string;
  settings: Record<string, unknown>;
  /**
   * What the credential test OBSERVED at the provider (`edgeProviderAccounts
   * .observedSettings`): facts planning needs that the operator never enters,
   * above all the zone's encryption mode.
   */
  observedSettings?: Record<string, string>;
}

/** Read an account's stored `observedSettings` blob; anything unusable is `{}`. */
export function parseObservedSettings(json: string | null | undefined): Record<string, string> {
  if (!json) return {};
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    return {};
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(raw as Record<string, unknown>))
    if (typeof v === 'string') out[k] = v;
  return out;
}

export interface IntentSlotLike {
  originPort: number;
  originTransport?: OriginTransport | null;
}

export interface BuildIntentArgs {
  account: IntentAccountLike;
  /** The referenced Cloudflare DNS account, for a provider that needs one (Fastly). */
  dnsAccount?: IntentAccountLike | null;
  /** The provider-side resource name (`edges.name`); the hostname label is derived from it. */
  specName: string;
  /** The effective, already rendered template params. */
  templateParams: Record<string, unknown>;
  templateHash: string;
  slot: IntentSlotLike;
  /**
   * Overrides the observed zone mode (tests, an operator-forced re-plan).
   * Ignored for a provider the zone mode does not govern.
   */
  zoneSslMode?: string;
  /**
   * Import only: the hostname that already exists at the provider. A provisioned
   * edge MINTS its hostname from the resource name; an adopted one must keep the
   * name the operator's resource already serves.
   */
  hostnameOverride?: string;
}

/** Thrown when an L7 edge is planned without what its intent needs; the rotation fails with the code. */
export class IntentError extends Error {
  constructor(public code: string) {
    super(code);
    this.name = 'IntentError';
  }
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

/**
 * The frozen intent for one new edge, or `null` for an L4 provider (nothing to
 * freeze). Throws `IntentError` with a short code when the account or the slot
 * cannot describe an L7 edge at all.
 */
export function buildProvisionIntent(a: BuildIntentArgs): ProvisionIntent | null {
  if (edgeLayerOf(a.account.provider) !== 'l7') return null;
  // The zone lives on the account itself (a provider that hosts its own DNS) or
  // on the referenced DNS account (a provider whose records FCP writes elsewhere).
  const zoneSource = a.dnsAccount ?? a.account;
  const zoneId = str(zoneSource.settings.zoneId);
  const zoneName = str(zoneSource.settings.zoneName);
  if (!zoneId || !zoneName) throw new IntentError('dns_zone_missing');
  const originTransport = a.slot.originTransport ?? null;
  if (!originTransport) throw new IntentError('origin_transport_missing');
  const tpl = a.templateParams;
  const hostname =
    a.hostnameOverride ??
    edgeHostnameFor(a.specName, zoneName, {
      labelLength: typeof tpl.labelLength === 'number' ? tpl.labelLength : 12,
      labelPrefix: str(tpl.labelPrefix),
    });
  // The zone's encryption mode decides how the front dials the origin ONLY
  // when the CDN fronting this edge is the zone's own proxy (`providesDns`).
  // It is OBSERVED at the provider (the credential test), never entered, so
  // such an account nobody has tested cannot be planned against: guessing a
  // mode would silently front a plaintext origin over HTTPS, or the other way
  // round. For a front whose records are only unproxied CNAMEs in someone
  // else's zone the mode is irrelevant: it is neither required nor frozen, and
  // it never refuses the origin transport.
  const zoneModeApplies = zoneModeGovernsOrigin(a.account.provider);
  const zoneSslMode = zoneModeApplies
    ? (a.zoneSslMode ?? zoneSource.observedSettings?.zoneSslMode)
    : undefined;
  if (zoneModeApplies) {
    if (!zoneSslMode) throw new IntentError('zone_mode_unknown');
    if (!zoneModeCarriesOrigin(zoneSslMode, originTransport))
      throw new IntentError('origin_tls_mismatch');
  }
  return {
    hostname,
    zoneId,
    zoneName,
    ...(a.dnsAccount ? { dnsAccountId: a.dnsAccount.id } : {}),
    ...(str(a.account.settings.tlsConfigurationId)
      ? { tlsConfigurationId: str(a.account.settings.tlsConfigurationId) }
      : {}),
    ...(str(a.account.settings.certificateAuthority)
      ? { certificateAuthority: str(a.account.settings.certificateAuthority) }
      : {}),
    originTransport: {
      scheme: originTransport.scheme,
      certPublic: originTransport.certPublic,
      certNames: [...originTransport.certNames],
      acceptsHostHeader: originTransport.acceptsHostHeader,
    },
    originPort: a.slot.originPort,
    ...(zoneSslMode ? { zoneSslMode } : {}),
    templateHash: a.templateHash,
    templateParams: tpl,
  };
}

export function intentHash(intent: ProvisionIntent): string {
  return intentFnv1a64Hex(canonicalJson(intent));
}

/** Read a stored intent back; a missing or malformed blob is `null`, never a guess. */
export function parseIntent(json: string | null | undefined): ProvisionIntent | null {
  if (!json) return null;
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    return null;
  }
  if (!raw || typeof raw !== 'object') return null;
  const o = raw as Record<string, unknown>;
  const ot = o.originTransport as Record<string, unknown> | undefined;
  if (typeof o.hostname !== 'string' || typeof o.zoneId !== 'string' || !ot) return null;
  return o as unknown as ProvisionIntent;
}

// --- qualification binding ---------------------------------------------------------------

export interface QualificationBinding {
  hostname: string;
  slotId: string;
  slotRevision: number;
  profileId: string;
  profileRevision: number;
  protocol: SlotProtocol;
  transportParamsHash: string;
  intentHash: string;
}

export interface BindingArgs {
  slot: {
    _id: string;
    revision?: number;
    originPort: number;
    originTransport?: OriginTransport | null;
  };
  profile: { _id: string; revision?: number; protocol: SlotProtocol };
  intent: ProvisionIntent;
  /**
   * Transport parameters the deployed Host carries beyond what the slot row
   * holds (path, service name, upgrade token). Absent = the slot's own shape is
   * the whole transport description.
   */
  transportParams?: Record<string, unknown>;
}

/**
 * The exact configuration a front qualification is a proof OF. Everything a
 * change of which would invalidate the proof is in here, so a stale binding is
 * not a qualification.
 */
export function qualificationBinding(a: BindingArgs): QualificationBinding {
  return {
    hostname: a.intent.hostname,
    slotId: a.slot._id,
    slotRevision: a.slot.revision ?? 0,
    profileId: a.profile._id,
    profileRevision: a.profile.revision ?? 0,
    protocol: a.profile.protocol,
    transportParamsHash: intentFnv1a64Hex(
      canonicalJson({
        protocol: a.profile.protocol,
        originPort: a.slot.originPort,
        originTransport: a.slot.originTransport ?? null,
        ...(a.transportParams ?? {}),
      }),
    ),
    intentHash: intentHash(a.intent),
  };
}

export interface StoredQualification {
  ok: boolean;
  code?: string;
  checkedAt: number;
  expiresAt: number;
  binding: QualificationBinding;
}

export type QualificationVerdict = 'ok' | 'missing' | 'failed' | 'expired' | 'stale';

/**
 * Whether the stored qualification still proves `binding`. `missing`/`failed`
 * mean nothing was proven; `expired` and `stale` mean the proof no longer
 * describes what would be published.
 */
export function qualificationVerdict(
  stored: StoredQualification | null | undefined,
  binding: QualificationBinding,
  now: number,
): QualificationVerdict {
  if (!stored) return 'missing';
  if (!stored.ok) return 'failed';
  if (stored.expiresAt <= now) return 'expired';
  const b = stored.binding;
  const same =
    b.hostname === binding.hostname &&
    b.slotId === binding.slotId &&
    b.slotRevision === binding.slotRevision &&
    b.profileId === binding.profileId &&
    b.profileRevision === binding.profileRevision &&
    b.protocol === binding.protocol &&
    b.transportParamsHash === binding.transportParamsHash &&
    b.intentHash === binding.intentHash;
  return same ? 'ok' : 'stale';
}

export function qualificationCurrent(
  stored: StoredQualification | null | undefined,
  binding: QualificationBinding,
  now: number,
): boolean {
  return qualificationVerdict(stored, binding, now) === 'ok';
}

/** The publish refusal code for a verdict (`ok` has none). */
export function qualificationRefusal(v: QualificationVerdict): string | null {
  switch (v) {
    case 'ok':
      return null;
    case 'expired':
    case 'stale':
      return 'front_qualification_stale';
    default:
      return 'front_unqualified';
  }
}
