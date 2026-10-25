/**
 * The wire contract between FCP and its client-check service (the
 * `edge-client-check` container, docker/edge-client-check/server.ts; docs/edges.md
 * § "FCP's own client check"). Pure and runtime-neutral: the Convex action that
 * calls the service and the service itself import it, so the two never disagree.
 *
 * The service runs ONE real client engine with ONE outbound FCP built from its
 * own check credential's test link, fetches an egress-IP page through it, and
 * answers what happened. It takes requests only from FCP (`signing.ts`).
 */
import type {
  ClientCheckEngine,
  ClientCheckSessionCode,
} from '../../../../src/shared/contracts/edgeCodes';

export const CLIENT_CHECK_PATHS = { check: '/v1/check', health: '/v1/health' } as const;

/** Milliseconds since the epoch, as decimal text. */
export const CLIENT_CHECK_TIME_HEADER = 'x-fcp-check-time';
/** Lower-case hex HMAC-SHA256 (`signing.ts`). */
export const CLIENT_CHECK_SIGNATURE_HEADER = 'x-fcp-check-signature';
/** A request whose time is further than this from the service's clock is refused. */
export const CLIENT_CHECK_MAX_SKEW_MS = 60_000;
/** The largest request body the service reads. */
export const CLIENT_CHECK_MAX_BODY_BYTES = 16_384;

/** How long the engine has to start listening, and the fetch through it to answer. */
export const CLIENT_CHECK_START_MS = 5_000;
export const CLIENT_CHECK_FETCH_MS = 15_000;
/** What FCP waits for one answer: both bounds above plus the engine's teardown. */
export const CLIENT_CHECK_CALL_MS = 30_000;

export interface ClientCheckRequest {
  engine: ClientCheckEngine;
  /** The engine's own outbound object (sing-box `outbounds[]` entry, Xray `outbounds[]` entry). */
  outbound: Record<string, unknown>;
  /** The outbound speaks REALITY: a handshake handed to the target reads as a refusal. */
  reality: boolean;
}

export interface ClientCheckResponse {
  ok: boolean;
  engine: ClientCheckEngine;
  engineVersion: string | null;
  /** The address the egress page saw, canonical; null unless the fetch answered one. */
  egressIp: string | null;
  ms: number;
  code: ClientCheckSessionCode;
}

export interface ClientCheckHealth {
  ok: true;
  engines: Array<{ engine: ClientCheckEngine; version: string | null }>;
  /** The egress page's host (never its path or query). */
  egressHost: string;
}

/** Refusals carry this envelope, like every FCP error. */
export interface ClientCheckError {
  error: { code: string; message: string };
}

/** The service's refusal codes (HTTP status in the comment). */
export type ClientCheckRefusal =
  | 'not_configured' // 503: no secret set
  | 'unauthorized' // 401: signature, time or replay
  | 'busy' // 429: a session is running
  | 'invalid_request' // 400: body shape
  | 'unsupported_type' // 400: an outbound type the allowlist does not hold
  | 'destination_not_public' // 400: the outbound dials a private, reserved or named address
  | 'too_large'; // 413
