/**
 * Zod schemas for the subset of Outline Manager API responses we consume.
 * The stock Outline API surface is documented at
 * https://github.com/Jigsaw-Code/outline-server — we model only what the
 * client actually calls. Permissive (`passthrough`) where the upstream may
 * add fields between versions without breaking us.
 */
import { z } from 'zod';

/**
 * Standard Outline access key. `accessUrl` is the `ss://…` URL the user
 * pastes into their VPN client; we hand it through unchanged (optionally
 * with a prefix-disguise query param added in the OutlineBackend layer).
 */
export const OutlineAccessKey = z
  .object({
    id: z.string(),
    name: z.string().nullable().optional(),
    password: z.string().optional(),
    port: z.number().int().optional(),
    method: z.string().optional(),
    accessUrl: z.string(),
    /**
     * Per-key data limit (server-side enforced). Absent if unlimited.
     */
    dataLimit: z
      .object({
        bytes: z.number().int().nonnegative(),
      })
      .optional(),
  })
  .passthrough();
export type OutlineAccessKey = z.infer<typeof OutlineAccessKey>;

/** `POST /access-keys` body for the WebSocket-wrapped fork. Stock Outline ignores this. */
export const OutlineWebsocketBody = z.object({
  enabled: z.boolean(),
  tcpPath: z.string(),
  udpPath: z.string(),
  domain: z.string(),
  tls: z.boolean(),
});
export type OutlineWebsocketBody = z.infer<typeof OutlineWebsocketBody>;

export const OutlineAccessKeysList = z.object({
  accessKeys: z.array(OutlineAccessKey),
});
export type OutlineAccessKeysList = z.infer<typeof OutlineAccessKeysList>;

/**
 * Response shape of `GET /metrics/transfer` — a map of access-key id to
 * total bytes transferred since the server's collection window started.
 *
 * The actual Outline endpoint returns `{ bytesTransferredByUserId: { id: bytes } }`.
 * We unwrap that in the client and expose the inner map directly.
 */
export const OutlineTransferMetrics = z.object({
  bytesTransferredByUserId: z.record(z.string(), z.number().nonnegative()),
});
export type OutlineTransferMetrics = z.infer<typeof OutlineTransferMetrics>;
