/**
 * The argument validator of a typed profile edit (lib/backend/patchOps.ts), in
 * Convex terms. Its own module: the claim (backendWrites.ts) and the staged
 * port change (backendPortChanges.ts) both take it, and neither may import the
 * other's module graph just for a validator.
 */
import { v } from 'convex/values';

const transportTemplate = v.union(
  v.object({
    kind: v.union(v.literal('reality'), v.literal('xhttp-reality')),
    port: v.number(),
    target: v.string(),
    serverNames: v.array(v.string()),
    acceptProxyProtocol: v.boolean(),
  }),
  v.object({ kind: v.literal('ws'), port: v.number(), path: v.string() }),
);

export const patchOp = v.union(
  v.object({
    op: v.literal('setRealityServerNames'),
    inboundTag: v.string(),
    names: v.array(v.string()),
  }),
  v.object({ op: v.literal('setRealityTarget'), inboundTag: v.string(), target: v.string() }),
  v.object({ op: v.literal('setInboundPort'), inboundTag: v.string(), port: v.number() }),
  v.object({
    op: v.literal('addInboundFromTemplate'),
    inboundTag: v.string(),
    template: transportTemplate,
  }),
);
