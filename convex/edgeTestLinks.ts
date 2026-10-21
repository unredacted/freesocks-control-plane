/**
 * The isolated TEST LINK (docs/edges.md § "Publication"): the one verification
 * mechanism for an L4 candidate that is not yet published (setup stage 4b,
 * spares, retests). It fetches the test credential's OWN subscription body
 * (edgeTestCredentials.ts) and runs the REAL renderer with `published = [this
 * candidate only]` in dry-run: no pool change, no epoch bump, no Host write,
 * no snapshot.
 *
 * Before first publication the FCP Host (and its `<node>-origin-<key>` remark)
 * does not exist in that body, and the renderer only makes a candidate
 * eligible when its listener's source entry matched, so the builder uses a
 * TEST-ONLY MATCHER: it resolves the body's entry for the EXACT intended
 * transport (`panelBinding.configProfileInboundUuid` -> the backend Host(s) on
 * that transport at `originAddress:originPort`, else the listener's own FCP
 * Host once one exists) and checks the entry against the listener's protocol
 * facts. An ambiguous or missing match is refused (`edge.test_link_no_match`);
 * the single matched entry is rendered through a TRANSIENT context (a
 * whole-body matcher over that one entry mapped to the candidate's listener).
 * Persisted listener match rules are never changed, and the output contains
 * ONLY the candidate connection: no direct entry, no backup, no auto group.
 *
 * The response carries the binding the confirmation must echo
 * (`edgeVerification.binding` derives the same one from the same rows), so
 * `POST edges/{id}/verify` accepts it and refuses a mismatch.
 */
import { verificationListenerOf } from './lib/edges/verificationContext';
import { ConvexError, v } from 'convex/values';
import type { FunctionReturnType } from 'convex/server';
import { internalAction, internalQuery } from './_generated/server';
import type { ActionCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { capabilitiesOf } from './lib/backends/capabilities';
import { PROVIDERS, type BackendConfig } from './lib/backends/registry';
import { panelDigestKey } from './lib/backend/key';
import type { BackendHost } from './lib/backends/types';
import { resolveEdgeConfig } from './lib/edgeConfig';
import { sameAddress } from './lib/edges/hosts';
import { hostPort } from './lib/edges/ip';
import { effectiveRule, type DeliveryStyle, type EffectiveRule } from './lib/edges/render';
import { decodeLinkList, linkAddresses } from './lib/edges/render/links';
import { fragmentText, parseProxyUri, uriAgrees, uriSupported } from './lib/edges/render/uri';
import { applyEdgeRender } from './lib/edges/renderPipeline';
import type { ListenerProto } from './lib/edges/protocols';
import {
  learnedBinding,
  needsEndpointVerification,
  verificationBinding,
} from './lib/edges/verification';
import { toPublishedEdge } from './edgeRender';
import { listenerRemark } from './relayListeners';

/** A link-list client the backend serves plain share links to (the test link is always `links`). */
export const TEST_LINK_USER_AGENT = 'v2rayNG/1.8.29';
/** The flow a VLESS REALITY account over raw TCP holds on the backend (Xray refuses any other). */
export const REALITY_RAW_FLOW = 'xtls-rprx-vision';
const TEST_RENDER_KEY = 'fcp-test-link';

export interface TestLinkBinding {
  edgeId: string;
  endpoint: string;
  listenerKey: string;
  listenerRevision: number;
  configHash: string;
  issuedAt: string;
}

export interface TestLinkResult {
  link: string;
  format: 'links';
  binding: TestLinkBinding;
  /** The temporary credential behind the link (Outline), released when the sheet closes. */
  credentialId: string | null;
}

export const context = internalQuery({
  args: { edgeId: v.id('edges') },
  handler: async (ctx, { edgeId }) => {
    const edge = await ctx.db.get(edgeId);
    if (!edge) throw new ConvexError({ code: 'not_found', message: 'Edge not found' });
    if (!needsEndpointVerification(edge))
      throw new ConvexError({
        code: 'edge.l7_proof_required',
        message: 'A CDN front is verified by its authenticated proof, not by a test link',
      });
    if (edge.status !== 'active')
      throw new ConvexError({ code: 'edge.edge_not_active', message: 'The edge is not active' });
    const listener = await ctx.db.get(edge.listenerId);
    if (!listener || listener.retired)
      throw new ConvexError({ code: 'edge.listener_retired', message: 'Listener not found' });
    const relay = await ctx.db.get(edge.relayId);
    if (!relay) throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
    const vl = await verificationListenerOf(ctx.db, listener);
    // An address the edge learned after its confirmation is tested on its own:
    // the link carries that address only, and the binding is the one that serves it.
    const learned = learnedBinding(edge, vl);
    const binding = learned ?? verificationBinding(edge, vl);
    if (!binding)
      throw new ConvexError({ code: 'edge.no_address', message: 'The edge has no address yet' });
    if (!relay.backendServerId)
      throw new ConvexError({
        code: 'edge.test_link_no_match',
        message: 'A manual origin has no credential body to build a test link from',
      });
    const server = await ctx.db.get(relay.backendServerId);
    if (!server) throw new ConvexError({ code: 'backend.not_found' });
    const caps = capabilitiesOf(server.backend);
    const cfg = await resolveEdgeConfig(ctx.db);
    const base = effectiveRule(cfg.render, cfg.render.clients.other);
    const rule: EffectiveRule = {
      ...base,
      enabled: true,
      includeBackup: false,
      maxEntries: 1,
      autoGroup: false,
      dropTemplateEntries: true,
      primaryLabel: `FCP test ${relay.slug} ${listener.listenerKey}`,
    };
    const proto: ListenerProto = {
      protocol: listener.protocol,
      streamTransport: listener.streamTransport,
      security: listener.security,
    };
    // An ENROLLED node's transport has no Host before its first publication
    // (FCP creates a fronted node's Host only when it publishes), so the
    // credential's body carries no entry to template from. For a REALITY
    // listener (raw, or XHTTP under REALITY) the entry is built from the
    // transport's live parameters, as the direct test link is
    // (nodeActivation.buildDirectTestLink).
    const origin = relay.origin;
    const enrolled =
      origin.kind === 'panel-node' &&
      !!(await ctx.db
        .query('panelNodeIntents')
        .withIndex('by_server_name', (q) =>
          q.eq('backendServerId', relay.backendServerId!).eq('name', origin.nodeName),
        )
        .unique());
    const synth =
      enrolled &&
      listener.panelBinding &&
      listener.protocol === 'vless' &&
      listener.security === 'reality' &&
      (listener.streamTransport === 'raw' || listener.streamTransport === 'xhttp')
        ? {
            backend: server.backend,
            config: server.config,
            profileUuid: listener.panelBinding.configProfileUuid,
            tag: listener.panelBinding.inboundTag,
            remark: listenerRemark(listener) ?? listener.listenerKey,
            stream:
              listener.streamTransport === 'xhttp'
                ? ({
                    kind: 'xhttp',
                    path: listener.transportParams?.path ?? '/',
                    mode: listener.transportParams?.mode ?? 'auto',
                  } as const)
                : ({ kind: 'raw' } as const),
          }
        : null;
    return {
      relayId: relay._id,
      synth,
      originAddress: relay.originAddress,
      hostManagement: caps.hostManagement,
      deliveryStyle: (caps.accessKeyDelivery ? 'single-key' : 'subscription') as DeliveryStyle,
      inboundUuid: listener.panelBinding?.configProfileInboundUuid?.toLowerCase() ?? null,
      originPort: listener.originPort,
      ownRemarks: [
        ...(listenerRemark(listener) ? [listenerRemark(listener)!] : []),
        ...(listener.legacyHosts ?? []).map((h) => h.remark),
      ],
      proto,
      listenerKey: listener.listenerKey,
      published: toPublishedEdge(
        learned ? { ...edge, addresses: { ...(edge.learnedAddresses ?? {}) } } : edge,
        listener,
        0,
        true,
      ),
      rule,
      binding,
      epoch: relay.publicationEpoch,
    };
  },
});

type Ctx = FunctionReturnType<typeof internal.edgeTestLinks.context>;

/**
 * The test-only matcher: the ONE line of a link-list body that is the
 * intended transport's entry. `hosts` is the backend's Host list (null when the
 * backend has none: the body is then matched by origin address:port alone).
 */
export function selectTestEntry(
  body: string,
  c: Pick<
    Ctx,
    'originAddress' | 'originPort' | 'inboundUuid' | 'ownRemarks' | 'proto' | 'deliveryStyle'
  >,
  hosts: BackendHost[] | null,
): { line: string } | { code: 'no_match' | 'ambiguous_match' } {
  const decoded = decodeLinkList(body);
  if (!decoded) return { code: 'no_match' };
  const parsed = decoded.lines
    .map((line) => ({ line, uri: parseProxyUri(line) }))
    .filter((e) => e.uri !== null && uriSupported(e.uri, c.proto) && uriAgrees(e.uri, c.proto));
  if (c.deliveryStyle === 'single-key') {
    // A single access key IS the body: one entry, at the origin.
    const atOrigin = parsed.filter(
      (e) => sameAddress(e.uri!.host, c.originAddress) && e.uri!.port === c.originPort,
    );
    if (atOrigin.length === 1) return { line: atOrigin[0].line };
    return { code: atOrigin.length === 0 ? 'no_match' : 'ambiguous_match' };
  }
  // The Hosts on the intended transport (enabled) name the entries by remark.
  const onInbound = (hosts ?? []).filter(
    (h) =>
      !h.isDisabled &&
      c.inboundUuid !== null &&
      (h.inbound?.configProfileInboundUuid ?? '').toLowerCase() === c.inboundUuid,
  );
  const directRemarks = new Set(
    onInbound
      .filter((h) => sameAddress(h.address, c.originAddress) && h.port === c.originPort)
      .map((h) => h.remark),
  );
  const remarkOf = (e: (typeof parsed)[number]) => fragmentText(e.uri!) ?? '';
  // 1. The direct entry: named by a Host on the transport AND at the origin address:port.
  //    Without a Host list (or a backend binding) the address:port alone identifies it.
  const direct = parsed.filter(
    (e) =>
      sameAddress(e.uri!.host, c.originAddress) &&
      e.uri!.port === c.originPort &&
      (hosts === null || c.inboundUuid === null || directRemarks.has(remarkOf(e))),
  );
  if (direct.length === 1) return { line: direct[0].line };
  if (direct.length > 1) return { code: 'ambiguous_match' };
  // 2. The listener's own FCP Host (after first publication, or an adopted legacy Host).
  const own = new Set(c.ownRemarks);
  const ownEntries = parsed.filter((e) => own.has(remarkOf(e)));
  if (ownEntries.length === 1) return { line: ownEntries[0].line };
  return { code: ownEntries.length === 0 ? 'no_match' : 'ambiguous_match' };
}

/**
 * The source entry of an enrolled node's REALITY transport before its first
 * Host exists: the origin's own qualification credential (the one whose body
 * was fetched) at the origin address, with the transport's live REALITY
 * parameters. Rendered like any matched entry; null when either is missing.
 */
async function synthesizedEntry(
  ctx: ActionCtx,
  relayId: Id<'relays'>,
  synth: NonNullable<Ctx['synth']>,
  c: Pick<Ctx, 'originAddress' | 'originPort'>,
): Promise<string | null> {
  const relay = await ctx.runQuery(internal.relays.get, { id: relayId });
  const uuid = relay?.qualificationUserId;
  const writes = PROVIDERS[synth.backend].backendWrites;
  if (!uuid || !writes) return null;
  const params = await writes.readInboundForTest(
    synth.config as BackendConfig,
    synth.profileUuid,
    synth.tag,
    (await panelDigestKey()).key,
  );
  if (!params) return null;
  return realityEntryLine(uuid, c.originAddress, c.originPort, params, synth.remark, synth.stream);
}

/** The stream of a REALITY transport: raw TCP, or XHTTP with its path and mode. */
export type RealityStream = { kind: 'raw' } | { kind: 'xhttp'; path: string; mode: string };

/**
 * One VLESS REALITY share link (pure). Over raw TCP the backend gives its
 * accounts XTLS Vision, and Xray refuses a session asking for another flow;
 * over XHTTP there is no flow and the link carries the path and mode. An IPv6
 * origin is bracketed in the authority.
 */
export function realityEntryLine(
  uuid: string,
  address: string,
  port: number,
  params: { serverNames: string[]; publicKey: string; shortId: string },
  remark: string,
  stream: RealityStream = { kind: 'raw' },
): string {
  const q = new URLSearchParams({
    encryption: 'none',
    ...(stream.kind === 'raw'
      ? { flow: REALITY_RAW_FLOW, type: 'tcp' }
      : { type: 'xhttp', path: stream.path, mode: stream.mode }),
    security: 'reality',
    sni: params.serverNames[0] ?? '',
    fp: 'chrome',
    pbk: params.publicKey,
    sid: params.shortId,
  });
  return `vless://${uuid}@${hostPort(address, port)}?${q.toString()}#${encodeURIComponent(remark)}`;
}

export const build = internalAction({
  args: {
    edgeId: v.id('edges'),
    /**
     * TEST-ONLY: render the link with exactly this server name instead of the
     * listener's own. It lets an operator prove, with the isolated test
     * credential, that the NODE accepts a name before any member is given it.
     * The name reaches no subscription through this path.
     */
    candidateSni: v.optional(v.string()),
  },
  handler: async (ctx, { edgeId, candidateSni }): Promise<TestLinkResult> => {
    const base = await ctx.runQuery(internal.edgeTestLinks.context, { edgeId });
    const c = candidateSni
      ? {
          ...base,
          published: {
            ...base.published,
            serverNames: [{ sni: candidateSni, status: 'active' as const }],
            sniPick: undefined,
          },
        }
      : base;
    const cred = await ctx.runAction(internal.edgeTestCredentials.ensure, {
      relayId: c.relayId as Id<'relays'>,
      purpose: 'test_link',
    });
    if (!cred.ok)
      throw new ConvexError({
        code: `edge.${cred.code}`,
        message: 'No test credential is available for this origin',
      });
    const fetched = await ctx.runAction(internal.backends.fetchSubscriptionContent, {
      backend: cred.fetchRef.backend,
      backendServerId: cred.fetchRef.backendServerId,
      backendShortId: cred.fetchRef.backendShortId,
      subscriptionUrl: cred.fetchRef.subscriptionUrl,
      userAgent: TEST_LINK_USER_AGENT,
      unpinned: true,
    });
    const hosts = c.hostManagement
      ? await ctx.runAction(internal.backends.listHosts, {
          backendServerId: cred.fetchRef.backendServerId,
        })
      : null;
    let picked = selectTestEntry(fetched.content, c, hosts);
    if ('code' in picked && picked.code === 'no_match' && c.synth) {
      const line = await synthesizedEntry(ctx, c.relayId as Id<'relays'>, c.synth, c);
      if (line) picked = { line };
    }
    if ('code' in picked)
      throw new ConvexError({
        code: 'edge.test_link_no_match',
        message:
          picked.code === 'ambiguous_match'
            ? 'The credential body carries more than one entry for this transport'
            : 'The credential body carries no entry for this transport',
      });
    // The transient context: one whole-body matcher over the single entry,
    // mapped to the candidate's listener; the candidate is the whole pool.
    const out = applyEdgeRender(
      {
        epoch: c.epoch,
        matchers: [
          {
            listenerKey: c.listenerKey,
            rule: { kind: 'whole-body' },
            proto: c.proto,
            originAddress: c.originAddress,
            originPort: c.originPort,
          },
        ],
        published: [c.published],
        rule: c.rule,
        preferDistinctProviders: false,
        originAddress: c.originAddress,
        deliveryStyle: c.deliveryStyle,
      },
      picked.line,
      TEST_RENDER_KEY,
      { now: Date.now() },
    );
    if (out.delivery.kind !== 'serve')
      throw new ConvexError({
        code: 'edge.test_link_render_failed',
        message: `The candidate could not be rendered (${out.delivery.reason})`,
      });
    const link = out.body.trim();
    const addresses = linkAddresses(link);
    if (addresses.length !== 1 || addresses.some((a) => sameAddress(a.address, c.originAddress)))
      throw new ConvexError({
        code: 'edge.test_link_render_failed',
        message: 'The rendered test link did not contain exactly the candidate connection',
      });
    return {
      link,
      format: 'links',
      binding: {
        edgeId: edgeId as string,
        endpoint: c.binding.endpoint,
        listenerKey: c.binding.listenerKey,
        listenerRevision: c.binding.listenerRevision,
        configHash: c.binding.configHash,
        issuedAt: new Date().toISOString(),
      },
      credentialId: cred.credentialId ? (cred.credentialId as string) : null,
    };
  },
});
