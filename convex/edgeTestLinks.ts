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
import { ConvexError, v } from 'convex/values';
import type { FunctionReturnType } from 'convex/server';
import { internalAction, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { capabilitiesOf } from './lib/backends/capabilities';
import type { BackendHost } from './lib/backends/types';
import { resolveEdgeConfig } from './lib/edgeConfig';
import { sameAddress } from './lib/edges/hosts';
import { effectiveRule, type DeliveryStyle, type EffectiveRule } from './lib/edges/render';
import { decodeLinkList, linkAddresses } from './lib/edges/render/links';
import { fragmentText, parseProxyUri, uriAgrees, uriSupported } from './lib/edges/render/uri';
import { applyEdgeRender } from './lib/edges/renderPipeline';
import type { ListenerProto } from './lib/edges/protocols';
import { needsEndpointVerification, verificationBinding } from './lib/edges/verification';
import { toPublishedEdge } from './edgeRender';
import { listenerRemark } from './relayListeners';

/** A link-list client the backend serves plain share links to (the test link is always `links`). */
export const TEST_LINK_USER_AGENT = 'v2rayNG/1.8.29';
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
    const binding = verificationBinding(edge, listener);
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
    return {
      relayId: relay._id,
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
      published: toPublishedEdge(edge, listener, 0, true),
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
    const picked = selectTestEntry(fetched.content, c, hosts);
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
