/**
 * Wire contracts for server management (`/api/v1/admin/servers/*`): what Admin
 * -> Servers shows of a panel's nodes, config profiles, Hosts and squads.
 * Every shape is non-secret by construction: a REALITY inbound carries its
 * server names, its target and its PUBLIC key, never the private key, the
 * short ids or the client list.
 */
import { z } from 'zod';

export const ServerManageConfig = z.object({
  'manage.enabled': z.boolean(),
  'manage.observe': z.boolean(),
});
export type ServerManageConfig = z.infer<typeof ServerManageConfig>;

export const ServerConfigView = z.object({ config: ServerManageConfig });

export const ServerObserveState = z.object({
  observedAt: z.string().nullable(),
  attemptedAt: z.string().nullable(),
  /** null = never looked. */
  ok: z.boolean().nullable(),
  errorCode: z.string().nullable(),
  counts: z
    .object({ nodes: z.number(), profiles: z.number(), hosts: z.number(), squads: z.number() })
    .nullable(),
});
export type ServerObserveState = z.infer<typeof ServerObserveState>;

export const ServerSummary = z.object({
  config: ServerManageConfig,
  instances: z.array(
    ServerObserveState.extend({
      id: z.string(),
      slug: z.string(),
      name: z.string(),
      backend: z.string(),
      isActive: z.boolean(),
      /** Whether this backend type can be observed at all. */
      observable: z.boolean(),
      /** Whether this backend type can be written to at all. */
      writable: z.boolean(),
      /** The node role has reported that it follows the ownership protocol. */
      setUp: z.boolean(),
    }),
  ),
});
export type ServerSummary = z.infer<typeof ServerSummary>;

export const PanelHostView = z.object({
  hostUuid: z.string(),
  remark: z.string(),
  address: z.string(),
  port: z.number(),
  sni: z.string().nullable(),
  host: z.string().nullable(),
  path: z.string().nullable(),
  alpn: z.string().nullable(),
  fingerprint: z.string().nullable(),
  securityLayer: z.string().nullable(),
  isDisabled: z.boolean(),
  isHidden: z.boolean(),
  tag: z.string().nullable(),
  viewPosition: z.number().nullable(),
  configProfileUuid: z.string().nullable(),
  inboundUuid: z.string().nullable(),
  nodeUuids: z.array(z.string()),
});
export type PanelHostView = z.infer<typeof PanelHostView>;

export const PanelInboundView = z.object({
  tag: z.string(),
  inboundUuid: z.string(),
  protocol: z.string(),
  port: z.number().nullable(),
  listen: z.string().nullable(),
  network: z.string(),
  security: z.string(),
  serverNames: z.array(z.string()).nullable(),
  realityTarget: z.string().nullable(),
  tlsServerName: z.string().nullable(),
  path: z.string().nullable(),
  serviceName: z.string().nullable(),
  realityPublicKey: z.string().nullable(),
  /** The profile stores a public key that does not belong to its private key. */
  realityPublicKeyMismatch: z.boolean(),
});
export type PanelInboundView = z.infer<typeof PanelInboundView>;

export const PanelNodeView = z.object({
  nodeUuid: z.string(),
  name: z.string(),
  address: z.string().nullable(),
  port: z.number().nullable(),
  countryCode: z.string().nullable(),
  online: z.boolean(),
  isDisabled: z.boolean(),
  usersOnline: z.number(),
  tags: z.array(z.string()),
  profile: z
    .object({
      profileUuid: z.string(),
      name: z.string(),
      inboundCount: z.number(),
      changedAt: z.string().nullable(),
    })
    .nullable(),
  inbounds: z.array(
    PanelInboundView.extend({
      hosts: z.array(PanelHostView),
      squads: z.array(z.object({ squadUuid: z.string(), name: z.string() })),
    }),
  ),
});
export type PanelNodeView = z.infer<typeof PanelNodeView>;

export const ServerTree = z.object({
  instance: z.object({ id: z.string(), slug: z.string(), name: z.string() }),
  observable: z.boolean(),
  state: ServerObserveState,
  nodes: z.array(PanelNodeView),
  profiles: z.array(
    z.object({
      profileUuid: z.string(),
      name: z.string(),
      shapeHash: z.string(),
      changedAt: z.string().nullable(),
      /** Edited on the panel by something other than FCP, and not yet acknowledged. */
      foreignEditAt: z.string().nullable(),
      nodeCount: z.number(),
      inbounds: z.array(PanelInboundView),
    }),
  ),
  squads: z.array(
    z.object({
      squadUuid: z.string(),
      name: z.string(),
      membersCount: z.number().nullable(),
      inboundTags: z.array(z.string().nullable()),
      inboundUuids: z.array(z.string()),
    }),
  ),
  hosts: z.array(PanelHostView),
  /** What hangs off no node: a profile nothing runs, a Host on an inbound nothing serves. */
  unattached: z.object({ profiles: z.array(z.string()), hosts: z.array(z.string()) }),
});
export type ServerTree = z.infer<typeof ServerTree>;

export const PlacementValidation = z.object({
  observedAt: z.string().nullable(),
  modes: z.array(
    z.object({
      modeSlug: z.string(),
      squads: z.number(),
      unknownHere: z.number(),
      withoutInbounds: z.array(z.string()),
    }),
  ),
});
export type PlacementValidation = z.infer<typeof PlacementValidation>;

// --- writes: the operations ledger ------------------------------------------------------------

export const PanelOpState = z.enum([
  'working',
  'waiting_for_nodes',
  'done',
  'refused',
  'outcome_unknown',
  'recovered',
]);
export type PanelOpState = z.infer<typeof PanelOpState>;

/** One change to a panel: sent once, then looked at until it is seen (docs/servers.md). */
export const PanelOpView = z.object({
  id: z.string(),
  kind: z.enum(['host', 'squad', 'node', 'profile']),
  verb: z.string(),
  label: z.string(),
  state: PanelOpState,
  request: z.string(),
  panelState: z.string(),
  asyncEffect: z.string(),
  open: z.boolean(),
  errorCode: z.string().nullable(),
  createdAt: z.string(),
  settledAt: z.string().nullable(),
  recovered: z.boolean(),
});
export type PanelOpView = z.infer<typeof PanelOpView>;
export const PanelOpList = z.object({ ops: z.array(PanelOpView) });

/** The four conditions an unknown outcome is released on, each attested by name. */
export const RecoveryAttestation = z.object({
  credentialsRevoked: z.boolean(),
  noInFlightExecutor: z.boolean(),
  queueDrained: z.boolean(),
  freshReadAt: z.number(),
  note: z.string().optional(),
});
export type RecoveryAttestation = z.infer<typeof RecoveryAttestation>;

export const HostWrite = z.object({
  remark: z.string(),
  address: z.string(),
  port: z.number(),
  inboundUuid: z.string(),
  sni: z.string().nullable().optional(),
  host: z.string().nullable().optional(),
  path: z.string().nullable().optional(),
  alpn: z.string().nullable().optional(),
  fingerprint: z.string().nullable().optional(),
  isDisabled: z.boolean().optional(),
  restore: z.boolean().optional(),
});
export type HostWrite = z.infer<typeof HostWrite>;

export const NodeWrite = z.object({
  name: z.string(),
  address: z.string(),
  port: z.number().optional(),
  countryCode: z.string().optional(),
  configProfileUuid: z.string(),
  activeInboundUuids: z.array(z.string()),
  restore: z.boolean().optional(),
});
export type NodeWrite = z.infer<typeof NodeWrite>;

export const ProfilePatchOp = z.discriminatedUnion('op', [
  z.object({
    op: z.literal('setRealityServerNames'),
    inboundTag: z.string(),
    names: z.array(z.string()),
  }),
  z.object({ op: z.literal('setRealityTarget'), inboundTag: z.string(), target: z.string() }),
]);
export type ProfilePatchOp = z.infer<typeof ProfilePatchOp>;

// --- bootstrap contract v2: backend setup (modes) --------------------------------------------

/** How a mode's transport reaches members. */
export const ModeTransport = z.enum(['reality', 'xhttp-reality', 'ws']);
export type ModeTransport = z.infer<typeof ModeTransport>;
export const ModeFronting = z.enum(['direct', 'edge-l4', 'edge-l7']);
export type ModeFronting = z.infer<typeof ModeFronting>;
export const ModeShape = z.object({ transport: ModeTransport, fronting: ModeFronting });
export type ModeShape = z.infer<typeof ModeShape>;

/** The combinations a node can be built for. Anything else is refused at setup. */
export const MODE_SHAPES: readonly ModeShape[] = [
  { transport: 'reality', fronting: 'direct' },
  { transport: 'reality', fronting: 'edge-l4' },
  { transport: 'xhttp-reality', fronting: 'edge-l4' },
  { transport: 'ws', fronting: 'edge-l7' },
];
export const shapeAllowed = (s: ModeShape): boolean =>
  MODE_SHAPES.some((m) => m.transport === s.transport && m.fronting === s.fronting);

/**
 * One mode a backend is set up for: the connection mode it feeds, the group
 * name on the backend, its shape, and (REALITY transports) the server-name
 * family whose target and names its transport carries.
 */
export const ModeSetupInput = z.object({
  slug: z.string().min(1).max(40),
  name: z.string().regex(/^[A-Za-z0-9_-]{2,20}$/),
  shape: ModeShape,
  familySlug: z.string().min(1).max(40).optional(),
  /** Edge-fronted REALITY: the L4 forwarder prepends a PROXY-protocol header. */
  acceptProxyProtocol: z.boolean().default(false),
  /** The WebSocket transport's loopback path and port (Caddy proxies to it). */
  ws: z.object({ path: z.string().min(1), port: z.number().int().min(1024).max(65535) }).optional(),
});
export type ModeSetupInput = z.infer<typeof ModeSetupInput>;

/** The four modes a fresh backend is offered (editable; a table, not a fixed set). */
export const DEFAULT_MODE_SETUP: readonly ModeSetupInput[] = [
  {
    slug: 'privacy-reality',
    name: 'Privacy-Reality',
    shape: { transport: 'reality', fronting: 'direct' },
    acceptProxyProtocol: false,
  },
  {
    slug: 'freedom-reality',
    name: 'Freedom-Reality',
    shape: { transport: 'reality', fronting: 'edge-l4' },
    acceptProxyProtocol: false,
  },
  {
    slug: 'freedom-xhttp',
    name: 'Freedom-XHTTP',
    shape: { transport: 'xhttp-reality', fronting: 'edge-l4' },
    acceptProxyProtocol: false,
  },
  {
    slug: 'freedom-ws',
    name: 'Freedom-WebSocket',
    shape: { transport: 'ws', fronting: 'edge-l7' },
    acceptProxyProtocol: false,
    ws: { path: '/ws', port: 8443 },
  },
];

/**
 * Group names an earlier setup gave the same modes. An adopted backend's
 * groups are found under these and renamed in place (their ids and every
 * member assignment survive); nothing is created beside them.
 */
export const LEGACY_GROUP_NAMES: Readonly<Record<string, readonly string[]>> = {
  'privacy-reality': ['FreeSocks-Reality'],
  'freedom-reality': ['FreeSocks-Relay'],
  'freedom-ws': ['FreeSocks-Fronted', 'FreeSocks-Fastly'],
};

/** What "Set up this backend" is asked for. Non-secret: names, shapes, families. */
export const PanelSetupInput = z.object({
  profileName: z.string().min(1).max(60).default('FreeSocks-Config'),
  modes: z.array(ModeSetupInput).min(1).max(12),
  /** The Cloudflare account whose zone WebSocket nodes get their origin names in; null = explicit hostnames per node. */
  originDns: z.object({ accountId: z.string() }).nullable().default(null),
  /** A backend that already has nodes or addresses is taken over only when the operator says so (typed). */
  adopt: z.boolean().default(false),
});
export type PanelSetupInput = z.infer<typeof PanelSetupInput>;

export const PanelSetupState = z.enum(['pending', 'ready', 'failed']);

export const ModeSetupView = z.object({
  slug: z.string(),
  name: z.string(),
  shape: ModeShape,
  familySlug: z.string().nullable(),
  tag: z.string(),
  group: z.object({ uuid: z.string().nullable(), renamedFrom: z.string().nullable() }),
  placement: z.enum(['pending', 'bound', 'skipped']),
  transport: z
    .object({
      port: z.number(),
      path: z.string().nullable(),
      serverNames: z.array(z.string()),
      target: z.string().nullable(),
    })
    .nullable(),
  family: z.enum(['none', 'bound', 'unbound', 'target_mismatch']),
});
export type ModeSetupView = z.infer<typeof ModeSetupView>;

export const PanelSetupView = z.object({
  exists: z.boolean(),
  state: PanelSetupState.nullable(),
  step: z.string().nullable(),
  code: z.string().nullable(),
  generation: z.number(),
  running: z.boolean(),
  profile: z.object({ name: z.string(), uuid: z.string().nullable() }).nullable(),
  modes: z.array(ModeSetupView),
  templates: z.array(
    z.object({ family: z.string(), state: z.enum(['matched', 'drifted', 'refused']) }),
  ),
  privacy: z.enum(['ok', 'drifted']).nullable(),
  originDns: z.object({ accountId: z.string(), zoneName: z.string() }).nullable(),
  /** Whether this backend was taken over with existing nodes or addresses. */
  adopted: z.boolean(),
  updatedAt: z.string().nullable(),
});
export type PanelSetupView = z.infer<typeof PanelSetupView>;

// --- bootstrap contract v2: node enrollment (the role) --------------------------------------

/**
 * `PUT {slug}/nodes/by-name/{name}`: the enrollment input (the mode, the
 * label) is taken once; the observations are taken on every run. The role
 * never sends FCP-owned machine settings.
 */
export const NodeRegistration = z.object({
  roleContractVersion: z.number().int().min(1),
  /** The connection mode this node serves (one per node); the machine shape follows from it. */
  mode: z.string().min(1).max(40),
  label: z.string().min(1).max(63).optional(),
  observed: z.object({
    management: z.object({ address: z.string().min(2), port: z.number().int().min(1).max(65535) }),
    publicIps: z.object({ v4: z.string().optional(), v6: z.string().optional() }).default({}),
    capabilities: z
      .object({ caddy: z.boolean().default(false), ipv6: z.boolean().default(false) })
      .default({ caddy: false, ipv6: false }),
  }),
});
export type NodeRegistration = z.infer<typeof NodeRegistration>;

export const NodeAppliedReport = z.object({
  appliedRevision: z.number().int().min(1),
  caddy: z.object({ certificateReady: z.boolean().optional() }).optional(),
  nodeStarted: z.boolean(),
});
export type NodeAppliedReport = z.infer<typeof NodeAppliedReport>;

export const NodeStage = z.enum([
  'registered',
  'bootstrap_available',
  'machine_applied',
  'machine_ready',
  'candidates_verified',
  'awaiting_approval',
  'activating',
  'live',
]);
export type NodeStage = z.infer<typeof NodeStage>;

export const NodeDisposition = z.enum(['staged', 'activating', 'live', 'unavailable', 'retiring']);

/** The mode a node serves, as the views carry it. */
export const NodeModeRef = z.object({ slug: z.string(), name: z.string(), shape: ModeShape });
export type NodeModeRef = z.infer<typeof NodeModeRef>;

/** What the role may read about its own node. Never a secret, never another node. */
export const NodeRoleView = z.object({
  name: z.string(),
  mode: NodeModeRef,
  registration: z.object({
    state: z.string(),
    code: z.string().nullable(),
    generation: z.number(),
  }),
  stage: NodeStage,
  delivery: NodeDisposition,
  machineRevision: z.number(),
  appliedRevision: z.number().nullable(),
  node: z.object({ uuid: z.string().nullable(), port: z.number() }),
  origin: z.object({ hostname: z.string().nullable(), dns: z.string() }),
  retirement: z.object({ stage: z.string(), code: z.string().nullable() }).nullable(),
  updatedAt: z.string(),
});
export type NodeRoleView = z.infer<typeof NodeRoleView>;

/** One enrolled node as the Servers page shows it (`GET {slug}/nodes/intents`). */
export const NodeIntentView = z.object({
  id: z.string(),
  name: z.string(),
  mode: NodeModeRef,
  state: z.enum(['pending', 'ready', 'blocked', 'retiring', 'retired']),
  code: z.string().nullable(),
  stage: NodeStage,
  disposition: NodeDisposition,
  machineRevision: z.number(),
  appliedRevision: z.number().nullable(),
  nodeUuid: z.string().nullable(),
  /** The node's own addresses on the backend (one per family name on a direct node). */
  addressUuids: z.array(z.string()),
  origin: z.object({ hostname: z.string().nullable(), dns: z.string() }),
  maintenance: z.boolean(),
  run: z
    .object({ id: z.string(), state: z.string(), stage: z.string(), code: z.string().nullable() })
    .nullable(),
  retirement: z.object({ stage: z.string(), code: z.string().nullable() }).nullable(),
  registeredAt: z.string(),
  updatedAt: z.string(),
});
export type NodeIntentView = z.infer<typeof NodeIntentView>;
export const NodeIntentList = z.object({ intents: z.array(NodeIntentView) });

/** The review card an approval names (`GET …/intents/{id}/review`). */
export const ActivationReview = z.object({
  shape: z.object({
    mode: z.string(),
    modeShape: ModeShape,
    ingress: z.unknown().nullable(),
    configRevision: z.string(),
    authRevision: z.string().nullable(),
    listenerKeys: z.array(z.string()),
    provider: z.object({ accountId: z.string().nullable(), templateHash: z.string().nullable() }),
    subscriptionTemplates: z.record(z.string(), z.string()),
    /** A direct node's addresses: one tuple per family name. */
    addressTuples: z.array(
      z.object({ address: z.string(), port: z.number(), sni: z.string().nullable() }),
    ),
  }),
  reviewHash: z.string(),
  blockers: z.array(z.string()),
  stage: NodeStage,
});
export type ActivationReview = z.infer<typeof ActivationReview>;

/** The isolated direct test link and the binding its confirmation must echo. */
export const DirectTestLink = z.object({
  link: z.string(),
  binding: z.object({
    intentId: z.string(),
    inboundUuid: z.string(),
    endpoint: z.string(),
    machineRevision: z.number(),
    configRevision: z.string(),
    authRevision: z.string().nullable(),
    params: z.object({
      sni: z.string(),
      fingerprint: z.string(),
      shortIdRef: z.number(),
      publicKey: z.string(),
    }),
    credentialRef: z.string(),
    issuedAt: z.string(),
  }),
});
export type DirectTestLink = z.infer<typeof DirectTestLink>;

/** `POST …/bootstrap`: the machine configuration plus the node secret, served once per call. */
export const NodeBootstrap = z.object({
  machineRevision: z.number(),
  secretKey: z.string(),
  node: z.object({ port: z.number(), name: z.string(), mode: NodeModeRef }),
  ingress: z
    .object({
      hostname: z.string(),
      externalPort: z.number(),
      routes: z.array(z.object({ path: z.string(), port: z.number() })),
    })
    .nullable(),
  origin: z.object({ hostname: z.string().nullable(), dns: z.string() }),
});
export type NodeBootstrap = z.infer<typeof NodeBootstrap>;

/** What a typed profile edit would do. Non-secret: names, targets, counts. */
export const ProfilePatchPreview = z.object({
  profileName: z.string(),
  baseToken: z.string(),
  expectedToken: z.string(),
  changed: z.boolean(),
  changes: z.array(
    z.object({
      inboundTag: z.string(),
      field: z.enum(['serverNames', 'target']),
      before: z.union([z.array(z.string()), z.string(), z.null()]),
      after: z.union([z.array(z.string()), z.string()]),
    }),
  ),
  touchedTags: z.array(z.string()),
  inboundUuids: z.record(z.string(), z.string()),
  ops: z.array(ProfilePatchOp),
  restartsNodes: z.array(z.string()),
  affectedRelays: z.array(
    z.object({
      relaySlug: z.string(),
      listenerKeys: z.array(z.string()),
      publishedEdges: z.number(),
    }),
  ),
});
export type ProfilePatchPreview = z.infer<typeof ProfilePatchPreview>;
