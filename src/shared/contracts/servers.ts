/**
 * Wire contracts for server management (`/api/v1/admin/servers/*`): what Admin
 * -> Servers shows of a panel's nodes, config profiles, Hosts and modeGroups.
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
    .object({
      nodes: z.number(),
      profiles: z.number(),
      addresses: z.number(),
      modeGroups: z.number(),
    })
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

export const AddressView = z.object({
  addressUuid: z.string(),
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
  transportUuid: z.string().nullable(),
  nodeUuids: z.array(z.string()),
});
export type AddressView = z.infer<typeof AddressView>;

export const TransportView = z.object({
  tag: z.string(),
  transportUuid: z.string(),
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
export type TransportView = z.infer<typeof TransportView>;

export const NodeView = z.object({
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
      transportCount: z.number(),
      changedAt: z.string().nullable(),
    })
    .nullable(),
  transports: z.array(
    TransportView.extend({
      addresses: z.array(AddressView),
      modeGroups: z.array(z.object({ groupUuid: z.string(), name: z.string() })),
    }),
  ),
});
export type NodeView = z.infer<typeof NodeView>;

export const ServerTree = z.object({
  instance: z.object({ id: z.string(), slug: z.string(), name: z.string() }),
  observable: z.boolean(),
  state: ServerObserveState,
  nodes: z.array(NodeView),
  profiles: z.array(
    z.object({
      profileUuid: z.string(),
      name: z.string(),
      shapeHash: z.string(),
      changedAt: z.string().nullable(),
      /** Edited on the panel by something other than FCP, and not yet acknowledged. */
      foreignEditAt: z.string().nullable(),
      nodeCount: z.number(),
      transports: z.array(TransportView),
    }),
  ),
  modeGroups: z.array(
    z.object({
      groupUuid: z.string(),
      name: z.string(),
      membersCount: z.number().nullable(),
      transportTags: z.array(z.string().nullable()),
      transportUuids: z.array(z.string()),
    }),
  ),
  addresses: z.array(AddressView),
  /** What hangs off no node: a profile nothing runs, a Host on an inbound nothing serves. */
  unattached: z.object({ profiles: z.array(z.string()), addresses: z.array(z.string()) }),
});
export type ServerTree = z.infer<typeof ServerTree>;

export const PlacementValidation = z.object({
  observedAt: z.string().nullable(),
  modes: z.array(
    z.object({
      modeSlug: z.string(),
      modeGroups: z.number(),
      unknownHere: z.number(),
      withoutTransports: z.array(z.string()),
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
export const OpView = z.object({
  id: z.string(),
  kind: z.enum(['host', 'squad', 'node', 'profile']),
  verb: z.string(),
  label: z.string(),
  state: PanelOpState,
  request: z.string(),
  panelState: z.string(),
  asyncEffect: z.string(),
  /** The nodes the backend queued work on for this change (they restart for it). */
  asyncNodeUuids: z.array(z.string()).default([]),
  open: z.boolean(),
  errorCode: z.string().nullable(),
  createdAt: z.string(),
  settledAt: z.string().nullable(),
  recovered: z.boolean(),
});
export type OpView = z.infer<typeof OpView>;
export const PanelOpList = z.object({ ops: z.array(OpView) });

/** The four conditions an unknown outcome is released on, each attested by name. */
export const RecoveryAttestation = z.object({
  credentialsRevoked: z.boolean(),
  noInFlightExecutor: z.boolean(),
  queueDrained: z.boolean(),
  freshReadAt: z.number(),
  note: z.string().optional(),
});
export type RecoveryAttestation = z.infer<typeof RecoveryAttestation>;

export const AddressWrite = z.object({
  remark: z.string(),
  address: z.string(),
  port: z.number(),
  transportUuid: z.string(),
  sni: z.string().nullable().optional(),
  host: z.string().nullable().optional(),
  path: z.string().nullable().optional(),
  alpn: z.string().nullable().optional(),
  fingerprint: z.string().nullable().optional(),
  securityLayer: z.string().nullable().optional(),
  isDisabled: z.boolean().optional(),
  isHidden: z.boolean().optional(),
  tag: z.string().nullable().optional(),
  nodeUuids: z.array(z.string()).optional(),
  restore: z.boolean().optional(),
});
export type AddressWrite = z.infer<typeof AddressWrite>;

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

/**
 * The catalogue a new transport is made from. A REALITY template names its
 * server-name family; the preview answers it with the family's target and
 * usable names filled in, and the apply takes that back verbatim.
 */
export const TransportTemplateOp = z.discriminatedUnion('kind', [
  z.object({
    kind: z.enum(['reality', 'xhttp-reality']),
    port: z.number().int(),
    familySlug: z.string().min(1).max(40).optional(),
    target: z.string().optional(),
    serverNames: z.array(z.string()).optional(),
    acceptProxyProtocol: z.boolean().optional(),
  }),
  z.object({ kind: z.literal('ws'), port: z.number().int(), path: z.string() }),
]);
export type TransportTemplateOp = z.infer<typeof TransportTemplateOp>;

export const ProfilePatchOp = z.discriminatedUnion('op', [
  z.object({
    op: z.literal('setRealityServerNames'),
    transportTag: z.string(),
    names: z.array(z.string()),
  }),
  z.object({ op: z.literal('setRealityTarget'), transportTag: z.string(), target: z.string() }),
  /** Move a transport to another port. Staged until the nodes' firewalls let it in. */
  z.object({ op: z.literal('setInboundPort'), transportTag: z.string(), port: z.number().int() }),
  /** Add a transport made from a template. No node serves it until one is assigned to it. */
  z.object({
    op: z.literal('addInboundFromTemplate'),
    transportTag: z.string(),
    template: TransportTemplateOp,
  }),
]);
export type ProfilePatchOp = z.infer<typeof ProfilePatchOp>;

/** `PATCH …/addresses/{uuid}`: every field optional (a `transportUuid` moves the address). */
export const AddressPatch = AddressWrite.omit({ restore: true }).partial();
export type AddressPatch = z.infer<typeof AddressPatch>;

/** `POST …/modeGroups` (create) and, all optional, `PATCH …/modeGroups/{uuid}`. */
export const ModeGroupWrite = z.object({
  name: z.string(),
  transportUuids: z.array(z.string()),
  restore: z.boolean().optional(),
});
export type ModeGroupWrite = z.infer<typeof ModeGroupWrite>;
export const ModeGroupPatch = ModeGroupWrite.omit({ restore: true }).partial();
export type ModeGroupPatch = z.infer<typeof ModeGroupPatch>;

/** `POST …/profiles/{uuid}/preview`. */
export const ProfilePatchPreviewRequest = z.object({ ops: z.array(ProfilePatchOp) });

/**
 * `POST …/profiles/{uuid}/apply` (and `…/port-change`): what the preview
 * answered, verbatim. `expectedToken` is null only for a new REALITY transport,
 * whose key is made in the attempt.
 */
export const ProfilePatchApply = z.object({
  ops: z.array(ProfilePatchOp),
  baseToken: z.string(),
  expectedToken: z.string().nullable(),
  transportUuids: z.record(z.string(), z.string()),
  unmanaged: z.enum(['hold', 'acknowledge']).optional(),
});
export type ProfilePatchApply = z.infer<typeof ProfilePatchApply>;

/** Who confirms that a node's firewall lets a port in: the node role, or an admin. */
export const FirewallConfirmer = z.enum(['role', 'operator']);
export type FirewallConfirmer = z.infer<typeof FirewallConfirmer>;

/**
 * A port change waiting for the nodes' firewalls (docs/servers.md "Firewall
 * acknowledgement"). Nothing is sent until every node has confirmed the port.
 */
export const PortChangeView = z.object({
  id: z.string(),
  profileUuid: z.string(),
  profileName: z.string(),
  transportTag: z.string(),
  fromPort: z.number().nullable(),
  toPort: z.number(),
  /** `recovered`: settled by a recorded recovery, which does not say whether the port moved. */
  state: z.enum(['waiting', 'applying', 'applied', 'refused', 'cancelled', 'recovered']),
  code: z.string().nullable(),
  /** The change on the backend, once it was sent. */
  op: OpView.nullable(),
  nodes: z.array(
    z.object({
      name: z.string(),
      confirmedBy: FirewallConfirmer,
      state: z.enum(['waiting', 'confirmed', 'cancelled']),
      confirmedAt: z.string().nullable(),
    }),
  ),
  createdAt: z.string(),
  updatedAt: z.string(),
});
export type PortChangeView = z.infer<typeof PortChangeView>;
export const PortChangeList = z.object({ changes: z.array(PortChangeView) });

/** `POST …/port-changes/{id}/acknowledge`: an admin confirms nodes no role reports for. */
export const PortChangeAcknowledge = z.object({ nodeNames: z.array(z.string()).min(1).max(200) });

/** `POST {slug}/nodes/{uuid}/rename`. */
export const NodeRenameRequest = z.object({ name: z.string() });

/**
 * A node rename (docs/servers.md "Renaming a node"): the backend row first,
 * then the Host remarks FCP wrote, then members' pins. Members keep
 * connecting throughout; the old name keeps resolving to the node.
 */
export const NodeRenameView = z.object({
  id: z.string(),
  nodeUuid: z.string(),
  from: z.string(),
  to: z.string(),
  state: z.enum(['running', 'done', 'failed']),
  step: z.enum(['backend', 'hosts', 'subscriptions', 'done']),
  code: z.string().nullable(),
  /** Host remarks the backend refused to change: the rename holds until an operator retries. */
  refusedHosts: z.array(z.object({ remark: z.string(), code: z.string() })).default([]),
  createdAt: z.string(),
  updatedAt: z.string(),
});
export type NodeRenameView = z.infer<typeof NodeRenameView>;
export const NodeRenameList = z.object({ renames: z.array(NodeRenameView) });

/** A port a node's firewall must let in, as the node role reads it. */
export const FirewallPort = z.object({
  port: z.number(),
  protocol: z.literal('tcp'),
  /** `serving`: a transport (or the node's own proxy) listens there; `pending`: a staged change waits for it. */
  reason: z.enum(['serving', 'pending']),
});
export type FirewallPort = z.infer<typeof FirewallPort>;

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

/** What "Set up this backend" is asked for. Non-secret: names, shapes, families. */
export const BackendSetupInput = z.object({
  profileName: z.string().min(1).max(60).default('FreeSocks-Config'),
  modes: z.array(ModeSetupInput).min(1).max(12),
  /** The Cloudflare account whose zone WebSocket nodes get their origin names in; null = explicit hostnames per node. */
  originDns: z.object({ accountId: z.string() }).nullable().default(null),
  /** A backend that already has nodes or addresses is taken over only when the operator says so (typed). */
  adopt: z.boolean().default(false),
});
export type BackendSetupInput = z.infer<typeof BackendSetupInput>;

export const PanelSetupState = z.enum(['pending', 'ready', 'failed']);

export const ModeSetupView = z.object({
  slug: z.string(),
  name: z.string(),
  shape: ModeShape,
  familySlug: z.string().nullable(),
  /** As the mode was asked for (a change of the setup sends them back unchanged). */
  acceptProxyProtocol: z.boolean(),
  ws: z.object({ path: z.string(), port: z.number() }).nullable(),
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
  family: z.enum(['none', 'bound', 'unbound', 'target_mismatch', 'bound_elsewhere']),
});
export type ModeSetupView = z.infer<typeof ModeSetupView>;

export const BackendSetupView = z.object({
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
  /**
   * Whether FCP writes this backend (set up, or adopted): a new request is a
   * CHANGE of its setup, which keeps the profile and every mode as they are.
   */
  established: z.boolean(),
  updatedAt: z.string().nullable(),
});
export type BackendSetupView = z.infer<typeof BackendSetupView>;

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
  /**
   * The machine's own name (the role sends its inventory host name), shown to
   * operators next to the node. Never member-facing. A value that is not a
   * plain host name is ignored, not refused.
   */
  // `.catch`: an unusable value (too long, not a string) reads as absent instead
  // of failing the whole registration.
  machineName: z.string().max(253).optional().catch(undefined),
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
  /**
   * The ports the node's firewall lets in for FCP after this run (every port the
   * node's view listed, once opened). Confirms the pending port changes of this
   * node whose port is listed. A role that omits it confirms nothing.
   */
  firewall: z
    .object({
      ports: z
        .array(z.object({ port: z.number().int().min(1).max(65535), protocol: z.literal('tcp') }))
        .max(64),
    })
    .optional(),
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
  /** Every port the node's firewall must let in (the node's own API port is the role's business). */
  firewall: z.object({ ports: z.array(FirewallPort) }).default({ ports: [] }),
  updatedAt: z.string(),
});
export type NodeRoleView = z.infer<typeof NodeRoleView>;

/** One enrolled node as the Servers page shows it (`GET {slug}/nodes/intents`). */
export const NodeIntentView = z.object({
  id: z.string(),
  name: z.string(),
  /** The machine's own name as the role reported it (operator-only); null when none was. */
  machineName: z.string().nullable().default(null),
  mode: NodeModeRef,
  /** Members can pick the mode (Connection modes). Off: the node reaches nobody. */
  modeEnabled: z.boolean().default(true),
  state: z.enum(['pending', 'ready', 'blocked', 'retiring', 'retired']),
  code: z.string().nullable(),
  stage: NodeStage,
  disposition: NodeDisposition,
  machineRevision: z.number(),
  appliedRevision: z.number().nullable(),
  /** When the node role last reported in (a run starts with a report); null on older servers. */
  roleSeenAt: z.string().nullable().default(null),
  nodeUuid: z.string().nullable(),
  /** The node's own addresses on the backend (one per family name on a direct node). */
  addressUuids: z.array(z.string()),
  /** Taken over as it was: the role never runs this machine (docs/servers.md). */
  adopted: z.boolean(),
  origin: z.object({ hostname: z.string().nullable(), dns: z.string() }),
  maintenance: z.boolean(),
  run: z
    .object({ id: z.string(), state: z.string(), stage: z.string(), code: z.string().nullable() })
    .nullable(),
  /**
   * The open guided setup run protecting a fronted node (Edges), if any: the
   * Servers page links to its progress and mirrors its approval card.
   */
  protection: z
    .object({
      runId: z.string(),
      stage: z.string(),
      state: z.string(),
      need: z.string().nullable(),
    })
    .nullable()
    .default(null),
  /**
   * The retirement, if any: its stage, why it waits (`code`), where `draining`
   * stopped (`step`: origin | credentials | addresses | dns | panel_row), who
   * asked, whether it waited for (or got) an admin's decision (`decision`),
   * and since when it waits at this point (`since`).
   */
  retirement: z
    .object({
      stage: z.string(),
      code: z.string().nullable(),
      step: z.string().nullable().default(null),
      requestedBy: z.enum(['role', 'admin']).default('admin'),
      decision: z.boolean().default(false),
      requestedAt: z.string().nullable().default(null),
      since: z.string().nullable().default(null),
    })
    .nullable(),
  registeredAt: z.string(),
  updatedAt: z.string(),
});
export type NodeIntentView = z.infer<typeof NodeIntentView>;
export const AdoptNodeResult = z.object({ intentId: z.string(), addresses: z.number() });

/** A shared change's hold on nodes FCP does not manage (released by an admin). */
export const MaintenanceHoldView = z.object({
  id: z.string(),
  reason: z.string(),
  heldNodeNames: z.array(z.string()),
  closed: z.number(),
  since: z.string(),
});
export type MaintenanceHoldView = z.infer<typeof MaintenanceHoldView>;
export const NodeIntentList = z.object({
  intents: z.array(NodeIntentView),
  holds: z.array(MaintenanceHoldView).default([]),
});

/** The review card an approval names (`GET …/intents/{id}/review`). */
export const ActivationReview = z.object({
  shape: z.object({
    mode: z.string(),
    modeShape: ModeShape,
    ingress: z.unknown().nullable(),
    configRevision: z.string(),
    authRevision: z.string().nullable(),
    /** A fronted node's required listeners, each with the account, location and template it is fronted by. */
    listeners: z.array(
      z.object({
        listenerKey: z.string(),
        accountId: z.string().nullable(),
        locationId: z.string().nullable().optional(),
        templateHash: z.string().nullable(),
      }),
    ),
    subscriptionTemplates: z.record(z.string(), z.string()),
    /** A direct node's addresses: one tuple per family name. */
    addressTuples: z.array(
      z.object({ address: z.string(), port: z.number(), sni: z.string().nullable() }),
    ),
  }),
  reviewHash: z.string(),
  /** What keeps the node from approval now (`servers.*` codes); empty = Approve is enabled. */
  blockers: z.array(z.string()),
  stage: NodeStage,
  /**
   * Shown, never hashed: the standby addresses a fronted node's approval
   * releases (the run's candidates, one per required listener).
   */
  display: z
    .object({
      standbys: z.array(
        z.object({
          listenerKey: z.string(),
          layer: z.enum(['l4', 'l7']),
          endpoint: z.string().nullable(),
          accountName: z.string().nullable(),
          /** The location the address is in (null on an import without an account). */
          locationLabel: z.string().nullable().default(null),
          provider: z.string().nullable(),
        }),
      ),
    })
    .default({ standbys: [] }),
});
export type ActivationReview = z.infer<typeof ActivationReview>;

/** The isolated direct test link and the binding its confirmation must echo. */
export const DirectTestLink = z.object({
  link: z.string(),
  binding: z.object({
    intentId: z.string(),
    transportUuid: z.string(),
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

/**
 * `POST …/confirm`: the binding the test link answered, echoed back. Its
 * output-only `intentId` and `issuedAt` are accepted and discarded (the path
 * names the node; the server recomputes everything else from live rows).
 */
export const DirectTestConfirm = z.object({
  binding: DirectTestLink.shape.binding.omit({ intentId: true, issuedAt: true }),
});

/** `POST …/bootstrap`: the machine configuration plus the node secret, served once per call. */
export const NodeBootstrap = z.object({
  machineRevision: z.number(),
  secretKey: z.string(),
  node: z.object({ port: z.number(), name: z.string(), mode: NodeModeRef }),
  ingress: z
    .object({
      hostname: z.string(),
      externalPort: z.number(),
      // `upstream: 'h2c'`: proxy this route over HTTP/2 cleartext (a gRPC transport).
      routes: z.array(
        z.object({ path: z.string(), port: z.number(), upstream: z.literal('h2c').optional() }),
      ),
    })
    .nullable(),
  origin: z.object({ hostname: z.string().nullable(), dns: z.string() }),
  firewall: z.object({ ports: z.array(FirewallPort) }).default({ ports: [] }),
});
export type NodeBootstrap = z.infer<typeof NodeBootstrap>;

/** What a typed profile edit would do. Non-secret: names, targets, counts. */
export const ProfilePatchPreview = z.object({
  profileName: z.string(),
  baseToken: z.string(),
  /** Null when a new REALITY transport's key is made in the attempt: the token is known only then. */
  expectedToken: z.string().nullable(),
  changed: z.boolean(),
  changes: z.array(
    z.object({
      transportTag: z.string(),
      field: z.enum(['serverNames', 'target', 'port', 'transport']),
      before: z.union([z.array(z.string()), z.string(), z.number(), z.null()]),
      after: z.union([z.array(z.string()), z.string(), z.number()]),
    }),
  ),
  touchedTags: z.array(z.string()),
  transportUuids: z.record(z.string(), z.string()),
  ops: z.array(ProfilePatchOp),
  restartsNodes: z.array(z.string()),
  affectedRelays: z.array(
    z.object({
      relaySlug: z.string(),
      listenerKeys: z.array(z.string()),
      publishedEdges: z.number(),
    }),
  ),
  /**
   * A port change: the nodes whose firewall must let the new port in before
   * anything is sent, and who confirms each. Null for an edit that opens no port.
   */
  firewall: z
    .object({
      port: z.number(),
      nodes: z.array(
        z.object({
          name: z.string(),
          confirmedBy: FirewallConfirmer,
          /** False for a node FCP does not manage: it needs a treatment (`unmanaged`). */
          enrolled: z.boolean(),
        }),
      ),
    })
    .nullable()
    .default(null),
  /**
   * Addresses on a moved transport that FCP does not own: they keep the port
   * they name (a forwarder in front may map it), so they are listed, never moved.
   */
  otherAddresses: z
    .array(z.object({ remark: z.string(), address: z.string(), port: z.number() }))
    .default([]),
});
export type ProfilePatchPreview = z.infer<typeof ProfilePatchPreview>;
