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
