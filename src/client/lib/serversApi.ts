/**
 * Client data layer for Admin -> Servers (`/api/v1/admin/servers/*`). The only
 * place these API paths are built. Three layers, as in edgesApi.ts:
 *   1. one typed function per route, through `apiClient` (which seals by the
 *      shared policy in envelope.ts);
 *   2. `serverKeys`, the TanStack key tree rooted at ['admin','servers'];
 *   3. `*Query()` wrappers with their polling cadence, plus invalidators.
 *
 * Cadence: the backend is only re-read every ten minutes (the healthcheck) or on
 * an explicit Refresh, so the cached tree is polled gently (60 s).
 */
import { createQuery, type QueryClient } from '@tanstack/svelte-query';
import { z } from 'zod';
import { apiClient } from './api';
import {
  ActivationReview,
  DirectTestLink,
  AdoptNodeResult,
  NodeIntentList,
  PanelOpList,
  OpView,
  BackendSetupView,
  PlacementValidation,
  NodeRenameList,
  NodeRenameView,
  PortChangeList,
  PortChangeView,
  ProfilePatchPreview,
  ServerSummary,
  ServerTree,
  type BackendSetupInput,
  type AddressPatch,
  type AddressWrite,
  type ModeGroupPatch,
  type ModeGroupWrite,
  type NodeWrite,
  type ProfilePatchApply,
  type ProfilePatchOp,
  type RecoveryAttestation,
  type ServerManageConfig,
} from '../../shared/contracts/servers';

const BASE = '/api/v1/admin/servers';
const slugPath = (slug: string) => `${BASE}/${encodeURIComponent(slug)}`;

export const fetchServerSummary = () => apiClient.get(`${BASE}/summary`, ServerSummary);
export const fetchServerTree = (slug: string) =>
  apiClient.get(`${slugPath(slug)}/tree`, ServerTree);
/** Re-read the backend now; answers the fresh tree. Rate-limited server-side. */
export const refreshServer = (slug: string) =>
  apiClient.post(`${slugPath(slug)}/refresh`, {}, ServerTree);
export const validatePlacements = (slug: string) =>
  apiClient.post(`${slugPath(slug)}/placements/validate`, {}, PlacementValidation);
export const patchServerConfig = (patch: Partial<ServerManageConfig>) =>
  apiClient.patch(`${BASE}/config`, patch, z.object({ changedKeys: z.array(z.string()) }));

// --- writes. Every one answers the op it became (sent once, then looked at). -----------------
const Ok = z.object({ ok: z.literal(true) });
type Patch<T> = Partial<Omit<T, 'restore'>>;

export const fetchOps = (slug: string) => apiClient.get(`${slugPath(slug)}/ops`, PanelOpList);
export const observeOp = (slug: string, id: string) =>
  apiClient.post(`${slugPath(slug)}/ops/${encodeURIComponent(id)}/observe`, {}, OpView);
/** The server makes the fresh read itself; the operator attests the other three. */
export const recoverOp = (
  slug: string,
  id: string,
  attest: Omit<RecoveryAttestation, 'freshReadAt'>,
) => apiClient.post(`${slugPath(slug)}/ops/${encodeURIComponent(id)}/recover`, attest, OpView);

export const createAddress = (slug: string, address: AddressWrite) =>
  apiClient.post(`${slugPath(slug)}/addresses`, address, OpView);
export const updateAddress = (slug: string, uuid: string, fields: AddressPatch) =>
  apiClient.patch(`${slugPath(slug)}/addresses/${encodeURIComponent(uuid)}`, fields, OpView);
export const deleteAddress = (slug: string, uuid: string) =>
  apiClient.delete(`${slugPath(slug)}/addresses/${encodeURIComponent(uuid)}`, OpView);

export const createModeGroup = (slug: string, group: ModeGroupWrite) =>
  apiClient.post(`${slugPath(slug)}/modeGroups`, group, OpView);
export const updateModeGroup = (slug: string, uuid: string, fields: ModeGroupPatch) =>
  apiClient.patch(`${slugPath(slug)}/modeGroups/${encodeURIComponent(uuid)}`, fields, OpView);
export const deleteModeGroup = (slug: string, uuid: string) =>
  apiClient.delete(`${slugPath(slug)}/modeGroups/${encodeURIComponent(uuid)}`, OpView);

export const createNode = (slug: string, node: NodeWrite) =>
  apiClient.post(`${slugPath(slug)}/nodes`, node, OpView);
export const updateNode = (
  slug: string,
  uuid: string,
  fields: Patch<Omit<NodeWrite, 'configProfileUuid'>> & { configProfileUuid?: string },
) => apiClient.patch(`${slugPath(slug)}/nodes/${encodeURIComponent(uuid)}`, fields, OpView);
export const nodeAction = (slug: string, uuid: string, action: 'enable' | 'disable' | 'restart') =>
  apiClient.post(`${slugPath(slug)}/nodes/${encodeURIComponent(uuid)}/${action}`, {}, OpView);
/** `removeOnly`: take the row off the backend and say the process may keep running. */
export const deleteNode = (slug: string, uuid: string, removeOnly: boolean) =>
  apiClient.delete(
    `${slugPath(slug)}/nodes/${encodeURIComponent(uuid)}${removeOnly ? '?removeOnly=1' : ''}`,
    OpView,
  );

export const previewProfilePatch = (slug: string, profileUuid: string, ops: ProfilePatchOp[]) =>
  apiClient.post(
    `${slugPath(slug)}/profiles/${encodeURIComponent(profileUuid)}/preview`,
    { ops },
    ProfilePatchPreview,
  );
/** Apply takes what the preview answered, verbatim. */
export const applyProfilePatch = (
  slug: string,
  profileUuid: string,
  preview: ProfilePatchPreview,
  /** What happens to nodes FCP does not manage that run the touched transports. */
  unmanaged?: 'hold' | 'acknowledge',
) =>
  apiClient.post(
    `${slugPath(slug)}/profiles/${encodeURIComponent(profileUuid)}/apply`,
    {
      ops: preview.ops,
      baseToken: preview.baseToken,
      expectedToken: preview.expectedToken,
      transportUuids: preview.transportUuids,
      ...(unmanaged ? { unmanaged } : {}),
    } satisfies ProfilePatchApply,
    OpView,
  );

/**
 * Stage a previewed port change: nothing is sent until every node that will
 * listen on the port has confirmed its firewall (docs/servers.md).
 */
export const stagePortChange = (
  slug: string,
  profileUuid: string,
  preview: ProfilePatchPreview,
  unmanaged?: 'hold' | 'acknowledge',
) =>
  apiClient.post(
    `${slugPath(slug)}/profiles/${encodeURIComponent(profileUuid)}/port-change`,
    {
      ops: preview.ops,
      baseToken: preview.baseToken,
      expectedToken: preview.expectedToken,
      transportUuids: preview.transportUuids,
      ...(unmanaged ? { unmanaged } : {}),
    } satisfies ProfilePatchApply,
    PortChangeView,
  );
export const fetchPortChanges = (slug: string) =>
  apiClient.get(`${slugPath(slug)}/port-changes`, PortChangeList);
/** An admin confirms the firewall of nodes no role reports for. */
export const acknowledgePortChange = (slug: string, id: string, nodeNames: string[]) =>
  apiClient.post(
    `${slugPath(slug)}/port-changes/${encodeURIComponent(id)}/acknowledge`,
    { nodeNames },
    PortChangeView,
  );
export const cancelPortChange = (slug: string, id: string) =>
  apiClient.post(
    `${slugPath(slug)}/port-changes/${encodeURIComponent(id)}/cancel`,
    {},
    PortChangeView,
  );

/**
 * Rename a node: the backend row, every reference FCP keeps, the Host remarks
 * FCP wrote and members' pins, one step at a time (docs/servers.md).
 */
export const renameNode = (slug: string, uuid: string, name: string) =>
  apiClient.post(
    `${slugPath(slug)}/nodes/${encodeURIComponent(uuid)}/rename`,
    { name },
    NodeRenameView,
  );
/** Try again the Host remarks a rename holds on, once whatever refused them is fixed. */
export const retryRename = (slug: string, id: string) =>
  apiClient.post(`${slugPath(slug)}/renames/${encodeURIComponent(id)}/retry`, {}, NodeRenameView);
export const fetchRenames = (slug: string) =>
  apiClient.get(`${slugPath(slug)}/renames`, NodeRenameList);

/** Adopt a node that already serves members, as it is (live at once). */
export const adoptNode = (
  slug: string,
  body: { nodeUuid: string; mode: string; externallyFronted?: boolean },
) => apiClient.post(`${slugPath(slug)}/nodes/adopt`, body, AdoptNodeResult);
/** Release the hold a shared change put on nodes FCP does not manage. */
export const releaseHold = (slug: string, holdId: string) =>
  apiClient.post(`${slugPath(slug)}/holds/${encodeURIComponent(holdId)}/release`, {}, Ok);

/** "I have looked at it": clears the edited-elsewhere flag of one profile. */
export const acknowledgeForeignEdit = (slug: string, profileUuid: string) =>
  apiClient.post(
    `${slugPath(slug)}/profiles/${encodeURIComponent(profileUuid)}/acknowledge`,
    {},
    Ok,
  );

// --- the bootstrap contract: setting up a backend, enrolled nodes, activation ---------------------
export const fetchSetup = (slug: string) =>
  apiClient.get(`${slugPath(slug)}/setup`, BackendSetupView);
export const startSetup = (slug: string, input: BackendSetupInput) =>
  apiClient.post(`${slugPath(slug)}/setup`, input, BackendSetupView);

export const fetchIntents = (slug: string) =>
  apiClient.get(`${slugPath(slug)}/nodes/intents`, NodeIntentList);
const intentPath = (slug: string, id: string) =>
  `${slugPath(slug)}/nodes/intents/${encodeURIComponent(id)}`;
export const fetchReview = (slug: string, id: string) =>
  apiClient.get(`${intentPath(slug, id)}/review`, ActivationReview);
export const buildDirectTestLink = (slug: string, id: string) =>
  apiClient.post(`${intentPath(slug, id)}/test-link`, {}, DirectTestLink);
export const confirmDirect = (slug: string, id: string, binding: DirectTestLink['binding']) =>
  apiClient.post(`${intentPath(slug, id)}/confirm`, { binding }, z.object({ stage: z.string() }));
export const approveNode = (slug: string, id: string, reviewHash: string) =>
  apiClient.post(
    `${intentPath(slug, id)}/approve`,
    { reviewHash },
    z.object({ runId: z.string() }),
  );
export const retireNode = (
  slug: string,
  id: string,
  decision?: { disposition: 'keep-dark' | 'migrate'; targetIntentId?: string },
) =>
  apiClient.post(`${intentPath(slug, id)}/retire`, decision ?? {}, z.object({ stage: z.string() }));
/** An adopted node's machine is never run by the role: an admin confirms it is gone. */
export const confirmWiped = (slug: string, id: string) =>
  apiClient.post(`${intentPath(slug, id)}/wiped`, {}, z.object({ stage: z.string() }));
export const finishMaintenance = (slug: string, id: string) =>
  apiClient.post(`${intentPath(slug, id)}/maintenance`, {}, z.object({ ok: z.literal(true) }));
/** Close the node for maintenance: members get the unavailable answer until it is approved again. */
export const startMaintenance = (slug: string, id: string) =>
  apiClient.post(
    `${intentPath(slug, id)}/maintenance`,
    { start: true },
    z.object({ ok: z.literal(true) }),
  );
export const patchNodeSettings = (
  slug: string,
  id: string,
  patch: Record<string, unknown>,
  maintenance = false,
) =>
  apiClient.post(
    `${intentPath(slug, id)}/settings`,
    { patch, maintenance },
    z.object({ change: z.string(), machineRevision: z.number() }),
  );

const ROOT = ['admin', 'servers'] as const;
export const serverKeys = {
  all: ROOT,
  summary: [...ROOT, 'summary'] as const,
  tree: (slug: string) => [...ROOT, 'tree', slug] as const,
  ops: (slug: string) => [...ROOT, 'ops', slug] as const,
  setup: (slug: string) => [...ROOT, 'setup', slug] as const,
  intents: (slug: string) => [...ROOT, 'intents', slug] as const,
  placements: (slug: string) => [...ROOT, 'placements', slug] as const,
  review: (slug: string, id: string) => [...ROOT, 'review', slug, id] as const,
  portChanges: (slug: string) => [...ROOT, 'portChanges', slug] as const,
  renames: (slug: string) => [...ROOT, 'renames', slug] as const,
};

/** Polled faster while a rename runs. */
export const renamesQuery = (slug: () => string | null) =>
  createQuery(() => ({
    queryKey: serverKeys.renames(slug() ?? ''),
    queryFn: () => fetchRenames(slug()!),
    enabled: !!slug(),
    refetchInterval: (q: { state: { data?: { renames: { state: string }[] } } }) =>
      q.state.data?.renames.some((r) => r.state === 'running') ? 3_000 : 60_000,
  }));

/** Polled faster while a change waits: the role's report confirms it whenever the role runs. */
export const portChangesQuery = (slug: () => string | null) =>
  createQuery(() => ({
    queryKey: serverKeys.portChanges(slug() ?? ''),
    queryFn: () => fetchPortChanges(slug()!),
    enabled: !!slug(),
    refetchInterval: (q: { state: { data?: { changes: { state: string }[] } } }) =>
      q.state.data?.changes.some((c) => c.state === 'waiting' || c.state === 'applying')
        ? 5_000
        : 60_000,
  }));

/** Polled faster while a setup run holds its lease. */
export const setupQuery = (slug: () => string | null) =>
  createQuery(() => ({
    queryKey: serverKeys.setup(slug() ?? ''),
    queryFn: () => fetchSetup(slug()!),
    enabled: !!slug(),
    refetchInterval: (q: { state: { data?: { running: boolean } } }) =>
      q.state.data?.running ? 3_000 : 60_000,
  }));

/** Polled faster while any node is between enrollment and live. */
export const intentsQuery = (slug: () => string | null) =>
  createQuery(() => ({
    queryKey: serverKeys.intents(slug() ?? ''),
    queryFn: () => fetchIntents(slug()!),
    enabled: !!slug(),
    refetchInterval: (q: { state: { data?: { intents: { stage: string; state: string }[] } } }) =>
      q.state.data?.intents.some((i) => i.stage !== 'live' || i.state === 'pending')
        ? 5_000
        : 60_000,
  }));

/** The approval card's review: re-read every 10 s so its blockers follow the node. */
export const reviewQuery = (slug: () => string | null, id: () => string | null) =>
  createQuery(() => ({
    queryKey: serverKeys.review(slug() ?? '', id() ?? ''),
    queryFn: () => fetchReview(slug()!, id()!),
    enabled: !!slug() && !!id(),
    staleTime: 5_000,
    refetchInterval: 10_000,
  }));

/** The mode pools checked against this backend's mode groups (counts and names only); read when `enabled`. */
export const placementCheckQuery = (slug: () => string | null, enabled: () => boolean) =>
  createQuery(() => ({
    queryKey: serverKeys.placements(slug() ?? ''),
    queryFn: () => validatePlacements(slug()!),
    enabled: !!slug() && enabled(),
    staleTime: 30_000,
  }));

export const serverSummaryQuery = () =>
  createQuery(() => ({
    queryKey: serverKeys.summary,
    queryFn: fetchServerSummary,
    staleTime: 30_000,
    refetchInterval: 60_000,
  }));

export const serverTreeQuery = (slug: () => string | null) =>
  createQuery(() => ({
    queryKey: serverKeys.tree(slug() ?? ''),
    queryFn: () => fetchServerTree(slug()!),
    enabled: !!slug(),
    staleTime: 30_000,
    refetchInterval: 60_000,
  }));

/** Open ops are looked at by the server's own cron; the list is polled faster while one is open. */
export const opsQuery = (slug: () => string | null, enabled: () => boolean) =>
  createQuery(() => ({
    queryKey: serverKeys.ops(slug() ?? ''),
    queryFn: () => fetchOps(slug()!),
    enabled: !!slug() && enabled(),
    refetchInterval: (q: { state: { data?: { ops: { open: boolean }[] } } }) =>
      q.state.data?.ops.some((o) => o.open) ? 5_000 : 60_000,
  }));

export function invalidateServers(qc: QueryClient): void {
  void qc.invalidateQueries({ queryKey: serverKeys.all });
}
