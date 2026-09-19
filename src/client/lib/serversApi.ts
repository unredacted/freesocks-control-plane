/**
 * Client data layer for Admin -> Servers (`/api/v1/admin/servers/*`). The only
 * place these API paths are built. Three layers, as in edgesApi.ts:
 *   1. one typed function per route, through `apiClient` (which seals by the
 *      shared policy in envelope.ts);
 *   2. `serverKeys`, the TanStack key tree rooted at ['admin','servers'];
 *   3. `*Query()` wrappers with their polling cadence, plus invalidators.
 *
 * Cadence: the panel is only re-read every ten minutes (the healthcheck) or on
 * an explicit Refresh, so the cached tree is polled gently (60 s).
 */
import { createQuery, type QueryClient } from '@tanstack/svelte-query';
import { z } from 'zod';
import { apiClient } from './api';
import {
  PanelOpList,
  PanelOpView,
  PlacementValidation,
  ProfilePatchPreview,
  ReservationList,
  ServerSummary,
  ServerTree,
  type HostWrite,
  type NodeWrite,
  type ProfilePatchOp,
  type RecoveryAttestation,
  type ServerManageConfig,
} from '../../shared/contracts/servers';

const BASE = '/api/v1/admin/servers';
const slugPath = (slug: string) => `${BASE}/${encodeURIComponent(slug)}`;

export const fetchServerSummary = () => apiClient.get(`${BASE}/summary`, ServerSummary);
export const fetchServerTree = (slug: string) =>
  apiClient.get(`${slugPath(slug)}/tree`, ServerTree);
/** Re-read the panel now; answers the fresh tree. Rate-limited server-side. */
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
  apiClient.post(`${slugPath(slug)}/ops/${encodeURIComponent(id)}/observe`, {}, PanelOpView);
/** The server makes the fresh read itself; the operator attests the other three. */
export const recoverOp = (
  slug: string,
  id: string,
  attest: Omit<RecoveryAttestation, 'freshReadAt'>,
) => apiClient.post(`${slugPath(slug)}/ops/${encodeURIComponent(id)}/recover`, attest, PanelOpView);

export const createHost = (slug: string, host: HostWrite) =>
  apiClient.post(`${slugPath(slug)}/hosts`, host, PanelOpView);
export const updateHost = (slug: string, uuid: string, fields: Patch<HostWrite>) =>
  apiClient.patch(`${slugPath(slug)}/hosts/${encodeURIComponent(uuid)}`, fields, PanelOpView);
export const deleteHost = (slug: string, uuid: string) =>
  apiClient.delete(`${slugPath(slug)}/hosts/${encodeURIComponent(uuid)}`, PanelOpView);

export interface SquadWrite {
  name: string;
  inboundUuids: string[];
  restore?: boolean;
}
export const createSquad = (slug: string, squad: SquadWrite) =>
  apiClient.post(`${slugPath(slug)}/squads`, squad, PanelOpView);
export const updateSquad = (slug: string, uuid: string, fields: Patch<SquadWrite>) =>
  apiClient.patch(`${slugPath(slug)}/squads/${encodeURIComponent(uuid)}`, fields, PanelOpView);
export const deleteSquad = (slug: string, uuid: string) =>
  apiClient.delete(`${slugPath(slug)}/squads/${encodeURIComponent(uuid)}`, PanelOpView);

export const createNode = (slug: string, node: NodeWrite) =>
  apiClient.post(`${slugPath(slug)}/nodes`, node, PanelOpView);
export const updateNode = (
  slug: string,
  uuid: string,
  fields: Patch<Omit<NodeWrite, 'configProfileUuid'>> & { configProfileUuid?: string },
) => apiClient.patch(`${slugPath(slug)}/nodes/${encodeURIComponent(uuid)}`, fields, PanelOpView);
export const nodeAction = (slug: string, uuid: string, action: 'enable' | 'disable' | 'restart') =>
  apiClient.post(`${slugPath(slug)}/nodes/${encodeURIComponent(uuid)}/${action}`, {}, PanelOpView);
/** `removeOnly`: take the row off the panel and say the process may keep running. */
export const deleteNode = (slug: string, uuid: string, removeOnly: boolean) =>
  apiClient.delete(
    `${slugPath(slug)}/nodes/${encodeURIComponent(uuid)}${removeOnly ? '?removeOnly=1' : ''}`,
    PanelOpView,
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
) =>
  apiClient.post(
    `${slugPath(slug)}/profiles/${encodeURIComponent(profileUuid)}/apply`,
    {
      ops: preview.ops,
      baseToken: preview.baseToken,
      expectedToken: preview.expectedToken,
      inboundUuids: preview.inboundUuids,
    },
    PanelOpView,
  );

export const fetchReservations = (slug: string) =>
  apiClient.get(`${slugPath(slug)}/reservations`, ReservationList);
export const recoverReservation = (slug: string, roleOpId: string, attest: RecoveryAttestation) =>
  apiClient.post(
    `${slugPath(slug)}/reservations/${encodeURIComponent(roleOpId)}/recover`,
    attest,
    Ok,
  );

const ROOT = ['admin', 'servers'] as const;
export const serverKeys = {
  all: ROOT,
  summary: [...ROOT, 'summary'] as const,
  tree: (slug: string) => [...ROOT, 'tree', slug] as const,
  ops: (slug: string) => [...ROOT, 'ops', slug] as const,
  reservations: (slug: string) => [...ROOT, 'reservations', slug] as const,
};

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

export const reservationsQuery = (slug: () => string | null, enabled: () => boolean) =>
  createQuery(() => ({
    queryKey: serverKeys.reservations(slug() ?? ''),
    queryFn: () => fetchReservations(slug()!),
    enabled: !!slug() && enabled(),
    refetchInterval: 60_000,
  }));

export function invalidateServers(qc: QueryClient): void {
  void qc.invalidateQueries({ queryKey: serverKeys.all });
}
