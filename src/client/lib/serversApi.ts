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
  PlacementValidation,
  ServerSummary,
  ServerTree,
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

const ROOT = ['admin', 'servers'] as const;
export const serverKeys = {
  all: ROOT,
  summary: [...ROOT, 'summary'] as const,
  tree: (slug: string) => [...ROOT, 'tree', slug] as const,
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

export function invalidateServers(qc: QueryClient): void {
  void qc.invalidateQueries({ queryKey: serverKeys.all });
}
