/**
 * Client data layer for server-name families (`/api/v1/admin/edges/sni/*`).
 * The only place these API paths are built. Same three layers as edgesApi.ts:
 * typed route functions, the key tree, query wrappers.
 */
import { createQuery, type QueryClient } from '@tanstack/svelte-query';
import { z } from 'zod';
import { apiClient } from './api';
import {
  SniConfigView,
  SniFamilyDetail,
  SniFamilyList,
  SniImportResult,
  SniReceiptConfirmed,
  SniRolloutPlan,
  SniRolloutStarted,
  SniRolloutStatus,
  SniTestLink,
  type SniConfig,
} from '../../shared/contracts/sni';

const BASE = '/api/v1/admin/edges/sni';
const enc = encodeURIComponent;
const Loose = z.object({}).passthrough();

export const fetchSniConfig = () => apiClient.get(`${BASE}/config`, SniConfigView);
export const patchSniConfig = (patch: Partial<SniConfig>) =>
  apiClient.patch(`${BASE}/config`, patch, z.object({ changedKeys: z.array(z.string()) }));

export const fetchFamilies = () => apiClient.get(`${BASE}/families`, SniFamilyList);
export const fetchFamily = (slug: string) =>
  apiClient.get(`${BASE}/families/${enc(slug)}`, SniFamilyDetail);
export const createFamily = (family: {
  slug: string;
  label: string;
  targetAddress: string;
  targetPort: number;
  requireH2: boolean;
}) => apiClient.post(`${BASE}/families`, family, Loose);
export const updateFamily = (
  slug: string,
  fields: { label?: string; enabled?: boolean; requireH2?: boolean },
) => apiClient.patch(`${BASE}/families/${enc(slug)}`, fields, Loose);
export const removeFamily = (slug: string) =>
  apiClient.delete(`${BASE}/families/${enc(slug)}`, Loose);

export const importNames = (slug: string, text: string) =>
  apiClient.post(`${BASE}/families/${enc(slug)}/names`, { text }, SniImportResult);
export type NameAction = 'retire' | 'reactivate' | 'burn' | 'recheck';
export const actOnNames = (slug: string, action: NameAction, snis: string[]) =>
  apiClient.post(`${BASE}/families/${enc(slug)}/names/${action}`, { snis }, Loose);
export const judgeNames = (
  slug: string,
  snis: string[],
  country: string,
  state: 'proven' | 'blocked' | 'unknown',
) => apiClient.post(`${BASE}/families/${enc(slug)}/names/country`, { snis, country, state }, Loose);

export const bindFamily = (slug: string, backendSlug: string, inboundTag: string) =>
  apiClient.post(`${BASE}/families/${enc(slug)}/bind`, { backendSlug, inboundTag }, Loose);
export const unbindFamily = (bindingId: string) =>
  apiClient.delete(`${BASE}/bindings/${enc(bindingId)}`, Loose);

export const planRollout = (bindingId: string) =>
  apiClient.post(`${BASE}/bindings/${enc(bindingId)}/plan`, {}, SniRolloutPlan);
export const startRollout = (bindingId: string) =>
  apiClient.post(`${BASE}/bindings/${enc(bindingId)}/rollout`, {}, SniRolloutStarted);
export const fetchRollout = (rolloutId: string) =>
  apiClient.get(`${BASE}/rollouts/${enc(rolloutId)}`, SniRolloutStatus);
/** A test link through one edge. Without `sni` the server picks (a witness when there is one). */
export const buildNameTestLink = (rolloutId: string, edgeId: string, sni?: string) =>
  apiClient.post(`${BASE}/rollouts/${enc(rolloutId)}/test-link`, { edgeId, sni }, SniTestLink);
export const confirmNameTest = (receiptId: string) =>
  apiClient.post(`${BASE}/receipts/${enc(receiptId)}/confirm`, {}, SniReceiptConfirmed);

const ROOT = ['admin', 'edges', 'sni'] as const;
export const sniKeys = {
  all: ROOT,
  config: [...ROOT, 'config'] as const,
  families: [...ROOT, 'families'] as const,
  family: (slug: string) => [...ROOT, 'family', slug] as const,
  rollout: (id: string) => [...ROOT, 'rollout', id] as const,
};

export const sniConfigQuery = () =>
  createQuery(() => ({ queryKey: sniKeys.config, queryFn: fetchSniConfig, staleTime: 30_000 }));
export const familiesQuery = () =>
  createQuery(() => ({
    queryKey: sniKeys.families,
    queryFn: fetchFamilies,
    refetchInterval: 60_000,
  }));
export const familyQuery = (slug: () => string) =>
  createQuery(() => ({
    queryKey: sniKeys.family(slug()),
    queryFn: () => fetchFamily(slug()),
    refetchInterval: 30_000,
  }));
export const rolloutQuery = (id: () => string | null) =>
  createQuery(() => ({
    queryKey: sniKeys.rollout(id() ?? ''),
    queryFn: () => fetchRollout(id()!),
    enabled: !!id(),
    refetchInterval: 10_000,
  }));

export function invalidateSni(qc: QueryClient): void {
  void qc.invalidateQueries({ queryKey: sniKeys.all });
}
