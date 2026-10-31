/**
 * Client data layer for server-name families (`/api/v1/admin/edges/sni/*`).
 * The only place these API paths are built. Same three layers as edgesApi.ts:
 * typed route functions, the key tree, query wrappers.
 */
import { createInfiniteQuery, createQuery, type QueryClient } from '@tanstack/svelte-query';
import { z } from 'zod';
import { apiClient } from './api';
import {
  EdgeNetworkList,
  EdgeNetworkRefreshed,
  type EdgeNetworkWrite,
  SniBindResult,
  SniConfigView,
  SniFamilyDetail,
  SniFamilyList,
  SniImportResult,
  SniReceiptConfirmed,
  SniRolloutPlan,
  SniRolloutStarted,
  SniRolloutStatus,
  SniTestLink,
  SniVantageApplied,
  SniVantageRequested,
  SniHuntCertRead,
  SniHuntChanged,
  SniHuntCtQueued,
  SniHuntImported,
  SniHuntOverview,
  SniHuntScopeView,
  SniManageDryRun,
  SniManaged,
  SniTransportsView,
  type HuntPlace,
  type SniManageRequest,
  type SniBindRequest,
  type SniConfigPatch,
} from '../../shared/contracts/sni';

const BASE = '/api/v1/admin/edges/sni';
const enc = encodeURIComponent;
const Loose = z.object({}).passthrough();

export const fetchSniConfig = () => apiClient.get(`${BASE}/config`, SniConfigView);
export const patchSniConfig = (patch: SniConfigPatch) =>
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
  /** A network's slug: the target and every name must resolve inside it. */
  network?: string;
}) => apiClient.post(`${BASE}/families`, family, Loose);
export const updateFamily = (
  slug: string,
  fields: { label?: string; enabled?: boolean; requireH2?: boolean; network?: string | null },
) => apiClient.patch(`${BASE}/families/${enc(slug)}`, fields, Loose);

// --- networks (docs/edges.md "Networks") ----------------------------------------------------
const NETWORKS = '/api/v1/admin/edges/networks';
export const fetchNetworks = () => apiClient.get(NETWORKS, EdgeNetworkList);
export const createNetwork = (n: EdgeNetworkWrite) => apiClient.post(NETWORKS, n, Loose);
export const updateNetwork = (slug: string, n: EdgeNetworkWrite) =>
  apiClient.patch(`${NETWORKS}/${enc(slug)}`, n, Loose);
export const removeNetwork = (slug: string) => apiClient.delete(`${NETWORKS}/${enc(slug)}`, Loose);
export const refreshNetwork = (slug: string) =>
  apiClient.post(`${NETWORKS}/${enc(slug)}/refresh`, {}, EdgeNetworkRefreshed);
/** A location's network (null: none, its addresses may teach it again). */
export const setLocationNetwork = (accountId: string, locationId: string, network: string | null) =>
  apiClient.post(
    `/api/v1/admin/edges/providers/${enc(accountId)}/locations/${enc(locationId)}/network`,
    { network },
    Loose,
  );
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

/** Check names from one opted-in country now (same gates and budget as the cron). */
export const checkNamesFrom = (slug: string, snis: string[], country: string) =>
  apiClient.post(`${BASE}/families/${enc(slug)}/vantage`, { snis, country }, SniVantageRequested);
/** Record the checks' current suggestions from one country as the operator's marks. */
export const applyVantage = (slug: string, snis: string[], country: string) =>
  apiClient.post(
    `${BASE}/families/${enc(slug)}/vantage/apply`,
    { snis, country },
    SniVantageApplied,
  );

export const bindFamily = (
  slug: string,
  backendSlug: string,
  transportTag: string,
  opts: { transportUuid?: string; takeNames?: boolean } = {},
) =>
  apiClient.post(
    `${BASE}/families/${enc(slug)}/bind`,
    { backendSlug, transportTag, ...opts } satisfies SniBindRequest,
    SniBindResult,
  );
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

// --- a transport's names (docs/edges.md "A transport's names") ------------------------------
/** Every REALITY transport of a backend, with where its names stand. */
export const fetchTransports = (backendSlug: string) =>
  apiClient.get(`${BASE}/transports?backend=${enc(backendSlug)}`, SniTransportsView);
/** What managing a transport's names would suggest (the network); nothing is written. */
export const previewManage = (body: Omit<SniManageRequest, 'dryRun'>) =>
  apiClient.post(`${BASE}/transports/manage`, { ...body, dryRun: true }, SniManageDryRun);
/** Manage a transport's names with FCP: a name list with its cover site, its names taken in. */
export const manageTransport = (body: Omit<SniManageRequest, 'dryRun'>) =>
  apiClient.post(`${BASE}/transports/manage`, body, SniManaged);

// --- finding names (docs/edges.md "Finding names") ------------------------------------------
const HUNT = `${BASE}/hunt`;
export const fetchHunt = () => apiClient.get(HUNT, SniHuntOverview);
export type HuntViewState = 'new' | 'failing' | 'gone' | 'ignored' | 'added' | 'all';
/** One page of a network's or family's candidates of one state (first page: no cursor). */
export const fetchHuntScope = (
  kind: 'network' | 'family',
  slug: string,
  state: HuntViewState = 'new',
  cursor?: string,
) => {
  const q = new URLSearchParams({ state });
  if (cursor) q.set('cursor', cursor);
  return apiClient.get(
    `${HUNT}/${kind === 'network' ? 'networks' : 'families'}/${enc(slug)}?${q.toString()}`,
    SniHuntScopeView,
  );
};
export const fetchHuntNetwork = (slug: string) => fetchHuntScope('network', slug);
export const fetchHuntFamily = (slug: string) => fetchHuntScope('family', slug);
export const startSweep = () => apiClient.post(`${HUNT}/sweep`, {}, Loose);
export const cancelSweep = () => apiClient.delete(`${HUNT}/sweep`, Loose);
/** Whether the sweep matches against a network, and where its nodes are (a place name). */
export const setNetworkHunt = (slug: string, body: { enabled: boolean; place?: HuntPlace }) =>
  apiClient.post(`${HUNT}/networks/${enc(slug)}`, body, Loose);
/** Pasted lines into a network or a family, or a seed file. */
export const importCandidates = (
  body: { network?: string; family?: string; text: string } | { seed: unknown },
) => apiClient.post(`${HUNT}/import`, body, SniHuntImported);
export const readTargetCert = (familySlug: string) =>
  apiClient.post(`${HUNT}/families/${enc(familySlug)}/cert`, {}, SniHuntCertRead);
export const lookUpCt = (domains: string[], scope: { network?: string; family?: string }) =>
  apiClient.post(`${HUNT}/ct`, { domains, ...scope }, SniHuntCtQueued);
export type CandidateAction = 'ignore' | 'unignore' | 'recheck' | 'measure';
export const actOnCandidates = (action: CandidateAction, ids: string[], kind?: 'name' | 'site') =>
  apiClient.post(
    `${HUNT}/candidates/${action}`,
    { ids, ...(kind ? { kind } : {}) },
    SniHuntChanged,
  );
/** Added through the family's normal path: each name is qualified like a pasted one. */
export const addCandidates = (familySlug: string, names: string[]) =>
  apiClient.post(`${HUNT}/candidates/add`, { family: familySlug, names }, SniImportResult);

const ROOT = ['admin', 'edges', 'sni'] as const;
export const sniKeys = {
  all: ROOT,
  config: [...ROOT, 'config'] as const,
  families: [...ROOT, 'families'] as const,
  family: (slug: string) => [...ROOT, 'family', slug] as const,
  rollout: (id: string) => [...ROOT, 'rollout', id] as const,
  networks: [...ROOT, 'networks'] as const,
  hunt: [...ROOT, 'hunt'] as const,
  huntNetwork: (slug: string) => [...ROOT, 'hunt', 'network', slug] as const,
  huntFamily: (slug: string) => [...ROOT, 'hunt', 'family', slug] as const,
  transports: (backendSlug: string) => [...ROOT, 'transports', backendSlug] as const,
};

/** A backend's transports and their names: sooner while a send runs or names are checked. */
export const transportsQuery = (backendSlug: () => string | null) =>
  createQuery(() => ({
    queryKey: sniKeys.transports(backendSlug() ?? ''),
    queryFn: () => fetchTransports(backendSlug()!),
    enabled: !!backendSlug(),
    refetchInterval: (q: { state: { data?: SniTransportsView } }) =>
      (q.state.data?.transports ?? []).some(
        (t) =>
          t.send?.phase === 'writing' ||
          (t.list?.counts.checking ?? 0) > 0 ||
          t.nodes.some((n) => n.autoTest?.state === 'testing'),
      )
        ? 10_000
        : 30_000,
  }));

export const networksQuery = () =>
  createQuery(() => ({ queryKey: sniKeys.networks, queryFn: fetchNetworks, staleTime: 30_000 }));

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

export const huntQuery = () =>
  createQuery(() => ({ queryKey: sniKeys.hunt, queryFn: fetchHunt, refetchInterval: 30_000 }));
export const huntNetworkQuery = (slug: () => string) =>
  createQuery(() => ({
    queryKey: sniKeys.huntNetwork(slug()),
    queryFn: () => fetchHuntNetwork(slug()),
    refetchInterval: 30_000,
  }));
export const huntFamilyQuery = (slug: () => string) =>
  createQuery(() => ({
    queryKey: sniKeys.huntFamily(slug()),
    queryFn: () => fetchHuntFamily(slug()),
    refetchInterval: 60_000,
  }));

/**
 * Every page of a name list's finds of one state, best first (a scope holds at
 * most 2,000: ten pages), so its page counts and lists all of them.
 */
async function fetchAllFinds(slug: string, state: HuntViewState): Promise<SniHuntScopeView> {
  let view = await fetchHuntScope('family', slug, state);
  const candidates = [...view.candidates];
  for (let n = 1; !view.page.done && view.page.cursor && n < 10; n++) {
    view = await fetchHuntScope('family', slug, state, view.page.cursor);
    candidates.push(...view.candidates);
  }
  return { ...view, candidates };
}

/** A name list's finds of one state, best first (its page: suggestions, or everything). */
export const familyFindsQuery = (
  slug: () => string,
  state: () => HuntViewState,
  enabled: () => boolean = () => true,
) =>
  createQuery(() => ({
    queryKey: [...sniKeys.hunt, 'finds', slug(), state()] as const,
    queryFn: () => fetchAllFinds(slug(), state()),
    enabled: enabled(),
    // Names waiting for their check move within minutes: read them again sooner.
    refetchInterval: (q: { state: { data?: SniHuntScopeView } }) =>
      (q.state.data?.candidates ?? []).some((c) => !c.check) ? 15_000 : 60_000,
  }));

/** A scope's candidates of one state, page after page ("Show more"). */
export const huntCandidatesQuery = (
  kind: () => 'network' | 'family',
  slug: () => string,
  state: () => HuntViewState,
) =>
  createInfiniteQuery(() => ({
    queryKey: [...sniKeys.hunt, 'candidates', kind(), slug(), state()] as const,
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam }: { pageParam: string | undefined }) =>
      fetchHuntScope(kind(), slug(), state(), pageParam),
    getNextPageParam: (last: SniHuntScopeView) => last.page.cursor ?? undefined,
    // Names waiting for their check move within minutes: read them again sooner.
    refetchInterval: (q: { state: { data?: { pages: SniHuntScopeView[] } } }) =>
      (q.state.data?.pages ?? []).some((p) => p.candidates.some((c) => !c.check)) ? 15_000 : 60_000,
  }));

export function invalidateSni(qc: QueryClient): void {
  void qc.invalidateQueries({ queryKey: sniKeys.all });
}
