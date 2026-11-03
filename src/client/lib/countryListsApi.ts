/**
 * Client data layer for country lists (`/api/v1/admin/edges/lists/*`,
 * docs/edges.md "Country lists"). The only place these API paths are built.
 * Same three layers as edgesApi.ts: typed route functions, the key tree,
 * query wrappers.
 */
import { createQuery, type QueryClient } from '@tanstack/svelte-query';
import { apiClient } from './api';
import {
  CountryListCreated,
  CountryListDetail,
  CountryListFeedsSet,
  CountryListLookup,
  CountryListOk,
  CountryListPartAdded,
  CountryListsResponse,
  CountryListUploadStarted,
  EdgeListMarks,
  splitUploadParts,
  type CountryListCreate,
  type CountryListPatch,
} from '../../shared/contracts/countryLists';

const BASE = '/api/v1/admin/edges/lists';
const enc = encodeURIComponent;

export const fetchCountryLists = (country?: string) =>
  apiClient.get(country ? `${BASE}?country=${enc(country)}` : BASE, CountryListsResponse);
export const fetchCountryList = (id: string) =>
  apiClient.get(`${BASE}/${enc(id)}`, CountryListDetail);
export const createCountryList = (body: CountryListCreate) =>
  apiClient.post(BASE, body, CountryListCreated);
export const updateCountryList = (id: string, body: CountryListPatch) =>
  apiClient.patch(`${BASE}/${enc(id)}`, body, CountryListOk);
export const removeCountryList = (id: string) =>
  apiClient.delete(`${BASE}/${enc(id)}`, CountryListOk);
export const fetchCountryListNow = (id: string) =>
  apiClient.post(`${BASE}/${enc(id)}/fetch`, {}, CountryListOk);
export const decideCountryListVersion = (
  id: string,
  versionId: string,
  decision: 'approve' | 'reject',
) => apiClient.post(`${BASE}/${enc(id)}/versions/${enc(versionId)}/${decision}`, {}, CountryListOk);
export const setCountryListFeeds = (
  id: string,
  feeds: Array<{ network: string } | { family: string }>,
) => apiClient.post(`${BASE}/${enc(id)}/feeds`, { feeds }, CountryListFeedsSet);
export const feedCountryListAgain = (id: string) =>
  apiClient.post(`${BASE}/${enc(id)}/feeds/again`, {}, CountryListFeedsSet);
export const lookupCountryLists = (entries: string[]) =>
  apiClient.post(`${BASE}/lookup`, { entries }, CountryListLookup);
export const fetchEdgeListMarks = (edgeId: string) =>
  apiClient.get(`${BASE}/marks?edge=${enc(edgeId)}`, EdgeListMarks);
export const markEdgeAddressSeen = (listId: string, markId: string) =>
  apiClient.post(`${BASE}/${enc(listId)}/marks/${enc(markId)}/seen`, {}, CountryListOk);

/**
 * Paste a list: start an upload, send its parts in order (each fits one
 * request), then finish it, which starts reading it into a version.
 */
export async function uploadCountryList(
  id: string,
  text: string,
  onProgress?: (sent: number, total: number) => void,
): Promise<void> {
  const started = await apiClient.post(`${BASE}/${enc(id)}/uploads`, {}, CountryListUploadStarted);
  const parts = splitUploadParts(text, started.partBytes);
  const path = `${BASE}/${enc(id)}/uploads/${enc(started.uploadId)}`;
  for (const [index, part] of parts.entries()) {
    await apiClient.post(`${path}/parts`, { index, text: part }, CountryListPartAdded);
    onProgress?.(index + 1, parts.length);
  }
  await apiClient.post(`${path}/finish`, {}, CountryListOk);
}

const ROOT = ['admin', 'edges', 'lists'] as const;
export const countryListKeys = {
  all: ROOT,
  lists: (country?: string) => [...ROOT, 'lists', country ?? ''] as const,
  list: (id: string) => [...ROOT, 'list', id] as const,
  marks: (edgeId: string) => [...ROOT, 'marks', edgeId] as const,
};

export function invalidateCountryLists(qc: QueryClient): void {
  void qc.invalidateQueries({ queryKey: countryListKeys.all });
}

/** Every list, or one country's: sooner while one is being read. */
export const countryListsQuery = (country?: () => string | undefined) =>
  createQuery(() => ({
    queryKey: countryListKeys.lists(country?.()),
    queryFn: () => fetchCountryLists(country?.()),
    refetchInterval: (q: { state: { data?: CountryListsResponse } }) =>
      (q.state.data?.lists ?? []).some((l) => l.busy) ? 3_000 : 60_000,
  }));

export const countryListQuery = (id: () => string) =>
  createQuery(() => ({
    queryKey: countryListKeys.list(id()),
    queryFn: () => fetchCountryList(id()),
    refetchInterval: (q: { state: { data?: CountryListDetail } }) =>
      q.state.data?.list.busy ? 3_000 : 60_000,
  }));

/** What the watched allowlists say about one edge's addresses (the edge sheet). */
export const edgeListMarksQuery = (edgeId: () => string | null) =>
  createQuery(() => ({
    queryKey: countryListKeys.marks(edgeId() ?? ''),
    queryFn: () => fetchEdgeListMarks(edgeId()!),
    enabled: !!edgeId(),
    refetchInterval: 60_000,
  }));
