/**
 * Centralized TanStack Query factories. Every page-level data fetch goes
 * through one of these so:
 *   - Cache keys are typed and stable across the SPA
 *   - `queryClient.invalidateQueries({ queryKey: queryKeys.account })` works
 *     reliably from anywhere (mutations, post-payment refresh, etc.)
 *   - We have one place to tune `staleTime` per endpoint
 */
import { createQuery, createInfiniteQuery } from '@tanstack/svelte-query';
import { z } from 'zod';
import { apiClient } from './api';
import { AuthMeResponse, PublicConfig } from '../../shared/contracts/auth';
import { AccountResponse } from '../../shared/contracts/account';
import {
  AppSettingsRecord,
  AuditEntry,
  OutlineServerAdmin,
  TierAdmin,
  UserAdmin,
} from '../../shared/contracts/admin';
import { ListTokensResponse } from '../../shared/contracts/tokens';
import { AdminAuthStatus } from '../../shared/contracts/auth';

// --- Cache keys --------------------------------------------------------------

export const queryKeys = {
  me: ['me'] as const,
  config: ['config'] as const,
  account: ['account'] as const,
  adminAuthStatus: ['admin', 'auth-status'] as const,
  adminTiers: ['admin', 'tiers'] as const,
  adminUsers: (q: string) => ['admin', 'users', q] as const,
  adminTokens: ['admin', 'tokens'] as const,
  adminAudit: ['admin', 'audit'] as const,
  adminSettings: ['admin', 'settings'] as const,
  adminOutlineServers: ['admin', 'outline-servers'] as const,
};

// --- Public surface ----------------------------------------------------------

/**
 * Current user identity. Treated as fresh for 60s — in practice the only thing
 * that changes mid-session is tier membership after a payment, and the focus
 * refetch + explicit refresh button cover that.
 */
export const meQuery = () =>
  createQuery(() => ({
    queryKey: queryKeys.me,
    queryFn: async () => {
      // Endpoint always succeeds and returns `{authenticated: false}` for
      // anonymous callers, so we don't need to swallow auth errors here.
      try {
        return await apiClient.get('/api/v1/me', AuthMeResponse);
      } catch {
        return { authenticated: false } satisfies z.infer<typeof AuthMeResponse>;
      }
    },
    staleTime: 60_000,
  }));

/**
 * Public config (member portal URLs, Turnstile site key, environment, backend
 * toggles). Most fields are env-var driven and only change on redeploy, but
 * the backend toggles are admin-editable at runtime — so we set staleTime to
 * 5 min instead of Infinity. That bounds the worst-case staleness after an
 * admin flips a toggle to roughly the server-side KV cache window.
 */
export const configQuery = () =>
  createQuery(() => ({
    queryKey: queryKeys.config,
    queryFn: () => apiClient.get('/api/v1/config', PublicConfig),
    staleTime: 5 * 60_000,
  }));

// --- Member surface ----------------------------------------------------------

export const accountQuery = () =>
  createQuery(() => ({
    queryKey: queryKeys.account,
    queryFn: () => apiClient.get('/api/v1/account', AccountResponse),
    staleTime: 30_000,
  }));

// --- Admin surface -----------------------------------------------------------

export const adminAuthStatusQuery = () =>
  createQuery(() => ({
    queryKey: queryKeys.adminAuthStatus,
    queryFn: () => apiClient.get('/api/admin/auth/status', AdminAuthStatus),
    staleTime: 0, // re-fetch after bootstrap completes
  }));

export const adminTiersQuery = () =>
  createQuery(() => ({
    queryKey: queryKeys.adminTiers,
    queryFn: async () => {
      const result = await apiClient.get(
        '/api/v1/admin/tiers',
        z.object({ tiers: z.array(TierAdmin) }),
      );
      return result.tiers;
    },
    staleTime: 30_000,
  }));

export const adminUsersQuery = (queryRef: () => string) =>
  createQuery(() => {
    const q = queryRef();
    return {
      queryKey: queryKeys.adminUsers(q),
      queryFn: async () => {
        const params = q ? `?q=${encodeURIComponent(q)}` : '';
        const result = await apiClient.get(
          `/api/v1/admin/users${params}`,
          z.object({ users: z.array(UserAdmin), nextCursor: z.string().nullable() }),
        );
        return result.users;
      },
      staleTime: 30_000,
    };
  });

export const adminTokensQuery = () =>
  createQuery(() => ({
    queryKey: queryKeys.adminTokens,
    queryFn: async () => {
      const result = await apiClient.get('/api/v1/admin/tokens', ListTokensResponse);
      return result.tokens;
    },
    staleTime: 30_000,
  }));

/**
 * Audit log uses createInfiniteQuery so the "Load more" button can fetch each
 * page lazily and we accumulate them in `data.pages`. Server uses opaque
 * keyset cursors (created_at, id), echoed back as `nextCursor`.
 */
const AuditPage = z.object({
  entries: z.array(AuditEntry),
  nextCursor: z.string().nullable(),
});
export const adminAuditQuery = () =>
  createInfiniteQuery(() => ({
    queryKey: queryKeys.adminAudit,
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam }) => {
      const url = pageParam
        ? `/api/v1/admin/audit?cursor=${encodeURIComponent(pageParam)}`
        : '/api/v1/admin/audit';
      return apiClient.get(url, AuditPage);
    },
    getNextPageParam: (lastPage) => lastPage.nextCursor ?? undefined,
    staleTime: 30_000,
  }));

/**
 * Global admin-editable settings (outline.enabled, default_backend, etc.).
 * Used by AdminSettings.svelte for the form, and by the public surface
 * (/get-key chooser, AppHeader nudges) to read the toggles. Cached server-side
 * 5 min via KV; client-side we set staleTime to 60s so admin edits propagate
 * quickly across tabs.
 */
const SettingsResponse = z.object({ settings: AppSettingsRecord });
export const appSettingsQuery = () =>
  createQuery(() => ({
    queryKey: queryKeys.adminSettings,
    queryFn: async () => {
      const result = await apiClient.get('/api/v1/admin/settings', SettingsResponse);
      return result.settings;
    },
    staleTime: 60_000,
  }));

/**
 * Registered Outline servers. Used by AdminOutlineServers.svelte for CRUD
 * and by TierEditor.svelte to populate the per-tier "server pool" multi-select
 * when `tier.backend === 'outline'`.
 */
const OutlineServersListResponse = z.object({ servers: z.array(OutlineServerAdmin) });
export const adminOutlineServersQuery = () =>
  createQuery(() => ({
    queryKey: queryKeys.adminOutlineServers,
    queryFn: async () => {
      const result = await apiClient.get(
        '/api/v1/admin/outline-servers',
        OutlineServersListResponse,
      );
      return result.servers;
    },
    staleTime: 30_000,
  }));
