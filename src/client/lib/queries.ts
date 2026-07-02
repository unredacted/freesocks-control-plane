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
import { AccountResponse, SubscriptionContentResponse } from '../../shared/contracts/account';
import {
  AdminListResponse,
  AdminCredentialsResponse,
  AdminStatusSummary,
  AppSettingsRecord,
  AuditEntry,
  BackendServerAdmin,
  MirrorProviderAdmin,
  TierAdmin,
  UserAdmin,
} from '../../shared/contracts/admin';
import { ListTokensResponse } from '../../shared/contracts/tokens';
import { AdminAuthStatus } from '../../shared/contracts/auth';
import { RateLimitListResponse } from '../../shared/contracts/rateLimits';
import { MembershipCodePage, PurchasedCodesResponse } from '../../shared/contracts/membershipCodes';
import { AdminBillingOverview, OrderStatusResponse } from '../../shared/contracts/billing';

// --- Cache keys --------------------------------------------------------------

export const queryKeys = {
  me: ['me'] as const,
  config: ['config'] as const,
  account: ['account'] as const,
  subscriptionContent: ['subscription', 'content'] as const,
  adminAuthStatus: ['admin', 'auth-status'] as const,
  adminStatus: ['admin', 'status'] as const,
  adminAdmins: ['admin', 'admins'] as const,
  adminCredentials: (adminId: string) => ['admin', 'admins', adminId, 'credentials'] as const,
  adminTiers: ['admin', 'tiers'] as const,
  adminUsers: (q: string, status = '', tier = '', drift = false) =>
    ['admin', 'users', q, status, tier, drift] as const,
  adminTokens: ['admin', 'tokens'] as const,
  adminAudit: ['admin', 'audit'] as const,
  adminSettings: ['admin', 'settings'] as const,
  adminBackendServers: ['admin', 'backend-servers'] as const,
  adminMirrorProviders: ['admin', 'mirror-providers'] as const,
  adminRateLimits: ['admin', 'rate-limits'] as const,
  adminMembershipCodes: (status: string) => ['admin', 'membership-codes', status] as const,
  adminBilling: (status: string) => ['admin', 'billing', status] as const,
  billingOrder: (ref: string) => ['billing', 'order', ref] as const,
  accountCodes: ['account', 'codes'] as const,
};

// --- Public surface ----------------------------------------------------------

/**
 * Current user identity. Treated as fresh for 60s; in practice the only thing
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
 * Public config (member portal URLs, Cap captcha site key, environment, backend
 * toggles). Most fields are env-var driven and only change on redeploy, but
 * the backend toggles are admin-editable at runtime, so we set staleTime to
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

/**
 * Member account view. `enabled` is optional so callers that may render while
 * still anonymous (e.g. /get-account before sign-up completes) can gate the
 * fetch and avoid a spurious 401; /account just calls `accountQuery()`.
 */
export const accountQuery = (enabled?: () => boolean) =>
  createQuery(() => ({
    queryKey: queryKeys.account,
    queryFn: () => apiClient.get('/api/v1/account', AccountResponse),
    staleTime: 30_000,
    ...(enabled ? { enabled: enabled() } : {}),
  }));

/**
 * Raw subscription content (the proxy config), delivered SEALED. Lazy: only
 * fetched while `enabled()` (the RawConfig viewer is open), so the config isn't
 * pulled for every account view — it's a deliberate, on-demand reveal.
 */
export const subscriptionContentQuery = (enabled: () => boolean) =>
  createQuery(() => ({
    queryKey: queryKeys.subscriptionContent,
    queryFn: () => apiClient.get('/api/v1/subscription/content', SubscriptionContentResponse),
    enabled: enabled(),
    staleTime: 60_000,
  }));

/**
 * Poll a billing order after the payment redirect returns to /account?order=ref.
 * The ONLY polling query in the SPA: `refetchInterval` keeps firing (4s) until a
 * terminal status, since crypto `confirming` can take minutes. Disabled when
 * there's no ref. `retry: false` so a 404 (ref not theirs / unknown) surfaces
 * immediately instead of hammering.
 */
export const billingOrderQuery = (refGetter: () => string | null) =>
  createQuery(() => {
    const ref = refGetter();
    return {
      queryKey: queryKeys.billingOrder(ref ?? ''),
      enabled: !!ref,
      queryFn: () =>
        apiClient.get(
          `/api/v1/billing/order/${encodeURIComponent(ref as string)}`,
          OrderStatusResponse,
        ),
      refetchInterval: (query: { state: { data?: { status?: string } } }) => {
        const s = query.state.data?.status;
        return s === 'paid' || s === 'failed' || s === 'expired' ? false : 4000;
      },
      staleTime: 0,
      retry: false,
    };
  });

/**
 * Gift codes the member has purchased (masked: prefix + status). For the "codes
 * you've bought" panel; gated so it isn't fetched while still anonymous.
 */
export const accountCodesQuery = (enabled?: () => boolean) =>
  createQuery(() => ({
    queryKey: queryKeys.accountCodes,
    queryFn: async () =>
      (await apiClient.get('/api/v1/account/codes', PurchasedCodesResponse)).codes,
    staleTime: 30_000,
    ...(enabled ? { enabled: enabled() } : {}),
  }));

// --- Admin surface -----------------------------------------------------------

export const adminAuthStatusQuery = () =>
  createQuery(() => ({
    queryKey: queryKeys.adminAuthStatus,
    queryFn: () => apiClient.get('/api/admin/auth/status', AdminAuthStatus),
    staleTime: 0, // re-fetch after bootstrap completes
  }));

export const adminStatusQuery = () =>
  createQuery(() => ({
    queryKey: queryKeys.adminStatus,
    queryFn: () => apiClient.get('/api/v1/admin/status', AdminStatusSummary),
    staleTime: 15_000,
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

export const adminAdminsQuery = () =>
  createQuery(() => ({
    queryKey: queryKeys.adminAdmins,
    queryFn: async () => (await apiClient.get('/api/v1/admin/admins', AdminListResponse)).admins,
    staleTime: 15_000,
  }));

/** An admin's passkeys — fetched lazily (only when a row is expanded). */
export const adminCredentialsQuery = (adminId: () => string | null, enabled: () => boolean) =>
  createQuery(() => ({
    queryKey: queryKeys.adminCredentials(adminId() ?? ''),
    queryFn: async () =>
      (
        await apiClient.get(
          `/api/v1/admin/admins/credentials/${encodeURIComponent(adminId()!)}`,
          AdminCredentialsResponse,
        )
      ).credentials,
    enabled: enabled() && !!adminId(),
    staleTime: 10_000,
  }));

// P1-16: paginated via createInfiniteQuery so the admin can "Load more" instead
// of silently seeing only the first page. A targeted search (q set) returns one
// page with nextCursor:null, so the button only appears on the unfiltered browse.
const UsersPage = z.object({ users: z.array(UserAdmin), nextCursor: z.string().nullable() });
export interface AdminUserFilters {
  q: string;
  status: string;
  tier: string;
  drift: boolean;
}
export const adminUsersQuery = (filtersRef: () => AdminUserFilters) =>
  createInfiniteQuery(() => {
    const { q, status, tier, drift } = filtersRef();
    return {
      // Same ['admin','users', ...] prefix, so existing prefix invalidations
      // still hit every filter combination.
      queryKey: queryKeys.adminUsers(q, status, tier, drift),
      initialPageParam: undefined as string | undefined,
      queryFn: ({ pageParam }: { pageParam: string | undefined }) => {
        const params = new URLSearchParams();
        if (q) params.set('q', q);
        if (status) params.set('status', status);
        if (tier) params.set('tier', tier);
        if (drift) params.set('drift', 'true');
        if (pageParam) params.set('cursor', pageParam);
        const qs = params.toString();
        return apiClient.get(`/api/v1/admin/users${qs ? `?${qs}` : ''}`, UsersPage);
      },
      getNextPageParam: (last: z.infer<typeof UsersPage>) => last.nextCursor ?? undefined,
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
export interface AuditFilters {
  action: string;
  actorType: string;
  /** Epoch-ms lower bound as a string ('' = none); the UI derives it from a date. */
  since: string;
}
export const adminAuditQuery = (filtersRef: () => AuditFilters) =>
  createInfiniteQuery(() => {
    const { action, actorType, since } = filtersRef();
    return {
      // Same ['admin','audit'] prefix so prefix invalidations still hit every
      // filter combination (mirrors adminUsersQuery).
      queryKey: [...queryKeys.adminAudit, action, actorType, since],
      initialPageParam: undefined as string | undefined,
      queryFn: ({ pageParam }: { pageParam: string | undefined }) => {
        const params = new URLSearchParams();
        if (action) params.set('action', action);
        if (actorType) params.set('actorType', actorType);
        if (since) params.set('since', since);
        if (pageParam) params.set('cursor', pageParam);
        const qs = params.toString();
        return apiClient.get(`/api/v1/admin/audit${qs ? `?${qs}` : ''}`, AuditPage);
      },
      getNextPageParam: (last: z.infer<typeof AuditPage>) => last.nextCursor ?? undefined,
      staleTime: 30_000,
    };
  });

/**
 * Global admin-editable settings (outline.enabled, default_backend, etc.).
 * Used by AdminSettings.svelte for the form, and by the public surface
 * (/get-account chooser, AppHeader nudges) to read the toggles. Cached server-side
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
 * Registered backend instances (Remnawave, Outline, ...). Used by
 * AdminBackendServers.svelte for CRUD.
 */
const BackendServersListResponse = z.object({ servers: z.array(BackendServerAdmin) });
export const adminBackendServersQuery = () =>
  createQuery(() => ({
    queryKey: queryKeys.adminBackendServers,
    queryFn: async () => {
      const result = await apiClient.get(
        '/api/v1/admin/backend-servers',
        BackendServersListResponse,
      );
      return result.servers;
    },
    staleTime: 30_000,
  }));

/** S3 mirror providers (subscription mirrors) for the AdminStorage CMS page. */
const MirrorProvidersListResponse = z.object({ providers: z.array(MirrorProviderAdmin) });
export const adminMirrorProvidersQuery = () =>
  createQuery(() => ({
    queryKey: queryKeys.adminMirrorProviders,
    queryFn: async () => {
      const result = await apiClient.get(
        '/api/v1/admin/mirror-providers',
        MirrorProvidersListResponse,
      );
      return result.providers;
    },
    staleTime: 30_000,
  }));

/** W2: admin-tunable rate-limit policies. */
export const adminRateLimitsQuery = () =>
  createQuery(() => ({
    queryKey: queryKeys.adminRateLimits,
    queryFn: async () => {
      const result = await apiClient.get('/api/v1/admin/rate-limits', RateLimitListResponse);
      return result.policies;
    },
    staleTime: 30_000,
  }));

/** Billing: the config + recent orders for the AdminBilling page. */
export const adminBillingQuery = (statusRef: () => string) =>
  createQuery(() => {
    const status = statusRef();
    return {
      queryKey: queryKeys.adminBilling(status),
      queryFn: () => {
        const params = status ? `?status=${encodeURIComponent(status)}` : '';
        return apiClient.get(`/api/v1/admin/billing${params}`, AdminBillingOverview);
      },
      staleTime: 30_000,
    };
  });

/**
 * W4: minted membership codes (masked), optionally filtered by status.
 * Paginated via createInfiniteQuery (mirrors adminUsersQuery / adminAuditQuery)
 * so the admin can "Load more" instead of silently seeing only the first page.
 * Server uses an opaque keyset cursor over `_creationTime`, echoed as nextCursor.
 */
export const adminMembershipCodesQuery = (statusRef: () => string) =>
  createInfiniteQuery(() => {
    const status = statusRef();
    return {
      queryKey: queryKeys.adminMembershipCodes(status),
      initialPageParam: undefined as string | undefined,
      queryFn: ({ pageParam }: { pageParam: string | undefined }) => {
        const params = new URLSearchParams();
        if (status) params.set('status', status);
        if (pageParam) params.set('cursor', pageParam);
        const qs = params.toString();
        return apiClient.get(
          `/api/v1/admin/membership-codes${qs ? `?${qs}` : ''}`,
          MembershipCodePage,
        );
      },
      getNextPageParam: (last: z.infer<typeof MembershipCodePage>) => last.nextCursor ?? undefined,
      staleTime: 30_000,
    };
  });
