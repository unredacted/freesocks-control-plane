/**
 * HTTP-action helpers (P7) — the small replacements for the Hono middleware
 * chain + lib/errors + middleware/services.resolveClientIp. Every public route
 * in convex/http.ts is a bare httpAction; these give it the request-id, the
 * `{ error: { code, message } }` envelope the SPA already parses, cookie-based
 * session resolution, and the fail-closed client-IP trust rules.
 *
 * Auth model: the member + admin sessions are httpOnly signed cookies (no JWT,
 * no Convex ctx.auth). Authenticated data flows through these HTTP actions, not
 * the reactive query channel — so the cookie never has to be readable by JS.
 */
import type { ActionCtx } from '../_generated/server';
import { internal } from '../_generated/api';
import type { Id } from '../_generated/dataModel';
import { parseCookies, verifySignedValue } from './cookies';
import { randomHex } from './crypto';

export const MEMBER_COOKIE = 'fs_session';
export const ADMIN_COOKIE = 'fs_admin_session';

export function newRequestId(): string {
  return randomHex(16);
}

/** Secure cookies everywhere except a local `development` deploy (http://localhost). */
export function secureCookies(): boolean {
  return process.env.ENVIRONMENT !== 'development';
}

export function json(data: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

export function errorJson(
  code: string,
  message: string,
  status: number,
  details?: Record<string, unknown>,
): Response {
  return json({ error: { code, message, ...(details ? { details } : {}) } }, status);
}

export async function readJson<T = Record<string, unknown>>(req: Request): Promise<T> {
  const ct = req.headers.get('content-type') ?? '';
  const len = req.headers.get('content-length');
  if (len === '0' || !ct.toLowerCase().includes('json')) return {} as T;
  return (await req.json()) as T;
}

export function bearerToken(req: Request): string | null {
  const h = req.headers.get('authorization');
  if (!h || !h.toLowerCase().startsWith('bearer ')) return null;
  const t = h.slice(7).trim();
  return t || null;
}

/**
 * Resolve the client IP with the same fail-closed trust rules as the old
 * middleware: Workers' `cf-connecting-ip` (unspoofable) is honoured if present;
 * off-Workers we only trust `x-forwarded-for` when the operator set
 * TRUSTED_PROXY=true behind a normalizing reverse proxy. Returns null rather
 * than a shared fallback (which would itself be a rate-limit-bypass bucket).
 */
export function resolveClientIp(req: Request): string | null {
  const cf = req.headers.get('cf-connecting-ip');
  if (cf && cf.trim()) return cf.trim();
  if (process.env.TRUSTED_PROXY === 'true') {
    const first = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim();
    if (first) return first;
  }
  return null;
}

export interface MemberAuth {
  userId: Id<'users'>;
  source: 'cookie' | 'token';
  scopes?: string[];
}

/** Member identity: the fs_session cookie, OR an fsv1_ token with subjectType:user. */
export async function resolveMember(ctx: ActionCtx, req: Request): Promise<MemberAuth | null> {
  const raw = parseCookies(req.headers.get('cookie'))[MEMBER_COOKIE];
  const key = process.env.SESSION_SIGNING_KEY;
  if (raw && key) {
    const sid = await verifySignedValue(raw, key);
    if (sid) {
      const sess = await ctx.runQuery(internal.sessions.bySid, { sid });
      if (sess && sess.kind === 'member' && sess.userId) {
        return { userId: sess.userId, source: 'cookie' };
      }
    }
  }
  const bearer = bearerToken(req);
  if (bearer) {
    const tok = await ctx.runAction(internal.apiTokens.resolveToken, { plaintext: bearer });
    if (tok && tok.subjectType === 'user' && tok.subjectUserId) {
      return { userId: tok.subjectUserId, source: 'token', scopes: tok.scopes };
    }
  }
  return null;
}

/** fsv1_ bearer resolution (service or user token). */
export async function resolveBearer(ctx: ActionCtx, req: Request) {
  const t = bearerToken(req);
  if (!t) return null;
  return ctx.runAction(internal.apiTokens.resolveToken, { plaintext: t });
}

export interface AdminAuth {
  adminUserId?: Id<'adminUsers'>;
  sid?: string;
  tokenScopes?: string[];
}

/** Admin identity: the fs_admin_session cookie, OR an fsv1_ token with any admin:* scope. */
export async function resolveAdmin(ctx: ActionCtx, req: Request): Promise<AdminAuth | null> {
  const raw = parseCookies(req.headers.get('cookie'))[ADMIN_COOKIE];
  const key = process.env.ADMIN_SESSION_SIGNING_KEY;
  if (raw && key) {
    const sid = await verifySignedValue(raw, key);
    if (sid) {
      const sess = await ctx.runQuery(internal.sessions.bySid, { sid });
      if (sess && sess.kind === 'admin' && sess.adminUserId) {
        return { adminUserId: sess.adminUserId, sid };
      }
    }
  }
  const tok = await resolveBearer(ctx, req);
  if (tok && tok.scopes.some((s) => s.startsWith('admin:'))) {
    return { tokenScopes: tok.scopes };
  }
  return null;
}

export function hasScope(scopes: string[] | undefined, required: string): boolean {
  return Boolean(scopes?.includes(required));
}
