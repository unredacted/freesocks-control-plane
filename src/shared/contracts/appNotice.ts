/**
 * The kinds of app the app notice goes to (convex/lib/appNotice.ts): the
 * subscription format the app reads, never its name or version. The single
 * source of the set, zod-free so Convex can value-import it: the schema
 * validator (convex/lib/appNotice.ts `appNoticeFamilyValidator`) and the
 * account contract (./account.ts) both derive from it.
 */
export const APP_NOTICE_FAMILIES = ['clash', 'singbox', 'links'] as const;
export type AppNoticeFamily = (typeof APP_NOTICE_FAMILIES)[number];
