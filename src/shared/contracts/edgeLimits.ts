/**
 * How many edge addresses FCP may run: per provider account, per location and
 * per origin. One table for the server checks (`edgeProviderAccounts`,
 * `edgeLocations`, `relays`, `lib/edgeConfig.ts`), the request contracts and
 * the admin forms, so a bound cannot drift between them.
 */

/** Live (not yet destroyed) edges of one account, and of one location when it sets its own cap. */
export const MAX_LIVE_EDGES_CEILING = 1000;
/** What a new account may keep live when its creator leaves the cap out. */
export const DEFAULT_MAX_LIVE_EDGES = 100;

/**
 * New billable edges per account per UTC day: the guard against a runaway
 * loop. 0 means no daily limit and is refused outside development.
 */
export const DAILY_ALLOCATION_CEILING = 1000;
/** What a new account may create per day when its creator leaves the budget out. */
export const DEFAULT_DAILY_ALLOCATION_BUDGET = 50;

/**
 * The published-pool cap per origin (`relays.desiredPublished`): a provider
 * set may want an address per listener, per diversity group and per pick, and
 * a set whose steady-state cover would exceed this is refused
 * (`edge.set_too_large`).
 */
export const MAX_DESIRED_PUBLISHED = 64;

/** The ceiling of the fleet default pool size (`edge.desiredPublishedDefault`, whose default stays 2). */
export const MAX_DESIRED_PUBLISHED_DEFAULT = 64;
