import { z } from 'zod';

/**
 * Single source of truth for the set of proxy-backend TYPES (the proxy software:
 * Remnawave, Outline, and any future WireGuard / 3x-ui / ...). A backend type is
 * distinct from a backend INSTANCE: each type can have many instances (deployed
 * servers), stored as rows in the `backendServers` table and managed in the
 * admin CMS.
 *
 * To add a backend type:
 *   1. add its id to BACKEND_IDS below (drives the client BackendId everywhere),
 *   2. add a matching `v.literal` to the `backendId` validator in convex/schema.ts
 *      and a config variant to the `backendServerConfig` union there,
 *   3. write a provider in convex/lib/backends/<id>.ts and register it in
 *      convex/lib/backends/registry.ts,
 *   4. add a `<id>.enabled` default + label in convex/appSettings.ts,
 *   5. add the type to the admin server editor's field set.
 * See docs/backends.md for the full checklist.
 */
export const BACKEND_IDS = ['remnawave', 'outline'] as const;
export type BackendId = (typeof BACKEND_IDS)[number];
export const BackendId = z.enum(BACKEND_IDS);
