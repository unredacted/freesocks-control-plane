import { z } from 'zod';
import { BACKEND_IDS } from './backendIds';

/**
 * Zod layer over the backend-type id set. The tuple itself lives in
 * ./backendIds.ts (zod-free, so Convex code can value-import it); this module
 * adds the zod enum the client contracts consume. A backend type is distinct
 * from a backend INSTANCE: each type can have many instances (deployed
 * servers), stored as rows in the `backendServers` table and managed in the
 * admin CMS.
 *
 * To add a backend type:
 *   1. add its id to BACKEND_IDS in ./backendIds.ts (every derived union,
 *      validator, and Record<BackendId, ...> map follows or fails to compile),
 *   2. add a config variant to the `backendServerConfig` union in
 *      convex/schema.ts,
 *   3. write a provider in convex/lib/backends/<id>.ts, register it in
 *      convex/lib/backends/registry.ts, and declare its capability record in
 *      convex/lib/backends/capabilities.ts,
 *   4. add a `<id>.enabled` default + label in convex/appSettings.ts,
 *   5. add the type to the admin server editor's field set.
 * See docs/backends.md for the full checklist.
 */
export { BACKEND_IDS, isBackendId } from './backendIds';
export type BackendId = import('./backendIds').BackendId;
export const BackendId = z.enum(BACKEND_IDS);
