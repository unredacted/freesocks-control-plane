import { defineSchema } from 'convex/server';

/**
 * Convex schema for FreeSocks Control Plane (migration target).
 *
 * Intentionally EMPTY for migration phase P1: deploying an empty schema to the
 * self-hosted backend verifies the backend + CLI wiring end-to-end before any
 * tables exist. Phase P2 ports the 16 tables from `src/server/db/schema.ts`
 * here — integer PKs/FKs become `Id<>` references, uniqueness is enforced in
 * mutations (Convex has no UNIQUE constraint), and JSON-as-TEXT columns become
 * nested validators. See `.claude/plans/how-hard-or-feasible-harmonic-dahl.md`.
 */
export default defineSchema({});
