/**
 * The read-only fleet observability one backend instance reports (Remnawave
 * panel stats), cached by the backend-healthcheck cron in `backendServerHealth`
 * so the admin dashboard never makes a live backend call. Shared by the schema
 * and the mutation that stamps it.
 */
import { v } from 'convex/values';

export const fleetStatsValidator = v.object({
  onlineNow: v.number(),
  nodesOnline: v.number(),
  nodesTotal: v.number(),
  distinctCountries: v.number(),
  monthTrafficBytes: v.number(),
  lifetimeTrafficBytes: v.number(),
  panelVersion: v.string(),
});
