/**
 * N-backend helpers for the MEMBER surfaces: the enabled-backend list with
 * labels + member-safe capabilities, driven by publicConfig.backends.list.
 * Against an older server that doesn't ship `list` yet (deploy skew), the
 * legacy per-id flags/labels are synthesized into the same shape with the
 * historical hardcoded capabilities — so call sites never branch on backend-id
 * literals again. Admin-facing display names stay in backendLabels.ts.
 */
import type { PublicConfig } from '../../shared/contracts/auth';

export interface BackendEntry {
  id: string;
  label: string;
  enabled: boolean;
  capabilities: {
    /** Device (HWID) limits apply on this backend. */
    devices: boolean;
    /** Delivery is a bare access key, not a multi-config subscription. */
    accessKeyOnly: boolean;
  };
}

type BackendsConfig = PublicConfig['backends'] | undefined;

/** Every backend the config knows, enabled or not (callers filter). */
export function allBackends(backends: BackendsConfig): BackendEntry[] {
  if (!backends) return [];
  if (backends.list.length > 0) return backends.list;
  // Deploy-skew synthesis from the legacy flags (historical capabilities).
  return [
    {
      id: 'remnawave',
      label: backends.labels.remnawave,
      enabled: backends.remnawaveEnabled,
      capabilities: { devices: true, accessKeyOnly: false },
    },
    {
      id: 'outline',
      label: backends.labels.outline,
      enabled: backends.outlineEnabled,
      capabilities: { devices: false, accessKeyOnly: true },
    },
  ];
}

export function enabledBackends(backends: BackendsConfig): BackendEntry[] {
  return allBackends(backends).filter((b) => b.enabled);
}

/** The entry for one backend id (enabled or not), or null. */
export function backendEntry(
  backends: BackendsConfig,
  id: string | null | undefined,
): BackendEntry | null {
  if (!id) return null;
  return allBackends(backends).find((b) => b.id === id) ?? null;
}
