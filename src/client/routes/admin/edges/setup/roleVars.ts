/**
 * The node role's variables as copyable text (pure; unit-tested). The server
 * sends public values only (slug, listener keys, the register path and scope,
 * the Host mode): never a token, never an address.
 *
 * Exports:
 *   ROLE_VAR_LABELS                   what each known variable is, in words
 *   roleVarRows(vars)                 stable order: known keys first, then the rest A to Z
 *   formatRoleVars(vars)              YAML-style lines ("key: value"; lists as flow sequences)
 */
export const ROLE_VAR_LABELS: Record<string, string> = {
  fcp_relay_slug: 'The slug the role registers under',
  fcp_relay_listeners: 'Listener keys this relay already has',
  fcp_relay_register_path: 'Where the role sends its registration',
  fcp_relay_register_scope: 'The scope the role token needs',
  fcp_relay_host_mode: 'Who writes the panel Hosts',
};

const ORDER = Object.keys(ROLE_VAR_LABELS);
const LIST_KEYS = new Set(['fcp_relay_listeners']);

export interface RoleVarRow {
  key: string;
  value: string;
  label: string | null;
}

export function roleVarRows(vars: Record<string, string> | null | undefined): RoleVarRow[] {
  if (!vars) return [];
  const keys = Object.keys(vars).sort((a, b) => {
    const ia = ORDER.indexOf(a);
    const ib = ORDER.indexOf(b);
    if (ia !== -1 || ib !== -1) return (ia === -1 ? 999 : ia) - (ib === -1 ? 999 : ib);
    return a.localeCompare(b);
  });
  return keys.map((key) => ({ key, value: vars[key] ?? '', label: ROLE_VAR_LABELS[key] ?? null }));
}

const PLAIN = /^[A-Za-z0-9_./-]+$/;
function scalar(v: string): string {
  if (PLAIN.test(v) && !/^(true|false|null|yes|no|on|off|~)$/i.test(v) && !/^[\d.]+$/.test(v))
    return v;
  return `"${v.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

export function formatRoleVars(vars: Record<string, string> | null | undefined): string {
  return roleVarRows(vars)
    .map(({ key, value }) => {
      if (LIST_KEYS.has(key)) {
        const items = value
          .split(',')
          .map((s) => s.trim())
          .filter((s) => s !== '');
        return `${key}: [${items.map(scalar).join(', ')}]`;
      }
      return `${key}: ${scalar(value)}`;
    })
    .join('\n');
}
