/**
 * What each provider account's settings hold and where each value comes from
 * (pure; unit-tested). The server returns the credential field NAMES per
 * provider (`credentialFields` of the accounts response) but no descriptor for
 * the non-secret settings, so the account form's field table lives here and is
 * pinned against EDGE_PROVIDER_IDS by a test.
 *
 *  - `select` fields are filled from the discovery lists (projects, regions,
 *    networks, subnets, zones, TLS configurations), from the accounts already
 *    added (the DNS account) or from a fixed list;
 *  - `text` fields are public identifiers the operator types;
 *  - `step` says which stepper step shows the field: identifiers a provider
 *    needs on every request belong with the credentials, the rest is placement.
 *
 * Exports:
 *   PROVIDER_FIELDS, CREDENTIAL_LABELS, CREDENTIAL_HELP, DEFAULT_SETTINGS
 *   fieldsFor(provider, step), optionsFor(field, ctx), settingsBody(provider, values)
 *   missingRequired(provider, values, step?), applyDiscovery(provider, values, discovered)
 */
import type {
  EdgeDiscoverResponse,
  EdgeProviderAccountAdmin,
  EdgeProviderId,
} from '@shared/contracts/edges';
import { EDGE_PROVIDER_META } from '@client/lib/edgeProviderMeta';

export type FieldSource =
  | 'projects'
  | 'regions'
  | 'networks'
  | 'subnets'
  | 'zones'
  | 'tlsConfigurations'
  | 'dnsAccounts'
  | 'fixed';

export interface ProviderField {
  key: string;
  label: string;
  kind: 'text' | 'select';
  step: 'credentials' | 'placement';
  from?: FieldSource;
  options?: Array<{ id: string; label: string }>;
  required: boolean;
  advanced?: boolean;
  help?: string;
  placeholder?: string;
  /** Stored as a number. */
  numeric?: boolean;
  /** Derived from another field; shown, never typed. */
  readOnly?: boolean;
}

export const PROVIDER_FIELDS: Record<EdgeProviderId, ProviderField[]> = {
  gcore: [
    {
      key: 'projectId',
      label: 'Project',
      kind: 'select',
      step: 'placement',
      from: 'projects',
      required: true,
      numeric: true,
    },
    {
      key: 'regionId',
      label: 'Region',
      kind: 'select',
      step: 'placement',
      from: 'regions',
      required: true,
      numeric: true,
    },
    {
      key: 'networkId',
      label: 'Private network',
      kind: 'select',
      step: 'placement',
      from: 'networks',
      required: false,
      advanced: true,
      help: 'Leave empty for a public address. Choose a network and a subnet for the private address plus floating IP mode.',
    },
    {
      key: 'subnetId',
      label: 'Subnet',
      kind: 'select',
      step: 'placement',
      from: 'subnets',
      required: false,
      advanced: true,
    },
  ],
  upcloud: [
    {
      key: 'zone',
      label: 'Zone',
      kind: 'select',
      step: 'placement',
      from: 'regions',
      required: true,
    },
  ],
  scaleway: [
    {
      key: 'accessKey',
      label: 'Access key (public id)',
      kind: 'text',
      step: 'credentials',
      required: true,
      help: 'The public id paired with the secret key. Not a secret.',
    },
    {
      key: 'zone',
      label: 'Zone',
      kind: 'select',
      step: 'placement',
      from: 'regions',
      required: true,
    },
    {
      key: 'projectId',
      label: 'Project id',
      kind: 'text',
      step: 'placement',
      required: false,
      advanced: true,
      help: 'Leave empty to use the default project of the API key.',
    },
  ],
  ovh: [
    {
      key: 'applicationKey',
      label: 'Application key (public id)',
      kind: 'text',
      step: 'credentials',
      required: true,
    },
    {
      key: 'endpoint',
      label: 'API endpoint',
      kind: 'select',
      step: 'credentials',
      from: 'fixed',
      options: [
        { id: 'ovh-eu', label: 'Europe' },
        { id: 'ovh-ca', label: 'Canada' },
        { id: 'ovh-us', label: 'United States' },
      ],
      required: true,
    },
    {
      key: 'serviceName',
      label: 'Public Cloud project',
      kind: 'select',
      step: 'placement',
      from: 'projects',
      required: true,
    },
    {
      key: 'regionName',
      label: 'Region',
      kind: 'select',
      step: 'placement',
      from: 'regions',
      required: true,
    },
    {
      key: 'networkId',
      label: 'Private network',
      kind: 'select',
      step: 'placement',
      from: 'networks',
      required: true,
      help: 'The network the balancer address lives in.',
    },
    {
      key: 'subnetId',
      label: 'Subnet',
      kind: 'select',
      step: 'placement',
      from: 'subnets',
      required: true,
    },
    {
      key: 'gatewayId',
      label: 'Existing gateway id',
      kind: 'text',
      step: 'placement',
      required: false,
      advanced: true,
      help: 'Leave empty to let each edge create its own gateway (a template setting).',
    },
  ],
  cloudflare: [
    {
      key: 'zoneId',
      label: 'DNS zone',
      kind: 'select',
      step: 'placement',
      from: 'zones',
      required: true,
      help: 'Every edge of this account gets one hostname directly under the zone apex.',
    },
    {
      key: 'zoneName',
      label: 'Zone name',
      kind: 'text',
      step: 'placement',
      required: true,
      readOnly: true,
      help: 'Filled from the chosen zone.',
      placeholder: 'front.example',
    },
    {
      key: 'accountId',
      label: 'Account id',
      kind: 'text',
      step: 'placement',
      required: false,
      advanced: true,
      help: 'Only needed when the token can see several accounts. Not a secret.',
    },
  ],
  fastly: [
    {
      key: 'dnsAccountId',
      label: 'DNS account',
      kind: 'select',
      step: 'placement',
      from: 'dnsAccounts',
      required: true,
      help: 'The account whose zone holds the hostname records and the certificate challenges. Add that account first.',
    },
    {
      key: 'certificateAuthority',
      label: 'Certificate authority',
      kind: 'select',
      step: 'placement',
      from: 'fixed',
      options: [
        { id: 'certainly', label: 'Certainly (default)' },
        { id: 'lets-encrypt', label: "Let's Encrypt" },
        { id: 'globalsign', label: 'GlobalSign (paid plans only)' },
      ],
      required: true,
    },
    {
      key: 'tlsConfigurationId',
      label: 'TLS configuration',
      kind: 'select',
      step: 'placement',
      from: 'tlsConfigurations',
      required: false,
      advanced: true,
      help: 'Leave empty to use the default configuration of the account.',
    },
  ],
};

/** Secret field names as the server lists them, in words. Unknown names are humanised by the form. */
export const CREDENTIAL_LABELS: Record<string, string> = {
  apiKey: 'API key',
  token: 'API token',
  secretKey: 'Secret key',
  applicationSecret: 'Application secret',
  consumerKey: 'Consumer key',
  apiToken: 'API token',
};

/** What each provider's token must be allowed to do. */
export const CREDENTIAL_HELP: Partial<Record<EdgeProviderId, string>> = {
  cloudflare:
    'A zone-scoped API token with Zone DNS Edit, Zone Read, Zone Settings Read, SSL and Certificates Read, plus Origin Rules Edit when an edge needs an origin port other than the zone default.',
  fastly:
    'An API token with the global scope, issued on a dedicated automation user. The account also needs the WebSockets product entitlement.',
};

/** The few settings with a sensible value before the operator picks anything. */
export const DEFAULT_SETTINGS: Partial<Record<EdgeProviderId, Record<string, string>>> = {
  ovh: { endpoint: 'ovh-eu' },
  fastly: { certificateAuthority: 'certainly' },
};

export function credentialLabel(name: string): string {
  return (
    CREDENTIAL_LABELS[name] ??
    name.replace(/([a-z])([A-Z])/g, '$1 $2').replace(/^./, (c) => c.toUpperCase())
  );
}

export function fieldsFor(provider: EdgeProviderId, step?: ProviderField['step']): ProviderField[] {
  const all = PROVIDER_FIELDS[provider];
  return step ? all.filter((f) => f.step === step) : all;
}

export interface OptionsContext {
  discovered: EdgeDiscoverResponse | null;
  accounts: readonly Pick<EdgeProviderAccountAdmin, 'id' | 'name' | 'provider'>[];
  values: Record<string, string>;
}

export function optionsFor(
  f: ProviderField,
  ctx: OptionsContext,
): Array<{ id: string; label: string }> {
  if (f.from === 'fixed') return f.options ?? [];
  if (f.from === 'dnsAccounts')
    return ctx.accounts
      .filter((a) => EDGE_PROVIDER_META[a.provider].providesDns)
      .map((a) => ({ id: a.id, label: a.name }));
  const d = ctx.discovered;
  if (!d) return [];
  switch (f.from) {
    case 'projects':
      return d.projects ?? [];
    case 'regions':
      return d.regions ?? [];
    case 'zones':
      return d.zones ?? [];
    case 'tlsConfigurations':
      return d.tlsConfigurations ?? [];
    case 'networks':
      return (d.networks ?? []).map((n) => ({ id: n.id, label: n.label }));
    case 'subnets':
      return (d.networks ?? []).find((n) => n.id === ctx.values['networkId'])?.subnets ?? [];
    default:
      return [];
  }
}

/** The settings object the server validates (numbers where the adapter wants them, blanks dropped). */
export function settingsBody(
  provider: EdgeProviderId,
  values: Record<string, string>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const f of PROVIDER_FIELDS[provider]) {
    const raw = (values[f.key] ?? '').trim();
    if (!raw) continue;
    out[f.key] = f.numeric ? Number(raw) : raw;
  }
  return out;
}

/** Labels of required fields still empty (optionally only those of one step). */
export function missingRequired(
  provider: EdgeProviderId,
  values: Record<string, string>,
  step?: ProviderField['step'],
): string[] {
  return fieldsFor(provider, step)
    .filter((f) => f.required && (values[f.key] ?? '').trim() === '')
    .map((f) => f.label);
}

/**
 * After a discovery: pre-select every select that has exactly one choice, keep
 * the zone name in step with the zone, and drop a choice the new lists no
 * longer offer (a subnet of another network).
 */
export function applyDiscovery(
  provider: EdgeProviderId,
  values: Record<string, string>,
  ctx: Omit<OptionsContext, 'values'>,
): Record<string, string> {
  const next = { ...values };
  for (const f of PROVIDER_FIELDS[provider]) {
    if (f.kind !== 'select' || f.from === 'fixed') continue;
    const opts = optionsFor(f, { ...ctx, values: next });
    const current = next[f.key] ?? '';
    if (current && opts.length > 0 && !opts.some((o) => o.id === current)) next[f.key] = '';
    if (!next[f.key] && opts.length === 1 && opts[0]) next[f.key] = opts[0].id;
    if (f.from === 'zones') {
      const chosen = opts.find((o) => o.id === next[f.key]);
      if (chosen) next['zoneName'] = chosen.label;
    }
  }
  return next;
}
