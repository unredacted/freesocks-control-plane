/**
 * A node's provider OPTIONS at one pick, applied (pure, isolate-safe): what
 * certificate an edge built for the pick gets, and whether an existing edge was
 * built with what the pick asks for now. Model: lib/edges/providers/options.ts
 * and docs/edges.md § "Provider options".
 */
import type { EdgeProviderId } from '../edgeProviderIds';
import { legacyOptionDefaults } from './accountSettings';
import {
  defaultsOf,
  parseOptionValues,
  pickKeys,
  sameValues,
  splitChoices,
  type Values,
} from './providers/options';
import { EDGE_CERTIFICATE_OPTIONS, certificateKeysOf, optionFieldsOf } from './providers/templates';

/**
 * An account's defaults for its provider's certificate options: the stored
 * blob, over any copy a row from before options still keeps under `settings`.
 */
export function accountOptionDefaultsOf(r: {
  provider: EdgeProviderId;
  settings: unknown;
  optionDefaults?: string;
}): Values {
  return {
    ...legacyOptionDefaults(r.provider, r.settings as Record<string, unknown>),
    ...parseOptionValues(r.optionDefaults),
  };
}

/**
 * The certificate values an edge built for a pick gets: the declared defaults,
 * the account's defaults over them, the pick's own choices over those.
 */
export function certificateValuesFor(
  provider: EdgeProviderId,
  accountDefaults: Values,
  choices: Values | null,
): Values {
  const keys = certificateKeysOf(provider);
  if (keys.length === 0) return {};
  const { certificate } = splitChoices(optionFieldsOf(provider), choices ?? {});
  return pickKeys(
    {
      ...defaultsOf(EDGE_CERTIFICATE_OPTIONS[provider].fields),
      ...accountDefaults,
      ...certificate,
    },
    keys,
  );
}

export interface BuiltEdge {
  provider?: EdgeProviderId;
  /** The pick's choices frozen when the edge was planned (JSON), absent for an edge from before. */
  choices?: string;
  /** What the edge's intent froze (L7): its certificate values among them. */
  intent: Values | null;
}

/**
 * Whether `edge` was built with what its pick asks for now. Tuning: the frozen
 * choices against the pick's. Certificate: the values the intent froze against
 * what the pick would get now. An edge from before options under a pick from
 * before options always fits (nothing was chosen on either side).
 */
export function builtForChoices(
  edge: BuiltEdge,
  wanted: Values | null,
  accountDefaults: Values,
  parse: (json: string | undefined) => Values,
): boolean {
  if (wanted === null && edge.choices === undefined) return true;
  if (!edge.provider) return true;
  const fields = optionFieldsOf(edge.provider);
  const frozen = edge.choices !== undefined ? parse(edge.choices) : {};
  if (!sameValues(splitChoices(fields, frozen).tuning, splitChoices(fields, wanted ?? {}).tuning))
    return false;
  const keys = certificateKeysOf(edge.provider);
  if (keys.length === 0 || !edge.intent) return true;
  const built = pickKeys(
    { ...defaultsOf(EDGE_CERTIFICATE_OPTIONS[edge.provider].fields), ...edge.intent },
    keys,
  );
  return sameValues(built, certificateValuesFor(edge.provider, accountDefaults, wanted));
}
