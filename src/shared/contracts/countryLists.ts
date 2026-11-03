/**
 * Country lists (`/api/v1/admin/edges/lists/*`, convex/countryLists.ts,
 * docs/edges.md "Country lists"): community lists of names and ranges that
 * work in a country (allowlists) or are blocked there (blocklists). Counts and
 * codes only: a list's names and ranges never leave the server, except as the
 * answer to a lookup an operator typed.
 */
import { z } from 'zod';

/**
 * One upload part: its text, JSON-encoded, in UTF-8 bytes. Sealed with HPKE
 * (base64 grows it by a third), a full part plus its envelope stays under the
 * API's 64 KiB request cap; a test sends one to prove it.
 */
export const UPLOAD_PART_BYTES = 44_000;
/** A whole paste, in UTF-8 bytes. Larger lists come by address. */
export const UPLOAD_MAX_BYTES = 4 * 1024 * 1024;
/** Operator networks (ASNs) one list may cover. */
export const MAX_LIST_NETWORKS = 32;

/**
 * What one code point adds to `JSON.stringify(text)` in UTF-8 bytes. JSON
 * escapes per character, so sizes add up along a string and a part's size is
 * the sum over its characters plus its two quotes: linear, however long.
 */
function charBytes(ch: string): number {
  const cp = ch.codePointAt(0)!;
  if (ch === '"' || ch === '\\') return 2;
  if (cp < 0x20)
    return ch === '\b' || ch === '\f' || ch === '\n' || ch === '\r' || ch === '\t' ? 2 : 6;
  if (cp < 0x80) return 1;
  if (cp < 0x800) return 2;
  // A lone surrogate is written as \uXXXX.
  if (cp >= 0xd800 && cp <= 0xdfff) return 6;
  return cp < 0x10000 ? 3 : 4;
}

/** `JSON.stringify(text)` in UTF-8 bytes, without building it. */
export function encodedBytes(text: string): number {
  let n = 2;
  for (const ch of text) n += charBytes(ch);
  return n;
}

/**
 * Text cut into upload parts at line ends (a line too long for one part is cut
 * where it must). Joined in order, the parts are the text again. Each part's
 * JSON-encoded size is at most `maxBytes`; the work is linear in the text.
 */
export function splitUploadParts(text: string, maxBytes = UPLOAD_PART_BYTES): string[] {
  const parts: string[] = [];
  let cur = '';
  let curBytes = 2;
  const push = () => {
    if (cur) parts.push(cur);
    cur = '';
    curBytes = 2;
  };
  for (const line of text.match(/[^\n]*\n|[^\n]+$/g) ?? []) {
    const lineBytes = encodedBytes(line) - 2;
    if (curBytes + lineBytes <= maxBytes) {
      cur += line;
      curBytes += lineBytes;
      continue;
    }
    push();
    if (2 + lineBytes <= maxBytes) {
      cur = line;
      curBytes = 2 + lineBytes;
      continue;
    }
    // One line longer than a part: whole code points until it fits.
    let piece: string[] = [];
    let pieceBytes = 2;
    for (const ch of line) {
      const b = charBytes(ch);
      if (pieceBytes + b > maxBytes) {
        parts.push(piece.join(''));
        piece = [];
        pieceBytes = 2;
      }
      piece.push(ch);
      pieceBytes += b;
    }
    cur = piece.join('');
    curBytes = pieceBytes;
  }
  push();
  return parts;
}

export const CountryListRegime = z.enum(['allowlist', 'blocklist']);
export type CountryListRegime = z.infer<typeof CountryListRegime>;

/** Why a version waits for a person (lib/edges/lists/guards.ts). */
export const CountryListHoldReason = z.enum([
  'first_version',
  'emptied',
  'jump',
  'replaced',
  'too_broad',
  'invalid',
  'capped',
]);
export type CountryListHoldReason = z.infer<typeof CountryListHoldReason>;

const DiffPart = z.object({ added: z.number(), removed: z.number(), common: z.number() });

export const CountryListVersion = z.object({
  id: z.string(),
  at: z.string(),
  source: z.enum(['fetch', 'upload']),
  status: z.enum(['staging', 'held', 'active', 'superseded', 'rejected', 'failed']),
  heldReasons: z.array(z.string()),
  counts: z.object({
    entries: z.number(),
    names: z.number(),
    wildcards: z.number(),
    v4Ranges: z.number(),
    v6Ranges: z.number(),
    /** IPv4 addresses covered. */
    v4: z.number(),
    /** IPv6 /64s covered. */
    v6: z.number(),
    invalid: z.number(),
    nonPublic: z.number(),
    tooBroad: z.number(),
    capped: z.number(),
  }),
  diff: z.object({ names: DiffPart, v4: DiffPart, v6: DiffPart }).nullable(),
  /** The first few lines that could not be read. */
  samples: z.array(z.string()),
  failure: z.string().nullable(),
  decidedAt: z.string().nullable(),
  /** A person used it or threw it away (otherwise FCP did, by the rules). */
  byPerson: z.boolean(),
});
export type CountryListVersion = z.infer<typeof CountryListVersion>;

export const CountryListSource = z.union([
  z.object({ kind: z.literal('url'), url: z.string() }),
  z.object({ kind: z.literal('paste') }),
]);
export type CountryListSource = z.infer<typeof CountryListSource>;

export const CountryListView = z.object({
  id: z.string(),
  label: z.string(),
  country: z.string(),
  regime: CountryListRegime,
  /** Operator networks (ASNs) it covers; empty: some networks in the country. */
  networks: z.array(z.number()),
  source: CountryListSource,
  fetchEveryHours: z.number(),
  enabled: z.boolean(),
  active: CountryListVersion.nullable(),
  held: CountryListVersion.nullable(),
  /** An ingest running now. */
  busy: z.enum(['fetch', 'upload']).nullable(),
  lastFetch: z.object({ at: z.string(), outcome: z.string() }).nullable(),
  /** When the source last said what the active version says. */
  confirmedAt: z.string().nullable(),
  /** Confirmed within `edge.lists.staleDays`: only a fresh list is read as evidence. */
  fresh: z.boolean(),
});
export type CountryListView = z.infer<typeof CountryListView>;

/** `GET lists` (`?country=` narrows it). */
export const CountryListsResponse = z.object({
  /** `edge.lists.enabled`: off, nothing is fetched and nothing reads a list. */
  enabled: z.boolean(),
  staleDays: z.number(),
  defaultFetchHours: z.number(),
  lists: z.array(CountryListView),
});
export type CountryListsResponse = z.infer<typeof CountryListsResponse>;

/** `GET lists/{id}`. */
export const CountryListDetail = z.object({
  enabled: z.boolean(),
  staleDays: z.number(),
  list: CountryListView,
  versions: z.array(CountryListVersion),
});
export type CountryListDetail = z.infer<typeof CountryListDetail>;

/** `POST lists`. */
export const CountryListCreate = z.object({
  label: z.string(),
  country: z.string(),
  regime: CountryListRegime,
  networks: z.array(z.union([z.number(), z.string()])).optional(),
  source: CountryListSource,
  fetchEveryHours: z.number().optional(),
  enabled: z.boolean().optional(),
});
export type CountryListCreate = z.infer<typeof CountryListCreate>;

/** `PATCH lists/{id}`. */
export const CountryListPatch = z.object({
  label: z.string().optional(),
  country: z.string().optional(),
  regime: CountryListRegime.optional(),
  networks: z.array(z.union([z.number(), z.string()])).optional(),
  url: z.string().optional(),
  fetchEveryHours: z.number().optional(),
  enabled: z.boolean().optional(),
});
export type CountryListPatch = z.infer<typeof CountryListPatch>;

export const CountryListCreated = z.object({ id: z.string() });
export const CountryListOk = z.object({ ok: z.literal(true) });

/** `POST lists/{id}/uploads`. */
export const CountryListUploadStarted = z.object({
  uploadId: z.string(),
  partBytes: z.number(),
  maxBytes: z.number(),
});
/** `POST lists/{id}/uploads/{uploadId}/parts`. */
export const CountryListPartAdded = z.object({ parts: z.number(), bytes: z.number() });

/** `POST lists/lookup`: which lists hold each name or address. */
export const CountryListLookup = z.object({
  results: z.array(
    z.object({
      entry: z.string(),
      kind: z.enum(['name', 'address', 'invalid']),
      lists: z.array(
        z.object({
          id: z.string(),
          label: z.string(),
          country: z.string(),
          regime: CountryListRegime,
          how: z.enum(['exact', 'wildcard', 'range']),
          enabled: z.boolean(),
          fresh: z.boolean(),
        }),
      ),
    }),
  ),
});
export type CountryListLookup = z.infer<typeof CountryListLookup>;
