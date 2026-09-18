/**
 * TagInput helpers (pure).
 *
 * Exports:
 *   splitTags(raw)                      split pasted / typed text on commas, whitespace and semicolons
 *   addTags(current, raw, opts)         -> { next, rejected } (normalised, de-duplicated, capped)
 *   normalizeHostname(raw)              lower-case DNS name or null
 *   normalizeCountry(raw)               upper-case ISO 3166-1 alpha-2 shape or null
 */
export function splitTags(raw: string): string[] {
  return raw
    .split(/[\s,;]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

export interface AddTagsOptions {
  /** Return the normalised tag, or null to reject it. */
  normalize?: (raw: string) => string | null;
  max?: number;
}

export function addTags(
  current: readonly string[],
  raw: string,
  opts: AddTagsOptions = {},
): { next: string[]; rejected: string[] } {
  const next = [...current];
  const rejected: string[] = [];
  for (const piece of splitTags(raw)) {
    const tag = opts.normalize ? opts.normalize(piece) : piece;
    if (tag === null || tag === '') {
      rejected.push(piece);
      continue;
    }
    if (next.includes(tag)) continue;
    if (opts.max !== undefined && next.length >= opts.max) {
      rejected.push(piece);
      continue;
    }
    next.push(tag);
  }
  return { next, rejected };
}

const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
export function normalizeHostname(raw: string): string | null {
  const name = raw.trim().toLowerCase().replace(/\.$/, '');
  if (name.length === 0 || name.length > 253) return null;
  const labels = name.split('.');
  if (labels.length < 2) return null;
  return labels.every((l) => LABEL.test(l)) ? name : null;
}

export function normalizeCountry(raw: string): string | null {
  const code = raw.trim().toUpperCase();
  return /^[A-Z]{2}$/.test(code) ? code : null;
}
