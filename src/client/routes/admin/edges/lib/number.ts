/**
 * NumberField parsing (pure).
 *
 * Exports: parseBounded(text, { min?, max?, integer? }) ->
 *   { ok: true, value } | { ok: false, message }   (message is operator-facing copy)
 */
export interface BoundedOptions {
  min?: number;
  max?: number;
  integer?: boolean;
}
export type BoundedResult = { ok: true; value: number } | { ok: false; message: string };

export function parseBounded(text: string, opts: BoundedOptions = {}): BoundedResult {
  const raw = text.trim();
  if (raw === '') return { ok: false, message: 'Enter a number.' };
  const value = Number(raw);
  if (!Number.isFinite(value)) return { ok: false, message: 'Enter a number.' };
  if (opts.integer !== false && !Number.isInteger(value)) {
    return { ok: false, message: 'Enter a whole number.' };
  }
  if (opts.min !== undefined && value < opts.min) {
    return { ok: false, message: `Must be at least ${opts.min}.` };
  }
  if (opts.max !== undefined && value > opts.max) {
    return { ok: false, message: `Must be at most ${opts.max}.` };
  }
  return { ok: true, value };
}
