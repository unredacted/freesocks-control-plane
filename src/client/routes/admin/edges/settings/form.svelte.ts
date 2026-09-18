/**
 * The settings page's edit state: the server view flattened (`base`), the
 * operator's pending edits by flat path, and which fields currently hold an
 * invalid text. Sections share ONE instance and each saves only its own paths.
 */
import type { EdgeConfigView } from '../../../../../shared/contracts/edges';
import {
  buildPatch,
  diffConfig,
  flattenConfig,
  pathCovers,
  sameValue,
  type ConfigChange,
  type FlatConfig,
} from './configDiff';

export class ConfigForm {
  readonly #view: () => EdgeConfigView | undefined;
  edits = $state<FlatConfig>({});
  invalid = $state<Record<string, boolean>>({});
  base: FlatConfig = $derived.by(() => {
    const v = this.#view();
    return v ? flattenConfig(v.config) : {};
  });

  constructor(view: () => EdgeConfigView | undefined) {
    this.#view = view;
  }

  get view(): EdgeConfigView | undefined {
    return this.#view();
  }

  get(path: string): unknown {
    return path in this.edits ? this.edits[path] : this.base[path];
  }
  bool(path: string): boolean {
    return this.get(path) === true;
  }
  num(path: string): number {
    const v = this.get(path);
    return typeof v === 'number' ? v : Number.NaN;
  }
  str(path: string): string {
    const v = this.get(path);
    return typeof v === 'string' ? v : '';
  }
  list(path: string): string[] {
    const v = this.get(path);
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
  }
  rule(path: string): Record<string, unknown> {
    const v = this.get(path);
    return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
  }

  set(path: string, value: unknown): void {
    if (sameValue(this.base[path], value)) delete this.edits[path];
    else this.edits[path] = value;
  }
  setRuleField(path: string, key: string, value: unknown): void {
    this.set(path, { ...this.rule(path), [key]: value });
  }
  setInvalid(key: string, bad: boolean): void {
    if (bad) this.invalid[key] = true;
    else delete this.invalid[key];
  }

  bounds(path: string): { min: number; max: number } | undefined {
    return this.view?.bounds[path];
  }
  defaultOf(path: string): unknown {
    return this.view?.defaults[path];
  }
  defaultNumber(path: string): number | undefined {
    const d = this.defaultOf(path);
    return typeof d === 'number' ? d : undefined;
  }

  changes(paths: readonly string[]): ConfigChange[] {
    return diffConfig(this.base, this.edits, paths);
  }
  patch(paths: readonly string[]): FlatConfig {
    return buildPatch(this.changes(paths));
  }
  hasInvalid(paths: readonly string[]): boolean {
    return Object.keys(this.invalid).some((k) => paths.some((p) => pathCovers(p, k)));
  }
  discard(paths: readonly string[]): void {
    for (const p of paths) delete this.edits[p];
    for (const k of Object.keys(this.invalid)) {
      if (paths.some((p) => pathCovers(p, k))) delete this.invalid[k];
    }
  }
}
