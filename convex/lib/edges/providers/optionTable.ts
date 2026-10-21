/**
 * The docs/edges.md table of every provider option, rendered from the option
 * registry alone (`providers/templates.ts`): `optionTable.test.ts` re-renders it
 * and fails when the checked-in section drifts, so the documented options,
 * defaults and API fields are always the ones FCP sends.
 */
import { EDGE_PROVIDER_IDS } from '../../edgeProviderIds';
import type { OptionField } from './options';
import { optionFieldsOf } from './templates';

export const OPTION_TABLE_HEADING = '### Every provider option';

const cell = (s: string): string => s.replace(/\|/g, '\\|');

function defaultWords(f: OptionField): string {
  const d = f.default;
  if (d === undefined || d === null || d === '') return "provider's own";
  if (f.type === 'select') return f.options?.find((o) => o.value === d)?.label ?? String(d);
  if (f.type === 'boolean') return d === true ? 'on' : 'off';
  if (Array.isArray(d)) return d.length === 0 ? 'none' : d.join(', ');
  if (typeof d === 'object') return Object.keys(d).length === 0 ? 'none' : JSON.stringify(d);
  return f.unit ? `${String(d)} ${f.unit}` : String(d);
}

function whereWords(f: OptionField): string {
  if (f.kind === 'certificate') return 'account default, per node';
  return f.regional ? 'template or location, per node' : 'template, per node';
}

const LIVE_WORDS: Record<string, string> = {
  in_place: 'in place',
  new_version: 'new service version',
  rebuild: 'rebuild',
};

/** One row per option a form shows (hidden ones are kept for stored templates only). */
export function renderOptionTable(): string {
  const rows: string[] = [
    '| provider | group | option | API field | default | chosen | live change at the provider |',
    '| --- | --- | --- | --- | --- | --- | --- |',
  ];
  for (const p of EDGE_PROVIDER_IDS) {
    for (const f of optionFieldsOf(p)) {
      if (f.hidden) continue;
      const api = f.wire ? `\`${f.wire.resource}.${f.wire.field}\`` : '';
      rows.push(
        `| ${p} | ${cell(f.group ?? '')} | ${cell(f.label)} | ${cell(api)} | ${cell(defaultWords(f))} | ${whereWords(f)} | ${f.live ? LIVE_WORDS[f.live] : ''} |`,
      );
    }
  }
  return rows.join('\n');
}
