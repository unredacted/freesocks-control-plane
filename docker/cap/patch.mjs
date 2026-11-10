import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

// Fail the image build on upstream drift, including a same-tag rebuild.
const pins = {
  'src/events/index.js': 'd44c7e77682dbd0215e7e98997b98e113e2860a7f5f4ccc1dbae855dc130ef1b',
  'src/events/context.js': '50b104a283be63a428d63589b5f915eb615b0e99b8656b79ae02d0637ddda3ea',
};
for (const [path, expected] of Object.entries(pins)) {
  if (createHash('sha256').update(readFileSync(path)).digest('hex') !== expected) {
    throw new Error(`Cap privacy overlay needs review: ${path} changed`);
  }
}

const path = 'src/events/index.js';
const events = readFileSync(path, 'utf8');
const start = events.indexOf('export function recordEvent(raw, extra) {');
const end = events.indexOf('export function contextFields(ctx) {', start);
if (start < 0 || end < 0) throw new Error('Cap event recorder not found');
// No events reach DuckDB, live-event listeners or webhook delivery. Merely
// setting ipMode=none would still store UA, language, fingerprint and timing.
writeFileSync(
  path,
  events.slice(0, start) + 'export function recordEvent() { return null; }\n\n' + events.slice(end),
);
writeFileSync('src/events/context.js', readFileSync(new URL('./context.mjs', import.meta.url)));
