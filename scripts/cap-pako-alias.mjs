import { createRequire } from 'node:module';

// Cap inserts a classic <script> and expects window.pako.inflateRaw. The
// public entry's import condition selects ESM; its require condition selects
// the UMD build that provides that global. Share this with the browser harness.
export const capPakoAlias = {
  find: /^pako\/browser\/inflate(?=\?|$)/,
  replacement: createRequire(import.meta.url).resolve('pako/browser/inflate'),
};
