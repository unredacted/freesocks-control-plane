#!/usr/bin/env bun
// Node-runtime floor for the "use node" Convex actions.
//
// Self-hosted Convex runs `"use node"` actions on the Node binary baked into
// the backend image (pinned by that repo's .nvmrc), which FCP does not control.
// The npm packages those actions import declare `engines.node`; this script
// derives the HIGHEST floor among them (never hand-copied) so the deploy can
// refuse a backend whose Node is too old instead of failing at first call.
//
//   bun scripts/node-floor.mjs            -> prints the floor (e.g. 22.22.2)
//   bun scripts/node-floor.mjs --check v22.22.2   -> exit 0 if >= floor, else 1
import { readFileSync } from 'node:fs';

// Packages imported from "use node" action modules. Keep in sync with the
// imports in convex/relayProviderOps.ts / convex/relayProbeOps.ts.
const NODE_ACTION_DEPS = [
  'globalping',
  '@scaleway/sdk-client',
  '@scaleway/sdk-lb',
  '@scaleway/sdk-std',
  'yaml',
];

function parseFloor(range) {
  // Accept ">=X.Y.Z", ">= X.Y.Z", "^X.Y.Z", "X.Y.Z"; ignore anything else.
  const m = /(\d+)\.(\d+)\.(\d+)/.exec(String(range ?? ''));
  return m ? m.slice(1, 4).map(Number) : null;
}
function cmp(a, b) {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

let floor = [0, 0, 0];
for (const name of NODE_ACTION_DEPS) {
  let pkg;
  try {
    pkg = JSON.parse(
      readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url)),
    );
  } catch {
    continue; // not installed here (e.g. a slim CI job) — skip, don't invent a floor
  }
  const f = parseFloor(pkg.engines?.node);
  if (f && cmp(f, floor) > 0) floor = f;
}
const floorStr = floor.join('.');

const args = process.argv.slice(2);
const checkIdx = args.indexOf('--check');
if (checkIdx === -1) {
  process.stdout.write(`${floorStr}\n`);
  process.exit(0);
}
const actual = parseFloor(args[checkIdx + 1]);
if (!actual) {
  process.stderr.write(`node-floor: cannot parse Node version "${args[checkIdx + 1] ?? ''}"\n`);
  process.exit(2);
}
if (cmp(actual, floor) < 0) {
  process.stderr.write(
    `node-floor: backend Node v${actual.join('.')} is below the ${floorStr} floor required by the "use node" action dependencies\n`,
  );
  process.exit(1);
}
process.stdout.write(`node-floor: backend Node v${actual.join('.')} >= ${floorStr} OK\n`);
