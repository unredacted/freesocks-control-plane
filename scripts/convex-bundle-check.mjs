#!/usr/bin/env node
/**
 * Offline reproduction of the bundle step of `convex deploy`, so a module that
 * only bundles in the Node runtime fails CI instead of the deployer.
 *
 * The Convex CLI treats EVERY source file under convex/ as an entry point (not
 * only the files that export functions): `_generated/`, dotfiles, `schema.ts`
 * and names with more than one dot (`*.test.ts`, `*.d.ts`) are skipped, and the
 * rest are split by the `"use node"` directive. Files without it are bundled
 * for the V8 isolate (esbuild platform `browser`), where a `node:*` import or a
 * dependency that requires a Node built-in is a hard error. `convex deploy
 * --dry-run` cannot stand in for this check: it pulls the deployment config
 * over the network before it reports the bundle. This script mirrors the CLI's
 * entry-point rules and esbuild options (convex@1.45 `src/bundler/index.ts`)
 * with the esbuild that ships with the installed `convex`, and adds one rule the
 * CLI only enforces by accident: an isolate entry point must not import a
 * `"use node"` module, even when that module happens to bundle. It also
 * refuses queries, mutations and HTTP actions defined in a `"use node"`
 * module, which the backend rejects at push time after bundling succeeded:
 * every `"use node"` bundle is loaded here and its exports are inspected the
 * way the backend's analyze step inspects them. Finally it refuses a dynamic
 * `import()` in isolate code, which bundles and passes the tests but throws
 * "dynamic module import unsupported" on the first call in a deployment.
 *
 * Usage: `bun run convex:bundle-check` (CI) or `node scripts/convex-bundle-check.mjs`.
 */
import { createRequire } from 'node:module';
import { readdirSync, readFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const convexDir = path.join(root, 'convex');

// The esbuild the Convex CLI itself resolves (an exact pin in its package.json),
// so this check never disagrees with the deployer over a bundler version.
const requireHere = createRequire(import.meta.url);
const convexPkgDir = (() => {
  let dir = path.dirname(requireHere.resolve('convex'));
  while (!existsSync(path.join(dir, 'package.json'))) dir = path.dirname(dir);
  return dir;
})();
const esbuild = createRequire(path.join(convexPkgDir, 'package.json'))('esbuild');

const ENTRY_POINT_EXTENSIONS = ['.js', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts', '.jsx'];
const MUST_BE_ISOLATE = ['http', 'crons', 'schema', 'auth.config'];

function* walk(dir) {
  const entries = readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
  );
  for (const entry of entries) {
    const child = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      // A nested component directory is bundled on its own by the CLI.
      if (existsSync(path.join(child, 'convex.config.ts'))) continue;
      yield* walk(child);
    } else if (entry.isFile()) {
      yield child;
    }
  }
}

function entryPoints() {
  const out = [];
  for (const fpath of walk(convexDir)) {
    const rel = path.relative(convexDir, fpath);
    const base = path.basename(fpath);
    if (!ENTRY_POINT_EXTENSIONS.some((ext) => rel.endsWith(ext))) continue;
    if (rel.startsWith('_generated' + path.sep)) continue;
    if (base.startsWith('.') || base.startsWith('#')) continue;
    if (base === 'schema.ts' || base === 'schema.js') continue;
    if ((base.match(/\./g) ?? []).length > 1) continue;
    if (rel.includes(' ')) continue;
    out.push(fpath);
  }
  return out;
}

/**
 * The module's directive prologue: string-literal statements before the first
 * real statement, after any leading comments. The CLI parses the file with
 * Babel and reads `program.directives`; this is the same answer for every file
 * that parses.
 */
function directivesOf(source) {
  let s = source.replace(/^﻿/, '');
  const directives = [];
  for (;;) {
    s = s.replace(/^(\s+|\/\/[^\n]*\n|\/\*[\s\S]*?\*\/)+/, '');
    const m = /^(["'])((?:(?!\1)[^\\\n]|\\.)*)\1\s*;?/.exec(s);
    if (!m) return directives;
    directives.push(m[2]);
    s = s.slice(m[0].length);
  }
}

function split(files) {
  const isolate = [];
  const node = [];
  const problems = [];
  for (const fpath of files) {
    const rel = path.relative(convexDir, fpath);
    const source = readFileSync(fpath, 'utf8');
    const useNode = directivesOf(source).includes('use node');
    if (useNode && MUST_BE_ISOLATE.includes(rel.replace(/\.[^/.]+$/, ''))) {
      problems.push(`"use node" directive is not allowed for ${rel}.`);
    }
    (useNode ? node : isolate).push(fpath);
  }
  return { isolate, node, problems };
}

const asyncHooksShim = {
  name: 'convex-async-hooks-shim',
  setup(build) {
    if (build.initialOptions.platform !== 'browser') return;
    build.onResolve({ filter: /^(node:)?async_hooks$/ }, (args) => ({
      path: args.path,
      namespace: 'async-hooks-shim',
    }));
    build.onLoad({ filter: /.*/, namespace: 'async-hooks-shim' }, () => ({
      contents:
        'export const AsyncLocalStorage = globalThis.AsyncLocalStorage;' +
        'export const AsyncResource = globalThis.AsyncResource;' +
        'export default { AsyncLocalStorage, AsyncResource };',
      loader: 'js',
    }));
  },
};
const serverOnlyStub = {
  name: 'convex-server-only',
  setup(build) {
    build.onResolve({ filter: /^server-only$/ }, (args) => ({
      path: args.path,
      namespace: 'server-only-stub',
    }));
    build.onLoad({ filter: /.*/, namespace: 'server-only-stub' }, () => ({
      contents: '',
      loader: 'js',
    }));
  },
};

async function bundle(platform, entries) {
  try {
    const result = await esbuild.build({
      entryPoints: entries,
      bundle: true,
      platform,
      format: 'esm',
      target: 'esnext',
      jsx: 'automatic',
      outdir: 'out',
      outbase: convexDir,
      conditions: ['convex', 'module'],
      plugins: [asyncHooksShim, serverOnlyStub],
      write: false,
      sourcemap: false,
      splitting: true,
      chunkNames: path.join('_deps', '[hash]'),
      treeShaking: true,
      minifySyntax: true,
      minifyIdentifiers: true,
      metafile: true,
      logLevel: 'silent',
      absWorkingDir: root,
    });
    return { ok: true, result };
  } catch (err) {
    if (err && Array.isArray(err.errors)) return { ok: false, errors: err.errors };
    throw err;
  }
}

/**
 * Only actions may be defined in the Node runtime. The bundler cannot see this
 * (both bundles succeed); the backend's analyze step loads every pushed module
 * and rejects the push when a "use node" module exports a query, mutation or
 * HTTP action, whatever import form defined it. Do the same: bundle the Node
 * entry points for Node, load them, and read the markers `convex/server` puts on
 * every registered function (`isQuery`, `isMutation`, `isHttp`).
 */
async function nodeOnlyDefinesActions(nodeEntries) {
  const tmp = mkdtempSync(path.join(os.tmpdir(), 'convex-bundle-check-'));
  try {
    await esbuild.build({
      entryPoints: nodeEntries,
      bundle: true,
      platform: 'node',
      format: 'esm',
      target: 'esnext',
      outdir: tmp,
      outbase: convexDir,
      outExtension: { '.js': '.mjs' },
      conditions: ['convex', 'module'],
      plugins: [serverOnlyStub],
      write: true,
      splitting: false,
      logLevel: 'silent',
      absWorkingDir: root,
      // CommonJS dependencies inside an ESM bundle need a `require`.
      banner: {
        js: 'import { createRequire as __convexCheckCreateRequire } from "node:module"; const require = __convexCheckCreateRequire(import.meta.url);',
      },
    });
    const problems = [];
    for (const entry of nodeEntries) {
      const rel = path.relative(convexDir, entry).replace(/\.[^./]+$/, '');
      const mod = await import(pathToFileURL(path.join(tmp, `${rel}.mjs`)).href);
      for (const [name, value] of Object.entries(mod)) {
        if (!value || (typeof value !== 'function' && typeof value !== 'object')) continue;
        const kind = value.isQuery
          ? 'Query'
          : value.isMutation
            ? 'Mutation'
            : value.isHttp
              ? 'HTTP action'
              : null;
        if (kind) {
          problems.push(
            `\`${name}\` defined in \`${rel}.js\` is a ${kind} function. Only actions can be defined in Node.js. Move it to a module without the "use node" directive.`,
          );
        }
      }
    }
    return problems;
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

const HINT =
  'It looks like you are using Node APIs from a file without the "use node" directive.\n' +
  "Add 'use node'; as the first statement of every module that needs Node built-ins or a\n" +
  'Node-only dependency (adapter SDKs, sockets, probes) and import it only from other\n' +
  '"use node" modules. https://docs.convex.dev/functions/runtimes#nodejs-runtime';

async function main() {
  const { isolate, node, problems } = split(entryPoints());
  let failed = false;
  for (const p of problems) {
    failed = true;
    console.error(`convex-bundle-check: ${p}`);
  }

  const isolateBuild = await bundle('browser', isolate);
  if (!isolateBuild.ok) {
    failed = true;
    const formatted = await esbuild.formatMessages(isolateBuild.errors, {
      kind: 'error',
      color: false,
    });
    console.error(formatted.join('\n'));
    if (
      isolateBuild.errors.some((e) =>
        e.notes?.some((n) => n.text.includes('Are you trying to bundle for node?')),
      )
    ) {
      console.error(HINT);
    }
  } else {
    // An isolate entry point that reaches a "use node" module bundles the Node
    // flavour of that module into the V8 isolate. Even when esbuild accepts it,
    // it is the same bug one import away, so refuse it here.
    const nodeSet = new Set(node.map((f) => path.relative(root, f).split(path.sep).join('/')));
    const reached = Object.keys(isolateBuild.result.metafile.inputs).filter((p) => nodeSet.has(p));
    if (reached.length) {
      failed = true;
      console.error(
        'convex-bundle-check: isolate entry points import "use node" modules:\n' +
          reached.map((p) => `  ${p}`).join('\n') +
          '\nMove the shared pure helpers into a module without the directive, or import these only from "use node" files.',
      );
    }

    // The V8 isolate has no dynamic module loading: `await import('./x')` in a
    // query, mutation or isolate action throws "dynamic module import
    // unsupported" at CALL time, on the first request that reaches the line.
    // esbuild bundles it happily and vitest runs it happily, so nothing else
    // catches it before a deployment does.
    const dynamic = [];
    for (const [input, meta] of Object.entries(isolateBuild.result.metafile.inputs)) {
      if (!input.startsWith('convex/')) continue;
      for (const imp of meta.imports ?? []) {
        if (imp.kind === 'dynamic-import')
          dynamic.push(`  ${input} -> ${imp.original ?? imp.path}`);
      }
    }
    if (dynamic.length) {
      failed = true;
      console.error(
        'convex-bundle-check: dynamic import() in code bundled for the V8 isolate:\n' +
          dynamic.join('\n') +
          '\nUse a static import (function-only import cycles are fine in ESM), or move the code into a "use node" action.',
      );
    }
  }

  if (node.length) {
    const nodeBuild = await bundle('node', node);
    if (!nodeBuild.ok) {
      failed = true;
      const formatted = await esbuild.formatMessages(nodeBuild.errors, {
        kind: 'error',
        color: false,
      });
      console.error(formatted.join('\n'));
    } else {
      for (const p of await nodeOnlyDefinesActions(node)) {
        failed = true;
        console.error(`convex-bundle-check: ${p}`);
      }
    }
  }

  if (failed) {
    console.error(
      `convex-bundle-check: FAILED (${isolate.length} isolate + ${node.length} node entry points)`,
    );
    process.exit(1);
  }
  console.log(
    `convex-bundle-check: OK (${isolate.length} isolate + ${node.length} node entry points)`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
