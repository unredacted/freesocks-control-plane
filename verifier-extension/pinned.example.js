// TEMPLATE / reference shape for pinned.js. The real pinned.js is GENERATED from a
// reproducible build:
//   bun run build && bun run verifier:pin      (scripts/gen-verifier-pin.mjs)
// pinned.js is what makes the extension trustworthy: it ships inside the
// store-reviewed extension, NOT from the CDN, so the CDN cannot change it. See
// docs/oob-verification.md.
//
//   indexSha384  hex SHA-384 of a NONCE-NORMALIZED dist/index.html. Do NOT use a
//                raw `shasum -a 384 dist/index.html`: Caddy templates a per-request
//                CSP nonce into <meta name="csp-nonce">, so the pin is computed over
//                the canonicalized tag (the generator + background.js apply the same
//                normalization). index.html carries SRI for every chunk, so pinning
//                it transitively pins the whole bundle.
//   manifestPk / manifestPkPq
//                the baked manifest public keys (VITE_FS_MANIFEST_PK / _PK_PQ);
//                used by the optional manifest-signature check (see README).
export const PINNED = {
  origin: 'https://app.freesocks.org',
  indexSha384: 'REPLACE_WITH_HEX_SHA384_OF_dist_index_html',
  manifestPk: 'REPLACE_WITH_VITE_FS_MANIFEST_PK',
  manifestPkPq: 'REPLACE_WITH_VITE_FS_MANIFEST_PK_PQ',
};
