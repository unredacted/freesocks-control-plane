// Pinned trust anchors for the verifier extension. COPY this to `pinned.js` and
// fill the values from a REPRODUCIBLE build of the release you are pinning (see
// docs/oob-verification.md). pinned.js is what makes the extension trustworthy:
// it ships inside the store-reviewed extension, NOT from the CDN, so the CDN
// cannot change it.
//
//   indexSha384  hex SHA-384 of dist/index.html from the reproducible build:
//                  shasum -a 384 dist/index.html
//                (index.html carries SRI for every script/style, so pinning its
//                 hash transitively pins the whole bundle.)
//   manifestPk / manifestPkPq
//                the baked manifest public keys (bun scripts/e2ee-fingerprint.mjs,
//                or VITE_FS_MANIFEST_PK / VITE_FS_MANIFEST_PK_PQ from the build env);
//                used by the optional manifest-signature check (see README).
export const PINNED = {
  origin: 'https://app.freesocks.org',
  indexSha384: 'REPLACE_WITH_HEX_SHA384_OF_dist_index_html',
  manifestPk: 'REPLACE_WITH_VITE_FS_MANIFEST_PK',
  manifestPkPq: 'REPLACE_WITH_VITE_FS_MANIFEST_PK_PQ',
};
