# Subscription mirrors

A mirror is a copy of one member's subscription body in an S3-compatible bucket, at an
unguessable URL, so a member who cannot reach the site can still fetch their config. Mirrors
are the first piece of the "one front door" work.

**A member's config goes to a bucket only when that member asks for a mirror.** Nothing is
mirrored by default, there is no backfill and there is no bulk "mirror everyone" path. The
confidentiality trade (plaintext in a third-party bucket) is in
`docs/threat-model-cdn-blinding.md`.

Code: `convex/storage.ts` (`"use node"`: uploads, passes, read-back, withdrawal),
`convex/mirrorCopies.ts` (the sync ledger), `convex/lib/mirrorSync.ts` (its rules),
`convex/mirrorUploads.ts` (the barrier), `convex/mirrorProviders.ts` (the provider pool),
`subscriptions.subscriptionMirrors` (what each member holds), `MirrorHelp.svelte` (the member
flow), Admin -> Storage (`AdminStorage.svelte`, `MirrorSyncCard.svelte`).

## A member's mirror

- **Asking.** `POST /api/v1/mirror/request` (sealed) runs `storage.provisionMirror`: the next
  active provider the member has not tried (country-matched first, the country used once and
  never stored), up to `mirror.maxPerUser` (default 3). One object path per key
  (`mirrors/<128-bit hex>`), reused across providers. The body is rendered exactly like a refresh
  (edge rendering, member-facing entry names, the node pin) and written before the member is
  handed the URL. The member page offers mirrors only while a provider is active and the cap is
  above zero (`publicConfig.mirrorsEnabled`). A request that fails says so ("Couldn't add a mirror
  just now").
- **Keeping it current.** A full pass (`storage.drainMirrors`) re-renders every mirrored key and
  rewrites each copy whose object does not hold that body. It runs every six hours
  (`mirror-refresh`) and at once for any change members must see (an edge leaves the pool, a node
  closes, a key is held or released, lanes move: `scheduleMirrorRefresh`). One key's own changes
  refresh only that key, at once: a mode or server switch or a pin rotation
  (`invalidateDelivery`), the member's country (`setStoredCountry`), a re-issue that carries the
  mirror. The pass pages the ledger, so its cost follows the mirrors members asked for, not every
  active key, and it continues in new runs until it reaches the last one.
- **What the object holds.** An edge-required place with nothing renderable gets the unavailable
  stub, never the origin body. Every object is written with `Cache-Control: no-cache`, so a cache
  in front of a bucket revalidates instead of serving an old body (a withdrawn address, the stub
  and a re-issued key all depend on that). An upload whose delivery policy moved while it was in
  flight is repaired by the barrier (`docs/servers.md` "The mirror barrier"); the repair backs off
  per record (two retries at the grace, then doubling up to six hours).
- **Re-issue.** A mode or backend switch carries the mirrors (and the URL) to the new key, and
  the targeted refresh rewrites the objects with the new key's body within seconds. An upload of
  the old key that lands after the carry overwrites the shared object; FCP sees that, marks the
  live key's copies overwritten and rewrites them. A record left on the old key is judged by the
  live row that holds the copy now, so it repairs that row's object and never deletes it.
- **Regenerate.** A new URL by design: the old key's mirrors keep serving it through the 24 h
  grace and are deleted with it; the member asks again for mirrors of the new key.
- **Removing.** "Remove all mirrors" (`DELETE /api/v1/mirror`), the tombstone sweep, idle
  deactivation and an abandoned tombstone all delete the objects. A delete that fails is recorded
  (`mirrorUploads` kind `withdraw`) and the repair pass deletes it until it is gone: a member's
  config never stays in a bucket because one delete failed.

## Providers

- **Inactive** stops handing the provider to new mirrors. The mirrors members already hold on it
  stay in sync (stub, rotated addresses and held keys reach them too).
- **Removing** a provider that holds mirrors deactivates it, marks it `removing` and withdraws
  every copy on it (`storage.withdrawProviderMirrors`): the object is deleted, then the member's
  entry is dropped (they may ask for another mirror). The row goes when the last copy is gone; a
  delete that fails keeps that copy and is retried with a backoff, because the provider row holds
  the only credential that can reach its objects. One that holds no mirror goes at once.
- **The name** is how every copy finds its bucket, so it cannot change while the provider holds
  any. Add a new provider instead.
- **Test connection** writes a health object, reads it back through the public URL with no
  credentials and deletes it, and checks that the public URL does not list the bucket. A bucket
  for mirrors must: allow anonymous reads of objects, deny anonymous listing (the object path is a
  capability), keep no lifecycle rule that expires `mirrors/`, and sit behind no cache that ignores
  `Cache-Control`.

## The sync ledger

For every mirror a member asked for, `mirrorCopies` holds one row per copy (key x provider):
what FCP last wrote (`objectHash`), the body the last check rendered (`servedHash`, its origin
epoch, whether it is the stub), when it was last checked, synced, uploaded and read back, the
consecutive failures and the last one. It stays in step with `subscriptionMirrors` (every write
of that list goes through a helper), and holds no content, no country, no address and no IP.

| State     | Meaning                                                                                |
| --------- | -------------------------------------------------------------------------------------- |
| `in_sync` | the object holds what FCP would serve, as of the last check                            |
| `stale`   | known to differ, an upload is due (the reason says why)                                |
| `failing` | the last attempt failed: the backend body, the upload, the provider, or the public URL |
| `never`   | FCP knows of no object there (the public URL served nothing)                           |

Reasons: `content_changed`, `invalidated`, `country_changed`, `reissued`, `policy_moved`,
`overwritten`, `object_mismatch`, `missing`, `unchecked` (a mirror from before the ledger, until
its first check), `fetch_failed`, `upload_failed`, `provider_missing`, `url_unreadable`,
`url_stale`.

- **Checks.** Every refresh renders the body once and compares it with each copy's `objectHash`:
  equal is confirmed, different is written. The skip-if-unchanged is per copy, so a copy that
  missed a round (a failed provider, an older copy when a second mirror is added) is never masked
  by another.
- **Read-back** (`mirror-verify`, every 15 min): each copy's member-facing URL is read with a
  plain GET about every six hours (a new copy at the next run) and its sha256 compared with
  `objectHash`. Another body or nothing at all gets the object rewritten once; if a read after that
  rewrite finds the same, the URL itself is the problem (not publicly readable, wrong public URL,
  a cache keeping an old body) and the copy is `failing` (`url_unreadable` / `url_stale`) until a
  read matches again. A timeout or 5xx decides nothing and is retried.
- **Counts** are the `stats:mirrorCopies` counter (`lib/statusCounters.ts`), bumped by every
  state change and rebuilt daily with orphaned rows dropped (`mirror-copies-reconcile`). Never a
  scan of keys or of the ledger on a read path.
- **Attention.** A copy stale, failing or not uploaded for over an hour, or in sync but not
  checked for over 13 hours, shows on the dashboard (amber "Mirrors" line) and on Admin -> Storage,
  from bounded index reads. Admin -> Storage also lists every copy by state with its detail (hash
  prefixes only, never the object path or URL, which are capabilities) and a **Re-check** that
  renders and rewrites that copy and reads it back now (also the way out once a bucket is
  fixed).
- **Seeding.** Mirrors from before the ledger get their rows once, from a pass over the active
  keys: post-deploy (`storage:seedMirrorLedger`) or by the first mirror pass; nothing is uploaded
  by it.

API: `GET /api/v1/admin/mirror-sync[?state=&cursor=]` (summary + one page of copies),
`POST /api/v1/admin/mirror-sync/recheck {id}`; the dashboard reads `mirrors` from
`/api/v1/admin/status`.

## Cost

Per copy: about four GETs a day of a few KB (the read-back), plus a write only when what FCP
serves changed. No request carries anything but the object path the member's app fetches too.

## Tests

- `convex/lib/mirrorSync.test.ts`: the state rules.
- `convex/mirrorCopies.test.ts`: the ledger and every path that writes, moves or drops a copy.
- `bun run test:integration:s3`: the whole path against a real S3-compatible store (a throwaway
  SeaweedFS, `docker-compose.s3-test.yml`): request, refresh, read-back, an object deleted and
  one overwritten behind FCP's back, removal, a provider's withdrawal, a store that refuses writes,
  and the connection test.
