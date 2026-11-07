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
flow, "Trouble connecting?", right under the key on `/account` and `/get-account`),
`MirrorSuggestion.svelte` (the onboarding suggestion), Admin -> Storage (`AdminStorage.svelte`,
`MirrorSyncCard.svelte`).

## A member's mirror

- **Asking.** `POST /api/v1/mirror/request` (sealed both ways) runs `storage.provisionMirror`:
  the next active provider the member has not tried (country-matched first, the country used
  once and never stored), up to `mirror.maxPerUser` (default 3). The country that picks the host
  is, in order: the member's answer sent with the request (`region`, saved to the key first, see
  below), a host hint (`countryCode`, for a key with no country), "global" (`countryCode: null`),
  the key's stored answer (the opt-out picks global, never the CDN's reading), else the CDN
  country. A country in either field is refused in plaintext. One object path per key
  (`mirrors/<128-bit hex>`), reused across providers, with one object per format beside it
  ("Formats" below). Every object is rendered exactly like a refresh (edge rendering,
  member-facing entry names, the node pin) and written before the member is handed the URL. The member page offers mirrors only while a provider is active and the cap is
  above zero (`publicConfig.mirrorsEnabled`). A request that fails says so ("Couldn't add a mirror
  just now"). Two requests that raced to one provider for a key with no mirror yet each upload
  under their own path; the append that replaces the other's entry withdraws that object
  (`appendMirror`), and the member page holds both of its mirror buttons while either request
  runs.
- **Shaped for the member's answer.** A mirror is rendered for the key's stored answer to
  "Where are you connecting from?" (`sniRegion`), never a guess: no request reaches FCP when an
  app reads the bucket. Without an answer it gets the universal server names, no address only
  for some countries, and edges blocked in any listed country last. With `delivery.country.ask`
  on, the member page asks for the answer when a key without one gets a mirror, and sends it as
  `region` (a listed country or the opt-out `ZZ`): it is saved to every freedom-family key of
  the member (as the account card saves it, counted against `account.country.day`) BEFORE the
  object is rendered, so the first upload is already shaped for it. A key whose mode holds no
  country refuses it (`validation`). Changing the answer later rewrites the member's mirrors at
  once at the same URL (`country_changed` below). docs/privacy.md has what the object reveals.
- **Suggested at sign-up.** On `/get-account`, once the first key is issued, a visitor the CDN
  places in a country on the censored-country list is told the main link may be blocked there
  and offered a mirror link, the country prefilled. The account view carries only the server's
  verdict (`geoCountryCensored`, from this request's country, never the stored answer); the list
  stays server-side and neither the country nor the verdict is stored. No country, no suggestion.
  Still opt-in: the mirror is requested only on the member's click, through the same route. With
  a mirror on the key both links are listed and the member picks the one their app gets (the
  mirror is the recommendation); the pass (copy, download, QR) and the app buttons follow the
  pick, which is page state only. The pass shows the mirror's plain link list; each app's button
  imports the mirror in that app's format, and a Clash or sing-box app's card also shows its own
  mirror link to copy (FlClash and Mihomo Party import by paste). rawConfig modes get no
  suggestion, as they get no mirrors. The member's own stored answer
  wins over this request's country (`suggestionCountry` in `src/client/lib/mirrorSuggestion.ts`):
  a listed answer brings the suggestion even when the request looks elsewhere (a VPN), and "Somewhere
  else, or I'd rather not say" means no suggestion whatever the request says.
- **The member page** (with `delivery.country.ask` on; `src/client/lib/countryQuestion.ts`). Asked
  only when this build can seal and the key (or, before the first key, the mode picked) holds a
  country. Sign-up (`/get-account` step 3, `CountryQuestion.svelte`): required before "Get my free
  key", the listed countries then "Somewhere else, or I'd rather not say", never Automatic;
  prefilled from the guess or this request's listed country (and says so), otherwise "Choose one";
  sent sealed with the first key. A mirror (`MirrorHelp`, `MirrorSuggestion`): a key with an answer
  shows "Your mirror links are set up for Iran." (or "aren't set up for any country.") with Change
  and asks nothing more; a key without one asks the same question in place of the region picker
  and sends it with the request; mirrors the key already has get "Pick yours so they work better
  there." and a Save that goes through the account card's route (the server rewrites them at the
  same URLs). The account card says "This also shapes your mirror links." on a key with mirrors and
  warns that Automatic leaves them with no country. A privacy-family key keeps the old transient
  region picker.
- **Keeping it current.** A full pass (`storage.drainMirrors`) re-renders every mirrored key and
  rewrites each copy whose object does not hold that body. It runs every six hours
  (`mirror-refresh`) and at once for any change members must see (an edge leaves the pool, a node
  closes, a key is held or released, lanes move: `scheduleMirrorRefresh`). One key's own changes
  refresh only that key, at once: a mode or server switch or a pin rotation
  (`invalidateDelivery`), the member's country (`setStoredCountry`), a re-issue that carries the
  mirror. The pass pages the ledger, so its cost follows the mirrors members asked for, not every
  active key, and it continues in new runs until it reaches the last one.
- **What the object holds.** An edge-required place with nothing renderable gets the unavailable
  stub, never the origin body, and so does a body the Hysteria guard cannot repair
  (`lib/hysteriaGuard.ts`, which reads the link list, Mihomo YAML and sing-box JSON alike: an
  entry without the expected pin is dropped, or the body refused). The stub is valid in its
  object's format (`mirrorStub`): the plain-text line for the link list, and for `.yaml` and
  `.json` a config that loads but whose only entries are inert ones at loopback, every route to
  them, so the app fails closed. Every object is written with `Cache-Control: no-cache`, so a cache
  in front of a bucket revalidates instead of serving an old body (a withdrawn address, the stub
  and a re-issued key all depend on that). An upload whose delivery policy moved while it was in
  flight (the place's epoch, the key's own revision, the member's country or address lane) is
  repaired by the barrier (`docs/servers.md` "The mirror barrier"); the repair backs off
  per record (two retries at the grace, then doubling up to six hours).
- **Re-issue.** A mode or backend switch carries the mirrors (and the URL) to the new key, and
  the targeted refresh rewrites the objects with the new key's body within seconds. An upload of
  the old key that lands after the carry overwrites the shared object; FCP sees that, marks the
  live key's copies overwritten and rewrites them. A record left on the old key is judged by the
  live row that holds the copy now, so it repairs that row's object and never deletes it.
- **Regenerate.** A new URL by design: the old key's mirrors keep serving it through the 24 h
  grace and are deleted with it (and recorded for withdrawal when the grace ends, so a provider
  removed meanwhile keeps its credentials until they are gone); the member asks again for mirrors
  of the new key.
- **Removing.** "Remove all mirrors" (`DELETE /api/v1/mirror`), the tombstone sweep, idle
  deactivation and an abandoned tombstone all delete the objects. A delete that fails is recorded
  (`mirrorUploads` kind `withdraw`) and the repair pass deletes it until it is gone: a member's
  config never stays in a bucket because one delete failed.

## Formats

The main link picks the body's format per request from the app's User-Agent (`docs/backends.md`
"Subscription formats"). A bucket cannot, so a mirror is one object per format, at sibling paths
of the key's one random id (`src/shared/mirrorFormats.ts`):

| Format    | Object              | Read by                                                    |
| --------- | ------------------- | ---------------------------------------------------------- |
| `links`   | `mirrors/<id>`      | apps that read a share-link list (Hiddify, v2rayNG, ...)   |
| `clash`   | `mirrors/<id>.yaml` | Clash and Mihomo apps (Clash Verge, FlClash, Mihomo Party) |
| `singbox` | `mirrors/<id>.json` | sing-box apps (sing-box, Karing)                           |

- **Rendered like the main link's answer to that app.** Each format's body is fetched from the
  backend with a fixed User-Agent of its kind (`convex/lib/mirrorFormats.ts` `MIRROR_FETCH_UA`:
  none for `links`, as every mirror held before; a current Mihomo, never a legacy Clash core; the
  canonical sing-box app), pinned by the same rules (the other formats to the node the `links` body
  landed on whenever their body names it, so the key's recorded pin, and a server switch, cover
  every format; only a format that cannot carry that node resolves to another), edge-rendered for that client family (its
  per-client rules and leak checks) and finished with member-facing names. A format that cannot
  carry what the place serves (sing-box on XHTTP) holds the app notice, as the main link answers
  that app (no record that an app got it: nothing tells FCP an app read the mirror). Each object
  keeps the backend's `Content-Type`.
- **Which formats.** Every key whose backend delivers a subscription document gets all three; a
  bare access key (Outline) keeps the one `links` object. A copy holds them together: an upload
  writes every format, a provider counts as written only when every object was (each write
  settles before it is judged; an upload that failed keeps its barrier record open, so a copy
  written in part is rewritten whole, or withdrawn when nothing references it), and a format
  the key no longer keeps (a re-issue onto an access-key backend) is deleted with the next upload.
  The member's entry lists the formats written (`subscriptionMirrors[].formats`; absent = `links`
  only), and the member page offers a format's link only once it exists.
- **Which app gets which.** The catalog's `format` (`publicConfig.clients[].format`): the
  client row's own `format` (Admin -> Clients "Subscription format"; the defaults set it), else
  from the app's name by the rules a User-Agent goes by (`mirrorFormatOfApp`). MirrorHelp lists each
  mirror once per format, labelled with the catalog apps that read it ("For Clash, FlClash and
  Mihomo Party"); a format no catalog app reads is not offered.
- **Mirrors from before formats.** They hold the `links` object only, at the same URL, which keeps
  its meaning. The post-deploy seed (`storage:seedMirrorLedger`) counts copies not written in
  every format their key keeps and, when there are any, starts one mirror pass at once, so they
  gain their objects within that pass rather than at the next six-hourly sweep (bounded by it
  either way). Until then the member page leaves Clash and sing-box apps on the main link and
  says the mirror link for them is still being set up.
- **What a format's object cannot say.** The main link also sends `subscription-userinfo` (traffic
  and expiry), `profile-update-interval` and `profile-title`. A bucket serves only standard object
  headers (`Content-Type`, `Cache-Control`, `Content-Disposition`), so a mirror has none of them,
  in any format (the `links` object never had them either). What an app loses: no usage or expiry
  bar (the account page shows both); its own default refresh interval, or the one the member sets,
  instead of FCP's (a rotated address reaches it at its next refresh, as before); and the profile
  name, which the import button sets (`#FreeSocks`, `&name=`) and a pasted link leaves to the app
  (usually the URL's last part). None of them stops an app importing or refreshing the mirror.

## Providers

- **Inactive** stops handing the provider to new mirrors. The mirrors members already hold on it
  stay in sync (stub, rotated addresses and held keys reach them too).
- **Removing** a provider that holds mirrors deactivates it, marks it `removing` and withdraws
  every copy on it (`storage.withdrawProviderMirrors`): the object is deleted, then the member's
  entry is dropped (they may ask for another mirror). The row goes when the last copy is gone and
  no open upload or withdrawal record names the provider; a delete that fails keeps that copy and
  is retried with a backoff, because the provider row holds the only credential that can reach its
  objects. One that holds no mirror and no pending clean-up goes at once.
- **The name** is how every copy finds its bucket, so it cannot change while the provider holds
  any (or a pending clean-up names it). Add a new provider instead.
- **Test connection** writes a health object, reads it back through the public URL with no
  credentials and deletes it, and checks that the public URL does not list the bucket. A bucket
  for mirrors must: allow anonymous reads of objects, deny anonymous listing (the object path is a
  capability), keep no lifecycle rule that expires `mirrors/`, and sit behind no cache that ignores
  `Cache-Control`.

## The sync ledger

For every mirror a member asked for, `mirrorCopies` holds one row per copy (key x provider),
which covers all of the copy's format objects: their hashes are combined into one
(`mirrorSetHash`; a copy of the `links` object alone hashes as that body, so every hash recorded
before formats still means what it did). It holds what FCP last wrote (`objectHash`), the body the last check rendered (`servedHash`, its origin
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

- **Checks.** Every refresh renders each format's body once and compares their combined hash with
  each copy's `objectHash`: equal is confirmed, different is written (every format of that copy).
  The skip-if-unchanged is per copy, so a copy that missed a round (a failed provider, an older
  copy when a second mirror is added) is never masked by another. A country change, a re-render
  or a re-issue moves every format's body, so no format is left behind: the copy is written whole
  or stays stale.
- **Read-back** (`mirror-verify`, every 15 min): each copy's member-facing URLs (one per format it
  holds) are read with a plain GET about every six hours (a new copy at the next run) and their
  combined hash compared with `objectHash`; any one missing is `missing` (even while another format's read fails), and each read stops at 4
  MiB (a larger answer is not the object). Another body or
  nothing at all gets the object rewritten once and read back right after; if that read finds the
  same, the URL itself is the problem (not publicly readable, wrong public URL, a cache keeping an
  old body) and the copy is `failing` (`url_unreadable` / `url_stale`) until a read matches again.
  Only a copy awaiting that one confirmation is read again soon (`recheckAt`); a URL that keeps
  failing goes back to the normal cadence, so it never crowds out the others. A timeout or 5xx
  decides nothing. A refresh never clears a URL failure; the admin Re-check (rewrite, then read)
  does once the URL serves the object.
- **Counts** are the `stats:mirrorCopies` counter (`lib/statusCounters.ts`), bumped by every
  state change and rebuilt daily with orphaned rows dropped (`mirror-copies-reconcile`). Never a
  scan of keys or of the ledger on a read path.
- **Attention.** A copy stale, failing or not uploaded for over an hour, or in sync but not
  checked for over 13 hours, shows on the dashboard (amber "Mirrors" line) and on Admin -> Storage,
  from bounded index reads. Admin -> Storage also lists every copy by state with its detail (hash
  prefixes only, never the object path or URL, which are capabilities, and no member or key
  identifier: the feed is read with the settings scope) and a **Re-check** that
  renders and rewrites that copy and reads it back now (also the way out once a bucket is
  fixed).
- **Seeding.** Mirrors without ledger rows (from before the ledger, or added while older code
  ran after a rollback) get them from a pass over the active keys: on every deploy
  (`storage:seedMirrorLedger`, idempotent) and by the first mirror pass; nothing is uploaded by
  it.

API: `GET /api/v1/admin/mirror-sync[?state=&cursor=]` (summary + one page of copies),
`POST /api/v1/admin/mirror-sync/recheck {id}`; the dashboard reads `mirrors` from
`/api/v1/admin/status`.

## Cost

Per copy: about four read-backs a day, each one GET of a few KB per format (twelve GETs a day for
a three-format copy), plus a write of every format only when what FCP serves changed. A refresh
of a key fetches its backend body once per format (three fetches where it was one). Deletes are
one per format. At about 580 mirrored keys that is roughly 7,000 GETs a day on the buckets, three
objects per copy where there was one, and on a change (a rotation reaches every key) three PUTs
per copy; the ledger and the database reads are unchanged (one row per copy, as before). No
request carries anything but the object path the member's app fetches too.

## Tests

- `convex/lib/mirrorSync.test.ts`: the state rules.
- `convex/mirrorCopies.test.ts`: the ledger and every path that writes, moves or drops a copy.
- `bun run test:integration:s3`: the whole path against a real S3-compatible store (a throwaway
  SeaweedFS, `docker-compose.s3-test.yml`): request, refresh, read-back, an object deleted and
  one overwritten behind FCP's back, removal, a provider's withdrawal, a store that refuses writes,
  and the connection test.
- `convex/lib/mirrorFormats.test.ts`, the "every format of a mirror" cases in
  `convex/mirrorCopies.test.ts` and `convex/modeSwitchDelivery.test.ts`: the format rules, the
  objects written, read back, upgraded from before formats and deleted, each format rendered for
  its own family.
- `bun run test:compat` (`docs/client-compatibility.md`): a mirror of the compat key against the
  real panel, its Clash object run in Mihomo and its sing-box object in sing-box, each through
  all three proxies.
