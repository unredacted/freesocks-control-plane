# Client compatibility CI

`bun run test:compat` boots a disposable Remnawave panel, issues a test user, renders subscriptions through FCP's actual HTTP handler, and runs pinned client engines and the SFL Linux package. No existing account or production credentials are needed. Everything is in the **Client compatibility** workflow; the existing fast suite remains offline.

## What is proved

| Check                | Environment                                                                        | Acceptance                                                                                                                                                                                             |
| -------------------- | ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Catalog coverage     | Offline                                                                            | Every enabled default recommendation has a coverage entry; missing entries fail CI.                                                                                                                    |
| Subscription formats | Real Remnawave + FCP handlers in `convex-test`                                     | Nonempty expected format for each User-Agent; cache isolation; changed Host observed after cache invalidation; invalid subscription rejected.                                                          |
| Reference engines    | sing-box and Mihomo, exact versions and SHA-256 in manifest                        | Native config validation; REALITY handshake; HTTPS to a fresh nonce; remote hostname resolution; SOCKS5 UDP association carrying a real DNS question.                                                  |
| Network controls     | Separate Docker networks                                                           | Origin unreachable directly; wrong VLESS credential cannot pass through a fallback.                                                                                                                    |
| Packaged SFL         | Installed checksum-verified `.deb`, Debian container + Xvfb + the app's own daemon | Actual application opens generated deep link, accepts manually entered URL, validates and saves config with bundled core, then updates remote profile. Its real HTTP User-Agent is asserted.           |
| Report form          | Chromium and Firefox                                                               | Actual Svelte dialog and API transport; required reason, short/mobile viewport, successful POST, failed POST retains text, successful submission clears text. Responses are intercepted test fixtures. |
| Deployed smoke       | Actual public FCP fronts/mirrors                                                   | Dedicated canary subscription returns expected format, cache headers and native engine validation. Read only; does not connect the tunnel.                                                             |

The integration harness executes FCP's real route, provider and cache logic in the **Convex test runtime**, not a deployed Convex server. The live panel and proxy traffic are real. The deployed smoke workflow covers the public HTTP deployment separately. Backend authentication and rate-limit behavior remain covered by the normal backend suite; the report-form browser tests inject 401/429/502 responses and do not perform a real login.

A reference engine pass is **not** a packaged Hiddify, Karing, Clash, or mobile application pass. Contract User-Agents are regression inputs, not assertions about every current app release. The exact SFL 1.14.0 identity was extracted from its checksum-verified package: `SFL (sing-box 1.14.0; language en_US)`. This exposed the old FCP normalization rule's missing space/parenthesis form. SFW uses the same form with a different prefix (upstream `sing-box-for-desktop/src/main/userAgent.ts` picks `SFL` on Linux and `SFW` otherwise); only the SFL string is captured from a package here.

The packaged app shows its main UI, and validates every imported profile (`checkConfig`), only through its bundled `sing-box-daemon`, which the `.deb` normally starts via systemd. Without it the app sits on a "Cannot connect to the sing-box service" screen and the import dialog never mounts. `docker/compat/sfl-entrypoint.sh` therefore starts the daemon exactly as the shipped unit file does (`run --working-directory /var/lib/sing-box-daemon --socket /run/sing-box.socket`), waits for the socket, then runs the driver under Xvfb; on the Xfce VM runners the package's own postinst starts the real service. The driver (`tests/compat/sfl.ts`) attaches to the Electron renderer over CDP (`--remote-debugging-port=0`) because the official build disables Node inspector arguments, and it selects the main window by URL because the app also owns a tray window.

The tunnel fixture uses a minimal, test-owned Remnawave template with a SOCKS listener and REALITY outbound, and a sing-box server. It does not certify production routing rules, Xray server compatibility, TUN integration, IPv6, QR decoding, browser/OS protocol registration, or platform-specific HWID behavior. The existing subscription-front tests cover HWID forwarding/cache isolation; physical client HWID behavior requires device evidence. Outline's existing provider tests remain the automated backend coverage; its application and transport are not exercised here.

## Running locally

Requirements: Docker Compose, Bun, Node 22/24, OpenSSL, and outbound access to the pinned GitHub releases and container registries. Linux x64 is the CI target; Docker Desktop with Rosetta emulation runs the amd64 engines and the Electron app on Apple Silicon (the packaged-SFL step takes about 40 seconds there; a full run about 4 minutes with warm images). Node 22/24 is recommended for Playwright; the local Node 26 browser downloader has exhibited a hang.

```sh
bun install --frozen-lockfile
bun run test:compat
bunx playwright install chromium firefox
bun run test:compat:browser
bun --no-env-file scripts/compat/report.ts
```

The integration stack binds loopback port 3000 and the packaged-app bridge uses port 4179. Do not run it concurrently with another Remnawave integration stack. Both panel fixtures and generated private keys are throwaway. The wrapper always tears down its own Compose project and volumes; it never uses the application's production Compose project. `.cache/compat` and `test-results` are ignored by Git. The application runs with a fresh user-data directory.

Downloads verify pinned SHA-256 before extraction/execution. `FCP_COMPAT_CHANNEL=latest` instead resolves official stable release assets and their GitHub SHA-256 digests, then executes the same tests; this runs nightly separately from the pinned PR gate. It does not rewrite the committed pins. A changed upstream import UI or format fails discovery and requires review before updating the pins.

The public artifact contains test names, statuses, artifact versions/hashes and coverage limitations. Raw JUnit failures, generated configurations and engine logs are not uploaded because they can contain credentials. Browser traces/screenshots contain only fixture data. Packaged app screenshots are retained locally under `test-results/compat/sfl` for debugging.

## Full desktop VMs

The Debian container smoke test is not an Xfce test. The same SFL adapter can run on disposable, signed-in Xfce VMs with labels `fcp-debian-13-xfce` and `fcp-mx-25-2-xfce`. Provision Docker, Node 24, Bun and a running Xfce desktop session; run the Actions runner inside that session so DISPLAY, XAUTHORITY and DBUS_SESSION_BUS_ADDRESS are available. Allow package installation for that disposable runner. Record and pin the OS image/checksum in the VM provisioning system.

Enable repository variable `CLIENT_COMPAT_VM_RUNNERS=true` only after those runners are available. The job installs the verified package and sets `FCP_COMPAT_SFL_EXECUTABLE` to drive the actual desktop application. These jobs only run trusted main-branch code, never pull-request code. Destroy or reset each VM after the job. The runner label identifies the intended OS; inspect the OS record in the application result when certifying it.

## Deployed canaries

Create a dedicated test subscription and configure the `client-compatibility` Actions environment secret `FCP_COMPAT_SMOKE_TARGETS`:

```json
[
  { "name": "primary", "url": "https://example.test/api/v1/sub/DEDICATED_CANARY" },
  { "name": "mirror", "url": "https://mirror.example.test/api/v1/sub/DEDICATED_CANARY" }
]
```

Run **Deployed client compatibility** after deploying or changing a CDN/mirror configuration. Missing targets fail explicitly. HTTP redirects, errors, empty/wrong formats, unsafe shared-cache responses and invalid native configs fail. This workflow never creates, rotates or deletes an account. Use an unrestricted test tier for the format matrix; device-limit testing is a separate capability check.

## Application certification and adding coverage

`tests/compat/manifest.ts` records each catalog client's scope and remaining gaps. Add an entry whenever adding a default recommendation. For CMS-only recommendations, review/export the live catalog before a release: the offline coverage guard cannot inspect a production database. Add an adapter for the actual package instead of relabeling a shared engine test as application coverage.

Apps needing Apple hardware, Android devices, licensed installs or missing automation are explicitly unverified. `scripts/compat/certify.ts` fails until every recommended app has recent application evidence for the exact requested FCP commit in `tests/compat/application-evidence.json`. The committed file starts empty intentionally. Set `FCP_COMPAT_CERTIFY_COMMIT` and run the command as a release checklist gate; never invent passes to make it green. Each entry records:

- client, exact app version, OS, backend version and 40-character FCP commit;
- UTC `testedAt`, tester, and a URL to the test evidence;
- `import`, `connection`, `dns`, `https`: `passed`;
- `refresh`: `passed` (or `not-applicable` for Outline's static key).

Evidence expires after 30 days and certifies only the recorded configuration/version/OS. This is the place to attach full TUN/device tests; the automatic engine and SFL import jobs alone cannot certify every client. Configure branch protection to require **Subscriptions, engines and packaged SFL** and **Report form (Chromium and Firefox)**. A green PR means those automated checks passed; full application certification remains a distinct release decision.
