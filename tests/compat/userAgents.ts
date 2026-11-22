/**
 * THE USER-AGENT INVENTORY: what each proxy app really sends when it fetches
 * a subscription, with where that was read, and the family and format FCP
 * must give it (`convex/lib/edges/clientFamilies.ts`).
 *
 * The family decides an app's render rule, VLESS Encryption included
 * (`edge.render.clients.<family>`): an app that falls into `other` silently
 * gets the plain-only rule and the link list. So every string here is the
 * app's own default as its source (or, closed source, its developer) states
 * it, never a guess; anything not confirmed says so. The defaults only: most
 * apps let a member type another User-Agent.
 *
 * Pinned by `convex/clientUserAgents.test.ts` (in `bun run test`): each
 * string classifies to its family and format, the panel's default response
 * rules give it a body of that format (after FCP's rewrites,
 * `convex/lib/backends/remnawaveUserAgent.ts`), never the legacy Clash
 * template, and `other` only with a stated reason. The nightly `latest` job
 * (`scripts/compat/user-agent-drift.ts`) re-reads each `source` line at the
 * app's newest release and fails when it changed.
 *
 * Checked 2026-11-21 at the tags named.
 */
import type { RenderClientFamily } from '../../convex/lib/edgeConfig';
import type { SubscriptionFormat } from '../../convex/lib/edges/clientFamilies';

/** Where a User-Agent was read. */
export type UserAgentEvidence =
  | {
      /** The app's own source, at a release tag (or a pinned commit for apps without tags). */
      kind: 'source';
      repo: string;
      /** The release tag read (or the commit, for an app with no tags). */
      ref: string;
      /** The commit `ref` points to. */
      sha: string;
      path: string;
      line: number;
      /**
       * A verbatim piece of that line which must still be in the file at the
       * app's newest release: the drift check's anchor.
       */
      needle: string;
      /** What the drift check reads: the newest release (default) or a branch. */
      track?: { branch: string };
    }
  | { kind: 'docs'; url: string }
  | { kind: 'unconfirmed'; why: string; url?: string };

export interface AppUserAgent {
  app: string;
  /** The client catalog entry (`convex/lib/clientCatalog.ts` DEFAULT_CLIENTS), if any. */
  catalog?: string;
  /** The default User-Agent(s) as sent, at the version read. */
  userAgents: string[];
  family: RenderClientFamily;
  format: SubscriptionFormat;
  evidence: UserAgentEvidence[];
  /** Required for family `other`: why the plain rule of unrecognised apps is right. */
  other?: string;
  /** What it reads, its core and whether that speaks VLESS Encryption (`mlkem768x25519plus`). */
  notes: string;
}

const gh = (
  repo: string,
  ref: string,
  sha: string,
  path: string,
  line: number,
  needle: string,
  track?: { branch: string },
): UserAgentEvidence => ({
  kind: 'source',
  repo,
  ref,
  sha,
  path,
  line,
  needle,
  ...(track ? { track } : {}),
});

/** A permalink to a `source` line. */
export const evidenceUrl = (e: UserAgentEvidence): string | undefined =>
  e.kind === 'source' ? `https://github.com/${e.repo}/blob/${e.sha}/${e.path}#L${e.line}` : e.url;

export const appUserAgents: AppUserAgent[] = [
  // --- sing-box -------------------------------------------------------------
  {
    app: 'sing-box (SFA, SFI, SFM, SFT, SFL, SFW)',
    catalog: 'sing-box',
    userAgents: [
      'SFA (sing-box 1.14.4; language en_US)',
      'SFI (sing-box 1.14.4; language en_US)',
      'SFM (sing-box 1.14.4; language en_US)',
      'SFT (sing-box 1.14.4; language en_US)',
      'SFL (sing-box 1.14.4; language en_US)',
      // Captured from the checksum-verified SFL 1.14.0 package (docs/client-compatibility.md).
      'SFL (sing-box 1.14.0; language en_US)',
      'SFW (sing-box 1.14.4; language zh_CN)',
      // sing-box 1.13 shells, before "Unify user agent" (2026-08-21).
      'SFA/1.13.9 (613; sing-box 1.13.9; language en_US)',
      'SFI/1.13.9 (Build 613; sing-box 1.13.9; language en_US)',
    ],
    family: 'singbox',
    format: 'singbox-json',
    evidence: [
      // The shells have no tags of their own: SagerNet/sing-box v1.14.4 pins these commits.
      gh(
        'SagerNet/sing-box-for-android',
        'f87c2ebdb7e34754be751bb5e58926db2fed8f8c',
        'f87c2ebdb7e34754be751bb5e58926db2fed8f8c',
        'app/src/main/java/io/nekohasekai/sfa/utils/HTTPClient.kt',
        11,
        'var userAgent = "SFA (sing-box "',
        { branch: 'dev' },
      ),
      gh(
        'SagerNet/sing-box-for-apple',
        '2dd154e7586188d5fff8de615e8c821ed25ec089',
        '2dd154e7586188d5fff8de615e8c821ed25ec089',
        'Library/Network/HTTPClient.swift',
        7,
        'userAgent += " (sing-box "',
        { branch: 'dev' },
      ),
      gh(
        'SagerNet/sing-box-for-desktop',
        '8aab8eab022366e1032e952d499c9252b833e6c3',
        '8aab8eab022366e1032e952d499c9252b833e6c3',
        'src/main/userAgent.ts',
        6,
        '`${applicationName} (sing-box ${__APP_VERSION__}; language ',
        { branch: 'main' },
      ),
    ],
    notes:
      'sing-box JSON only. Official sing-box has no VLESS Encryption, and 1.14 rejects an outbound with an unknown `encryption` field (strict decoding), so the panel must never put one in its body.',
  },
  {
    app: 'Hiddify',
    catalog: 'Hiddify',
    userAgents: [
      'HiddifyNext/5.5.5 (android) like ClashMeta v2ray sing-box',
      'HiddifyNext/5.5.5 (ios) like ClashMeta v2ray sing-box',
      'HiddifyNext/5.5.5 (windows) like ClashMeta v2ray sing-box',
      'HiddifyNext/5.5.5 (macos) like ClashMeta v2ray sing-box',
      'HiddifyNext/5.5.5 (linux) like ClashMeta v2ray sing-box',
      // hiddify-core's own fetch (inner links, standalone mode): no space before "(".
      'HiddifyNext/4.0.0(linux) like ClashMeta v2ray sing-box',
    ],
    family: 'hiddify',
    format: 'links',
    evidence: [
      gh(
        'hiddify/hiddify-app',
        'v5.5.5',
        '7804cadac01419f31b1ec7802d9e1be599e66de2',
        'lib/core/model/app_info_entity.dart',
        20,
        '"HiddifyNext/$version ($operatingSystem) like ClashMeta v2ray sing-box"',
      ),
      gh(
        'hiddify/hiddify-core',
        'ad83d7570c06c012ad0589896138e5c1bf299c50',
        'ad83d7570c06c012ad0589896138e5c1bf299c50',
        'v2/config/subscription_links.go',
        75,
        'HiddifyNext/4.0.0',
        { branch: 'main' },
      ),
    ],
    notes:
      'Reads share links, sing-box JSON, Clash YAML and Xray JSON; the panel serves links. Its sing-box fork has VLESS Encryption from app 5.5.5 (2026-11-04; a 5.5.5-or-later build connected on an encrypted-only body, checked on a device 2026-11-22): FCP reads the version from this User-Agent and serves an older Hiddify the plain entry (`ENCRYPTION_FLOORS`, convex/lib/edges/clientFamilies.ts).',
  },
  {
    app: 'Karing',
    catalog: 'Karing',
    userAgents: ['Karing/1.2.26.2934'],
    family: 'singbox',
    format: 'singbox-json',
    evidence: [
      {
        kind: 'unconfirmed',
        why: 'HttpUtils.getUserAgent is not in the public repo. Third-party reconstructions agree only on the `Karing/<version>` prefix; the rest may append the apps it passes for (mihomo, sing-box, HiddifyNext...), so `karing` is matched before any of those.',
        url: 'https://github.com/KaringX/karing/blob/178d4a0cb9b2bda1644c04cdab229ff4adbf8231/lib/app/modules/setting_manager.dart#L1679-L1689',
      },
    ],
    notes:
      'Reads sing-box JSON, Clash YAML and links; the panel serves sing-box JSON (its `karing` rule). KaringX sing-box fork 1.14.0.',
  },
  {
    app: 'Husi',
    userAgents: ['husi/2.4.0 (sing-box v1.15.0-alpha.13)'],
    family: 'xray-links',
    format: 'links',
    evidence: [
      gh(
        'xchacha20-poly1305/husi',
        'v2.4.0',
        '36a2258f06acbc932080b60bea519ca81c82feec',
        'composeApp/src/jvmMain/kotlin/fr/husi/net/UserAgent.kt',
        9,
        '"husi/$VERSION_ESCAPE (sing-box $BOX_VERSION_ESCAPE)"',
      ),
    ],
    notes:
      'Reads links and sing-box JSON (no Clash YAML); the panel serves links. sing-box 1.15 alpha with its own VLESS fork that has `encryption` (experimental in 0.14.2 pre-releases; FCP serves the plain entry below 0.15.0 (`ENCRYPTION_FLOORS`, convex/lib/edges/clientFamilies.ts)). The core version token comes from the Go module version.',
  },
  {
    app: 'NekoBox (Android) and NekoRay (desktop, archived)',
    userAgents: [
      'NekoBox/Android/1.4.2 (Prefer ClashMeta Format)',
      'NekoBox/PC/4.0.1 (Prefer ClashMeta Format)',
    ],
    family: 'other',
    format: 'links',
    other:
      'The panel serves it links, and its sing-box fork (1.12 / 1.9) has no VLESS Encryption: it needs the plain link list, which is the `other` rule. Before 2026-11-21 its `ClashMeta` token put it in `mihomo`.',
    evidence: [
      gh(
        'MatsuriDayo/NekoBoxForAndroid',
        '1.4.2',
        '5768494d8ae3c74a057bb6d46c0f8dc071b0d821',
        'app/src/main/java/io/nekohasekai/sagernet/ktx/Nets.kt',
        66,
        '"NekoBox/Android/" + BuildConfig.VERSION_NAME + " (Prefer ClashMeta Format)"',
      ),
      gh(
        'MatsuriDayo/nekoray',
        '4.0.1',
        'adef6cd4af7dffc77235c524086f3dc4100d8457',
        'main/NekoGui.cpp',
        306,
        '"NekoBox/PC/" + version + " (Prefer ClashMeta Format)"',
      ),
    ],
    notes: 'Reads links, Clash YAML and sing-box JSON.',
  },
  {
    app: 'GUI.for.SingBox',
    userAgents: ['clash.meta/mihomo'],
    family: 'mihomo',
    format: 'clash-yaml',
    evidence: [
      gh(
        'GUI-for-Cores/GUI.for.SingBox',
        'v1.29.0',
        'fa6c4fd6ac561882304f032a5d7b5098a41e7f2e',
        'frontend/src/stores/subscribes.ts',
        282,
        'clash.meta/mihomo',
      ),
    ],
    notes:
      'Passes for Mihomo by default (a per-subscription header), so it is served the Mihomo body and needs its node-converter plugin to read it. Indistinguishable from Mihomo.',
  },
  // --- Mihomo / Clash -------------------------------------------------------
  {
    app: 'Clash Verge Rev',
    catalog: 'Clash',
    userAgents: ['clash-verge/v2.5.10'],
    family: 'mihomo',
    format: 'clash-yaml',
    evidence: [
      gh(
        'clash-verge-rev/clash-verge-rev',
        'v2.5.10',
        'c83f7ad529c7c9cb3d2d54a0955ef8c1b22a411b',
        'src-tauri/src/utils/network.rs',
        252,
        'format!("clash-verge/v{}", env!("CARGO_PKG_VERSION"))',
      ),
    ],
    notes: 'Clash YAML only. Bundles the latest stable Mihomo at build (1.19.33 for this tag).',
  },
  {
    app: 'FlClash',
    catalog: 'FlClash',
    userAgents: [
      'FlClash/v0.9.4 clash-verge Platform/android',
      'FlClash/v0.9.4 clash-verge Platform/macos',
      // The app name on Windows is the Runner.rc ProductName, on Linux the pubspec name.
      'clash/v0.9.4 clash-verge Platform/windows',
      'fl_clash/v0.9.4 clash-verge Platform/linux',
    ],
    family: 'mihomo',
    format: 'clash-yaml',
    evidence: [
      gh(
        'chen08209/FlClash',
        'v0.9.4',
        '89791d7c11978bf9b580ba71bffcb00506a17659',
        'lib/common/package.dart',
        9,
        "'$appName/v$version',",
      ),
      gh(
        'chen08209/FlClash',
        'v0.9.4',
        '89791d7c11978bf9b580ba71bffcb00506a17659',
        'windows/runner/Runner.rc',
        98,
        'VALUE "ProductName", "clash"',
      ),
    ],
    notes:
      'Clash YAML, and links (converted by its core). Mihomo fork at 1.19.34. The Windows and Linux names follow from package_info_plus (appName = ProductName on Windows, version.json app_name on Linux), read from source, not seen on a device. The panel took the Windows form for a legacy Clash core: FCP rewrites both to `FlClash/...` before it asks.',
  },
  {
    app: 'Clash Party (formerly Mihomo Party)',
    catalog: 'Clash Party',
    userAgents: ['mihomo.party/v2.0.5 (clash.meta)'],
    family: 'mihomo',
    format: 'clash-yaml',
    evidence: [
      gh(
        'mihomo-party-org/clash-party',
        'v2.0.5',
        '74c3d65e67b615013d0ec0ab870b43964fa07673',
        'src/main/config/profile.ts',
        651,
        '`mihomo.party/v${app.getVersion()} (clash.meta)`',
      ),
    ],
    notes: 'Clash YAML only (links only through Sub-Store). Latest stable Mihomo at build.',
  },
  {
    app: 'Sparkle',
    userAgents: ['clash.meta/v1.19.33', 'clash.meta/alpha-e89af72'],
    family: 'mihomo',
    format: 'clash-yaml',
    evidence: [
      gh(
        'xishang0128/sparkle',
        '1.26.10',
        '9a1b2a0e3a511dc8d0a31a0b4e480f7ac7108a80',
        'src/main/utils/userAgent.ts',
        21,
        'return `clash.meta/${result.version}`',
      ),
    ],
    notes: 'Clash YAML. Sends its running core version; the alpha string when the core is slow.',
  },
  {
    app: 'Clash Meta for Android',
    catalog: 'Clash Meta for Android',
    userAgents: ['ClashMetaForAndroid/2.11.37.Meta'],
    family: 'mihomo',
    format: 'clash-yaml',
    evidence: [
      gh(
        'MetaCubeX/ClashMetaForAndroid',
        'v2.11.37',
        'f454fa8c569ea2a2396f2fe453ac8263832001d8',
        'core/src/main/golang/native/config/fetch.go',
        42,
        '"ClashMetaForAndroid/" + app.VersionName()',
      ),
    ],
    notes: 'Clash YAML only; not user-configurable. Mihomo 1.19.34.',
  },
  {
    app: 'Clash Nyanpasu',
    userAgents: ['clash-nyanpasu/v2.0.1'],
    family: 'mihomo',
    format: 'clash-yaml',
    evidence: [
      gh(
        'libnyanpasu/clash-nyanpasu',
        'v2.0.1',
        '518bf49843e1f735380e11da1ebe2a85eb8ce8c6',
        'backend/tauri/src/service/profile_file.rs',
        2098,
        'format!("clash-nyanpasu/v{}", crate::utils::dirs::APP_VERSION)',
      ),
    ],
    notes: 'Clash YAML only. Mihomo 1.19.33.',
  },
  {
    app: 'Koala Clash',
    userAgents: ['koala-clash/1.6.1'],
    family: 'mihomo',
    format: 'clash-yaml',
    evidence: [
      gh(
        'coolcoala/koala-clash',
        '1.6.1',
        '364cfc60e00bd728bcb4da448d636ee814936c84',
        'src/main/utils/userAgent.ts',
        10,
        'return `koala-clash/${version}`',
      ),
    ],
    notes: 'Clash YAML. Latest stable Mihomo at build.',
  },
  {
    app: 'Prizrak-Box',
    userAgents: ['prizrak-box/v1.0.20', 'clash-verge/v2.3.0'],
    family: 'mihomo',
    format: 'clash-yaml',
    evidence: [
      gh(
        'legiz-ru/Prizrak-Box',
        'v1.0.20',
        'd94e39c38954f7bebff5025ff0b583186203a709',
        'src-go/api/handlers/pandora.go',
        158,
        'userAgent = "prizrak-box/" + config.Version',
      ),
    ],
    notes:
      'Clash YAML, links and sing-box JSON. `clash-verge/v2.3.0` with its HWID switch off. Its core is a Mihomo fork whose VLESS Encryption is unconfirmed; the Mihomo group puts the plain entry behind the encrypted one.',
  },
  {
    app: 'Mihomo (core, proxy providers)',
    userAgents: ['clash.meta/v1.19.34'],
    family: 'mihomo',
    format: 'clash-yaml',
    evidence: [
      gh(
        'MetaCubeX/mihomo',
        'v1.19.34',
        '0455d0d28c4526937380505153e65a843d8612e8',
        'config/config.go',
        504,
        'GlobalUA:          "clash.meta/" + C.Version',
      ),
    ],
    notes: 'A provider reads Clash YAML, else a link list. VLESS Encryption from 1.19.13.',
  },
  {
    app: 'ClashX Meta',
    userAgents: ['ClashX%20Meta/1 CFNetwork/1568.300.101 Darwin/24.4.0'],
    family: 'mihomo',
    format: 'clash-yaml',
    evidence: [
      gh(
        'MetaCubeX/ClashX.Meta',
        'v1.4.48',
        'cfa90dc4db5014b97d3291ac13f48af8f464280f',
        'ClashX/General/Managers/RemoteConfigManager.swift',
        157,
        'URLSession.shared.data(for:',
      ),
      {
        kind: 'unconfirmed',
        why: 'It sets no User-Agent, so macOS sends its CFNetwork default: the bundle name (PRODUCT_NAME "ClashX Meta", percent-encoded) and the build number (a CI commit count). The build and the CFNetwork/Darwin versions here are placeholders.',
      },
    ],
    notes:
      'Clash YAML only. Mihomo 1.19.34. The panel takes `clashx meta` with a space: FCP turns `%20` into one before it asks.',
  },
  {
    app: 'Stash',
    userAgents: ['Stash/2.7.0 Clash/1.11.0'],
    family: 'mihomo',
    format: 'clash-yaml',
    evidence: [
      {
        kind: 'unconfirmed',
        why: 'Closed source; stash.wiki documents no User-Agent. Panels key on the `Stash` prefix (Remnawave `^stash`, its own template); the rest of the string is a placeholder.',
        url: 'https://stash.wiki/en/features/service-provider-subscription',
      },
    ],
    notes: 'Clash YAML (its own core). Served the panel STASH template.',
  },
  // --- Xray link lists ------------------------------------------------------
  {
    app: 'v2rayNG',
    catalog: 'v2rayNG',
    userAgents: ['v2rayNG/2.3.15'],
    family: 'v2rayng',
    format: 'links',
    evidence: [
      gh(
        '2dust/v2rayNG',
        '2.3.15',
        '57907cf354d9769200ed4717b4430d605abe0952',
        'V2rayNG/app/src/main/java/com/v2ray/ang/util/HttpUtil.kt',
        160,
        '"v2rayNG/${BuildConfig.VERSION_NAME}"',
      ),
    ],
    notes:
      'Links and Xray JSON. Xray-core 2026-10-31 build: VLESS Encryption (`encryption=` read from the link). From 1.10.21, the first on the Xray wire of v25.8.31; an older one is served plain (`ENCRYPTION_FLOORS`, convex/lib/edges/clientFamilies.ts).',
  },
  {
    app: 'v2rayN',
    catalog: 'v2rayN',
    userAgents: ['v2rayN/7.25.6'],
    family: 'xray-links',
    format: 'links',
    evidence: [
      gh(
        '2dust/v2rayN',
        '7.25.6',
        '1883178b5f1e222b6c6db2782e7a3d989b7cc18f',
        'v2rayN/ServiceLib/Common/Utils.cs',
        931,
        ': $"{Global.AppName}/{GetVersionInfo()}"',
      ),
    ],
    notes:
      'Links, Xray JSON, sing-box JSON and Clash YAML; the panel serves links. Ships the latest Xray-core: VLESS Encryption, kept on import from 7.14.1; FCP serves the plain entry below 7.14.6, the first built on Xray v25.8.31 (`ENCRYPTION_FLOORS`, convex/lib/edges/clientFamilies.ts).',
  },
  {
    app: 'Throne (successor of NekoRay)',
    catalog: 'Throne',
    userAgents: ['Throne/1.4.2'],
    family: 'xray-links',
    format: 'links',
    evidence: [
      gh(
        'throneproj/Throne',
        '1.4.2',
        'a7986a03e978952b585ee1d24b6d8f2a48f7df41',
        'src/database/SettingsRepo.cpp',
        399,
        'QStringLiteral("Throne/") + version.toString()',
      ),
    ],
    notes:
      'Links, Clash YAML, sing-box JSON and Xray JSON; the panel serves links. A VLESS link with `encryption` goes to its Xray-core fork, from 1.1.0 (FCP reads 1.1.1 as the floor: the 1.1.0 betas without it send `Throne/1.1.0` too); an older one is served plain (`ENCRYPTION_FLOORS`, convex/lib/edges/clientFamilies.ts). Was `other` (plain) before 2026-11-21.',
  },
  {
    app: 'Exclave',
    userAgents: ['Exclave/0.17.68'],
    family: 'xray-links',
    format: 'links',
    evidence: [
      gh(
        'dyhkwong/Exclave',
        '0.17.68',
        'feb707b49720aa503b20e1ebbc05404be333fd8d',
        'app/src/main/java/io/nekohasekai/sagernet/ktx/Nets.kt',
        190,
        '"Exclave/${BuildConfig.VERSION_NAME}"',
      ),
    ],
    notes:
      'Links, Clash YAML, sing-box and Xray JSON; the panel serves links. Its v2ray-core v5 fork reads `mlkem768x25519plus` from the link, on the current wire from 0.16.2; an older one is served plain (`ENCRYPTION_FLOORS`, convex/lib/edges/clientFamilies.ts).',
  },
  {
    app: 'INCY',
    userAgents: ['INCY/2.5.1/ios CFNetwork/1568.300.101 Darwin/24.4.0', 'INCY/2.7.3/android'],
    family: 'other',
    format: 'links',
    other:
      'Closed source; its Xray-numbered core is not confirmed to read VLESS Encryption from a link, so it takes the plain rule until someone has seen it work.',
    evidence: [
      { kind: 'docs', url: 'https://docs.incy.cc/en/subscription-format/' },
      // A server log quoting it (the CFNetwork tail and the Android form are illustrative).
      { kind: 'docs', url: 'https://github.com/MHSanaei/3x-ui/issues/6273' },
    ],
    notes:
      'Closed source; the vendor documents `INCY/<version>/<platform>`. Links and Xray JSON per its docs. Xray-numbered core (26.9.9 per its store notes): VLESS Encryption from the link unconfirmed.',
  },
  {
    app: 'v2RayTun',
    userAgents: ['v2raytun/android', 'v2raytun/ios'],
    family: 'other',
    format: 'links',
    other:
      'Closed source; its Xray-core version and whether it reads VLESS Encryption from a link are unconfirmed, so it takes the plain rule until someone has seen it work.',
    evidence: [
      {
        kind: 'unconfirmed',
        why: 'Closed source and undocumented; clients that pass for it send `v2raytun/<platform>` (yanisplugg/yptun core/yptun-core/src/settings.rs).',
        url: 'https://docs.v2raytun.com/overview/device-limit.md',
      },
    ],
    notes: 'Xray-core (version unconfirmed).',
  },
  {
    app: 'Npv Tunnel',
    userAgents: ['ktor-client'],
    family: 'other',
    format: 'links',
    other:
      "Unconfirmed: panels match it by Ktor's default `ktor-client`, which any Ktor app sends, so FCP cannot tell it apart.",
    evidence: [
      {
        kind: 'unconfirmed',
        why: "Closed source. PasarGuard's default rules route `^[Kk]tor-client` to a setting named for Npv Tunnel.",
        url: 'https://github.com/PasarGuard/panel/blob/HEAD/app/db/migrations/versions/9af04c077ede_init_settings.py',
      },
    ],
    notes: 'Xray per third-party guides.',
  },
  // --- iOS and closed-source apps -------------------------------------------
  {
    app: 'Anywhere',
    catalog: 'Anywhere',
    userAgents: ['Anywhere'],
    family: 'xray-links',
    format: 'links',
    evidence: [
      gh(
        'NodePassProject/Anywhere',
        '8b1ec05bc5e0e2d4e477d9aced0b9832bbeff61d',
        '8b1ec05bc5e0e2d4e477d9aced0b9832bbeff61d',
        'Shared/Utilities/SubscriptionFetcher.swift',
        29,
        'request.setValue("Anywhere", forHTTPHeaderField: "User-Agent")',
        { branch: 'main' },
      ),
    ],
    notes:
      'Links (no vmess), Clash YAML and its own AJSON; the panel serves links. Its own Swift core reads `encryption=mlkem768x25519plus...` from a link (from 1.10), and only on iOS/macOS/tvOS 26, while the app installs on iOS 18. Its User-Agent shows neither, so FCP hands it both entries whatever the rule of its family (`ENCRYPTION_FLOORS`, convex/lib/edges/clientFamilies.ts). No tags: main at App Store 2.6.',
  },
  {
    app: 'Everywhere',
    userAgents: ['Everywhere/1.0 Clash/1.11.0'],
    family: 'mihomo',
    format: 'clash-yaml',
    evidence: [
      gh(
        'NodePassProject/Everywhere',
        '286165ae69df383d2b297c03c6336c66c83145b4',
        '286165ae69df383d2b297c03c6336c66c83145b4',
        'Everywhere/Configurations/ConfigurationsView.swift',
        253,
        'request.setValue("Everywhere/1.0 Clash/1.11.0", forHTTPHeaderField: "User-Agent")',
        { branch: 'main' },
      ),
    ],
    notes:
      "Keeps the body as its chosen core's whole config (Xray JSON, sing-box JSON or Mihomo YAML), whichever core it runs, so a link list works with none. FCP asks the panel as its bundled Mihomo 1.19.34: the Mihomo core works (VLESS Encryption too); a member on its Xray or sing-box core does not.",
  },
  {
    app: 'Happ',
    userAgents: ['Happ/5.5.0/ios', 'Happ/4.11.2/android'],
    family: 'happ',
    format: 'links',
    evidence: [
      {
        kind: 'unconfirmed',
        why: 'Closed source, and its docs give no default. Panels key on `Happ/`; a server log shows `Happ/5.5.0/ios/...` (tail cut). A provider or the member can change it (`change-user-agent`).',
        url: 'https://github.com/MHSanaei/3x-ui/issues/6273',
      },
    ],
    notes:
      'Links and Xray JSON; the panel serves links. Xray 26.10.31: VLESS Encryption in the core, and from a link too: a current build connected on an encrypted-only body, checked on a device (2026-11-22). No floor: its versions differ by platform (Android 3.3.0 was the first on Xray 25.9.11, iOS unknown) and nothing shows when its link parser began passing `encryption=`, so an older build may still fail on an encrypted-only body.',
  },
  {
    app: 'Streisand',
    userAgents: ['Streisand/1.7.1'],
    family: 'streisand',
    format: 'links',
    evidence: [
      {
        kind: 'unconfirmed',
        why: 'Closed source. Panels key on the `Streisand` prefix (Remnawave, Marzban, Hiddify); the version is a placeholder.',
        url: 'https://github.com/remnawave/backend/blob/6853666801d6d1925b6aec55824106100485777a/src/modules/subscription-template/constants/extended-clients.ts#L1-L24',
      },
    ],
    notes:
      'Links and Xray JSON; the panel serves links. Xray-numbered core 26.11.09: VLESS Encryption in the core, from a link unconfirmed. Plain below 1.6.62, its first core at v25.8.31 (`ENCRYPTION_FLOORS`, convex/lib/edges/clientFamilies.ts).',
  },
  {
    app: 'Shadowrocket',
    catalog: 'Shadowrocket',
    userAgents: ['Shadowrocket/2592 CFNetwork/1568.300.101 Darwin/24.4.0'],
    family: 'other',
    format: 'links',
    other:
      'Closed source with conflicting reports: its release notes claim VLESS Encryption since 2.2.78, while other panels hold it back because it imports such an entry as plain VLESS and fails without an error. Plain until someone has seen it work.',
    evidence: [
      {
        kind: 'unconfirmed',
        why: 'Closed source. Panels key on the `Shadowrocket` prefix, Xboard reading the number after it as a build; the CFNetwork tail is a placeholder.',
        url: 'https://github.com/cedar2025/Xboard/blob/d826a3b32f73bde24acce2a3ab033c6538ce121d/app/Protocols/Shadowrocket.php#L11-L25',
      },
    ],
    notes:
      'Links and Clash YAML; the panel serves links. Own core: VLESS Encryption since 2.2.78 per its release notes (from a link not stated).',
  },
  {
    app: 'V2Box',
    userAgents: ['V2Box/10.2.0'],
    family: 'xray-links',
    format: 'links',
    evidence: [
      {
        kind: 'unconfirmed',
        why: 'Closed source. Panels key on the `V2Box` prefix; the version is a placeholder.',
        url: 'https://github.com/hiddify/HiddifyPanel/blob/9f811a25aeac8df9c9995983ff4d8d036cd0ace2/hiddifypanel/hutils/flask.py#L160-L196',
      },
    ],
    notes:
      'Links and its own JSON. Xray-core 26.7.28: VLESS Encryption in the core. Plain below 9.8.8, its first core after Xray 25.7.26 (`ENCRYPTION_FLOORS`, convex/lib/edges/clientFamilies.ts).',
  },
  {
    app: 'FoXray',
    userAgents: ['FoXray/24.10.1'],
    family: 'other',
    format: 'links',
    other:
      'Last seen on Xray 24.9.30, before VLESS Encryption: an encrypted entry would not connect.',
    evidence: [
      {
        kind: 'unconfirmed',
        why: 'Closed source and perhaps delisted. Panels key on `FoXray` (Remnawave example `FoxRay`); the version is a placeholder.',
        url: 'https://github.com/remnawave/backend/blob/6853666801d6d1925b6aec55824106100485777a/libs/contract/models/response-rules/response-rules-examples.ts#L37',
      },
    ],
    notes: 'Links. Last seen on Xray 24.9.30, before VLESS Encryption.',
  },
  {
    app: 'Loon',
    userAgents: ['Loon/3.5.3'],
    family: 'other',
    format: 'links',
    other:
      'Its own core, and its manual lists no VLESS `encryption`: an encrypted entry would not connect.',
    evidence: [
      {
        kind: 'unconfirmed',
        why: 'Closed source. Panels key on the `Loon` prefix (subconverter, Xboard); the version is a placeholder.',
        url: 'https://github.com/tindy2013/subconverter/blob/b9ad0c2ee2b959e2b10195e928bf8f30f55a6a78/src/handler/interfaces.cpp#L58-L84',
      },
    ],
    notes:
      'Its own node lines and share links (vless since 3.3.0). Own core; its manual lists no VLESS `encryption`, so it may skip the encrypted entry.',
  },
  {
    app: 'Quantumult X',
    userAgents: ['Quantumult%20X/1.8.1'],
    family: 'other',
    format: 'links',
    other:
      'Its own `[server_remote]` format (others only through a parser script), and VLESS with `method=none` only: no VLESS Encryption, so the plain rule.',
    evidence: [
      {
        kind: 'unconfirmed',
        why: 'Closed source. Panels key on the `Quantumult%20X` prefix (subconverter, Xboard); the version is a placeholder.',
        url: 'https://github.com/tindy2013/subconverter/blob/b9ad0c2ee2b959e2b10195e928bf8f30f55a6a78/src/handler/interfaces.cpp#L58-L84',
      },
    ],
    notes:
      'Not something FCP serves a body it reads; listed so it is not mistaken for an unknown app.',
  },
  {
    app: 'Surge',
    userAgents: ['Surge/2900'],
    family: 'other',
    format: 'links',
    other:
      'Surge imports managed profiles and policy lists, not share-link lists, and the panel has no Surge template: no family body fits it.',
    evidence: [
      {
        kind: 'unconfirmed',
        why: 'Closed source. Panels key on the `Surge` prefix with a build number; the number is a placeholder.',
        url: 'https://github.com/tindy2013/subconverter/blob/b9ad0c2ee2b959e2b10195e928bf8f30f55a6a78/src/handler/interfaces.cpp#L58-L84',
      },
    ],
    notes: 'Its manual documents VLESS Encryption (https://manual.nssurge.com/policies/vless.md).',
  },
  // --- Outline --------------------------------------------------------------
  {
    app: 'Outline',
    catalog: 'Outline',
    userAgents: ['Go-http-client/1.1', 'Go-http-client/2.0'],
    family: 'other',
    format: 'links',
    other:
      "It fetches a dynamic key with Go's default User-Agent, which any Go program sends; its body is one Shadowsocks key, with no family rule to apply.",
    evidence: [
      gh(
        'Jigsaw-Code/outline-apps',
        'client_windows/v1.23.0-rc.1',
        '40b2a2304fe19e2dfae262bd605e04ef31e07a9e',
        'client/go/outline/fetch.go',
        32,
        'http.Client{',
        { branch: 'master' },
      ),
    ],
    notes: 'Shadowsocks only (no VLESS).',
  },
];
