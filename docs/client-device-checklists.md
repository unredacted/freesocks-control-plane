# Device evidence checklists

`scripts/compat/certify.ts` passes a release only when every catalogued app has a passing record in `tests/compat/application-evidence.json` for the exact FCP commit being released, less than 30 days old (`docs/client-compatibility.md` "Application certification and adding coverage"). CI cannot make most of those records: the apps below need a person and a device. Each checklist takes about ten minutes and ends in one record.

Every record is for one commit, so test every app against the same beta deployment of the release candidate, and record it within the 30 days before the release.

## Once per release candidate

1. Deploy the release candidate to beta (`docs/beta-deploy.md`) and note the commit it runs, on the stack host:

   ```bash
   git -C /root/freesocks-control-plane rev-parse HEAD
   ```

2. Note the backend version: the admin dashboard shows it after the panel's name (`v…`).
3. Sign in on the device's browser at the beta site with the device-test account. Its account number is in `/root/fcp-device-test/account-number` on the stack host (member tier: no traffic or device limit). Never use the deployed-smoke canary (`/root/fcp-canary`): regenerating its key breaks the smoke workflow. Leave the account in the default mode.
4. Make one private folder for this release candidate's screenshots. The screenshots show node names and addresses, so they never go in a public issue, a pull request or this repository. Its link is the record's `evidence`.

## The checks (every app)

Write down the app's exact version and the device's OS and version, then:

| Check      | Pass when                                                                                                                   | Screenshot                    |
| ---------- | --------------------------------------------------------------------------------------------------------------------------- | ----------------------------- |
| Import     | The app's button on the account page (or the copied link) adds a profile holding every server the account page lists.       | The app's server list.        |
| Connection | The app connects through one of those servers.                                                                              | The app's connected screen.   |
| HTTPS      | While connected, `https://ipleak.net` loads in the device's browser and shows an address that is not your own network's.    | The page's address section.   |
| DNS        | On the same page, no DNS server listed belongs to your own network or ISP (names resolved through the tunnel).              | The page's DNS section.       |
| Refresh    | The app's update action on the profile succeeds: its last-updated time changes and the list still matches the account page. | The profile after the update. |

A check that fails is a bug: report it and record nothing for that app. `scripts/compat/evidence.ts` refuses to write a record with a failed check.

## Record it

From a checkout of the release candidate's branch:

```bash
bun --no-env-file scripts/compat/evidence.ts --client "Hiddify" --app-version "4.1.2" --os "Android 15 (Pixel 8)" --backend-version "2.4.3" --commit "<commit from step 1>" --tested-by "<your name>" --evidence "<private folder link>"
```

`--client` is the app's name exactly as in the headings below. The script asks you to confirm each check, then appends the record. Commit the file in a pull request. Before releasing:

```bash
FCP_COMPAT_CERTIFY_COMMIT="<commit from step 1>" bun --no-env-file scripts/compat/certify.ts
```

## The apps

Install every app from its official source only (its own GitHub releases, Google Play or the App Store). Where an app runs on several platforms, one passing platform makes the record; note the platform in `--os`.

### sing-box

The CI suite drives the Linux app's import and refresh, but not a tunnel, so a device run is still needed. Android (SFA) or iOS/macOS (SFI/SFM).

- Import: the account page's sing-box button opens the app's new-profile screen with the URL filled in; create it.
- Connect: the profile's start switch on the dashboard; allow the VPN prompt.
- Refresh: the profile's Update action.
- Version: the app's settings or about screen.

### Hiddify

Android, iOS, Windows, macOS or Linux.

- Import: the account page's Hiddify button; confirm the import in the app.
- Connect: the large connect button; allow the VPN prompt.
- Refresh: the profile's menu, Update.
- Version: Settings, About.

### Karing

Android, iOS, Windows, macOS or Linux.

- Import: the account page's Karing button; confirm the import.
- Connect: the connect switch on the home screen; allow the VPN prompt.
- Refresh: the profile's update action in its profile list.
- Version: Settings, About.

### Anywhere

iOS (App Store), on a real iPhone or iPad. The iOS Simulator cannot install App Store apps.

- Import: the account page's Anywhere button.
- Connect: the app's connect control; allow the VPN configuration prompt the first time.
- Refresh: Anywhere updates a subscription only by hand: its update action on the subscription.
- Version: the app's settings, or the App Store page.

### v2rayNG

Android.

- Import: the account page's v2rayNG button adds a subscription group; then the menu's "Update subscription" fills it.
- Connect: select a server, then the start button; allow the VPN prompt.
- Refresh: the menu's "Update subscription" again.
- Version: the navigation drawer or Settings.

### v2rayN

Windows (or its macOS or Linux build).

- Import: Subscription group, settings, Add: paste the copied URL; then update the subscriptions.
- Connect: select a server as active, then turn on the system proxy (or TUN).
- Refresh: update the subscriptions again. v2rayN removes a subscription's servers before parsing the new body, so check the list carefully.
- Version: the window title or Help, About.

### Clash

Clash Verge Rev on Windows, macOS or Linux.

- Import: the account page's Clash button, or Profiles, paste the URL, Import.
- Connect: select the profile, then turn on System Proxy (or TUN mode) in Settings.
- Refresh: the profile card's update action.
- Version: Settings.

### FlClash

Android, Windows, macOS or Linux.

- Import: Profiles, add, from URL: paste the copied URL.
- Connect: the start button on the dashboard; allow the VPN prompt on Android.
- Refresh: the profile's sync action.
- Version: Tools, About.

### Mihomo Party

Windows, macOS or Linux.

- Import: Profiles: paste the copied URL and import.
- Connect: turn on System Proxy (or TUN).
- Refresh: the profile's update action.
- Version: Settings.

### Throne

Windows or Linux.

- Import: Preferences, Groups, new group of the subscription type with the copied URL; then update it.
- Connect: select a server, start it, and turn on the system proxy (or TUN).
- Refresh: the group's update action.
- Version: Help, About (or the window title).

### Shadowrocket

iOS (paid App Store app), on a real iPhone or iPad. The iOS Simulator cannot install App Store apps.

- Import: the account page's Shadowrocket button adds the subscription.
- Connect: select a server, then the connection switch; allow the VPN configuration prompt the first time.
- Refresh: the subscription's update action (swipe or long-press it).
- Version: Settings, at the bottom.

### Outline

Outline serves a static key and has no refresh (the record says `not-applicable`). It needs an account on an Outline backend; beta has none today, so Outline cannot be recorded until one exists.

- Import: copy the account page's access key; the app offers to add it (or Add server, paste).
- Connect: the server's connect button; allow the VPN prompt.
- Version: the app's about screen.
