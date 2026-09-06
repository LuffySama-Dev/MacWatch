# MacWatch

MacWatch is a native macOS 14+ menu-bar security monitor written in Swift and SwiftUI with Apple frameworks only. It records a deliberately narrow set of observable security-relevant changes locally and can optionally export allowlisted telemetry directly to SigNoz Cloud.

> [!WARNING]
> MacWatch is a personal monitoring prototype, not antivirus or endpoint protection. It does not block activity, prove that an event is malicious, or prove that a Mac is safe. An empty history means only **no events were detected by the enabled monitors**. The current development build is not a signed and notarized release.

## Current coverage

| Monitor | What it observes | Important limitation |
|---|---|---|
| Camera | Connected CoreMediaIO camera devices and whether a device reports running | Polled every 2 seconds; responsible process is unknown; no frames are captured |
| Microphone | CoreAudio input devices and whether a device reports running | Polled every 2 seconds; responsible process is unknown; no audio is captured |
| Startup changes | Added, removed, or modified `~/Library/LaunchAgents/*.plist` files | Polled every 10 seconds; the first scan is only a baseline |
| SSH configuration | Remote Login state, allowed users, readable `sshd` configuration fingerprints, and the current user's `authorized_keys` fingerprint | Polled every 15 seconds; this does not report failed authentication |
| Active SSH sessions | Terminal-backed remote sessions visible in the macOS login-session table | Polled every 15 seconds; noninteractive commands and port forwarding may be invisible |
| Listening endpoints | TCP listeners and unconnected UDP bindings, including address, port, exposure, and visible owner metadata | Polled every 15 seconds; a listener is not proof of firewall or internet reachability |
| Sleep and wake | Observed sleep/wake transitions and monitoring gaps | The app cannot record after it has been killed or while the Mac is asleep |
| Health and export | Per-monitor freshness, queue state, export failures, and heartbeat | A heartbeat proves only that telemetry arrived, not that every monitor is healthy |

SSH authentication success/failure monitoring is **disabled in the current build**. Its Endpoint Security source is retained for future use, but the system extension is not embedded, activated, or polled. Apple must approve the restricted Endpoint Security entitlement before that feature can be shipped.

See [the full capability matrix](Docs/CAPABILITY_MATRIX.md) for precise coverage and blind spots.

## Permissions and prompts

| Permission or access | Current behavior |
|---|---|
| Camera and microphone | MacWatch does **not** request access because it never opens capture devices; it reads public device-running state only |
| Notifications | Optional; requested only when the user explicitly enables notifications in the UI |
| Keychain | The SigNoz ingestion key is stored as a generic-password item; macOS may show an access prompt when the app's build identity changes |
| Full Disk Access | Not required or requested by the currently active monitors. Some unreadable files or process metadata may remain unavailable and are reported as reduced health |
| Administrator access | Not requested; MacWatch never enables Remote Login, changes the firewall, installs startup items, or modifies security settings |
| Network access | Needed only when SigNoz export is enabled |
| System Extension approval | Not requested in the current build; it would be required only for the disabled Endpoint Security integration |

Never grant a permission merely to make a warning disappear. Confirm that the prompt belongs to the MacWatch build you intended to run.

## Build and run

### Xcode app build (recommended)

1. Install current Xcode and, if necessary, select it:

   ```sh
   sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
   ```

2. Open `MacWatch.xcodeproj`.
3. In the top scheme selector choose **MacWatch**—not `MacWatch-Package`, `MacWatchCore`, or `MacWatchEndpointSecurity`—and select **My Mac**.
4. Press **Run** (`⌘R`). MacWatch appears only in the menu bar because it is an `LSUIElement` app.

### Command line

```sh
cd /path/to/MacWatch
swift build --product MacWatch
swift run MacWatch
swift run MacWatchSelfTest
```

The Swift Package executable is useful for development but is not a normal signed `.app` bundle. Use the Xcode project for ordinary menu-bar behavior and local notifications.

## SigNoz Cloud

Cloud export is off by default.

1. In **MacWatch → Cloud**, enter the current regional base endpoint, for example `https://ingest.in.signoz.cloud:443`.
2. Enter the ingestion key, enable export, and press **Save locally**. The key is stored in Keychain under service `com.macwatch.telemetry`; it is never written to source code or event exports.
3. Send the clearly labeled test event and confirm both the event and `macwatch.heartbeat` in SigNoz before relying on dashboards or alerts.

MacWatch sends OTLP/HTTP JSON directly to `/v1/logs` and `/v1/metrics`. Destination validation accepts only `https://ingest.<region>.signoz.cloud:443`, preserves TLS verification, and refuses redirects.

Cloud logs use an explicit allowlist. Common records include the event ID, event kind, test flag, monitor name, installation ID, and app version. Listening-endpoint opened/closed records additionally include:

- `server.address`
- `server.port`
- `network.transport`
- `network.exposure`
- `process.name`

The local bind address and process name can reveal information about the Mac's network layout and running software. Enable export only to a SigNoz account you control. Usernames, remote SSH source addresses, hostname, PIDs, executable paths, filenames, command lines, signature identifiers, captured content, and Keychain secrets are excluded.

See [SigNoz setup](Docs/SIGNOZ_SETUP.md) for dashboard fields, queries, alerts, and missing-data guidance.

## Privacy and security boundaries

MacWatch never captures screen contents, camera frames, microphone audio, keystrokes, clipboard data, documents, or browsing history. It never kills processes, blocks connections, changes the firewall, or changes sharing/security settings.

Local history can contain device names, LaunchAgent filenames and paths, visible signature metadata, SSH account/source details for active sessions, and listening-process metadata. Local files are bounded but are **not tamper-proof**. A privileged attacker can stop or alter MacWatch, suppress delivery, steal its ingestion credential, or fabricate future local events. Data already delivered to SigNoz is independently retained, but that does not make the monitored Mac trustworthy.

Polling can miss brief activity. Sleep, shutdown, app exit, network loss, invalid credentials, rate limiting, and service outages can create telemetry gaps. Screen-capture detection, enumeration of other apps' privacy grants, non-SSH remote-session proof, SSH authentication outcomes, and continuous established-connection attribution are unavailable.

## Storage and retention

- Local state: `~/Library/Application Support/MacWatch/`
- Preferences: macOS user defaults for `com.personal.MacWatch`
- Ingestion credential: Keychain generic-password item, service `com.macwatch.telemetry`
- History: 1–365 days, 30 by default, hard maximum 5,000 events
- Telemetry queue: hard maximum 500 records; stale heartbeats are discarded

## Safe validation

Run the automated suite:

```sh
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift test
```

For manual checks, use only accounts, devices, and private networks you control. Do not expose a test SSH account or temporary listener to the public internet. Follow the [benign validation checklist](Docs/MANUAL_VALIDATION.md).

With MacWatch already running, generate safe startup-change and loopback-listener events with:

```sh
./Scripts/generate-test-telemetry.sh
```

You may pass two different high ports, for example `./Scripts/generate-test-telemetry.sh 53123 53124`. The script creates only a disabled test plist and loopback-only listeners, waits for MacWatch's polling intervals, and removes them before exiting. It does not toggle Remote Login, edit SSH keys, or put the Mac to sleep.

## Removal

1. Quit MacWatch and delete the app/build product.
2. If desired, remove `~/Library/Application Support/MacWatch/` and the app's preferences.
3. In Keychain Access, remove the `com.macwatch.telemetry` item if the ingestion credential should be forgotten.
4. Remove any notification permission and delete any SigNoz dashboards, alerts, or ingestion keys you no longer want. MacWatch never creates those cloud resources automatically.

## Project layout

- `MacWatchCore`: models, bounded storage, scanners, device polling, notification policy, telemetry encoding, queue, and exporter
- `MacWatchApp`: SwiftUI menu-bar UI and monitor orchestration
- `MacWatchSelfTest`: benign local self-test executable
- `MacWatchCoreTests`: unit and regression tests
- `MacWatchEndpointSecurity`: retained, disabled future SSH-authentication implementation
- `Scripts/generate-test-telemetry.sh`: benign startup and listening-endpoint telemetry generator

## Documentation

- [Capability matrix and official sources](Docs/CAPABILITY_MATRIX.md)
- [SigNoz ingestion, dashboard, and alert setup](Docs/SIGNOZ_SETUP.md)
- [Manual validation checklist](Docs/MANUAL_VALIDATION.md)
- [Future Endpoint Security signing requirements](Docs/ENDPOINT_SECURITY_SETUP.md)
