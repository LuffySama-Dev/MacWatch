import AppKit
import Combine
import Foundation
import MacWatchCore

@MainActor
final class AppModel: ObservableObject {
    @Published var events: [SecurityEvent] = []
    @Published var exportStatus = ExportStatus()
    @Published var endpointText = UserDefaults.standard.string(forKey: "signozEndpoint") ?? ""
    @Published var cloudEnabled = UserDefaults.standard.bool(forKey: "signozEnabled")
    @Published var settingsMessage = "Cloud export is off by default."
    @Published var notificationsMuted = UserDefaults.standard.bool(forKey: "notificationsMuted")
    @Published var selectedKinds = Set(EventKind.allCases)
    @Published var searchText = ""
    @Published var retentionDays = UserDefaults.standard.object(forKey: "retentionDays") as? Int ?? 30
    @Published var exportInterval = UserDefaults.standard.object(forKey: "exportInterval") as? Double ?? 30
    @Published var activeSSHSessions: [SSHActiveSession] = []
    @Published var listeningEndpoints: [ListeningEndpoint] = []
    // SSH authentication protection is paused until the Endpoint Security
    // entitlement is available. The implementation is retained for later use.
    // @Published var sshProtectionMessage = "Enable SSH login protection to monitor successful and failed authentication."

    @Published private var monitorHealth = MonitorHealthTracker()
    @Published private var healthNow = Date()
    var monitors: [MonitorStatus] {
        monitorDefinitions.map { definition in
            var result = definition
            if definition.state == .active || definition.state == .periodic {
                if !awake || !monitorHealth.isHealthy(id: definition.id, now: healthNow) {
                    result.state = .interrupted
                    result.detail = "Awaiting a recent successful scan, or the monitor is unavailable. " + definition.detail
                }
            }
            return result
        }
    }
    private let monitorDefinitions: [MonitorStatus] = [
        .init(id: "camera", name: "Camera activity", coverage: "Connected CoreMediaIO camera devices", state: .active, detail: "Device activation only; responsible process is unknown."),
        .init(id: "microphone", name: "Microphone activity", coverage: "CoreAudio input devices", state: .active, detail: "Device activation only; responsible process is unknown."),
        .init(id: "startup", name: "Startup changes", coverage: "~/Library/LaunchAgents/*.plist", state: .periodic, detail: "Polled every 10 seconds; first scan is the baseline."),
        .init(id: "ssh", name: "Remote Login / SSH configuration", coverage: "Remote Login, allowed users, sshd configuration, and ~/.ssh/authorized_keys", state: .periodic, detail: "Polled every 15 seconds; contents and key material are never exported."),
        // Disabled for now: requires Apple's restricted Endpoint Security entitlement.
        // .init(id: "ssh-auth", name: "SSH authentication activity", coverage: "Successful logins, failed attempts, session closure, and repeated-failure bursts", state: .periodic, detail: "Reads a bounded store created by the optional privileged Endpoint Security recorder every 30 seconds; local account/address details are excluded from cloud telemetry."),
        .init(id: "ssh-sessions", name: "Active SSH sessions", coverage: "Remote terminal sessions", state: .periodic, detail: "Polled every 15 seconds."),
        .init(id: "ports", name: "Listening ports", coverage: "TCP listeners and unconnected bound UDP endpoints", state: .periodic, detail: "Polled every 15 seconds; loopback-only and network-reachable bindings are distinguished."),
        .init(id: "screen", name: "Screen capture", coverage: "No automatic coverage", state: .unavailable, detail: "No universal public API provides reliable detection under this app's constraints."),
        .init(id: "remote", name: "Remote access", coverage: "Manual review", state: .manual, detail: "MacWatch cannot prove an active remote session without privileged/restricted facilities."),
        .init(id: "network", name: "Established per-process connections", coverage: "No automatic coverage", state: .unavailable, detail: "Listening endpoints are covered separately; complete established-connection attribution requires stronger facilities.")
    ]

    private let store: EventStore
    private let notificationService = LocalNotificationService()
    private var telemetry: TelemetryExporter!
    private var deviceMonitor: DeviceActivityMonitor?
    private var startupMonitor: StartupDirectoryMonitor?
    private var sshMonitor: SSHConfigurationMonitor?
    // private var sshAuthenticationMonitor: SSHAuthenticationMonitor?
    private var sshActiveSessionMonitor: SSHActiveSessionMonitor?
    private var listeningEndpointMonitor: ListeningEndpointMonitor?
    private var sleepWake: SleepWakeObserver?
    private var heartbeatTimer: Timer?
    private var flushTimer: Timer?
    private var awake = true
    private let installationID: String
    private let appVersion: String
    private let knownSSHSourcesURL: URL
    private var knownSSHSources: Set<String>
    private var sshSessionStarts: [String: Date] = [:]
    private var recentSSHClosures: [String: Date] = [:]
    // private var systemExtensionController: SystemExtensionController?

    init() {
        let fm = FileManager.default
        let support = (try? fm.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true))?
            .appending(path: "MacWatch", directoryHint: .isDirectory) ?? fm.temporaryDirectory.appending(path: "MacWatch")
        knownSSHSourcesURL = support.appending(path: "known-ssh-sources.json")
        if let data = try? Data(contentsOf: knownSSHSourcesURL),
           let saved = try? JSONDecoder.macWatch.decode(Set<String>.self, from: data) { knownSSHSources = saved }
        else { knownSSHSources = [] }
        store = EventStore(fileURL: support.appending(path: "events.json"), retentionDays: UserDefaults.standard.object(forKey: "retentionDays") as? Int ?? 30)
        events = store.load().sorted { $0.observedAt > $1.observedAt }
        let existingID = UserDefaults.standard.string(forKey: "installationID")
        installationID = existingID ?? UUID().uuidString
        if existingID == nil { UserDefaults.standard.set(installationID, forKey: "installationID") }
        appVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "development"
        telemetry = TelemetryExporter(queueFile: support.appending(path: "telemetry-queue.json")) { status in
            Task { @MainActor [weak self] in self?.exportStatus = status }
        }

        let launchAgents = fm.homeDirectoryForCurrentUser.appending(path: "Library/LaunchAgents", directoryHint: .isDirectory)
        startupMonitor = StartupDirectoryMonitor(directory: launchAgents, baselineURL: support.appending(path: "launchagents-baseline.json"), healthHandler: healthCallback(["startup"])) { [weak self] change in
            Task { @MainActor in self?.recordStartup(change) }
        } errorHandler: { [weak self] error in
            Task { @MainActor in self?.record(.init(kind: .monitorError, severity: .error, monitor: "Startup", summary: "Startup monitor could not scan its directory", details: error.localizedDescription)) }
        }
        let cameraHealth = healthCallback(["camera"])
        let microphoneHealth = healthCallback(["microphone"])
        deviceMonitor = DeviceActivityMonitor(healthHandler: { medium, success in
            if medium == .camera { cameraHealth(success) } else { microphoneHealth(success) }
        }) { [weak self] state, old in
            Task { @MainActor in self?.recordDevice(state, old: old) }
        }
        sshMonitor = SSHConfigurationMonitor(scanner: SSHConfigurationScanner(), baselineURL: support.appending(path: "ssh-baseline.json"), healthHandler: healthCallback(["ssh"])) { [weak self] change in
            Task { @MainActor in self?.recordSSH(change) }
        } errorHandler: { [weak self] error in
            Task { @MainActor in self?.record(.init(kind: .monitorError, severity: .error, monitor: "SSH", summary: "SSH monitor could not save its baseline", details: error.localizedDescription)) }
        }
        // SSHAuthenticationMonitor is intentionally not created while the
        // restricted Endpoint Security integration is paused.
        sshActiveSessionMonitor = SSHActiveSessionMonitor(healthHandler: healthCallback(["ssh-sessions"])) { [weak self] sessions, changes in
            Task { @MainActor in self?.handleActiveSSHSessions(sessions, changes: changes) }
        } errorHandler: { [weak self] error in
            Task { @MainActor in self?.record(.init(kind: .monitorError, severity: .error, monitor: "SSH Sessions", summary: "Active SSH sessions could not be read", details: error.localizedDescription), notify: false) }
        }
        listeningEndpointMonitor = ListeningEndpointMonitor(baselineURL: support.appending(path: "listening-endpoints-baseline.json"), healthHandler: healthCallback(["ports"])) { [weak self] endpoints, changes in
            Task { @MainActor in self?.handleListeningEndpoints(endpoints, changes: changes) }
        } errorHandler: { [weak self] error in
            Task { @MainActor in self?.record(.init(kind: .monitorError, severity: .error, monitor: "Listening Ports", summary: "Listening ports could not be inventoried", details: error.localizedDescription), notify: false) }
        }
        sleepWake = SleepWakeObserver { [weak self] date in
            Task { @MainActor in self?.handleSleep(date) }
        } onWake: { [weak self] date, gap in
            Task { @MainActor in self?.handleWake(date, gap: gap) }
        }

        // SystemExtensionController activation is intentionally paused.

        startupMonitor?.start(); deviceMonitor?.start(); sshMonitor?.start(); sshActiveSessionMonitor?.start(); listeningEndpointMonitor?.start()
        heartbeatTimer = .scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in Task { @MainActor in self?.maintenance() } }
        resetFlushTimer()
        if cloudEnabled {
            Task {
                do { try await telemetry.configure(endpointText: endpointText, key: nil, enabled: true) }
                catch { cloudEnabled = false; UserDefaults.standard.set(false, forKey: "signozEnabled"); settingsMessage = error.localizedDescription }
            }
        }
    }

    // func enableSSHProtection() { systemExtensionController?.activate() }
    // func disableSSHProtection() { systemExtensionController?.deactivate() }

    private func healthCallback(_ ids: [String]) -> @Sendable (Bool) -> Void {
        { [weak self] success in
            let observedAt = Date()
            Task { @MainActor in
                guard let self else { return }
                for id in ids {
                    self.monitorHealth.record(id: id, success: success, at: observedAt)
                }
                self.healthNow = Date()
            }
        }
    }

    private func maintenance() {
        healthNow = Date()
        do { events = try store.prune().sorted { $0.observedAt > $1.observedAt } }
        catch { settingsMessage = error.localizedDescription }
        heartbeat()
    }

    // refreshSSHProtectionStatus() is paused with the Endpoint Security integration.

    func setCloudEnabled(_ enabled: Bool) async {
        if !enabled {
            await telemetry.disable()
            UserDefaults.standard.set(false, forKey: "signozEnabled")
        }
    }

    var filteredEvents: [SecurityEvent] {
        events.filter { event in
            selectedKinds.contains(event.kind) && (searchText.isEmpty || [event.summary, event.details, event.monitor].contains { $0.localizedCaseInsensitiveContains(searchText) })
        }
    }

    func record(_ event: SecurityEvent, notify: Bool = true) {
        do { events = try store.append(event).sorted { $0.observedAt > $1.observedAt } }
        catch { settingsMessage = error.localizedDescription }
        if notify && !notificationsMuted { notificationService.post(for: event) }
        if cloudEnabled {
            Task {
                if let data = try? TelemetryEncoder.logPayload(event: event, installationID: installationID, appVersion: appVersion) {
                    await telemetry.enqueue(.init(signal: .logs, observedAt: event.observedAt, payload: data))
                }
            }
        }
    }

    private func recordDevice(_ state: DeviceUseState, old: DeviceUseState?) {
        guard let old else { return } // initial inventory is state, not an incident
        if !state.connected && old.connected {
            record(.init(kind: .monitorInterrupted, severity: .notice, monitor: state.medium.rawValue.capitalized,
                         summary: "\(state.name) disconnected", details: "Coverage for this device ended when it disconnected.", deviceName: state.name), notify: false)
        } else if state.connected && !old.connected {
            record(.init(kind: .monitorRestored, severity: .info, monitor: state.medium.rawValue.capitalized,
                         summary: "\(state.name) reconnected", details: "Device polling coverage resumed."), notify: false)
        } else if state.active != old.active {
            let activating = state.active
            let kind: EventKind = state.medium == .camera ? (activating ? .cameraActivated : .cameraDeactivated) : (activating ? .microphoneActivated : .microphoneDeactivated)
            record(.init(kind: kind, severity: activating ? .warning : .info, monitor: state.medium.rawValue.capitalized,
                         summary: "\(state.medium.rawValue.capitalized) \(activating ? "became active" : "became inactive")",
                         details: "This is a device-use observation, not proof of malicious activity. MacWatch cannot reliably identify the responsible process.",
                         deviceName: state.name, processAttribution: "Unknown"), notify: activating)
        }
    }

    private func recordStartup(_ change: StartupChange) {
        let kind: EventKind; let entry: StartupEntry; let action: String
        switch change {
        case .added(let value): kind = .startupAdded; entry = value; action = "added"
        case .removed(let value): kind = .startupRemoved; entry = value; action = "removed"
        case .modified(_, let value): kind = .startupModified; entry = value; action = "modified"
        }
        record(.init(kind: kind, severity: .warning, monitor: "Startup", summary: "LaunchAgent \(action): \(entry.relativeName)",
                     details: "A change in the monitored startup folder is an observation, not proof of compromise.", startupCategory: "user_launch_agent",
                     executablePath: entry.executablePath, signature: entry.signature))
    }

    private func recordSSH(_ change: SSHConfigurationChange) {
        switch change {
        case .remoteLogin(_, let new):
            let enabled = new == .enabled
            record(.init(kind: enabled ? .remoteLoginEnabled : .remoteLoginDisabled,
                         severity: enabled ? .warning : (new == .unknown ? .notice : .info), monitor: "SSH",
                         summary: new == .unknown ? "Remote Login status became unavailable" : "Remote Login was \(enabled ? "enabled" : "disabled")",
                         details: "This records the system Remote Login configuration, not an active SSH session."), notify: enabled)
        case .accessPolicy(_, let new):
            let scope = new.available ? (new.allowsAllLocalUsers ? "all local users" : "a restricted user list") : "an unavailable policy"
            record(.init(kind: .sshAccessChanged, severity: new.allowsAllLocalUsers ? .warning : .notice, monitor: "SSH",
                         summary: "SSH allowed-user policy changed", details: "The SSH access policy now represents \(scope). Usernames remain local and are excluded from cloud telemetry."))
        case .systemConfiguration:
            record(.init(kind: .sshConfigurationChanged, severity: .warning, monitor: "SSH",
                         summary: "SSH server configuration changed", details: "The fingerprint of sshd_config or its readable drop-in files changed; configuration contents were not stored."))
        case .authorizedKeys(_, let new):
            let action = new.state == .absent ? "removed" : (new.state == .unreadable ? "became unreadable" : "changed")
            record(.init(kind: .sshAuthorizedKeysChanged, severity: .warning, monitor: "SSH",
                         summary: "SSH authorized keys \(action)", details: "The current user's authorized_keys fingerprint changed; key material was not stored or exported."))
        }
    }

    private func recordSSHAuthentication(_ event: SSHAuthenticationEvent) {
        let account = event.accountName ?? "unknown account"
        let source = event.sourceAddress ?? "unknown address"
        switch event.kind {
        case .failed:
            record(.init(observedAt: event.observedAt, kind: .sshLoginFailed, severity: .notice, monitor: "SSH Authentication",
                         summary: "Failed SSH login from \(source)", details: "Account: \(account). Method: \(event.method ?? "unknown").",
                         sourceAddress: event.sourceAddress, accountName: event.accountName, authenticationMethod: event.method), notify: false)
        case .succeeded:
            let isNewSource = event.sourceAddress.map(registerKnownSSHSource) ?? false
            sshSessionStarts[sshSessionKey(account: event.accountName, source: event.sourceAddress)] = event.observedAt
            record(.init(observedAt: event.observedAt, kind: .sshLoginSucceeded, severity: .warning, monitor: "SSH Authentication",
                         summary: "Successful SSH login from \(source)", details: "Account: \(account). Method: \(event.method ?? "unknown"). Verify that this access was expected.",
                         sourceAddress: event.sourceAddress, accountName: event.accountName, authenticationMethod: event.method), notify: !isNewSource)
            if isNewSource {
                record(.init(observedAt: event.observedAt, kind: .sshLoginFromNewSource, severity: .error, monitor: "SSH Authentication",
                             summary: "SSH login from a new source: \(source)",
                             details: "This source address has not previously completed a recognized SSH login. Account: \(account).",
                             sourceAddress: event.sourceAddress, accountName: event.accountName, authenticationMethod: event.method))
            }
        case .sessionClosed:
            recordSSHSessionClosure(account: event.accountName, source: event.sourceAddress, at: event.observedAt, suppliedDuration: nil)
        }
    }

    private func recordSSHFailureBurst(source: String, count: Int, window: TimeInterval) {
        record(.init(kind: .sshLoginAttemptBurst, severity: .error, monitor: "SSH Authentication",
                     summary: "Repeated SSH login failures from \(source)",
                     details: "Observed \(count) failed SSH authentication attempts within \(Int(window / 60)) minutes.",
                     sourceAddress: source, attemptCount: count))
    }

    private func handleActiveSSHSessions(_ sessions: [SSHActiveSession], changes: [SSHActiveSessionChange]) {
        activeSSHSessions = sessions
        for change in changes {
            switch change {
            case .observed(let session):
                let key = sshSessionKey(account: session.accountName, source: session.sourceAddress)
                if sshSessionStarts[key] == nil { sshSessionStarts[key] = session.startedAt ?? Date() }
                let isNewSource = registerKnownSSHSource(session.sourceAddress)
                record(.init(observedAt: session.startedAt ?? Date(), kind: .sshSessionObserved, severity: .warning, monitor: "SSH Sessions",
                             summary: "Active SSH session observed from \(session.sourceAddress)",
                             details: "Account: \(session.accountName). Terminal: \(session.terminal).",
                             sourceAddress: session.sourceAddress, accountName: session.accountName), notify: false)
                if isNewSource {
                    record(.init(kind: .sshLoginFromNewSource, severity: .error, monitor: "SSH Sessions",
                                 summary: "Active SSH session from a new source: \(session.sourceAddress)",
                                 details: "This source was first observed in the active SSH session inventory. Account: \(session.accountName).",
                                 sourceAddress: session.sourceAddress, accountName: session.accountName))
                }
            case .ended(let session, let duration):
                recordSSHSessionClosure(account: session.accountName, source: session.sourceAddress, at: Date(), suppliedDuration: duration)
            }
        }
    }

    private func recordSSHSessionClosure(account: String?, source: String?, at date: Date, suppliedDuration: TimeInterval?) {
        let key = sshSessionKey(account: account, source: source)
        if let recent = recentSSHClosures[key], date.timeIntervalSince(recent) < 60 { return }
        recentSSHClosures[key] = date
        let duration = suppliedDuration ?? sshSessionStarts[key].map { max(0, date.timeIntervalSince($0)) }
        sshSessionStarts[key] = nil
        let accountText = account ?? "unknown account"; let sourceText = source ?? "unknown address"
        let durationText = duration.map { " Duration: \(Self.durationText($0))." } ?? " Duration unavailable."
        record(.init(observedAt: date, kind: .sshSessionClosed, severity: .info, monitor: "SSH Sessions",
                     summary: "SSH session closed for \(accountText)", details: "Remote address: \(sourceText).\(durationText)",
                     sourceAddress: source, accountName: account), notify: false)
    }

    private func registerKnownSSHSource(_ source: String) -> Bool {
        let inserted = knownSSHSources.insert(source).inserted
        guard inserted else { return false }
        do {
            try FileManager.default.createDirectory(at: knownSSHSourcesURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try JSONEncoder.macWatch.encode(knownSSHSources).write(to: knownSSHSourcesURL, options: .atomic)
        } catch { settingsMessage = "Could not save known SSH sources: \(error.localizedDescription)" }
        return true
    }

    private func sshSessionKey(account: String?, source: String?) -> String {
        "\(account ?? "unknown")|\(source ?? "unknown")"
    }

    private static func durationText(_ interval: TimeInterval) -> String {
        let seconds = max(0, Int(interval)); let hours = seconds / 3_600; let minutes = (seconds % 3_600) / 60
        if hours > 0 { return "\(hours)h \(minutes)m" }
        if minutes > 0 { return "\(minutes)m \(seconds % 60)s" }
        return "\(seconds)s"
    }

    private func handleListeningEndpoints(_ endpoints: [ListeningEndpoint], changes: [ListeningEndpointChange]) {
        listeningEndpoints = endpoints
        for change in changes {
            let endpoint: ListeningEndpoint; let opened: Bool
            switch change {
            case .opened(let value): endpoint = value; opened = true
            case .closed(let value): endpoint = value; opened = false
            }
            let reachable = endpoint.exposure != .loopbackOnly
            let noun = endpoint.transport == .tcp ? "listener" : "binding"
            let address = "\(endpoint.localAddress):\(endpoint.localPort)"
            let exposure = endpoint.exposure == .allInterfaces ? "all interfaces" : (endpoint.exposure == .loopbackOnly ? "loopback only" : "a network interface")
            record(.init(kind: opened ? .listeningEndpointOpened : .listeningEndpointClosed,
                         severity: opened ? (reachable ? .warning : .notice) : .info, monitor: "Listening Ports",
                         summary: "\(endpoint.transport.rawValue.uppercased()) \(noun) \(opened ? "opened" : "closed"): \(address)",
                         details: "Process: \(endpoint.processName). Exposure: \(exposure). A bound port is an observation, not proof it is reachable through the firewall or router.",
                         processAttribution: endpoint.processName, executablePath: endpoint.executablePath,
                         networkTransport: endpoint.transport.rawValue,
                         localAddress: endpoint.localAddress, localPort: endpoint.localPort,
                         networkExposure: endpoint.exposure.rawValue), notify: opened && reachable)
        }
    }

    private func handleSleep(_ date: Date) {
        awake = false; healthNow = Date()
        record(.init(observedAt: date, kind: .monitorInterrupted, severity: .info, monitor: "Health", summary: "Monitoring paused for system sleep", details: "Device polling and heartbeats do not run while the Mac sleeps."), notify: false)
    }
    private func handleWake(_ date: Date, gap: TimeInterval?) {
        awake = true; startupMonitor?.pollNow()
        let length = gap.map { " Gap: \(Int($0)) seconds." } ?? ""
        record(.init(observedAt: date, kind: .monitorRestored, severity: .info, monitor: "Health", summary: "Monitoring resumed after wake", details: "MacWatch resumed polling.\(length)"), notify: false)
        maintenance()
    }
    private func heartbeat() {
        guard awake, cloudEnabled else { return }
        Task {
            let now = Date()
            let current = await telemetry.currentStatus()
            let values: [(String, Double, Bool)] = [
                ("macwatch.heartbeat", now.timeIntervalSince1970, true),
                ("macwatch.export.queue.size", Double(current.queued), false),
                ("macwatch.export.dropped.total", Double(current.dropped), false),
                ("macwatch.export.failure", current.lastError == nil ? 0 : 1, false)
            ]
            for (name, value, isHeartbeat) in values {
                if let payload = try? TelemetryEncoder.metricPayload(name: name, value: value, observedAt: now,
                                                                      installationID: installationID, appVersion: appVersion,
                                                                      attributes: ["monitor.state": "running"]) {
                    await telemetry.enqueue(.init(signal: .metrics, observedAt: now, payload: payload, isHeartbeat: isHeartbeat))
                }
            }
            for monitor in monitorDefinitions where monitor.state == .active || monitor.state == .periodic {
                let healthy = monitorHealth.isHealthy(id: monitor.id, now: now)
                if let payload = try? TelemetryEncoder.metricPayload(name: "macwatch.monitor.up", value: healthy ? 1 : 0,
                    observedAt: now, installationID: installationID, appVersion: appVersion,
                    attributes: ["monitor.name": monitor.id, "monitor.state": healthy ? "running" : "interrupted"]) {
                    await telemetry.enqueue(.init(signal: .metrics, observedAt: now, payload: payload, isHeartbeat: true))
                }
            }
            await telemetry.flush()
        }
    }

    func saveTelemetry(key: String) async {
        do {
            try await telemetry.configure(endpointText: endpointText, key: key.isEmpty ? nil : key, enabled: cloudEnabled)
            UserDefaults.standard.set(endpointText, forKey: "signozEndpoint"); UserDefaults.standard.set(cloudEnabled, forKey: "signozEnabled")
            settingsMessage = cloudEnabled ? "Saved. Export is enabled; the key is in Keychain." : "Saved. Cloud export remains disabled."
            if cloudEnabled { heartbeat() }
        } catch { await telemetry.disable(); cloudEnabled = false; UserDefaults.standard.set(false, forKey: "signozEnabled"); settingsMessage = error.localizedDescription }
    }
    func sendTestEvent() {
        record(.init(kind: .test, severity: .notice, monitor: "Test", summary: "TEST — user-triggered SigNoz validation event",
                     details: "Clearly labeled synthetic event; not a real security observation.", isTest: true), notify: false)
        Task { await telemetry.flush() }
    }
    func requestNotifications() async {
        do { settingsMessage = try await notificationService.requestAuthorization() ? "Notifications enabled." : "Notification permission was not granted." }
        catch { settingsMessage = error.localizedDescription }
    }
    func setMuted(_ muted: Bool) { notificationsMuted = muted; UserDefaults.standard.set(muted, forKey: "notificationsMuted") }
    func applyLocalSettings() {
        retentionDays = max(1, min(retentionDays, 365)); exportInterval = [15.0, 30.0, 60.0, 120.0].min(by: { abs($0 - exportInterval) < abs($1 - exportInterval) }) ?? 30
        store.retentionDays = retentionDays
        UserDefaults.standard.set(retentionDays, forKey: "retentionDays"); UserDefaults.standard.set(exportInterval, forKey: "exportInterval")
        do { events = try store.prune().sorted { $0.observedAt > $1.observedAt }; resetFlushTimer(); settingsMessage = "Local retention and export cadence saved." }
        catch { settingsMessage = error.localizedDescription }
    }
    private func resetFlushTimer() {
        flushTimer?.invalidate()
        flushTimer = .scheduledTimer(withTimeInterval: exportInterval, repeats: true) { [weak self] _ in Task { await self?.telemetry.flush() } }
    }
    func clearHistory() { do { try store.clear(); events = [] } catch { settingsMessage = error.localizedDescription } }
    func exportHistory() {
        let panel = NSSavePanel(); panel.nameFieldStringValue = "MacWatch-events.json"; panel.allowedContentTypes = [.json]
        if panel.runModal() == .OK, let url = panel.url { do { try store.export(to: url); settingsMessage = "Exported local history." } catch { settingsMessage = error.localizedDescription } }
    }
}
