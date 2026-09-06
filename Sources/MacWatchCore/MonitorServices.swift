@preconcurrency import AppKit
import CoreAudio
import CoreMediaIO
import Foundation
@preconcurrency import UserNotifications

public struct DeviceUseState: Equatable, Sendable {
    public let uniqueID: String
    public let name: String
    public let medium: Medium
    public let connected: Bool
    public let active: Bool
    public enum Medium: String, Sendable { case camera, microphone }
}

public final class DeviceActivityMonitor: @unchecked Sendable {
    private let healthHandler: @Sendable (DeviceUseState.Medium, Bool) -> Void
    private let queue = DispatchQueue(label: "MacWatch.DeviceActivity")
    private var timer: DispatchSourceTimer?
    private var previous: [String: DeviceUseState] = [:]
    private let handler: @Sendable (DeviceUseState, DeviceUseState?) -> Void

    public init(healthHandler: @escaping @Sendable (DeviceUseState.Medium, Bool) -> Void = { _, _ in }, handler: @escaping @Sendable (DeviceUseState, DeviceUseState?) -> Void) { self.healthHandler = healthHandler; self.handler = handler }
    public func start(interval: TimeInterval = 2) {
        queue.async {
            guard self.timer == nil else { return }
            let timer = DispatchSource.makeTimerSource(queue: self.queue)
            timer.schedule(deadline: .now(), repeating: interval)
            timer.setEventHandler { [weak self] in self?.poll() }
            self.timer = timer; timer.resume()
        }
    }
    public func stop() { queue.async { self.timer?.cancel(); self.timer = nil } }

    private func poll() {
        for medium in [DeviceUseState.Medium.camera, .microphone] {
            do {
                let states = try medium == .camera ? Self.cameraSnapshot() : Self.microphoneSnapshot()
                update(states, medium: medium)
                healthHandler(medium, true)
            } catch { healthHandler(medium, false) }
        }
    }

    private func update(_ states: [DeviceUseState], medium: DeviceUseState.Medium) {
        var current = Dictionary(uniqueKeysWithValues: states.map { ($0.uniqueID, $0) })
        for (id, state) in current {
            let old = previous[id]
            if old == nil || old?.active != state.active || old?.connected != state.connected { handler(state, old) }
        }
        for (id, old) in previous where old.medium == medium && current[id] == nil {
            let disconnected = DeviceUseState(uniqueID: id, name: old.name, medium: old.medium, connected: false, active: false)
            if old.connected { handler(disconnected, old) }
            current[id] = disconnected
        }
        previous = previous.filter { $0.value.medium != medium }.merging(current) { _, new in new }
    }

    public static func snapshot() -> [DeviceUseState] {
        ((try? cameraSnapshot()) ?? []) + ((try? microphoneSnapshot()) ?? [])
    }

    private static func cameraSnapshot() throws -> [DeviceUseState] {
        var devicesAddress = CMIOObjectPropertyAddress(
            mSelector: CMIOObjectPropertySelector(kCMIOHardwarePropertyDevices),
            mScope: CMIOObjectPropertyScope(kCMIOObjectPropertyScopeGlobal),
            mElement: CMIOObjectPropertyElement(kCMIOObjectPropertyElementMain)
        )
        var size: UInt32 = 0
        guard CMIOObjectGetPropertyDataSize(CMIOObjectID(kCMIOObjectSystemObject), &devicesAddress, 0, nil, &size) == noErr else { throw MacWatchError.storage("Device state could not be read") }
        guard size > 0 else { return [] }
        var ids = [CMIODeviceID](repeating: 0, count: Int(size) / MemoryLayout<CMIODeviceID>.size)
        let status = ids.withUnsafeMutableBytes { bytes in
            CMIOObjectGetPropertyData(CMIOObjectID(kCMIOObjectSystemObject), &devicesAddress, 0, nil, size, &size, bytes.baseAddress!)
        }
        guard status == noErr else { throw MacWatchError.storage("Device state could not be read") }
        return try ids.map { id in
            guard let alive = cmioUInt32(id, selector: CMIOObjectPropertySelector(kCMIODevicePropertyDeviceIsAlive)),
                  let running = cmioUInt32(id, selector: CMIOObjectPropertySelector(kCMIODevicePropertyDeviceIsRunningSomewhere)) else {
                throw MacWatchError.storage("Camera state could not be read")
            }
            return DeviceUseState(uniqueID: "camera:\(id)", name: cmioName(id) ?? "Camera \(id)", medium: .camera,
                                  connected: alive != 0, active: running != 0)
        }
    }

    private static func cmioUInt32(_ id: CMIODeviceID, selector: CMIOObjectPropertySelector) -> UInt32? {
        var address = CMIOObjectPropertyAddress(mSelector: selector, mScope: CMIOObjectPropertyScope(kCMIOObjectPropertyScopeGlobal),
                                                mElement: CMIOObjectPropertyElement(kCMIOObjectPropertyElementMain))
        var value: UInt32 = 0; var size = UInt32(MemoryLayout<UInt32>.size)
        return CMIOObjectGetPropertyData(id, &address, 0, nil, size, &size, &value) == noErr ? value : nil
    }

    private static func cmioName(_ id: CMIODeviceID) -> String? {
        var address = CMIOObjectPropertyAddress(mSelector: CMIOObjectPropertySelector(kCMIOObjectPropertyName),
                                                mScope: CMIOObjectPropertyScope(kCMIOObjectPropertyScopeGlobal),
                                                mElement: CMIOObjectPropertyElement(kCMIOObjectPropertyElementMain))
        var value: Unmanaged<CFString>?; var size = UInt32(MemoryLayout<Unmanaged<CFString>?>.size)
        guard CMIOObjectGetPropertyData(id, &address, 0, nil, size, &size, &value) == noErr, let value else { return nil }
        return value.takeRetainedValue() as String
    }

    private static func microphoneSnapshot() throws -> [DeviceUseState] {
        var devicesAddress = AudioObjectPropertyAddress(mSelector: kAudioHardwarePropertyDevices,
                                                        mScope: kAudioObjectPropertyScopeGlobal,
                                                        mElement: kAudioObjectPropertyElementMain)
        var size: UInt32 = 0
        guard AudioObjectGetPropertyDataSize(AudioObjectID(kAudioObjectSystemObject), &devicesAddress, 0, nil, &size) == noErr else { throw MacWatchError.storage("Device state could not be read") }
        guard size > 0 else { return [] }
        var ids = [AudioDeviceID](repeating: 0, count: Int(size) / MemoryLayout<AudioDeviceID>.size)
        let status = ids.withUnsafeMutableBytes { bytes in
            AudioObjectGetPropertyData(AudioObjectID(kAudioObjectSystemObject), &devicesAddress, 0, nil, &size, bytes.baseAddress!)
        }
        guard status == noErr else { throw MacWatchError.storage("Device state could not be read") }
        return try ids.compactMap { id in
            var streamsAddress = AudioObjectPropertyAddress(mSelector: kAudioDevicePropertyStreams,
                                                            mScope: kAudioObjectPropertyScopeInput,
                                                            mElement: kAudioObjectPropertyElementMain)
            var streamsSize: UInt32 = 0
            guard AudioObjectGetPropertyDataSize(id, &streamsAddress, 0, nil, &streamsSize) == noErr else { throw MacWatchError.storage("Audio streams could not be read") }
            guard streamsSize > 0 else { return nil }
            var runningAddress = AudioObjectPropertyAddress(mSelector: kAudioDevicePropertyDeviceIsRunningSomewhere,
                                                            mScope: kAudioObjectPropertyScopeInput,
                                                            mElement: kAudioObjectPropertyElementMain)
            var running: UInt32 = 0; var runningSize = UInt32(MemoryLayout<UInt32>.size)
            if AudioObjectGetPropertyData(id, &runningAddress, 0, nil, &runningSize, &running) != noErr {
                runningAddress.mScope = kAudioObjectPropertyScopeGlobal
                guard AudioObjectGetPropertyData(id, &runningAddress, 0, nil, &runningSize, &running) == noErr else {
                    throw MacWatchError.storage("Microphone state could not be read")
                }
            }
            return DeviceUseState(uniqueID: "microphone:\(id)", name: audioName(id) ?? "Microphone \(id)", medium: .microphone,
                                  connected: true, active: running != 0)
        }
    }

    private static func audioName(_ id: AudioDeviceID) -> String? {
        var address = AudioObjectPropertyAddress(mSelector: kAudioObjectPropertyName, mScope: kAudioObjectPropertyScopeGlobal,
                                                 mElement: kAudioObjectPropertyElementMain)
        var value: Unmanaged<CFString>?; var size = UInt32(MemoryLayout<Unmanaged<CFString>?>.size)
        guard AudioObjectGetPropertyData(id, &address, 0, nil, &size, &value) == noErr, let value else { return nil }
        return value.takeRetainedValue() as String
    }
}

public final class StartupDirectoryMonitor: @unchecked Sendable {
    private let healthHandler: @Sendable (Bool) -> Void
    private let scanner: StartupScanner
    private let baselineURL: URL
    private let queue = DispatchQueue(label: "MacWatch.StartupMonitor")
    private var timer: DispatchSourceTimer?
    private var baseline: [String: StartupEntry] = [:]
    private let changeHandler: @Sendable (StartupChange) -> Void
    private let errorHandler: @Sendable (Error) -> Void

    public init(directory: URL, baselineURL: URL, healthHandler: @escaping @Sendable (Bool) -> Void = { _ in },
                changeHandler: @escaping @Sendable (StartupChange) -> Void,
                errorHandler: @escaping @Sendable (Error) -> Void) {
        self.healthHandler = healthHandler
        scanner = StartupScanner(directory: directory); self.baselineURL = baselineURL
        self.changeHandler = changeHandler; self.errorHandler = errorHandler
    }
    public func start(interval: TimeInterval = 10) {
        queue.async {
            guard self.timer == nil else { return }
            if let data = try? Data(contentsOf: self.baselineURL),
               let saved = try? JSONDecoder.macWatch.decode([String: StartupEntry].self, from: data) {
                self.baseline = saved
                self.poll()
            } else { self.poll(initial: true) }
            let timer = DispatchSource.makeTimerSource(queue: self.queue)
            timer.schedule(deadline: .now() + interval, repeating: interval)
            timer.setEventHandler { [weak self] in self?.poll() }
            self.timer = timer; timer.resume()
        }
    }
    public func stop() { queue.async { self.timer?.cancel(); self.timer = nil } }
    public func pollNow() { queue.async { self.poll() } }
    private func poll(initial: Bool = false) {
        do {
            var complete = true
            let scan = try scanner.scan(previous: baseline) { error in
                complete = false
                errorHandler(error)
            }
            if !initial { StartupScanner.changes(from: baseline, to: scan).forEach(changeHandler) }
            try persist(scan); baseline = scan
            healthHandler(complete)
        } catch { healthHandler(false); errorHandler(error) }
    }
    private func persist(_ entries: [String: StartupEntry]) throws {
        try FileManager.default.createDirectory(at: baselineURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try JSONEncoder.macWatch.encode(entries).write(to: baselineURL, options: .atomic)
    }
}

public final class LocalNotificationService: @unchecked Sendable {
    private var deduplicator = NotificationDeduplicator()
    private let lock = NSLock()
    public var mutedUntil: Date?
    public init() {}
    public func requestAuthorization() async throws -> Bool {
        guard Self.hasApplicationBundle else { return false }
        return try await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])
    }
    public func post(for event: SecurityEvent) {
        guard Self.hasApplicationBundle else { return }
        lock.lock()
        defer { lock.unlock() }
        guard mutedUntil.map({ $0 <= Date() }) ?? true,
              deduplicator.shouldNotify(key: "\(event.kind.rawValue):\(event.deviceName ?? event.startupCategory ?? "general")") else { return }
        let content = UNMutableNotificationContent(); content.title = "MacWatch observation"; content.body = event.summary; content.sound = .default
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: event.id.uuidString, content: content, trigger: nil))
    }

    private static var hasApplicationBundle: Bool {
        Bundle.main.bundleURL.pathExtension.lowercased() == "app" && Bundle.main.bundleIdentifier != nil
    }
}

public final class SleepWakeObserver: @unchecked Sendable {
    private var tokens: [NSObjectProtocol] = []
    private var sleptAt: Date?
    public init(onSleep: @escaping @Sendable (Date) -> Void, onWake: @escaping @Sendable (Date, TimeInterval?) -> Void) {
        let center = NSWorkspace.shared.notificationCenter
        tokens.append(center.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { [weak self] _ in
            let now = Date(); self?.sleptAt = now; onSleep(now)
        })
        tokens.append(center.addObserver(forName: NSWorkspace.didWakeNotification, object: nil, queue: .main) { [weak self] _ in
            let now = Date(); onWake(now, self?.sleptAt.map { now.timeIntervalSince($0) }); self?.sleptAt = nil
        })
    }
    deinit { tokens.forEach(NSWorkspace.shared.notificationCenter.removeObserver) }
}

public enum RemoteLoginState: String, Codable, Sendable {
    case enabled, disabled, unknown
}

public struct SSHAccessPolicy: Codable, Equatable, Sendable {
    public let available: Bool
    public let allowsAllLocalUsers: Bool
    public let users: [String]
    public let nestedGroups: [String]

    public init(available: Bool, allowsAllLocalUsers: Bool, users: [String], nestedGroups: [String]) {
        self.available = available
        self.allowsAllLocalUsers = allowsAllLocalUsers
        self.users = users.sorted()
        self.nestedGroups = nestedGroups.sorted()
    }
}

public struct SSHFileFingerprint: Codable, Equatable, Sendable {
    public enum State: String, Codable, Sendable { case absent, readable, unreadable }
    public let state: State
    public let hash: UInt64?

    public init(state: State, hash: UInt64? = nil) {
        self.state = state; self.hash = hash
    }
}

public struct SSHConfigurationSnapshot: Codable, Equatable, Sendable {
    public let remoteLogin: RemoteLoginState
    public let access: SSHAccessPolicy
    public let systemConfiguration: SSHFileFingerprint
    public let authorizedKeys: SSHFileFingerprint

    public init(remoteLogin: RemoteLoginState, access: SSHAccessPolicy,
                systemConfiguration: SSHFileFingerprint, authorizedKeys: SSHFileFingerprint) {
        self.remoteLogin = remoteLogin; self.access = access
        self.systemConfiguration = systemConfiguration; self.authorizedKeys = authorizedKeys
    }
}

public enum SSHConfigurationChange: Equatable, Sendable {
    case remoteLogin(old: RemoteLoginState, new: RemoteLoginState)
    case accessPolicy(old: SSHAccessPolicy, new: SSHAccessPolicy)
    case systemConfiguration(old: SSHFileFingerprint, new: SSHFileFingerprint)
    case authorizedKeys(old: SSHFileFingerprint, new: SSHFileFingerprint)
}

public struct SSHConfigurationScanner: Sendable {
    public let launchDaemonPlist: URL
    public let systemConfigurationFile: URL
    public let systemConfigurationDirectory: URL
    public let authorizedKeysFile: URL

    public init(
        launchDaemonPlist: URL = URL(fileURLWithPath: "/System/Library/LaunchDaemons/ssh.plist"),
        systemConfigurationFile: URL = URL(fileURLWithPath: "/etc/ssh/sshd_config"),
        systemConfigurationDirectory: URL = URL(fileURLWithPath: "/etc/ssh/sshd_config.d", isDirectory: true),
        authorizedKeysFile: URL = FileManager.default.homeDirectoryForCurrentUser.appending(path: ".ssh/authorized_keys")
    ) {
        self.launchDaemonPlist = launchDaemonPlist
        self.systemConfigurationFile = systemConfigurationFile
        self.systemConfigurationDirectory = systemConfigurationDirectory
        self.authorizedKeysFile = authorizedKeysFile
    }

    public func scan() -> SSHConfigurationSnapshot {
        let launchctl = Self.run("/bin/launchctl", arguments: ["print-disabled", "system"])
        let defaultDisabled = Self.defaultDisabled(in: launchDaemonPlist)
        let state = launchctl.status == 0
            ? Self.remoteLoginState(from: launchctl.output, defaultDisabled: defaultDisabled)
            : .unknown
        return SSHConfigurationSnapshot(
            remoteLogin: state,
            access: Self.accessPolicy(),
            systemConfiguration: Self.configurationFingerprint(main: systemConfigurationFile, directory: systemConfigurationDirectory),
            authorizedKeys: Self.fingerprint(of: authorizedKeysFile)
        )
    }

    public static func changes(from old: SSHConfigurationSnapshot, to new: SSHConfigurationSnapshot) -> [SSHConfigurationChange] {
        var changes: [SSHConfigurationChange] = []
        if old.remoteLogin != new.remoteLogin { changes.append(.remoteLogin(old: old.remoteLogin, new: new.remoteLogin)) }
        if old.access != new.access { changes.append(.accessPolicy(old: old.access, new: new.access)) }
        if old.systemConfiguration != new.systemConfiguration {
            changes.append(.systemConfiguration(old: old.systemConfiguration, new: new.systemConfiguration))
        }
        if old.authorizedKeys != new.authorizedKeys {
            changes.append(.authorizedKeys(old: old.authorizedKeys, new: new.authorizedKeys))
        }
        return changes
    }

    public static func remoteLoginState(from launchctlOutput: String, defaultDisabled: Bool?) -> RemoteLoginState {
        for line in launchctlOutput.split(whereSeparator: \Character.isNewline) where line.contains("com.openssh.sshd") {
            if line.contains("=> enabled") { return .enabled }
            if line.contains("=> disabled") { return .disabled }
        }
        guard let defaultDisabled else { return .unknown }
        return defaultDisabled ? .disabled : .enabled
    }

    private static func defaultDisabled(in url: URL) -> Bool? {
        guard let data = try? Data(contentsOf: url),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil),
              let dictionary = plist as? [String: Any] else { return nil }
        return dictionary["Disabled"] as? Bool
    }

    private static func accessPolicy() -> SSHAccessPolicy {
        let access = run("/usr/bin/dscl", arguments: [".", "-read", "/Groups/com.apple.access_ssh", "GroupMembership", "NestedGroups"])
        guard access.status == 0 else {
            return SSHAccessPolicy(available: false, allowsAllLocalUsers: false, users: [], nestedGroups: [])
        }
        let localAccounts = run("/usr/bin/dscl", arguments: [".", "-read", "/Groups/localaccounts", "GeneratedUID"])
        let localAccountsID = values(for: "GeneratedUID", in: localAccounts.output).first
        let users = values(for: "GroupMembership", in: access.output)
        let groups = values(for: "NestedGroups", in: access.output)
        return SSHAccessPolicy(available: true, allowsAllLocalUsers: localAccountsID.map(groups.contains) ?? false,
                               users: users, nestedGroups: groups)
    }

    private static func values(for key: String, in output: String) -> [String] {
        output.split(whereSeparator: \Character.isNewline).compactMap { line -> [String]? in
            let prefix = "\(key):"
            guard line.hasPrefix(prefix) else { return nil }
            return line.dropFirst(prefix.count).split(whereSeparator: \Character.isWhitespace).map(String.init)
        }.flatMap { $0 }.sorted()
    }

    private static func configurationFingerprint(main: URL, directory: URL) -> SSHFileFingerprint {
        var urls = [main]
        if let children = try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: [.isRegularFileKey],
                                                                        options: [.skipsHiddenFiles]) {
            urls += children.sorted { $0.lastPathComponent < $1.lastPathComponent }
        }
        let existing = urls.filter { FileManager.default.fileExists(atPath: $0.path) }
        guard !existing.isEmpty else { return .init(state: .absent) }
        var combined = Data()
        for url in existing {
            guard let data = try? Data(contentsOf: url) else { return .init(state: .unreadable) }
            combined.append(Data(url.path.utf8)); combined.append(0); combined.append(data); combined.append(0)
        }
        return .init(state: .readable, hash: StartupScanner.fnv1a(combined))
    }

    private static func fingerprint(of url: URL) -> SSHFileFingerprint {
        guard FileManager.default.fileExists(atPath: url.path) else { return .init(state: .absent) }
        guard let data = try? Data(contentsOf: url) else { return .init(state: .unreadable) }
        return .init(state: .readable, hash: StartupScanner.fnv1a(data))
    }

    private static func run(_ executable: String, arguments: [String]) -> (status: Int32, output: String) {
        let process = Process(); let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: executable); process.arguments = arguments
        process.standardOutput = pipe; process.standardError = pipe
        do { try process.run() } catch { return (-1, error.localizedDescription) }
        let data = pipe.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
        return (process.terminationStatus, String(decoding: data, as: UTF8.self))
    }
}

public final class SSHConfigurationMonitor: @unchecked Sendable {
    private let healthHandler: @Sendable (Bool) -> Void
    private let scanner: SSHConfigurationScanner
    private let baselineURL: URL
    private let queue = DispatchQueue(label: "MacWatch.SSHConfiguration")
    private var timer: DispatchSourceTimer?
    private var baseline: SSHConfigurationSnapshot?
    private let changeHandler: @Sendable (SSHConfigurationChange) -> Void
    private let errorHandler: @Sendable (Error) -> Void

    public init(scanner: SSHConfigurationScanner = SSHConfigurationScanner(), baselineURL: URL,
                healthHandler: @escaping @Sendable (Bool) -> Void = { _ in },
                changeHandler: @escaping @Sendable (SSHConfigurationChange) -> Void,
                errorHandler: @escaping @Sendable (Error) -> Void) {
        self.healthHandler = healthHandler
        self.scanner = scanner; self.baselineURL = baselineURL
        self.changeHandler = changeHandler; self.errorHandler = errorHandler
    }

    public func start(interval: TimeInterval = 15) {
        queue.async {
            guard self.timer == nil else { return }
            let current = self.scanner.scan()
            if let data = try? Data(contentsOf: self.baselineURL),
               let saved = try? JSONDecoder.macWatch.decode(SSHConfigurationSnapshot.self, from: data) {
                SSHConfigurationScanner.changes(from: saved, to: current).forEach(self.changeHandler)
            }
            self.baseline = current
            do { try self.persist(current); self.healthHandler(Self.readable(current)) } catch { self.healthHandler(false); self.errorHandler(error) }
            let timer = DispatchSource.makeTimerSource(queue: self.queue)
            timer.schedule(deadline: .now() + interval, repeating: interval)
            timer.setEventHandler { [weak self] in self?.poll() }
            self.timer = timer; timer.resume()
        }
    }

    public func stop() { queue.async { self.timer?.cancel(); self.timer = nil } }
    public func pollNow() { queue.async { self.poll() } }

    private func poll() {
        let current = scanner.scan()
        if let baseline { SSHConfigurationScanner.changes(from: baseline, to: current).forEach(changeHandler) }
        do { try persist(current); baseline = current; healthHandler(Self.readable(current)) } catch { healthHandler(false); errorHandler(error) }
    }

    private static func readable(_ snapshot: SSHConfigurationSnapshot) -> Bool {
        snapshot.remoteLogin != .unknown && snapshot.access.available &&
        snapshot.systemConfiguration.state != .unreadable && snapshot.authorizedKeys.state != .unreadable
    }

    private func persist(_ snapshot: SSHConfigurationSnapshot) throws {
        try FileManager.default.createDirectory(at: baselineURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try JSONEncoder.macWatch.encode(snapshot).write(to: baselineURL, options: .atomic)
    }
}

public struct SSHAuthenticationEvent: Codable, Equatable, Sendable {
    public enum Kind: String, Codable, Sendable { case failed, succeeded, sessionClosed }
    public let observedAt: Date
    public let kind: Kind
    public let accountName: String?
    public let sourceAddress: String?
    public let method: String?

    public init(observedAt: Date, kind: Kind, accountName: String?, sourceAddress: String?, method: String?) {
        self.observedAt = observedAt; self.kind = kind; self.accountName = accountName
        self.sourceAddress = sourceAddress; self.method = method
    }
}

public struct SSHAuthenticationRecord: Equatable, Sendable {
    public let event: SSHAuthenticationEvent
    public let fingerprint: UInt64
}

public enum SSHAuthenticationLogError: LocalizedError, Sendable {
    case unavailable(String)
    public var errorDescription: String? {
        switch self { case .unavailable(let message): return "SSH authentication log unavailable: \(message)" }
    }
}

public struct SSHAuthenticationLogScanner: Sendable {
    public static let defaultEventStoreURL = URL(fileURLWithPath: "/Library/Application Support/MacWatch/ssh-auth-events.json")
    public static let defaultStatusURL = URL(fileURLWithPath: "/Library/Application Support/MacWatch/ssh-recorder-status.txt")
    private let eventStoreURL: URL
    private let statusURL: URL?

    public init(eventStoreURL: URL = Self.defaultEventStoreURL, statusURL: URL? = nil) {
        self.eventStoreURL = eventStoreURL
        self.statusURL = statusURL ?? (eventStoreURL == Self.defaultEventStoreURL ? Self.defaultStatusURL : nil)
    }

    public func records(since: Date) throws -> [SSHAuthenticationRecord] {
        if let statusURL {
            guard let status = try? String(contentsOf: statusURL, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines) else {
                throw SSHAuthenticationLogError.unavailable("the embedded Endpoint Security extension is not activated or has not started")
            }
            let fields = status.split(separator: "|", maxSplits: 1).map(String.init)
            guard fields.count == 2, fields[0] == "running",
                  let heartbeat = ISO8601DateFormatter().date(from: fields[1]),
                  abs(Date().timeIntervalSince(heartbeat)) <= 90 else {
                throw SSHAuthenticationLogError.unavailable("the Endpoint Security extension reported: \(status)")
            }
        }
        guard FileManager.default.fileExists(atPath: eventStoreURL.path) else {
            throw SSHAuthenticationLogError.unavailable("the embedded Endpoint Security extension is not activated or has not started")
        }
        let data: Data
        do { data = try Data(contentsOf: eventStoreURL) }
        catch { throw SSHAuthenticationLogError.unavailable("the Endpoint Security event store is not readable: \(error.localizedDescription)") }
        let events: [SSHAuthenticationEvent]
        do { events = try JSONDecoder.macWatch.decode([SSHAuthenticationEvent].self, from: data) }
        catch { throw SSHAuthenticationLogError.unavailable("the Endpoint Security event store is invalid: \(error.localizedDescription)") }
        return events.filter { $0.observedAt >= since }.map { event in
            let identity = "\(event.observedAt.timeIntervalSince1970)|\(event.kind.rawValue)|\(event.accountName ?? "")|\(event.sourceAddress ?? "")|\(event.method ?? "")"
            return SSHAuthenticationRecord(event: event, fingerprint: StartupScanner.fnv1a(Data(identity.utf8)))
        }.sorted { $0.event.observedAt < $1.event.observedAt }
    }

}

private struct SSHAuthenticationCursor: Codable {
    var lastScanAt: Date
    var recentFingerprints: [UInt64]
    var burstDetector: SSHFailureBurstDetector?
}

public struct SSHFailureBurstDetector: Codable, Sendable {
    public let threshold: Int
    public let window: TimeInterval
    private var failuresBySource: [String: [Date]] = [:]
    private var lastBurstBySource: [String: Date] = [:]

    public init(threshold: Int = 5, window: TimeInterval = 300) {
        self.threshold = max(2, threshold); self.window = max(1, window)
    }

    public static let maximumSources = 1_024
    public static let maximumFailuresPerSource = 1_024

    public mutating func prune(now: Date) {
        for source in Array(failuresBySource.keys) {
            let recent = failuresBySource[source, default: []].filter { now.timeIntervalSince($0) <= window }
            failuresBySource[source] = recent.isEmpty ? nil : Array(recent.suffix(Self.maximumFailuresPerSource))
        }
        lastBurstBySource = lastBurstBySource.filter { now.timeIntervalSince($0.value) <= window && failuresBySource[$0.key] != nil }
        let excess = failuresBySource.count - Self.maximumSources
        if excess > 0 {
            let oldest = failuresBySource.keys.sorted {
                let a = failuresBySource[$0]?.last ?? .distantPast
                let b = failuresBySource[$1]?.last ?? .distantPast
                return a == b ? $0 < $1 : a < b
            }
            for source in oldest.prefix(excess) { failuresBySource[source] = nil; lastBurstBySource[source] = nil }
        }
    }

    public mutating func recordFailure(source: String, at date: Date) -> Int? {
        prune(now: date)
        var failures = failuresBySource[source, default: []]
        failures.append(date)
        failures.removeAll { date.timeIntervalSince($0) > window }
        failuresBySource[source] = Array(failures.suffix(Self.maximumFailuresPerSource))
        prune(now: date)
        guard failures.count >= threshold,
              lastBurstBySource[source].map({ date.timeIntervalSince($0) >= window }) ?? true else { return nil }
        lastBurstBySource[source] = date
        return failures.count
    }
}

public final class SSHAuthenticationMonitor: @unchecked Sendable {
    private let healthHandler: @Sendable (Bool) -> Void
    private let scanner: SSHAuthenticationLogScanner
    private let cursorURL: URL
    private let queue = DispatchQueue(label: "MacWatch.SSHAuthentication")
    private var timer: DispatchSourceTimer?
    private var cursor: SSHAuthenticationCursor?
    private var burstDetector = SSHFailureBurstDetector()
    private var errorReported = false
    private let eventHandler: @Sendable (SSHAuthenticationEvent) -> Void
    private let burstHandler: @Sendable (String, Int, TimeInterval) -> Void
    private let errorHandler: @Sendable (Error) -> Void

    public init(scanner: SSHAuthenticationLogScanner = SSHAuthenticationLogScanner(), cursorURL: URL,
                healthHandler: @escaping @Sendable (Bool) -> Void = { _ in },
                eventHandler: @escaping @Sendable (SSHAuthenticationEvent) -> Void,
                burstHandler: @escaping @Sendable (String, Int, TimeInterval) -> Void,
                errorHandler: @escaping @Sendable (Error) -> Void) {
        self.healthHandler = healthHandler
        self.scanner = scanner; self.cursorURL = cursorURL; self.eventHandler = eventHandler
        self.burstHandler = burstHandler; self.errorHandler = errorHandler
    }

    public func start(interval: TimeInterval = 30) {
        queue.async {
            guard self.timer == nil else { return }
            if let data = try? Data(contentsOf: self.cursorURL),
               let saved = try? JSONDecoder.macWatch.decode(SSHAuthenticationCursor.self, from: data) {
                self.cursor = saved
                self.burstDetector = saved.burstDetector ?? SSHFailureBurstDetector()
                self.poll()
            } else {
                self.cursor = SSHAuthenticationCursor(lastScanAt: Date(), recentFingerprints: [], burstDetector: self.burstDetector)
                self.persistCursor(reportHealth: false)
                self.poll()
            }
            let timer = DispatchSource.makeTimerSource(queue: self.queue)
            timer.schedule(deadline: .now() + interval, repeating: interval)
            timer.setEventHandler { [weak self] in self?.poll() }
            self.timer = timer; timer.resume()
        }
    }

    public func stop() { queue.async { self.timer?.cancel(); self.timer = nil } }
    public func pollNow() { queue.async { self.poll() } }

    private func poll() {
        let now = Date()
        guard var cursor else { return }
        let oldestRecovery = now.addingTimeInterval(-86_400)
        let since = max(cursor.lastScanAt.addingTimeInterval(-5), oldestRecovery)
        do {
            let records = try scanner.records(since: since)
            var seen = Set(cursor.recentFingerprints)
            for record in records where !seen.contains(record.fingerprint) {
                seen.insert(record.fingerprint); cursor.recentFingerprints.append(record.fingerprint)
                handle(record.event)
            }
            cursor.recentFingerprints = Array(cursor.recentFingerprints.suffix(512))
            burstDetector.prune(now: now)
            cursor.lastScanAt = now; cursor.burstDetector = burstDetector
            self.cursor = cursor; persistCursor()
        } catch {
            healthHandler(false)
            if !errorReported { errorReported = true; errorHandler(error) }
        }
    }

    private func handle(_ event: SSHAuthenticationEvent) {
        eventHandler(event)
        guard event.kind == .failed, let source = event.sourceAddress else { return }
        if let count = burstDetector.recordFailure(source: source, at: event.observedAt) {
            burstHandler(source, count, burstDetector.window)
        }
    }

    private func persistCursor(reportHealth: Bool = true) {
        guard let cursor else { return }
        do {
            try FileManager.default.createDirectory(at: cursorURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try JSONEncoder.macWatch.encode(cursor).write(to: cursorURL, options: .atomic)
            errorReported = false
            if reportHealth { healthHandler(true) }
        } catch {
            healthHandler(false)
            if !errorReported { errorReported = true; errorHandler(error) }
        }
    }
}

public enum SSHActiveSessionChange: Equatable, Sendable {
    case observed(SSHActiveSession)
    case ended(SSHActiveSession, duration: TimeInterval?)
}

public struct SSHActiveSessionScanner: Sendable {
    public init() {}

    public func sessions(now: Date = Date()) throws -> [SSHActiveSession] {
        let result = Self.runWho()
        guard result.status == 0 else {
            throw SSHAuthenticationLogError.unavailable(result.output.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        return Self.parseWhoOutput(result.output, now: now)
    }

    public static func parseWhoOutput(_ output: String, now: Date) -> [SSHActiveSession] {
        output.split(whereSeparator: \Character.isNewline).compactMap { line in
            let fields = line.split(whereSeparator: \Character.isWhitespace).map(String.init)
            guard fields.count >= 8, fields[1].hasPrefix("ttys"),
                  let hostField = fields.last, hostField.hasPrefix("("), hostField.hasSuffix(")") else { return nil }
            let source = String(hostField.dropFirst().dropLast())
            guard !source.isEmpty else { return nil }
            let pid = Int32(fields[6])
            let startedAt = loginDate(month: fields[2], day: fields[3], time: fields[4], now: now)
            return SSHActiveSession(accountName: fields[0], sourceAddress: source, terminal: fields[1],
                                    processID: pid, startedAt: startedAt)
        }.sorted { ($0.startedAt ?? .distantPast) < ($1.startedAt ?? .distantPast) }
    }

    private static func loginDate(month: String, day: String, time: String, now: Date) -> Date? {
        let calendar = Calendar(identifier: .gregorian)
        let currentYear = calendar.component(.year, from: now)
        let formatter = DateFormatter(); formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "MMM d HH:mm yyyy"
        guard var date = formatter.date(from: "\(month) \(day) \(time) \(currentYear)") else { return nil }
        if date.timeIntervalSince(now) > 86_400,
           let previousYear = calendar.date(byAdding: .year, value: -1, to: date) { date = previousYear }
        return date
    }

    private static func runWho() -> (status: Int32, output: String) {
        let process = Process(); let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/who"); process.arguments = ["-u"]
        var environment = ProcessInfo.processInfo.environment; environment["LC_ALL"] = "C"; process.environment = environment
        process.standardOutput = pipe; process.standardError = pipe
        do { try process.run() } catch { return (-1, error.localizedDescription) }
        let data = pipe.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
        return (process.terminationStatus, String(decoding: data, as: UTF8.self))
    }
}

public final class SSHActiveSessionMonitor: @unchecked Sendable {
    private let healthHandler: @Sendable (Bool) -> Void
    private let scanner: SSHActiveSessionScanner
    private let queue = DispatchQueue(label: "MacWatch.SSHActiveSessions")
    private var timer: DispatchSourceTimer?
    private var previous: [String: SSHActiveSession] = [:]
    private var errorReported = false
    private let updateHandler: @Sendable ([SSHActiveSession], [SSHActiveSessionChange]) -> Void
    private let errorHandler: @Sendable (Error) -> Void

    public init(scanner: SSHActiveSessionScanner = SSHActiveSessionScanner(),
                healthHandler: @escaping @Sendable (Bool) -> Void = { _ in },
                updateHandler: @escaping @Sendable ([SSHActiveSession], [SSHActiveSessionChange]) -> Void,
                errorHandler: @escaping @Sendable (Error) -> Void) {
        self.healthHandler = healthHandler
        self.scanner = scanner; self.updateHandler = updateHandler; self.errorHandler = errorHandler
    }

    public func start(interval: TimeInterval = 15) {
        queue.async {
            guard self.timer == nil else { return }
            self.poll()
            let timer = DispatchSource.makeTimerSource(queue: self.queue)
            timer.schedule(deadline: .now() + interval, repeating: interval)
            timer.setEventHandler { [weak self] in self?.poll() }
            self.timer = timer; timer.resume()
        }
    }

    public func stop() { queue.async { self.timer?.cancel(); self.timer = nil } }
    public func pollNow() { queue.async { self.poll() } }

    private func poll() {
        let now = Date()
        do {
            let sessions = try scanner.sessions(now: now)
            let current = Dictionary(uniqueKeysWithValues: sessions.map { ($0.id, $0) })
            var changes = current.keys.filter { previous[$0] == nil }.sorted().compactMap { current[$0].map(SSHActiveSessionChange.observed) }
            changes += previous.keys.filter { current[$0] == nil }.sorted().compactMap { key in
                previous[key].map { session in
                    .ended(session, duration: session.startedAt.map { max(0, now.timeIntervalSince($0)) })
                }
            }
            previous = current; errorReported = false; updateHandler(sessions, changes); healthHandler(true)
        } catch {
            healthHandler(false)
            if !errorReported { errorReported = true; errorHandler(error) }
        }
    }
}
