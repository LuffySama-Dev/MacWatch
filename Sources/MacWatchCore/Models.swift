import Foundation

public enum EventKind: String, Codable, CaseIterable, Sendable {
    case cameraActivated, cameraDeactivated
    case microphoneActivated, microphoneDeactivated
    case startupAdded, startupRemoved, startupModified
    case remoteLoginEnabled, remoteLoginDisabled
    case sshAccessChanged, sshConfigurationChanged, sshAuthorizedKeysChanged
    case sshLoginFailed, sshLoginSucceeded, sshLoginFromNewSource
    case sshSessionObserved, sshSessionClosed, sshLoginAttemptBurst
    case listeningEndpointOpened, listeningEndpointClosed
    case monitorError, monitorInterrupted, monitorRestored
    case telemetryFailure, telemetryDropped
    case test
}

public struct SSHActiveSession: Identifiable, Codable, Equatable, Sendable {
    public let id: String
    public let accountName: String
    public let sourceAddress: String
    public let terminal: String
    public let processID: Int32?
    public let startedAt: Date?

    public init(accountName: String, sourceAddress: String, terminal: String,
                processID: Int32? = nil, startedAt: Date? = nil) {
        self.accountName = accountName; self.sourceAddress = sourceAddress; self.terminal = terminal
        self.processID = processID; self.startedAt = startedAt
        self.id = "\(accountName)|\(terminal)|\(processID.map(String.init) ?? "unknown")"
    }
}

public enum EventSeverity: String, Codable, CaseIterable, Sendable {
    case info, notice, warning, error
}

public struct SecurityEvent: Identifiable, Codable, Equatable, Sendable {
    public let id: UUID
    public let observedAt: Date
    public let kind: EventKind
    public let severity: EventSeverity
    public let monitor: String
    public let summary: String
    public let details: String
    public let deviceName: String?
    public let processAttribution: String?
    public let startupCategory: String?
    public let executablePath: String?
    public let signature: SignatureInfo?
    public let sourceAddress: String?
    public let accountName: String?
    public let authenticationMethod: String?
    public let attemptCount: Int?
    public let networkTransport: String?
    public let localAddress: String?
    public let localPort: UInt16?
    public let networkExposure: String?
    public let isTest: Bool

    public init(
        id: UUID = UUID(), observedAt: Date = Date(), kind: EventKind,
        severity: EventSeverity, monitor: String, summary: String, details: String,
        deviceName: String? = nil, processAttribution: String? = nil,
        startupCategory: String? = nil, executablePath: String? = nil,
        signature: SignatureInfo? = nil, sourceAddress: String? = nil,
        accountName: String? = nil, authenticationMethod: String? = nil,
        attemptCount: Int? = nil, networkTransport: String? = nil,
        localAddress: String? = nil, localPort: UInt16? = nil,
        networkExposure: String? = nil, isTest: Bool = false
    ) {
        self.id = id; self.observedAt = observedAt; self.kind = kind
        self.severity = severity; self.monitor = monitor; self.summary = summary
        self.details = details; self.deviceName = deviceName
        self.processAttribution = processAttribution; self.startupCategory = startupCategory
        self.executablePath = executablePath; self.signature = signature; self.isTest = isTest
        self.sourceAddress = sourceAddress; self.accountName = accountName
        self.authenticationMethod = authenticationMethod; self.attemptCount = attemptCount
        self.networkTransport = networkTransport; self.localAddress = localAddress
        self.localPort = localPort; self.networkExposure = networkExposure
    }
}

public struct SignatureInfo: Codable, Equatable, Sendable {
    public let status: String
    public let identifier: String?
    public let teamIdentifier: String?
    public init(status: String, identifier: String? = nil, teamIdentifier: String? = nil) {
        self.status = status; self.identifier = identifier; self.teamIdentifier = teamIdentifier
    }
}

public struct MonitorStatus: Identifiable, Equatable, Sendable {
    public let id: String
    public var name: String
    public var coverage: String
    public var state: State
    public var detail: String
    public enum State: String, Sendable { case active, periodic, manual, unavailable, interrupted }
    public init(id: String, name: String, coverage: String, state: State, detail: String) {
        self.id = id; self.name = name; self.coverage = coverage; self.state = state; self.detail = detail
    }
}

public enum MacWatchError: LocalizedError {
    case invalidEndpoint, insecureEndpoint, storage(String), keychain(OSStatus), encoding
    public var errorDescription: String? {
        switch self {
        case .invalidEndpoint: return "Enter a valid SigNoz OTLP base endpoint."
        case .insecureEndpoint: return "The ingestion endpoint must use HTTPS."
        case .storage(let message): return "Local storage error: \(message)"
        case .keychain(let status): return "Keychain error (\(status))."
        case .encoding: return "Could not encode telemetry."
        }
    }
}

public struct MonitorHealthTracker: Sendable {
    private var lastSuccess: [String: Date] = [:]
    private var lastObservation: [String: Date] = [:]
    private var failed: Set<String> = []
    public init() {}
    public mutating func record(id: String, success: Bool, at date: Date = Date()) {
        if let last = lastObservation[id], date < last { return }
        lastObservation[id] = date
        if success { lastSuccess[id] = date; failed.remove(id) }
        else { failed.insert(id) }
    }
    public func isHealthy(id: String, now: Date = Date(), maximumAge: TimeInterval = 90) -> Bool {
        guard !failed.contains(id), let last = lastSuccess[id] else { return false }
        return now.timeIntervalSince(last) <= maximumAge
    }
}
