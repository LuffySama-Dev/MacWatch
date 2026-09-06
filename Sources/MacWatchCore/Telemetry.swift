import Foundation
import Security

public enum TelemetrySignal: String, Codable, Sendable { case logs, metrics }

public struct QueuedTelemetry: Identifiable, Codable, Equatable, Sendable {
    public let id: UUID
    public let signal: TelemetrySignal
    public let observedAt: Date
    public let payload: Data
    public var attempt: Int
    public var nextAttemptAt: Date
    public let isHeartbeat: Bool
    public init(id: UUID = UUID(), signal: TelemetrySignal, observedAt: Date, payload: Data,
                attempt: Int = 0, nextAttemptAt: Date = Date(), isHeartbeat: Bool = false) {
        self.id = id; self.signal = signal; self.observedAt = observedAt; self.payload = payload
        self.attempt = attempt; self.nextAttemptAt = nextAttemptAt; self.isHeartbeat = isHeartbeat
    }
}

public struct TelemetryQueue: Codable, Sendable {
    public private(set) var items: [QueuedTelemetry] = []
    public private(set) var droppedCount = 0
    public var capacity: Int
    public init(capacity: Int = 500) { self.capacity = max(10, min(capacity, 5_000)) }

    @discardableResult
    public mutating func enqueue(_ item: QueuedTelemetry) -> Bool {
        var overflowed = false
        if items.count >= capacity { items.removeFirst(); droppedCount += 1; overflowed = true }
        items.append(item)
        return overflowed
    }
    public mutating func remove(ids: Set<UUID>) { items.removeAll { ids.contains($0.id) } }
    public mutating func replace(_ item: QueuedTelemetry) {
        guard let index = items.firstIndex(where: { $0.id == item.id }) else { return }; items[index] = item
    }
    public mutating func discardStaleHeartbeats(now: Date, maximumAge: TimeInterval = 120) -> Int {
        let before = items.count
        items.removeAll { $0.isHeartbeat && now.timeIntervalSince($0.observedAt) > maximumAge }
        let removed = before - items.count; droppedCount += removed; return removed
    }
}

public enum TelemetryEncoder {
    public static let serviceName = "macwatch"

    public static func sanitizedAttributes(for event: SecurityEvent, installationID: String, appVersion: String) -> [String: Any] {
        var values: [String: Any] = [
            "event.id": event.id.uuidString,
            "event.kind": event.kind.rawValue,
            "event.is_test": event.isTest,
            "monitor.name": event.monitor,
            "capability.status": "observed",
            "installation.id": installationID,
            "service.version": appVersion
        ]
        if let category = event.startupCategory { values["startup.category"] = category }
        if event.kind == .listeningEndpointOpened || event.kind == .listeningEndpointClosed {
            if let transport = event.networkTransport, ["tcp", "udp"].contains(transport) {
                values["network.transport"] = transport
            }
            if let address = event.localAddress, isSafeListenerAddress(address) {
                values["server.address"] = address
            }
            if let port = event.localPort {
                values["server.port"] = Int(port)
            }
            if let exposure = event.networkExposure,
               ["loopbackOnly", "networkInterface", "allInterfaces"].contains(exposure) {
                values["network.exposure"] = exposure
            }
            if let processName = event.processAttribution, isSafeLabel(processName) {
                values["process.name"] = processName
            }
        }
        // Deliberately excludes summary/details, device names, filenames, paths,
        // process names, usernames, remote source addresses and signature identifiers.
        return values
    }

    public static func logPayload(event: SecurityEvent, installationID: String, appVersion: String) throws -> Data {
        let attributes = sanitizedAttributes(for: event, installationID: installationID, appVersion: appVersion)
        let record: [String: Any] = [
            "timeUnixNano": unixNanos(event.observedAt),
            "observedTimeUnixNano": unixNanos(Date()),
            "severityText": event.severity.rawValue.uppercased(),
            "body": ["stringValue": cloudBody(for: event)],
            "attributes": otlpAttributes(attributes)
        ]
        return try json(["resourceLogs": [[
            "resource": ["attributes": otlpAttributes(["service.name": serviceName, "installation.id": installationID, "service.version": appVersion])],
            "scopeLogs": [["scope": ["name": "MacWatch"], "logRecords": [record]]]
        ]]])
    }

    public static func metricPayload(name: String, value: Double, observedAt: Date, installationID: String,
                                     appVersion: String, attributes: [String: Any] = [:]) throws -> Data {
        let point: [String: Any] = ["timeUnixNano": unixNanos(observedAt), "asDouble": value, "attributes": otlpAttributes(attributes)]
        return try json(["resourceMetrics": [[
            "resource": ["attributes": otlpAttributes(["service.name": serviceName, "installation.id": installationID, "service.version": appVersion])],
            "scopeMetrics": [["scope": ["name": "MacWatch"], "metrics": [["name": name, "gauge": ["dataPoints": [point]]]]]]
        ]]])
    }

    public static func representativePreview() -> String {
        """
        {
          "service.name": "macwatch",
          "installation.id": "<random UUID>",
          "service.version": "<app version>",
          "event.id": "<random UUID>",
          "event.kind": "cameraActivated",
          "event.is_test": false,
          "monitor.name": "Camera",
          "capability.status": "observed"
        }
        Listening-port events additionally send: network.transport, server.address,
        server.port, network.exposure, and process.name.
        Excluded: usernames, remote source addresses, hostnames, process names,
        filenames, full paths, arguments, document or browsing content, media,
        and Keychain secrets.
        """
    }

    public static func batchPayload(signal: TelemetrySignal, payloads: [Data]) throws -> Data {
        let key = signal == .logs ? "resourceLogs" : "resourceMetrics"
        var combined: [Any] = []
        for payload in payloads {
            guard let root = try JSONSerialization.jsonObject(with: payload) as? [String: Any], let entries = root[key] as? [Any] else {
                throw MacWatchError.encoding
            }
            combined.append(contentsOf: entries)
        }
        return try json([key: combined])
    }

    private static func cloudBody(for event: SecurityEvent) -> String {
        if event.isTest { return "MacWatch test event" }
        if event.kind == .listeningEndpointOpened || event.kind == .listeningEndpointClosed,
           let address = event.localAddress, isSafeListenerAddress(address),
           let port = event.localPort {
            let transport = ["tcp", "udp"].contains(event.networkTransport ?? "")
                ? event.networkTransport!.uppercased() : "NETWORK"
            let endpoint = address.contains(":") ? "[\(address)]:\(port)" : "\(address):\(port)"
            let action = event.kind == .listeningEndpointOpened ? "opened" : "closed"
            let owner = event.processAttribution.flatMap { isSafeLabel($0) ? $0 : nil }
            return "MacWatch observed \(transport) listening endpoint \(action): \(endpoint)" +
                (owner.map { " (process: \($0))" } ?? "")
        }
        return "MacWatch observed \(event.kind.rawValue)"
    }
    private static func isSafeListenerAddress(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 255 else { return false }
        return value.unicodeScalars.allSatisfy {
            CharacterSet.alphanumerics.contains($0) || ".:*_-%".unicodeScalars.contains($0)
        }
    }
    private static func isSafeLabel(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 255 &&
            value.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) }
    }
    private static func unixNanos(_ date: Date) -> String { String(UInt64(max(0, date.timeIntervalSince1970) * 1_000_000_000)) }
    private static func otlpAttributes(_ values: [String: Any]) -> [[String: Any]] {
        values.keys.sorted().map { key in
            let value = values[key]!
            if let bool = value as? Bool { return ["key": key, "value": ["boolValue": bool]] }
            if let integer = value as? Int { return ["key": key, "value": ["intValue": String(integer)]] }
            if let double = value as? Double { return ["key": key, "value": ["doubleValue": double]] }
            return ["key": key, "value": ["stringValue": String(describing: value)]]
        }
    }
    private static func json(_ object: [String: Any]) throws -> Data {
        guard JSONSerialization.isValidJSONObject(object) else { throw MacWatchError.encoding }
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }
}

public final class KeychainStore: @unchecked Sendable {
    private let service = "com.macwatch.telemetry"
    public init() {}
    public func saveIngestionKey(_ key: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "signoz-ingestion-key"
        ]
        let valueData = Data(key.utf8)
        let updateStatus = SecItemUpdate(query as CFDictionary, [
            kSecValueData as String: valueData
        ] as CFDictionary)
        if updateStatus == errSecSuccess { return }
        guard updateStatus == errSecItemNotFound else { throw MacWatchError.keychain(updateStatus) }

        var newItem = query
        newItem.merge([
            kSecValueData as String: Data(key.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]) { _, replacement in replacement }
        let status = SecItemAdd(newItem as CFDictionary, nil)
        guard status == errSecSuccess else { throw MacWatchError.keychain(status) }
    }
    public func loadIngestionKey() throws -> String? {
        var item: CFTypeRef?
        let status = SecItemCopyMatching([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "signoz-ingestion-key",
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ] as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else { throw MacWatchError.keychain(status) }
        return String(data: data, encoding: .utf8)
    }
    public func deleteIngestionKey() throws {
        let status = SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "signoz-ingestion-key"
        ] as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw MacWatchError.keychain(status) }
    }
}

public struct EndpointValidator {
    public static func baseURL(from text: String) throws -> URL {
        guard let components = URLComponents(string: text.trimmingCharacters(in: .whitespacesAndNewlines)),
              components.scheme?.lowercased() == "https", components.host != nil,
              components.user == nil, components.password == nil, components.query == nil, components.fragment == nil,
              components.path.isEmpty || components.path == "/",
              let url = components.url else {
            if text.lowercased().hasPrefix("http://") { throw MacWatchError.insecureEndpoint }
            throw MacWatchError.invalidEndpoint
        }
        let host = components.host!.lowercased()
        guard host.hasPrefix("ingest."), host.hasSuffix(".signoz.cloud"), host.split(separator: ".").count >= 4,
              components.port == nil || components.port == 443 else { throw MacWatchError.invalidEndpoint }
        return url
    }
    public static func signalURL(base: URL, signal: TelemetrySignal) -> URL {
        if base.path.hasSuffix("/v1/logs") || base.path.hasSuffix("/v1/metrics") { return base }
        return base.appending(path: "v1/\(signal.rawValue)")
    }
}

public enum ExportDisposition: Equatable, Sendable {
    case success, partial(rejected: Int, message: String?), retry(after: TimeInterval?), permanent(String)
}

public enum ExportResponseParser {
    public static func disposition(status: Int, data: Data, retryAfter: String?) -> ExportDisposition {
        if status == 200 {
            guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return .success }
            let partial = (root["partialSuccess"] ?? root["partial_success"]) as? [String: Any]
            let rejectedValue = partial?["rejectedLogRecords"] ?? partial?["rejectedDataPoints"] ?? partial?["rejected_log_records"] ?? partial?["rejected_data_points"]
            let rejected = (rejectedValue as? Int) ?? Int(rejectedValue as? String ?? "") ?? 0
            let message = (partial?["errorMessage"] ?? partial?["error_message"]) as? String
            return (rejected > 0 || message != nil) ? .partial(rejected: rejected, message: message) : .success
        }
        if status == 429 || status == 502 || status == 503 || status == 504 {
            return .retry(after: retryAfter.flatMap(TimeInterval.init))
        }
        if (500...599).contains(status) { return .retry(after: nil) }
        return .permanent("HTTP \(status)")
    }
}

public enum Backoff {
    public static func delay(attempt: Int, randomUnit: Double) -> TimeInterval {
        let base = min(300.0, pow(2.0, Double(max(0, attempt))))
        return base * (0.75 + min(max(randomUnit, 0), 1) * 0.5)
    }
}
