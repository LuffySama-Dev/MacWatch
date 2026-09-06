import Foundation
import MacWatchCore

enum Failure: Error, CustomStringConvertible {
    case assertion(String)
    var description: String { switch self { case .assertion(let value): return value } }
}
func expect(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    if !condition() { throw Failure.assertion(message) }
}

do {
    let root = FileManager.default.temporaryDirectory.appending(path: "MacWatchSelfTest-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }

    let launchDirectory = root.appending(path: "LaunchAgents")
    try FileManager.default.createDirectory(at: launchDirectory, withIntermediateDirectories: true)
    let scanner = StartupScanner(directory: launchDirectory)
    let baseline = try scanner.scan()
    try expect(StartupScanner.changes(from: baseline, to: baseline).isEmpty, "baseline emitted a change")
    let plistURL = launchDirectory.appending(path: "benign-test.plist")
    var plist = try PropertyListSerialization.data(fromPropertyList: ["Label": "test", "Program": "/usr/bin/true"], format: .xml, options: 0)
    try plist.write(to: plistURL)
    let added = try scanner.scan()
    try expect(StartupScanner.changes(from: baseline, to: added).count == 1, "addition not detected")
    plist = try PropertyListSerialization.data(fromPropertyList: ["Label": "test", "Program": "/usr/bin/false"], format: .xml, options: 0)
    try plist.write(to: plistURL)
    let modified = try scanner.scan()
    try expect(StartupScanner.changes(from: added, to: modified).count == 1, "modification not detected")
    try FileManager.default.removeItem(at: plistURL)
    let removed = try scanner.scan()
    try expect(StartupScanner.changes(from: modified, to: removed).count == 1, "removal not detected")

    var notifications = NotificationDeduplicator(interval: 60)
    let now = Date(timeIntervalSince1970: 1_000)
    try expect(notifications.shouldNotify(key: "camera", now: now), "first notification denied")
    try expect(!notifications.shouldNotify(key: "camera", now: now.addingTimeInterval(30)), "duplicate notification allowed")
    try expect(notifications.shouldNotify(key: "camera", now: now.addingTimeInterval(60)), "notification did not reset")

    let store = EventStore(fileURL: root.appending(path: "events.json"), retentionDays: 7, maximumEvents: 100)
    let events = (0..<120).map { SecurityEvent(observedAt: now.addingTimeInterval(TimeInterval(-$0)), kind: .test, severity: .info, monitor: "Test", summary: "\($0)", details: "", isTest: true) }
    try expect(store.retained(events, now: now).count == 100, "retention bound failed")

    let sensitive = SecurityEvent(kind: .startupAdded, severity: .warning, monitor: "Startup", summary: "private summary", details: "secret details",
                                  deviceName: "Personal camera", processAttribution: "Private App", startupCategory: "user_launch_agent",
                                  executablePath: "/Users/person/private/tool", signature: .init(status: "present", identifier: "private.bundle"))
    let payload = try TelemetryEncoder.logPayload(event: sensitive, installationID: "random", appVersion: "1")
    let text = String(decoding: payload, as: UTF8.self)
    for forbidden in ["private summary", "secret details", "Personal camera", "Private App", "/Users/", "private.bundle"] {
        try expect(!text.localizedCaseInsensitiveContains(forbidden), "payload leaked: \(forbidden)")
    }
    try expect(text.contains("timeUnixNano") && text.contains("user_launch_agent"), "required OTLP fields missing")
    let batchData = try TelemetryEncoder.batchPayload(signal: .logs, payloads: [payload, payload])
    let batchRoot = try JSONSerialization.jsonObject(with: batchData) as! [String: Any]
    try expect((batchRoot["resourceLogs"] as? [Any])?.count == 2, "telemetry batching failed")

    var queue = TelemetryQueue(capacity: 10)
    for _ in 0..<10 { queue.enqueue(.init(signal: .logs, observedAt: now, payload: Data())) }
    try expect(queue.enqueue(.init(signal: .metrics, observedAt: now, payload: Data(), isHeartbeat: true)), "queue overflow not reported")
    try expect(queue.discardStaleHeartbeats(now: now.addingTimeInterval(121)) == 1, "stale heartbeat not dropped")
    try expect(ExportResponseParser.disposition(status: 401, data: Data(), retryAfter: nil) == .permanent("HTTP 401"), "auth failure should be permanent")
    try expect(ExportResponseParser.disposition(status: 429, data: Data(), retryAfter: "12") == .retry(after: 12), "rate-limit retry not honored")
    let partial = Data(#"{"partialSuccess":{"rejectedLogRecords":"2","errorMessage":"bad"}}"#.utf8)
    try expect(ExportResponseParser.disposition(status: 200, data: partial, retryAfter: nil) == .partial(rejected: 2, message: "bad"), "partial success not handled")
    try expect(Backoff.delay(attempt: 2, randomUnit: 0.5) == 4, "backoff calculation failed")
    do { _ = try EndpointValidator.baseURL(from: "http://example.com"); throw Failure.assertion("HTTP endpoint accepted") } catch MacWatchError.insecureEndpoint {}
    do { _ = try EndpointValidator.baseURL(from: "https://example.com"); throw Failure.assertion("non-SigNoz destination accepted") } catch MacWatchError.invalidEndpoint {}
    let validEndpoint = try EndpointValidator.baseURL(from: "https://ingest.us.signoz.cloud:443")
    try expect(validEndpoint.host == "ingest.us.signoz.cloud", "SigNoz Cloud endpoint rejected")

    let deviceStates = DeviceActivityMonitor.snapshot()
    let cameraCount = deviceStates.filter { $0.medium == .camera }.count
    let microphoneCount = deviceStates.filter { $0.medium == .microphone }.count
    let ssh = SSHConfigurationScanner().scan()
    let sshLogRecords = try? SSHAuthenticationLogScanner().records(since: Date().addingTimeInterval(-60))
    let activeSSHSessions = try SSHActiveSessionScanner().sessions()
    let listeningEndpoints = try ListeningEndpointScanner().scan()

    print("PASS: baseline/change detection")
    print("PASS: notification deduplication")
    print("PASS: retention bound")
    print("PASS: OTLP encoding and redaction")
    print("PASS: retry, partial success, and heartbeat freshness")
    print("PASS: HTTPS endpoint enforcement")
    print("INFO: public device inventory found \(cameraCount) camera(s), \(microphoneCount) input audio device(s)")
    print("INFO: Remote Login is \(ssh.remoteLogin.rawValue); SSH access policy readable: \(ssh.access.available)")
    if let sshLogRecords {
        print("INFO: embedded Endpoint Security extension store is readable; recognized \(sshLogRecords.count) event(s) from the last minute")
    } else {
        print("INFO: embedded Endpoint Security extension is not activated or unavailable")
    }
    print("INFO: SSH active-session inventory is readable; found \(activeSSHSessions.count) terminal session(s)")
    print("INFO: listening-endpoint inventory found \(listeningEndpoints.filter { $0.transport == .tcp }.count) TCP listener(s) and \(listeningEndpoints.filter { $0.transport == .udp }.count) bound UDP endpoint(s)")
} catch {
    fputs("FAIL: \(error)\n", stderr)
    exit(1)
}
