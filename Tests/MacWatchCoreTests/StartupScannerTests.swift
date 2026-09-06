import XCTest
@testable import MacWatchCore

final class StartupScannerTests: XCTestCase {
    func testInitialScanCanBeUsedAsBaselineWithoutChanges() throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let data = try PropertyListSerialization.data(fromPropertyList: ["Label": "test", "Program": "/usr/bin/true"], format: .xml, options: 0)
        try data.write(to: directory.appending(path: "test.plist"))
        let baseline = try StartupScanner(directory: directory).scan()
        XCTAssertEqual(StartupScanner.changes(from: baseline, to: baseline), [])
    }

    func testDetectsAdditionModificationAndRemoval() throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let scanner = StartupScanner(directory: directory)
        let url = directory.appending(path: "temporary-test.plist")
        try plist(program: "/usr/bin/true").write(to: url)
        let first = try scanner.scan()
        XCTAssertEqual(StartupScanner.changes(from: [:], to: first).count, 1)
        try plist(program: "/usr/bin/false").write(to: url)
        let second = try scanner.scan()
        guard case .modified = StartupScanner.changes(from: first, to: second).first else { return XCTFail("Expected modification") }
        try FileManager.default.removeItem(at: url)
        guard case .removed = StartupScanner.changes(from: second, to: try scanner.scan()).first else { return XCTFail("Expected removal") }
    }
    private func plist(program: String) throws -> Data {
        try PropertyListSerialization.data(fromPropertyList: ["Label": "test", "ProgramArguments": [program]], format: .xml, options: 0)
    }

    func testRemoteLoginParsingUsesOverrideAndPlistDefault() {
        XCTAssertEqual(SSHConfigurationScanner.remoteLoginState(from: #"\"com.openssh.sshd\" => enabled"#, defaultDisabled: true), .enabled)
        XCTAssertEqual(SSHConfigurationScanner.remoteLoginState(from: #"\"com.openssh.sshd\" => disabled"#, defaultDisabled: false), .disabled)
        XCTAssertEqual(SSHConfigurationScanner.remoteLoginState(from: "disabled services = {}", defaultDisabled: true), .disabled)
        XCTAssertEqual(SSHConfigurationScanner.remoteLoginState(from: "disabled services = {}", defaultDisabled: nil), .unknown)
    }

    func testSSHConfigurationChangeClassification() {
        let restricted = SSHAccessPolicy(available: true, allowsAllLocalUsers: false, users: ["alice"], nestedGroups: [])
        let broad = SSHAccessPolicy(available: true, allowsAllLocalUsers: true, users: [], nestedGroups: ["localaccounts"])
        let absent = SSHFileFingerprint(state: .absent)
        let readable = SSHFileFingerprint(state: .readable, hash: 42)
        let old = SSHConfigurationSnapshot(remoteLogin: .disabled, access: restricted, systemConfiguration: readable, authorizedKeys: absent)
        let new = SSHConfigurationSnapshot(remoteLogin: .enabled, access: broad, systemConfiguration: .init(state: .readable, hash: 43), authorizedKeys: readable)
        let changes = SSHConfigurationScanner.changes(from: old, to: new)
        XCTAssertEqual(changes.count, 4)
        XCTAssertTrue(changes.contains { if case .remoteLogin(old: .disabled, new: .enabled) = $0 { true } else { false } })
        XCTAssertTrue(changes.contains { if case .accessPolicy = $0 { true } else { false } })
        XCTAssertTrue(changes.contains { if case .systemConfiguration = $0 { true } else { false } })
        XCTAssertTrue(changes.contains { if case .authorizedKeys = $0 { true } else { false } })
    }

    func testEndpointSecurityStoreScan() throws {
        let failed = SSHAuthenticationEvent(observedAt: Date(timeIntervalSince1970: 20), kind: .failed,
                                            accountName: "admin", sourceAddress: "192.0.2.10", method: "Endpoint Security")
        let succeeded = SSHAuthenticationEvent(observedAt: Date(timeIntervalSince1970: 10), kind: .succeeded,
                                               accountName: "saurabh", sourceAddress: "2001:db8::2", method: "Endpoint Security")

        let directory = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = directory.appending(path: "events.json")
        let status = directory.appending(path: "status.txt")
        try JSONEncoder.macWatch.encode([failed, succeeded]).write(to: store)
        try Data("running|\(ISO8601DateFormatter().string(from: Date()))".utf8).write(to: status)
        let scanner = SSHAuthenticationLogScanner(eventStoreURL: store, statusURL: status)
        let records = try scanner.records(since: Date(timeIntervalSince1970: 0))
        XCTAssertEqual(records.map(\.event.kind), [.succeeded, .failed])

        try Data("running|2001-01-01T00:00:00Z".utf8).write(to: status)
        XCTAssertThrowsError(try scanner.records(since: Date(timeIntervalSince1970: 0)))
    }

    func testSSHFailureBurstDetectionIsBounded() {
        var detector = SSHFailureBurstDetector(threshold: 5, window: 300)
        let start = Date(timeIntervalSince1970: 1_000)
        for offset in 0..<4 { XCTAssertNil(detector.recordFailure(source: "192.0.2.1", at: start.addingTimeInterval(Double(offset)))) }
        XCTAssertEqual(detector.recordFailure(source: "192.0.2.1", at: start.addingTimeInterval(4)), 5)
        XCTAssertNil(detector.recordFailure(source: "192.0.2.1", at: start.addingTimeInterval(5)))
        XCTAssertNil(detector.recordFailure(source: "198.51.100.2", at: start.addingTimeInterval(5)))
        XCTAssertNil(detector.recordFailure(source: "192.0.2.1", at: start.addingTimeInterval(305)))
        XCTAssertNil(detector.recordFailure(source: "192.0.2.1", at: start.addingTimeInterval(306)))
        XCTAssertNil(detector.recordFailure(source: "192.0.2.1", at: start.addingTimeInterval(307)))
        XCTAssertNil(detector.recordFailure(source: "192.0.2.1", at: start.addingTimeInterval(308)))
        XCTAssertEqual(detector.recordFailure(source: "192.0.2.1", at: start.addingTimeInterval(309)), 5)
    }

    func testSSHFailureBurstStateSurvivesEncoding() throws {
        var detector = SSHFailureBurstDetector(threshold: 3, window: 60)
        let start = Date(timeIntervalSince1970: 2_000)
        XCTAssertNil(detector.recordFailure(source: "203.0.113.9", at: start))
        XCTAssertNil(detector.recordFailure(source: "203.0.113.9", at: start.addingTimeInterval(1)))
        var restored = try JSONDecoder.macWatch.decode(SSHFailureBurstDetector.self, from: JSONEncoder.macWatch.encode(detector))
        XCTAssertEqual(restored.recordFailure(source: "203.0.113.9", at: start.addingTimeInterval(2)), 3)
    }

    func testActiveSSHSessionParsingIgnoresLocalConsole() throws {
        let now = try XCTUnwrap(ISO8601DateFormatter().date(from: "2026-09-06T12:30:00+05:30"))
        let output = """
        saurabh console Sep  3 22:08 old 405
        alice ttys002 Sep  6 12:20 00:02 987 (192.0.2.44)
        bob ttys003 Dec 31 23:59 00:01 988 (2001:db8::4)
        """
        let sessions = SSHActiveSessionScanner.parseWhoOutput(output, now: now)
        XCTAssertEqual(sessions.count, 2)
        XCTAssertEqual(Set(sessions.map(\.sourceAddress)), ["192.0.2.44", "2001:db8::4"])
        XCTAssertEqual(sessions.first(where: { $0.accountName == "alice" })?.processID, 987)
        XCTAssertEqual(Calendar(identifier: .gregorian).component(.year, from: try XCTUnwrap(sessions.first(where: { $0.accountName == "bob" })?.startedAt)), 2025)
    }

    func testListeningEndpointParsingAndExposure() throws {
        let tcp = """
        tcp4 0 0 127.0.0.1.59101 *.* LISTEN 0 0 131072 131072 Notion:86517 00100
        tcp6 0 0 *.22 *.* LISTEN 0 0 131072 131072 launchd:1 00180
        tcp4 0 0 192.0.2.10.8080 *.* ESTABLISHED 0 0 131072 131072 Test:99 00100
        """
        let parsedTCP = ListeningEndpointScanner.parseTCP(tcp)
        XCTAssertEqual(parsedTCP.count, 2)
        XCTAssertEqual(parsedTCP.first(where: { $0.localPort == 59101 })?.exposure, .loopbackOnly)
        XCTAssertEqual(parsedTCP.first(where: { $0.localPort == 22 })?.exposure, .allInterfaces)
        XCTAssertEqual(parsedTCP.first(where: { $0.localPort == 59101 })?.processName, "Notion")

        let udp = """
        udp46 0 0 *.5353 *.* 0 0 786896 9216 Codex (Service):88203 00100
        udp6 0 0 2001:db8::2.59412 2001:db8::3.443 0 0 786896 9216 Browser Helper:886 00102
        """
        let parsedUDP = ListeningEndpointScanner.parseUDP(udp)
        XCTAssertEqual(parsedUDP.count, 1)
        XCTAssertEqual(parsedUDP[0].processName, "Codex (Service)")
        XCTAssertEqual(parsedUDP[0].family, .dual)
    }

    func testListeningEndpointChangesIgnoreProcessRestartButDetectOwnerReplacement() {
        let old = ListeningEndpoint(transport: .tcp, family: .ipv4, localAddress: "*", localPort: 8080,
                                    exposure: .allInterfaces, processName: "Server", processID: 10, executablePath: "/tmp/server")
        let restarted = ListeningEndpoint(transport: .tcp, family: .ipv4, localAddress: "*", localPort: 8080,
                                          exposure: .allInterfaces, processName: "Server", processID: 11, executablePath: "/tmp/server")
        XCTAssertTrue(ListeningEndpointScanner.changes(from: [old], to: [restarted]).isEmpty)
        let replaced = ListeningEndpoint(transport: .tcp, family: .ipv4, localAddress: "*", localPort: 8080,
                                         exposure: .allInterfaces, processName: "Other", processID: 12)
        XCTAssertEqual(ListeningEndpointScanner.changes(from: [old], to: [replaced]).count, 2)
        let pathReplacement = ListeningEndpoint(transport: .tcp, family: .ipv4, localAddress: "*", localPort: 8080,
                                                exposure: .allInterfaces, processName: "Server", processID: 12,
                                                executablePath: "/tmp/different-server")
        XCTAssertEqual(ListeningEndpointScanner.changes(from: [old], to: [pathReplacement]).count, 2)
    }
}

extension StartupScannerTests {
    func testUnreadablePlistPreservesBaselineAndDoesNotHideOtherChanges() throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let blocked = directory.appending(path: "blocked.plist")
        let changed = directory.appending(path: "changed.plist")
        let deleted = directory.appending(path: "deleted.plist")
        let data = try plist(program: "/usr/bin/true")
        for file in [blocked, changed, deleted] { try data.write(to: file) }
        let scanner = StartupScanner(directory: directory)
        let baseline = try scanner.scan()
        try FileManager.default.setAttributes([.posixPermissions: 0], ofItemAtPath: blocked.path)
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: blocked.path) }
        guard !FileManager.default.isReadableFile(atPath: blocked.path) else { throw XCTSkip("Requires an unprivileged test user") }
        try plist(program: "/usr/bin/false").write(to: changed)
        try FileManager.default.removeItem(at: deleted)
        try data.write(to: directory.appending(path: "added.plist"))
        var errors = 0
        let current = try scanner.scan(previous: baseline) { _ in errors += 1 }
        XCTAssertEqual(errors, 1)
        XCTAssertEqual(current["blocked.plist"], baseline["blocked.plist"])
        let changes = StartupScanner.changes(from: baseline, to: current)
        XCTAssertEqual(changes.count, 3)
        XCTAssertTrue(changes.contains { if case .modified(_, let entry) = $0 { entry.relativeName == "changed.plist" } else { false } })
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: blocked.path)
        XCTAssertTrue(StartupScanner.changes(from: current, to: try scanner.scan()).isEmpty)
    }

    func testFailureBurstExpiresInactiveSourcesAndCapsState() throws {
        var detector = SSHFailureBurstDetector()
        let now = Date(timeIntervalSince1970: 1_000)
        for i in 0..<1_100 { _ = detector.recordFailure(source: "source-\(i)", at: now) }
        for _ in 0..<1_100 { _ = detector.recordFailure(source: "busy", at: now.addingTimeInterval(1)) }
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder.macWatch.encode(detector)) as? [String: Any])
        let sources = try XCTUnwrap(object["failuresBySource"] as? [String: [Any]])
        XCTAssertLessThanOrEqual(sources.count, SSHFailureBurstDetector.maximumSources)
        XCTAssertEqual(sources["busy"]?.count, SSHFailureBurstDetector.maximumFailuresPerSource)
        var restored = try JSONDecoder.macWatch.decode(SSHFailureBurstDetector.self, from: JSONEncoder.macWatch.encode(detector))
        restored.prune(now: now.addingTimeInterval(302))
        let expired = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder.macWatch.encode(restored)) as? [String: Any])
        XCTAssertTrue(try XCTUnwrap(expired["failuresBySource"] as? [String: Any]).isEmpty)
        XCTAssertTrue(try XCTUnwrap(expired["lastBurstBySource"] as? [String: Any]).isEmpty)
    }
}

extension StartupScannerTests {
    func testStartupMonitorReportsPartialFailureAndRecovery() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let directory = root.appending(path: "LaunchAgents")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let blocked = directory.appending(path: "blocked.plist")
        try plist(program: "/usr/bin/true").write(to: blocked)
        try FileManager.default.setAttributes([.posixPermissions: 0], ofItemAtPath: blocked.path)
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: blocked.path) }
        guard !FileManager.default.isReadableFile(atPath: blocked.path) else { throw XCTSkip("Requires an unprivileged test user") }
        let failed = expectation(description: "Partial scan is unhealthy")
        let recovered = expectation(description: "Successful scan restores health")
        let monitor = StartupDirectoryMonitor(directory: directory, baselineURL: root.appending(path: "baseline.json"),
            healthHandler: { success in if success { recovered.fulfill() } else { failed.fulfill() } },
            changeHandler: { _ in }, errorHandler: { _ in })
        monitor.start(interval: 3_600)
        defer { monitor.stop() }
        await fulfillment(of: [failed], timeout: 3)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: blocked.path)
        monitor.pollNow()
        await fulfillment(of: [recovered], timeout: 3)
    }
}
