import XCTest
@testable import MacWatchCore

final class PolicyAndRetentionTests: XCTestCase {
    func testNotificationDeduplicationWindow() {
        var policy = NotificationDeduplicator(interval: 60)
        let now = Date(timeIntervalSince1970: 1_000)
        XCTAssertTrue(policy.shouldNotify(key: "camera", now: now))
        XCTAssertFalse(policy.shouldNotify(key: "camera", now: now.addingTimeInterval(59)))
        XCTAssertTrue(policy.shouldNotify(key: "camera", now: now.addingTimeInterval(60)))
    }
    func testRetentionByAgeAndBound() {
        let file = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let store = EventStore(fileURL: file, retentionDays: 7, maximumEvents: 100)
        let now = Date(timeIntervalSince1970: 2_000_000)
        var events = (0..<120).map { i in
            SecurityEvent(observedAt: now.addingTimeInterval(TimeInterval(-i)), kind: .test, severity: .info, monitor: "Test", summary: "\(i)", details: "", isTest: true)
        }
        events.append(SecurityEvent(observedAt: now.addingTimeInterval(-8 * 86_400), kind: .test, severity: .info, monitor: "Test", summary: "old", details: "", isTest: true))
        let kept = store.retained(events, now: now)
        XCTAssertEqual(kept.count, 100)
        XCTAssertFalse(kept.contains { $0.summary == "old" })
    }
}

extension PolicyAndRetentionTests {
    func testLoadAndExportRemoveExpiredHistoryFromDisk() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appending(path: "events.json")
        let expired = SecurityEvent(observedAt: Date().addingTimeInterval(-40 * 86_400), kind: .test,
                                    severity: .info, monitor: "Test", summary: "expired", details: "")
        let fresh = SecurityEvent(kind: .test, severity: .info, monitor: "Test", summary: "fresh", details: "")
        try JSONEncoder.macWatch.encode([expired, fresh]).write(to: file)
        let store = EventStore(fileURL: file, retentionDays: 1)
        XCTAssertEqual(store.load().map(\.id), [fresh.id])
        XCTAssertEqual(try JSONDecoder.macWatch.decode([SecurityEvent].self, from: Data(contentsOf: file)).map(\.id), [fresh.id])
        // Export must also enforce expiry, even without a preceding load.
        try JSONEncoder.macWatch.encode([expired, fresh]).write(to: file)
        let exported = root.appending(path: "export.json")
        try store.export(to: exported)
        XCTAssertEqual(try JSONDecoder.macWatch.decode([SecurityEvent].self, from: Data(contentsOf: exported)).map(\.id), [fresh.id])
        XCTAssertTrue(try store.prune(now: Date().addingTimeInterval(2 * 86_400)).isEmpty)
        XCTAssertTrue(store.load().isEmpty)
    }

    func testHealthRequiresRecentSuccessAndRecoversAfterFailure() {
        var health = MonitorHealthTracker()
        let now = Date(timeIntervalSince1970: 1_000)
        XCTAssertFalse(health.isHealthy(id: "startup", now: now))
        health.record(id: "startup", success: true, at: now)
        XCTAssertTrue(health.isHealthy(id: "startup", now: now))
        XCTAssertFalse(health.isHealthy(id: "startup", now: now.addingTimeInterval(91)))
        health.record(id: "startup", success: false, at: now)
        XCTAssertFalse(health.isHealthy(id: "startup", now: now))
        health.record(id: "startup", success: true, at: now.addingTimeInterval(1))
        XCTAssertTrue(health.isHealthy(id: "startup", now: now.addingTimeInterval(2)))
        XCTAssertFalse(health.isHealthy(id: "ssh-auth", now: now))
    }
}
