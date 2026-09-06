import XCTest
@testable import MacWatchCore

final class TelemetryTests: XCTestCase {
    func testPayloadEncodingAndRedaction() throws {
        let event = SecurityEvent(kind: .startupAdded, severity: .warning, monitor: "Startup", summary: "private summary",
                                  details: "secret details", deviceName: "Personal Camera", processAttribution: "Private App",
                                  startupCategory: "user_launch_agent", executablePath: "/Users/person/private/tool",
                                  signature: .init(status: "present", identifier: "private.bundle"), sourceAddress: "203.0.113.7",
                                  accountName: "private-account", authenticationMethod: "private-method", attemptCount: 7,
                                  networkTransport: "tcp-private", localAddress: "127.0.0.99", localPort: 65000,
                                  networkExposure: "private-exposure")
        let data = try TelemetryEncoder.logPayload(event: event, installationID: "random-install", appVersion: "1.0")
        let text = String(decoding: data, as: UTF8.self)
        XCTAssertTrue(text.contains("resourceLogs")); XCTAssertTrue(text.contains("timeUnixNano"))
        for forbidden in ["person", "private summary", "secret details", "Private App", "private.bundle", "/Users/", "203.0.113.7", "private-account", "private-method", "tcp-private", "127.0.0.99", "65000", "private-exposure"] {
            XCTAssertFalse(text.localizedCaseInsensitiveContains(forbidden), "Leaked \(forbidden)")
        }
        XCTAssertTrue(text.contains("user_launch_agent"))
        let batch = try TelemetryEncoder.batchPayload(signal: .logs, payloads: [data, data])
        let root = try XCTUnwrap(JSONSerialization.jsonObject(with: batch) as? [String: Any])
        XCTAssertEqual((root["resourceLogs"] as? [Any])?.count, 2)
    }
    func testListeningEndpointPayloadIncludesUsefulNetworkFieldsOnlyForPortEvents() throws {
        let event = SecurityEvent(
            kind: .listeningEndpointOpened, severity: .warning, monitor: "Listening Ports",
            summary: "private summary", details: "private details",
            processAttribution: "Test Listener", executablePath: "/Users/person/private/server",
            sourceAddress: "203.0.113.7", accountName: "private-account",
            networkTransport: "tcp", localAddress: "0.0.0.0", localPort: 8080,
            networkExposure: "allInterfaces"
        )
        let data = try TelemetryEncoder.logPayload(event: event, installationID: "random-install", appVersion: "1.0")
        let text = String(decoding: data, as: UTF8.self)
        XCTAssertTrue(text.contains(#""key":"network.transport","value":{"stringValue":"tcp"}"#))
        XCTAssertTrue(text.contains(#""key":"server.address","value":{"stringValue":"0.0.0.0"}"#))
        XCTAssertTrue(text.contains(#""key":"server.port","value":{"intValue":"8080"}"#))
        XCTAssertTrue(text.contains(#""key":"network.exposure","value":{"stringValue":"allInterfaces"}"#))
        XCTAssertTrue(text.contains(#""key":"process.name","value":{"stringValue":"Test Listener"}"#))
        XCTAssertTrue(text.contains("TCP listening endpoint opened: 0.0.0.0:8080"))
        for forbidden in ["private summary", "private details", "/Users/", "203.0.113.7", "private-account"] {
            XCTAssertFalse(text.localizedCaseInsensitiveContains(forbidden), "Leaked \(forbidden)")
        }
    }
    func testQueueBoundAndStaleHeartbeat() throws {
        var queue = TelemetryQueue(capacity: 10)
        let old = Date(timeIntervalSince1970: 1_000)
        for _ in 0..<11 { queue.enqueue(.init(signal: .logs, observedAt: old, payload: Data())) }
        XCTAssertEqual(queue.items.count, 10); XCTAssertEqual(queue.droppedCount, 1)
        queue.enqueue(.init(signal: .metrics, observedAt: old, payload: Data(), isHeartbeat: true))
        XCTAssertEqual(queue.discardStaleHeartbeats(now: old.addingTimeInterval(121)), 1)
    }
    func testBackoffAndRetryClassification() {
        XCTAssertEqual(Backoff.delay(attempt: 2, randomUnit: 0.5), 4, accuracy: 0.001)
        XCTAssertEqual(ExportResponseParser.disposition(status: 401, data: Data(), retryAfter: nil), .permanent("HTTP 401"))
        XCTAssertEqual(ExportResponseParser.disposition(status: 429, data: Data(), retryAfter: "12"), .retry(after: 12))
        let partial = Data(#"{"partialSuccess":{"rejectedLogRecords":"2","errorMessage":"bad"}}"#.utf8)
        XCTAssertEqual(ExportResponseParser.disposition(status: 200, data: partial, retryAfter: nil), .partial(rejected: 2, message: "bad"))
    }
    func testEndpointValidationRequiresHTTPS() throws {
        XCTAssertThrowsError(try EndpointValidator.baseURL(from: "http://example.com:4318"))
        XCTAssertThrowsError(try EndpointValidator.baseURL(from: "https://example.com"))
        XCTAssertEqual(try EndpointValidator.baseURL(from: "https://ingest.us.signoz.cloud:443").scheme, "https")
    }
}

private actor HeldExport {
    private var continuation: CheckedContinuation<(Data, URLResponse), Error>?
    private var request: URLRequest?
    private(set) var count = 0
    func send(_ request: URLRequest, started: XCTestExpectation) async throws -> (Data, URLResponse) {
        count += 1
        self.request = request
        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            started.fulfill()
        }
    }
    func finish() {
        guard let request, let continuation else { return }
        self.continuation = nil
        continuation.resume(returning: (Data("{}".utf8), HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!))
    }
}

extension TelemetryTests {
    func testDisableIgnoresInvalidEndpointAndFailedEnableStaysDisabled() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let exporter = TelemetryExporter(queueFile: root.appending(path: "queue.json"))
        try await exporter.configure(endpointText: "https://ingest.us.signoz.cloud", key: nil, enabled: true)
        try await exporter.configure(endpointText: "", key: nil, enabled: false)
        let disabled = await exporter.isEnabled()
        XCTAssertFalse(disabled)
        try await exporter.configure(endpointText: "https://ingest.us.signoz.cloud", key: nil, enabled: true)
        do {
            try await exporter.configure(endpointText: "invalid", key: nil, enabled: true)
            XCTFail("Invalid endpoint accepted")
        } catch {}
        let enabledAfterError = await exporter.isEnabled()
        XCTAssertFalse(enabledAfterError)
    }

    func testOverlappingFlushDoesNotDuplicateBatch() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let held = HeldExport()
        let started = expectation(description: "First request started")
        let exporter = TelemetryExporter(queueFile: root.appending(path: "queue.json"),
            transport: { try await held.send($0, started: started) }, credentialLoader: { "test-only" })
        try await exporter.configure(endpointText: "https://ingest.us.signoz.cloud", key: nil, enabled: true)
        await exporter.enqueue(.init(signal: .logs, observedAt: Date(), payload: Data("{\"resourceLogs\":[]}".utf8)))
        let first = Task { await exporter.flush() }
        await fulfillment(of: [started], timeout: 3)
        await exporter.flush()
        let requests = await held.count
        XCTAssertEqual(requests, 1)
        await held.finish()
        await first.value
        let status = await exporter.currentStatus()
        XCTAssertEqual(status.queued, 0)
        XCTAssertNotNil(status.lastSuccess)
    }

    func testDisableDuringRequestPreventsNextSignalAndPreservesQueue() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let held = HeldExport()
        let started = expectation(description: "Request started")
        let exporter = TelemetryExporter(queueFile: root.appending(path: "queue.json"),
            transport: { try await held.send($0, started: started) }, credentialLoader: { "test-only" })
        try await exporter.configure(endpointText: "https://ingest.us.signoz.cloud", key: nil, enabled: true)
        await exporter.enqueue(.init(signal: .logs, observedAt: Date(), payload: Data("{\"resourceLogs\":[]}".utf8)))
        await exporter.enqueue(.init(signal: .metrics, observedAt: Date(), payload: Data("{\"resourceMetrics\":[]}".utf8)))
        let first = Task { await exporter.flush() }
        await fulfillment(of: [started], timeout: 3)
        await exporter.disable()
        await held.finish()
        await first.value
        await exporter.flush()
        let requests = await held.count
        let status = await exporter.currentStatus()
        XCTAssertEqual(requests, 1)
        XCTAssertEqual(status.queued, 2)
        XCTAssertNil(status.lastSuccess)
    }
}
