import Foundation

public struct ExportStatus: Sendable {
    public var lastSuccess: Date?
    public var lastError: String?
    public var queued = 0
    public var dropped = 0
    public var rejected = 0
    public init() {}
}

private final class NoRedirectDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

public actor TelemetryExporter {
    private var queue: TelemetryQueue
    private let queueFile: URL
    private let session: URLSession
    private let keychain: KeychainStore
    private var flushing = false
    private var configurationGeneration = UUID()
    private var inFlight: Task<(Data, URLResponse), Error>?
    private let transport: (@Sendable (URLRequest) async throws -> (Data, URLResponse))?
    private let credentialLoader: (@Sendable () throws -> String?)?
    private var endpoint: URL?
    private var enabled = false
    private var status = ExportStatus()
    private let update: @Sendable (ExportStatus) -> Void

    public init(queueFile: URL, capacity: Int = 500, update: @escaping @Sendable (ExportStatus) -> Void = { _ in }) {
        self.init(queueFile: queueFile, capacity: capacity, transport: nil, credentialLoader: nil, update: update)
    }

    // Injectable dependencies allow tests without network access or real credentials.
    init(queueFile: URL, capacity: Int = 500,
         transport: (@Sendable (URLRequest) async throws -> (Data, URLResponse))?,
         credentialLoader: (@Sendable () throws -> String?)?,
         update: @escaping @Sendable (ExportStatus) -> Void = { _ in }) {
        self.transport = transport; self.credentialLoader = credentialLoader
        self.queueFile = queueFile; self.keychain = KeychainStore(); self.update = update
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 10; configuration.timeoutIntervalForResource = 20
        configuration.httpShouldSetCookies = false; configuration.urlCache = nil
        self.session = URLSession(configuration: configuration, delegate: NoRedirectDelegate(), delegateQueue: nil)
        if let data = try? Data(contentsOf: queueFile), let loaded = try? JSONDecoder.macWatch.decode(TelemetryQueue.self, from: data) {
            self.queue = loaded
        } else { self.queue = TelemetryQueue(capacity: capacity) }
    }

    public func isEnabled() -> Bool { enabled }

    public func configure(endpointText: String, key: String?, enabled: Bool) throws {
        disable()
        guard enabled else { return }
        let validated = try EndpointValidator.baseURL(from: endpointText)
        if let key, !key.isEmpty { try keychain.saveIngestionKey(key) }
        endpoint = validated
        self.enabled = true
    }
    public func disable() {
        enabled = false
        configurationGeneration = UUID()
        inFlight?.cancel()
    }
    public func removeCredential() throws { disable(); try keychain.deleteIngestionKey() }
    public func currentStatus() -> ExportStatus { status }

    public func enqueue(_ item: QueuedTelemetry) {
        let overflow = queue.enqueue(item)
        if overflow { status.lastError = "Telemetry queue reached its limit; oldest item dropped." }
        persistAndPublish()
    }

    public func flush(now: Date = Date()) async {
        guard enabled, !flushing, let endpoint else { return }
        flushing = true
        let generation = configurationGeneration
        defer { flushing = false; inFlight = nil; persistAndPublish() }
        let stale = queue.discardStaleHeartbeats(now: now)
        if stale > 0 { status.lastError = "Discarded \(stale) stale heartbeat(s); they were not sent as current liveness." }
        guard let key = try? (credentialLoader != nil ? credentialLoader!() : keychain.loadIngestionKey()), !key.isEmpty else {
            status.lastError = "SigNoz ingestion key is missing from Keychain."; persistAndPublish(); return
        }
        let ready = queue.items.filter { $0.nextAttemptAt <= now }
        for signal in [TelemetrySignal.logs, .metrics] {
            guard enabled, generation == configurationGeneration else { return }
            let batch = Array(ready.filter { $0.signal == signal }.prefix(20))
            guard !batch.isEmpty else { continue }
            var request = URLRequest(url: EndpointValidator.signalURL(base: endpoint, signal: signal))
            request.httpMethod = "POST"; request.httpBody = try? TelemetryEncoder.batchPayload(signal: signal, payloads: batch.map(\.payload)); request.timeoutInterval = 10
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.setValue(key, forHTTPHeaderField: "signoz-ingestion-key")
            do {
                let session = self.session
                let transport = self.transport
                let task = Task { [request] in
                    try Task.checkCancellation()
                    if let transport { return try await transport(request) }
                    return try await session.data(for: request)
                }
                inFlight = task
                let (data, response) = try await task.value
                inFlight = nil
                guard enabled, generation == configurationGeneration else { return }
                guard let http = response as? HTTPURLResponse else { throw URLError(.badServerResponse) }
                switch ExportResponseParser.disposition(status: http.statusCode, data: data, retryAfter: http.value(forHTTPHeaderField: "Retry-After")) {
                case .success:
                    queue.remove(ids: Set(batch.map(\.id))); status.lastSuccess = now; status.lastError = nil
                case .partial(let rejected, let message):
                    queue.remove(ids: Set(batch.map(\.id))); status.rejected += rejected
                    status.lastError = "SigNoz partially accepted a payload; \(rejected) record(s) rejected. \(message ?? "")"
                case .permanent(let message):
                    queue.remove(ids: Set(batch.map(\.id))); status.dropped += batch.count
                    status.lastError = "Permanent export failure: \(message). Check endpoint and ingestion key."
                case .retry(let serverDelay):
                    batch.forEach { retry($0, now: now, serverDelay: serverDelay) }
                }
            } catch {
                guard enabled, generation == configurationGeneration else { return }
                batch.forEach { retry($0, now: now, serverDelay: nil, message: error.localizedDescription) }
            }
        }
        persistAndPublish()
    }

    private func retry(_ original: QueuedTelemetry, now: Date, serverDelay: TimeInterval?, message: String? = nil) {
        var item = original; item.attempt += 1
        if item.attempt >= 8 {
            queue.remove(ids: [item.id]); status.dropped += 1
            status.lastError = "Export abandoned after 8 attempts. \(message ?? "")"; return
        }
        let delay = serverDelay ?? Backoff.delay(attempt: item.attempt, randomUnit: Double.random(in: 0...1))
        item.nextAttemptAt = now.addingTimeInterval(max(1, min(delay, 900))); queue.replace(item)
        status.lastError = "Export delayed; retry scheduled. \(message ?? "")"
    }

    private func persistAndPublish() {
        status.queued = queue.items.count; status.dropped = max(status.dropped, queue.droppedCount)
        try? FileManager.default.createDirectory(at: queueFile.deletingLastPathComponent(), withIntermediateDirectories: true)
        if let data = try? JSONEncoder.macWatch.encode(queue) { try? data.write(to: queueFile, options: Data.WritingOptions.atomic) }
        update(status)
    }
}
