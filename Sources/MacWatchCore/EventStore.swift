import Foundation

public final class EventStore: @unchecked Sendable {
    private let fileURL: URL
    private let queue = DispatchQueue(label: "MacWatch.EventStore")
    public var retentionDays: Int
    public var maximumEvents: Int

    public init(fileURL: URL, retentionDays: Int = 30, maximumEvents: Int = 5_000) {
        self.fileURL = fileURL
        self.retentionDays = max(1, min(retentionDays, 365))
        self.maximumEvents = max(100, min(maximumEvents, 50_000))
    }

    public func load() -> [SecurityEvent] {
        queue.sync {
            let saved = loadUnlocked()
            let events = retained(saved, now: Date())
            if events != saved { try? persistUnlocked(events) }
            return events
        }
    }

    @discardableResult
    public func append(_ event: SecurityEvent) throws -> [SecurityEvent] {
        try queue.sync {
            var events = loadUnlocked()
            events.append(event)
            events = retained(events, now: Date())
            try persistUnlocked(events)
            return events
        }
    }

    @discardableResult
    public func prune(now: Date = Date()) throws -> [SecurityEvent] {
        try queue.sync {
            let events = retained(loadUnlocked(), now: now)
            try persistUnlocked(events)
            return events
        }
    }

    public func clear() throws {
        try queue.sync { try persistUnlocked([]) }
    }

    public func export(to destination: URL) throws {
        let data = try JSONEncoder.macWatch.encode(load())
        try data.write(to: destination, options: .atomic)
    }

    public func retained(_ events: [SecurityEvent], now: Date) -> [SecurityEvent] {
        let cutoff = Calendar.current.date(byAdding: .day, value: -retentionDays, to: now) ?? now
        return Array(events.filter { $0.observedAt >= cutoff }.suffix(maximumEvents))
    }

    private func loadUnlocked() -> [SecurityEvent] {
        guard let data = try? Data(contentsOf: fileURL),
              let events = try? JSONDecoder.macWatch.decode([SecurityEvent].self, from: data) else { return [] }
        return events
    }

    private func persistUnlocked(_ events: [SecurityEvent]) throws {
        do {
            try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try JSONEncoder.macWatch.encode(events).write(to: fileURL, options: .atomic)
        } catch { throw MacWatchError.storage(error.localizedDescription) }
    }
}

public extension JSONEncoder {
    static var macWatch: JSONEncoder {
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601; encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return encoder
    }
}
public extension JSONDecoder {
    static var macWatch: JSONDecoder { let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601; return decoder }
}
