import Foundation

public struct NotificationDeduplicator: Sendable {
    private var lastSent: [String: Date] = [:]
    public var interval: TimeInterval
    public init(interval: TimeInterval = 300) { self.interval = interval }

    public mutating func shouldNotify(key: String, now: Date = Date()) -> Bool {
        if let last = lastSent[key], now.timeIntervalSince(last) < interval { return false }
        lastSent[key] = now
        return true
    }
}
