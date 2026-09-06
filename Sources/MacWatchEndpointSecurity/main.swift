import Darwin
import EndpointSecurity
import Foundation

private struct StoredSSHEvent: Codable {
    enum Kind: String, Codable { case failed, succeeded, sessionClosed }
    let observedAt: Date
    let kind: Kind
    let accountName: String?
    let sourceAddress: String?
    let method: String?
}

private let storeDirectory = URL(fileURLWithPath: "/Library/Application Support/MacWatch", isDirectory: true)
private let storeURL = storeDirectory.appending(path: "ssh-auth-events.json")
private let statusURL = storeDirectory.appending(path: "ssh-recorder-status.txt")
private let maximumEvents = 1_024
private let administratorGroupID = getgrnam("admin").map { $0.pointee.gr_gid } ?? 80
private let storeQueue = DispatchQueue(label: "com.personal.MacWatch.EndpointSecurity.store")
private var events: [StoredSSHEvent] = []

private func tokenString(_ token: es_string_token_t) -> String? {
    guard token.length > 0 else { return nil }
    return String(data: Data(bytes: token.data, count: Int(token.length)), encoding: .utf8)
}

private func secure(_ url: URL, mode: mode_t) {
    _ = chown(url.path, 0, administratorGroupID)
    _ = chmod(url.path, mode)
}

private func encoder() -> JSONEncoder {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    return encoder
}

private func prepareStore() {
    try? FileManager.default.createDirectory(at: storeDirectory, withIntermediateDirectories: true)
    secure(storeDirectory, mode: 0o750)
    let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
    events = (try? decoder.decode([StoredSSHEvent].self, from: Data(contentsOf: storeURL))) ?? []
    persistEvents()
}

private func persistEvents() {
    guard let data = try? encoder().encode(events),
          (try? data.write(to: storeURL, options: .atomic)) != nil else { return }
    secure(storeURL, mode: 0o640)
}

private func writeStatus(_ message: String) {
    guard let data = message.prefix(2_000).data(using: .utf8),
          (try? data.write(to: statusURL, options: .atomic)) != nil else { return }
    secure(statusURL, mode: 0o640)
}

private func writeRunningStatus() {
    writeStatus("running|\(ISO8601DateFormatter().string(from: Date()))")
}

private func append(_ event: StoredSSHEvent) {
    storeQueue.async {
        events.append(event)
        events = Array(events.suffix(maximumEvents))
        persistEvents()
    }
}

prepareStore()
var client: OpaquePointer?
let result = es_new_client(&client) { _, message in
    let observedAt = Date(timeIntervalSince1970: TimeInterval(message.pointee.time.tv_sec) + TimeInterval(message.pointee.time.tv_nsec) / 1_000_000_000)
    switch message.pointee.event_type {
    case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN:
        let login = message.pointee.event.openssh_login.pointee
        append(.init(observedAt: observedAt, kind: login.success ? .succeeded : .failed,
                     accountName: tokenString(login.username), sourceAddress: tokenString(login.source_address),
                     method: "Endpoint Security"))
    case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT:
        let logout = message.pointee.event.openssh_logout.pointee
        append(.init(observedAt: observedAt, kind: .sessionClosed,
                     accountName: tokenString(logout.username), sourceAddress: tokenString(logout.source_address), method: nil))
    default:
        break
    }
}

guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let client else {
    writeStatus("Endpoint Security client creation failed (\(result.rawValue)). Check approval, Full Disk Access, and the Endpoint Security entitlement.")
    exit(78)
}

var subscriptions = [ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN, ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT]
guard es_subscribe(client, &subscriptions, UInt32(subscriptions.count)) == ES_RETURN_SUCCESS else {
    writeStatus("Endpoint Security could not subscribe to OpenSSH events.")
    es_delete_client(client)
    exit(69)
}

writeRunningStatus()
let heartbeat = DispatchSource.makeTimerSource(queue: storeQueue)
heartbeat.schedule(deadline: .now() + 30, repeating: 30)
heartbeat.setEventHandler(handler: writeRunningStatus)
heartbeat.resume()
dispatchMain()
