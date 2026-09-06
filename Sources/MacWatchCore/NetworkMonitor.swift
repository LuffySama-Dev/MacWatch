import Foundation

public enum NetworkTransport: String, Codable, Sendable { case tcp, udp }
public enum NetworkAddressFamily: String, Codable, Sendable { case ipv4, ipv6, dual, unknown }
public enum NetworkExposure: String, Codable, Sendable { case loopbackOnly, networkInterface, allInterfaces }

public struct ListeningEndpoint: Codable, Equatable, Identifiable, Sendable {
    public let transport: NetworkTransport
    public let family: NetworkAddressFamily
    public let localAddress: String
    public let localPort: UInt16
    public let exposure: NetworkExposure
    public let processName: String
    public let processID: Int32?
    public let executablePath: String?

    public var id: String {
        "\(transport.rawValue)|\(family.rawValue)|\(localAddress)|\(localPort)|\(processName)"
    }

    public init(transport: NetworkTransport, family: NetworkAddressFamily, localAddress: String,
                localPort: UInt16, exposure: NetworkExposure, processName: String,
                processID: Int32? = nil, executablePath: String? = nil) {
        self.transport = transport; self.family = family; self.localAddress = localAddress
        self.localPort = localPort; self.exposure = exposure; self.processName = processName
        self.processID = processID; self.executablePath = executablePath
    }
}

public enum ListeningEndpointChange: Equatable, Sendable {
    case opened(ListeningEndpoint)
    case closed(ListeningEndpoint)
}

public enum ListeningEndpointScannerError: LocalizedError, Sendable {
    case commandFailed(String)
    public var errorDescription: String? {
        switch self { case .commandFailed(let message): return "Listening-port inventory failed: \(message)" }
    }
}

public struct ListeningEndpointScanner: Sendable {
    public init() {}

    public func scan() throws -> [ListeningEndpoint] {
        let tcp = Self.runNetstat(protocolName: "tcp")
        guard tcp.status == 0 else { throw ListeningEndpointScannerError.commandFailed(tcp.output) }
        let udp = Self.runNetstat(protocolName: "udp")
        guard udp.status == 0 else { throw ListeningEndpointScannerError.commandFailed(udp.output) }
        var endpoints = Self.parseTCP(tcp.output) + Self.parseUDP(udp.output)
        let paths = Self.processPaths(for: Set(endpoints.compactMap(\.processID)))
        endpoints = endpoints.map { endpoint in
            ListeningEndpoint(transport: endpoint.transport, family: endpoint.family,
                              localAddress: endpoint.localAddress, localPort: endpoint.localPort,
                              exposure: endpoint.exposure, processName: endpoint.processName,
                              processID: endpoint.processID,
                              executablePath: endpoint.processID.flatMap { paths[$0] })
        }
        return Array(Dictionary(endpoints.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first }).values)
            .sorted(by: Self.sortEndpoints)
    }

    public static func parseTCP(_ output: String) -> [ListeningEndpoint] {
        output.split(whereSeparator: \Character.isNewline).compactMap { line in
            guard let fields = captures(#"^\s*(tcp\S*)\s+\d+\s+\d+\s+(\S+)\s+\S+\s+LISTEN(?:\s+(.*))?$"#, in: String(line)),
                  let local = parseLocalEndpoint(fields[1]) else { return nil }
            let owner = fields.count > 2 ? parseOwner(fields[2]) : nil
            return ListeningEndpoint(transport: .tcp, family: family(from: fields[0]),
                                     localAddress: local.address, localPort: local.port,
                                     exposure: exposure(for: local.address), processName: owner?.name ?? "Unknown",
                                     processID: owner?.pid)
        }
    }

    public static func parseUDP(_ output: String) -> [ListeningEndpoint] {
        output.split(whereSeparator: \Character.isNewline).compactMap { line in
            guard let fields = captures(#"^\s*(udp\S*)\s+\d+\s+\d+\s+(\S+)\s+(\S+)(?:\s+(.*))?$"#, in: String(line)),
                  fields[2] == "*.*", let local = parseLocalEndpoint(fields[1]) else { return nil }
            let owner = fields.count > 3 ? parseOwner(fields[3]) : nil
            return ListeningEndpoint(transport: .udp, family: family(from: fields[0]),
                                     localAddress: local.address, localPort: local.port,
                                     exposure: exposure(for: local.address), processName: owner?.name ?? "Unknown",
                                     processID: owner?.pid)
        }
    }

    public static func changes(from old: [ListeningEndpoint], to new: [ListeningEndpoint]) -> [ListeningEndpointChange] {
        let before = Dictionary(old.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        let after = Dictionary(new.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        var replaced = Set<String>()
        for key in before.keys where after[key] != nil {
            if let oldPath = before[key]?.executablePath, let newPath = after[key]?.executablePath, oldPath != newPath {
                replaced.insert(key)
            }
        }
        let closed = before.keys.filter { after[$0] == nil || replaced.contains($0) }.sorted().compactMap { before[$0].map(ListeningEndpointChange.closed) }
        let opened = after.keys.filter { before[$0] == nil || replaced.contains($0) }.sorted().compactMap { after[$0].map(ListeningEndpointChange.opened) }
        return closed + opened
    }

    private static func parseLocalEndpoint(_ value: String) -> (address: String, port: UInt16)? {
        guard let separator = value.lastIndex(of: "."), separator < value.index(before: value.endIndex),
              let port = UInt16(value[value.index(after: separator)...]), port > 0 else { return nil }
        return (String(value[..<separator]), port)
    }

    private static func parseOwner(_ remainder: String) -> (name: String, pid: Int32)? {
        guard let fields = captures(#"^\s*\d+\s+\d+\s+\d+\s+\d+\s+(.+?):(\d+)(?:\s|$)"#, in: remainder),
              let pid = Int32(fields[1]) else { return nil }
        return (fields[0].trimmingCharacters(in: .whitespaces), pid)
    }

    private static func family(from raw: String) -> NetworkAddressFamily {
        if raw.hasSuffix("46") || raw.hasSuffix("64") { return .dual }
        if raw.hasSuffix("4") { return .ipv4 }
        if raw.hasSuffix("6") { return .ipv6 }
        return .unknown
    }

    private static func exposure(for address: String) -> NetworkExposure {
        if address == "*" || address == "0.0.0.0" || address == "::" { return .allInterfaces }
        if address == "::1" || address.hasPrefix("127.") { return .loopbackOnly }
        return .networkInterface
    }

    private static func captures(_ pattern: String, in text: String) -> [String]? {
        guard let expression = try? NSRegularExpression(pattern: pattern),
              let match = expression.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) else { return nil }
        return (1..<match.numberOfRanges).map { index in
            let range = match.range(at: index)
            guard range.location != NSNotFound, let swiftRange = Range(range, in: text) else { return "" }
            return String(text[swiftRange])
        }
    }

    private static func runNetstat(protocolName: String) -> (status: Int32, output: String) {
        run("/usr/sbin/netstat", arguments: ["-anv", "-p", protocolName])
    }

    private static func processPaths(for pids: Set<Int32>) -> [Int32: String] {
        guard !pids.isEmpty else { return [:] }
        let result = run("/bin/ps", arguments: ["-p", pids.sorted().map(String.init).joined(separator: ","), "-o", "pid=,comm="])
        guard result.status == 0 else { return [:] }
        var paths: [Int32: String] = [:]
        for line in result.output.split(whereSeparator: \Character.isNewline) {
            let text = String(line)
            guard let fields = captures(#"^\s*(\d+)\s+(.+)$"#, in: text), let pid = Int32(fields[0]) else { continue }
            paths[pid] = fields[1]
        }
        return paths
    }

    private static func run(_ executable: String, arguments: [String]) -> (status: Int32, output: String) {
        let process = Process(); let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: executable); process.arguments = arguments
        process.standardOutput = pipe; process.standardError = pipe
        var environment = ProcessInfo.processInfo.environment; environment["LC_ALL"] = "C"; process.environment = environment
        do { try process.run() } catch { return (-1, error.localizedDescription) }
        let data = pipe.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
        return (process.terminationStatus, String(decoding: data, as: UTF8.self))
    }

    private static func sortEndpoints(_ lhs: ListeningEndpoint, _ rhs: ListeningEndpoint) -> Bool {
        let exposureRank: [NetworkExposure: Int] = [.allInterfaces: 0, .networkInterface: 1, .loopbackOnly: 2]
        if exposureRank[lhs.exposure] != exposureRank[rhs.exposure] { return exposureRank[lhs.exposure]! < exposureRank[rhs.exposure]! }
        if lhs.localPort != rhs.localPort { return lhs.localPort < rhs.localPort }
        return lhs.id < rhs.id
    }
}

public final class ListeningEndpointMonitor: @unchecked Sendable {
    private let healthHandler: @Sendable (Bool) -> Void
    private let scanner: ListeningEndpointScanner
    private let baselineURL: URL
    private let queue = DispatchQueue(label: "MacWatch.ListeningEndpoints")
    private var timer: DispatchSourceTimer?
    private var baseline: [ListeningEndpoint]?
    private var errorReported = false
    private let updateHandler: @Sendable ([ListeningEndpoint], [ListeningEndpointChange]) -> Void
    private let errorHandler: @Sendable (Error) -> Void

    public init(scanner: ListeningEndpointScanner = ListeningEndpointScanner(), baselineURL: URL,
                healthHandler: @escaping @Sendable (Bool) -> Void = { _ in },
                updateHandler: @escaping @Sendable ([ListeningEndpoint], [ListeningEndpointChange]) -> Void,
                errorHandler: @escaping @Sendable (Error) -> Void) {
        self.healthHandler = healthHandler
        self.scanner = scanner; self.baselineURL = baselineURL
        self.updateHandler = updateHandler; self.errorHandler = errorHandler
    }

    public func start(interval: TimeInterval = 15) {
        queue.async {
            guard self.timer == nil else { return }
            do {
                let current = try self.scanner.scan()
                if let data = try? Data(contentsOf: self.baselineURL),
                   let saved = try? JSONDecoder.macWatch.decode([ListeningEndpoint].self, from: data) {
                    self.updateHandler(current, ListeningEndpointScanner.changes(from: saved, to: current))
                } else { self.updateHandler(current, []) }
                self.baseline = current; try self.persist(current); self.healthHandler(true)
            } catch { self.healthHandler(false); self.errorReported = true; self.errorHandler(error) }
            let timer = DispatchSource.makeTimerSource(queue: self.queue)
            timer.schedule(deadline: .now() + interval, repeating: interval)
            timer.setEventHandler { [weak self] in self?.poll() }
            self.timer = timer; timer.resume()
        }
    }

    public func stop() { queue.async { self.timer?.cancel(); self.timer = nil } }
    public func pollNow() { queue.async { self.poll() } }

    private func poll() {
        do {
            let current = try scanner.scan()
            let changes = baseline.map { ListeningEndpointScanner.changes(from: $0, to: current) } ?? []
            try persist(current); baseline = current; errorReported = false; updateHandler(current, changes); healthHandler(true)
        } catch {
            healthHandler(false)
            if !errorReported { errorReported = true; errorHandler(error) }
        }
    }

    private func persist(_ endpoints: [ListeningEndpoint]) throws {
        try FileManager.default.createDirectory(at: baselineURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try JSONEncoder.macWatch.encode(endpoints).write(to: baselineURL, options: .atomic)
    }
}
