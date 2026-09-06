import Foundation
import Security

public struct StartupEntry: Codable, Equatable, Sendable {
    public let relativeName: String
    public let modifiedAt: Date
    public let size: UInt64
    public let contentHash: UInt64
    public let executablePath: String?
    public let signature: SignatureInfo?
}

public enum StartupChange: Equatable, Sendable {
    case added(StartupEntry), removed(StartupEntry), modified(old: StartupEntry, new: StartupEntry)
}

public struct StartupScanner: Sendable {
    public let directory: URL
    public init(directory: URL) { self.directory = directory }

    public func scan() throws -> [String: StartupEntry] {
        var firstError: Error?
        let entries = try scan(previous: [:]) { if firstError == nil { firstError = $0 } }
        if let firstError { throw firstError }
        return entries
    }

    public func scan(previous: [String: StartupEntry], onError: (Error) -> Void) throws -> [String: StartupEntry] {
        guard FileManager.default.fileExists(atPath: directory.path) else { return [:] }
        let urls = try FileManager.default.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: [.isRegularFileKey, .contentModificationDateKey, .fileSizeKey],
            options: [.skipsHiddenFiles]
        ).filter { $0.pathExtension.lowercased() == "plist" }
        var result: [String: StartupEntry] = [:]
        for url in urls {
            do {
                let values = try url.resourceValues(forKeys: [.isRegularFileKey, .contentModificationDateKey, .fileSizeKey])
                guard values.isRegularFile == true else { continue }
                let data = try Data(contentsOf: url, options: .mappedIfSafe)
                let executable = Self.executablePath(from: data)
                let signature = executable.map { Self.signatureInfo(for: URL(fileURLWithPath: $0)) }
                result[url.lastPathComponent] = StartupEntry(
                    relativeName: url.lastPathComponent,
                    modifiedAt: values.contentModificationDate ?? .distantPast,
                    size: UInt64(values.fileSize ?? data.count), contentHash: Self.fnv1a(data),
                    executablePath: executable, signature: signature
                )
            } catch {
                result[url.lastPathComponent] = previous[url.lastPathComponent]
                onError(error)
            }
        }
        return result
    }

    public static func changes(from old: [String: StartupEntry], to new: [String: StartupEntry]) -> [StartupChange] {
        let removed = old.keys.filter { new[$0] == nil }.sorted().compactMap { old[$0].map(StartupChange.removed) }
        let added = new.keys.filter { old[$0] == nil }.sorted().compactMap { new[$0].map(StartupChange.added) }
        let modified = old.keys.filter { key in new[key] != nil && old[key]!.contentHash != new[key]!.contentHash }.sorted().map {
            StartupChange.modified(old: old[$0]!, new: new[$0]!)
        }
        return removed + added + modified
    }

    static func executablePath(from plistData: Data) -> String? {
        guard let object = try? PropertyListSerialization.propertyList(from: plistData, format: nil),
              let dictionary = object as? [String: Any] else { return nil }
        if let program = dictionary["Program"] as? String { return program }
        if let arguments = dictionary["ProgramArguments"] as? [String], let first = arguments.first { return first }
        return nil
    }

    static func fnv1a(_ data: Data) -> UInt64 {
        data.reduce(UInt64(14695981039346656037)) { ($0 ^ UInt64($1)) &* 1099511628211 }
    }

    static func signatureInfo(for url: URL) -> SignatureInfo {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode) == errSecSuccess, let staticCode else {
            return SignatureInfo(status: "Not a recognized signed code object")
        }
        var information: CFDictionary?
        let status = SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information)
        guard status == errSecSuccess, let dict = information as? [String: Any] else {
            return SignatureInfo(status: "Signature information unavailable")
        }
        let validity = SecStaticCodeCheckValidity(staticCode, SecCSFlags(rawValue: kSecCSCheckAllArchitectures), nil)
        return SignatureInfo(
            status: validity == errSecSuccess ? "Signature valid at scan time (not a safety verdict)" : "Signature present but validation failed (not a compromise verdict)",
            identifier: dict[kSecCodeInfoIdentifier as String] as? String,
            teamIdentifier: dict[kSecCodeInfoTeamIdentifier as String] as? String
        )
    }
}
