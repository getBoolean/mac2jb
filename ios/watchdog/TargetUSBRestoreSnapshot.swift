import CryptoKit
import Darwin
import Foundation
import MAC2JBUSBRestoreShim

// Read-only target capture for the entitled watchdog. The active device
// profile's build tuple and stock source digest are guards; no private
// serial/description bytes are logged.
enum TargetUSBRestoreSnapshotError: Error {
    case changedTarget, unavailable
}

struct TargetUSBRestoreSnapshot {
    static let stateDirectory = "/var/jb/var/lib/mac2jb-u2-native"
    static var profileStore: USBDeviceProfileStore {
        USBDeviceProfileStore(path: stateDirectory + "/device-profile.json")
    }

    // The learned profile for this exact product/OS build. Learns and stores a
    // new one only while no journal exists and USB is healthy; otherwise a
    // missing or stale profile blocks every publication.
    static func activeProfile() throws -> USBDeviceProfile {
        let product = try sysctlString("hw.machine")
        let build = try sysctlString("kern.osversion")
        let store = profileStore
        if let profile = store.load(), profile.productType == product, profile.osBuild == build {
            return profile
        }
        guard !FileManager.default.fileExists(atPath: stateDirectory + "/restore-journal.json") else {
            throw TargetUSBRestoreSnapshotError.changedTarget
        }
        let profile = try USBDeviceProfile.learn(try deviceFacts(product: product, build: build))
        try store.save(profile)
        return profile
    }

    static func deviceFacts(product: String, build: String) throws -> USBDeviceProfile.Facts {
        var registryID: UInt64 = 0
        guard MAC2JBUSBCaptureControllerRegistryID(&registryID) == MAC2JBUSBSuccess, registryID > 0 else {
            throw TargetUSBRestoreSnapshotError.unavailable
        }
        var bytes: UnsafeMutablePointer<UInt8>?
        var length = 0
        var liveID: UInt64 = 0
        guard MAC2JBUSBCaptureLiveDescription(&bytes, &length, &liveID) == MAC2JBUSBSuccess,
              let bytes, liveID == registryID else {
            throw TargetUSBRestoreSnapshotError.unavailable
        }
        let liveData = Data(bytes: bytes, count: length)
        MAC2JBUSBFreeCapturedDescription(bytes)
        guard let live = try PropertyListSerialization.propertyList(
            from: liveData, options: [], format: nil) as? [String: Any] else {
            throw TargetUSBRestoreSnapshotError.unavailable
        }
        var configured = false
        guard MAC2JBUSBCopyConfiguredState(registryID, &configured) == MAC2JBUSBSuccess else {
            throw TargetUSBRestoreSnapshotError.unavailable
        }
        var buffer = [CChar](repeating: 0, count: 16_384)
        guard MAC2JBUSBCopyFunctionClients(registryID, &buffer, buffer.count) == MAC2JBUSBSuccess else {
            throw TargetUSBRestoreSnapshotError.unavailable
        }
        var clients: [String: [(client: String, process: String?, pid: Int32?)]] = [:]
        for line in String(cString: buffer).split(separator: "\n") {
            let fields = line.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
            guard fields.count == 3, !fields[0].isEmpty else { continue }
            var entries = clients[fields[0]] ?? []
            if !fields[1].isEmpty {
                // IOUserClientCreator is "pid <n>, <process>".
                var pid: Int32?
                var process: String?
                if fields[2].hasPrefix("pid "), let comma = fields[2].firstIndex(of: ",") {
                    pid = Int32(fields[2][fields[2].index(fields[2].startIndex, offsetBy: 4)..<comma])
                    process = fields[2][fields[2].index(after: comma)...]
                        .trimmingCharacters(in: .whitespaces)
                }
                entries.append((client: fields[1], process: process, pid: pid))
            }
            clients[fields[0]] = entries
        }
        return USBDeviceProfile.Facts(
            productType: product, osBuild: build,
            stockSource: FileManager.default.contents(atPath: USBDeviceProfile.stockSourcePath),
            liveDescription: live, configured: configured, functionClients: clients,
            launchdLabels: launchdLabels())
    }

    // pid -> label from `launchctl list` when a launchctl binary exists (jailbreak).
    private static func launchdLabels() -> [Int32: String] {
        for path in ["/var/jb/usr/bin/launchctl", "/var/jb/bin/launchctl", "/bin/launchctl"]
        where access(path, X_OK) == 0 {
            guard let data = spawnOutput([path, "list"]) else { continue }
            var labels: [Int32: String] = [:]
            for row in String(decoding: data, as: UTF8.self).split(separator: "\n") {
                let columns = row.split(separator: "\t").map(String.init)
                if columns.count == 3, let pid = Int32(columns[0]) { labels[pid] = columns[2] }
            }
            return labels
        }
        return [:]
    }

    private static func spawnOutput(_ argv: [String]) -> Data? {
        var fds: [Int32] = [0, 0]
        guard pipe(&fds) == 0 else { return nil }
        var actions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&actions)
        posix_spawn_file_actions_adddup2(&actions, fds[1], STDOUT_FILENO)
        posix_spawn_file_actions_addclose(&actions, fds[0])
        var cArgs = argv.map { strdup($0) } + [nil]
        var pid: pid_t = 0
        let spawned = posix_spawn(&pid, argv[0], &actions, nil, &cArgs, environ)
        posix_spawn_file_actions_destroy(&actions)
        cArgs.forEach { free($0) }
        close(fds[1])
        defer { close(fds[0]) }
        guard spawned == 0 else { return nil }
        var output = Data()
        var chunk = [UInt8](repeating: 0, count: 4096)
        while output.count < 1_048_576 {
            let count = read(fds[0], &chunk, chunk.count)
            if count <= 0 { break }
            output.append(chunk, count: count)
        }
        var status: Int32 = 0
        waitpid(pid, &status, 0)
        return output
    }

    let identity: USBRestoreIdentity
    let liveDescription: Data

    static func captureIdentity() throws -> USBRestoreIdentity {
        let profile = try activeProfile()
        let product = profile.productType
        let build = profile.osBuild
        let source = FileManager.default.contents(atPath: profile.stockSourcePath)
        guard source?.count == profile.stockSourceSize,
              source.map(digest) == profile.stockSourceSHA256 else {
            throw TargetUSBRestoreSnapshotError.changedTarget
        }
        let boot = try sysctlBytes("kern.boottime")
        var registryID: UInt64 = 0
        guard MAC2JBUSBCaptureControllerRegistryID(&registryID) ==
                MAC2JBUSBSuccess, registryID > 0 else {
            throw TargetUSBRestoreSnapshotError.unavailable
        }
        return USBRestoreIdentity(
            productType: product, osBuild: build,
            controllerIdentity: String(registryID),
            // Devices without a stock plist bind the empty-input digest instead.
            bootSession: digest(boot), sourceSHA256: profile.stockSourceSHA256 ?? digest(Data()))
    }

    static func capture() throws -> Self {
        let snapshot = try captureRaw()
        let stockCount = try activeProfile().liveDescriptionFieldCount
        guard var plist = try PropertyListSerialization.propertyList(
            from: snapshot.liveDescription, options: [], format: nil) as? [String: Any],
              (plist.count == stockCount || plist.count == stockCount + 1) else {
            throw TargetUSBRestoreSnapshotError.unavailable
        }
        if plist.count == stockCount, plist["AllowMultipleCreates"] == nil {
            return snapshot
        }
        #if MAC2JB_U2_POST_CLONE
        // A successful replacement leaves this permission marker in the live
        // registry. It is not a USB descriptor field. Journal the complete
        // current description with only that marker removed, so a later
        // no-op or fault trial can still restore every function and scalar.
        guard plist.count == stockCount + 1,
              let flag = plist.removeValue(forKey: "AllowMultipleCreates") as? Bool,
              flag, plist.count == stockCount,
              let normalized = try? PropertyListSerialization.data(
                fromPropertyList: plist, format: .binary, options: 0) else {
            throw TargetUSBRestoreSnapshotError.unavailable
        }
        return Self(identity: snapshot.identity, liveDescription: normalized)
        #else
        throw TargetUSBRestoreSnapshotError.unavailable
        #endif
    }

    // Restoration verification must read a controller that may retain its
    // replacement permission flag. The verifier checks that flag and all
    // original values; this method alone does not accept the new state.
    static func captureForVerification() throws -> Self {
        try captureRaw()
    }

    private static func captureRaw() throws -> Self {
        let identity = try captureIdentity()
        var bytes: UnsafeMutablePointer<UInt8>?
        var length = 0
        var registryID: UInt64 = 0
        guard MAC2JBUSBCaptureLiveDescription(&bytes, &length, &registryID) ==
                MAC2JBUSBSuccess,
              let bytes else {
            throw TargetUSBRestoreSnapshotError.unavailable
        }
        defer { MAC2JBUSBFreeCapturedDescription(bytes) }
        guard length > 8,
              String(registryID) == identity.controllerIdentity else {
            throw TargetUSBRestoreSnapshotError.unavailable
        }
        let live = Data(bytes: bytes, count: length)
        return Self(identity: identity, liveDescription: live)
    }

    private static func sysctlBytes(_ name: String) throws -> Data {
        var length = 0
        guard sysctlbyname(name, nil, &length, nil, 0) == 0,
              (1...256).contains(length) else {
            throw TargetUSBRestoreSnapshotError.unavailable
        }
        var bytes = [UInt8](repeating: 0, count: length)
        let status = bytes.withUnsafeMutableBytes { buffer in
            sysctlbyname(name, buffer.baseAddress, &length, nil, 0)
        }
        guard status == 0, (1...bytes.count).contains(length) else {
            throw TargetUSBRestoreSnapshotError.unavailable
        }
        return Data(bytes.prefix(length))
    }

    private static func sysctlString(_ name: String) throws -> String {
        let data = try sysctlBytes(name)
        guard let text = String(data: Data(data.prefix { $0 != 0 }), encoding: .ascii),
              !text.isEmpty else {
            throw TargetUSBRestoreSnapshotError.unavailable
        }
        return text
    }

    private static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
