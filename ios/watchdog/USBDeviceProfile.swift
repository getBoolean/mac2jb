import CryptoKit
import Foundation

// Per-device facts the USB restore broker needs. Nothing model- or
// build-specific is compiled in: the broker *learns* this profile on the device
// the first time it runs on a given product/OS build, while USB is healthy
// (controller configured, every function served) and no journal exists, and
// stores it in its private state directory. After an OS update it re-learns
// under the same conditions; until then it refuses to publish. The profile holds
// no serial numbers, UDIDs or other private identifiers.
struct USBDeviceProfile: Codable, Equatable {
    struct Owner: Codable, Equatable {
        // USBDeviceFunction whose registration a user-space process owns.
        let function: String
        let process: String
        // launchd label when it could be resolved (jailbreak); nil under TrollStore.
        let launchdLabel: String?
    }

    let schemaVersion: Int
    let productType: String
    let osBuild: String
    let stockSourcePath: String
    // nil when the device has no stock USB configuration plist at that path.
    let stockSourceSHA256: String?
    let stockSourceSize: Int?
    // Field count of the stock live registry description.
    let liveDescriptionFieldCount: Int
    let usbVendorID: Int
    let usbProductID: Int
    let healthyBcdUSB: Int
    let healthyMPS0: Int
    let functions: [String]
    // Functions whose client exists only while a host is connected.
    let hostDependentFunctions: [String]
    let owners: [Owner]

    enum Failure: Error { case invalid(String), notHealthy(String) }

    static let stockSourcePath = "/System/Library/AppleUSBDevice/USBDeviceConfiguration.plist"
    // iOS-wide rule, not device data: ptpd attaches to PTP but exits ~10 s after
    // a description swap when no host is connected, so PTP's missing client is
    // an effect of being off bus and never blocks it.
    static let hostDependentFunctionNames: Set<String> = ["PTP"]
    static let ownerClientClass = "IOUSBDeviceInterfaceUserClient"

    // Raw observations gathered on the device (see TargetUSBDeviceFacts).
    struct Facts {
        let productType: String
        let osBuild: String
        let stockSource: Data?
        let liveDescription: [String: Any]
        let configured: Bool
        // function name -> (client class, creator process name, creator pid)
        let functionClients: [String: [(client: String, process: String?, pid: Int32?)]]
        // pid -> launchd label (empty when launchctl is unavailable)
        let launchdLabels: [Int32: String]
    }

    static func learn(_ facts: Facts) throws -> USBDeviceProfile {
        guard facts.configured else { throw Failure.notHealthy("controller not configured") }
        var live = facts.liveDescription
        if live["AllowMultipleCreates"] as? Bool == true { live.removeValue(forKey: "AllowMultipleCreates") }
        func int(_ key: String) throws -> Int {
            guard let value = live[key] as? Int else { throw Failure.invalid("live " + key) }
            return value
        }
        let functions = facts.functionClients.keys.sorted()
        let hostDependent = functions.filter { hostDependentFunctionNames.contains($0) }
        let unserved = functions.filter { facts.functionClients[$0]?.isEmpty ?? true }
            .filter { !hostDependentFunctionNames.contains($0) }
        guard unserved.isEmpty else {
            throw Failure.notHealthy("unserved functions: " + unserved.joined(separator: ","))
        }
        var owners: [Owner] = []
        for function in functions where !hostDependentFunctionNames.contains(function) {
            for client in facts.functionClients[function] ?? [] where client.client == ownerClientClass {
                guard let process = client.process else { continue }
                let label = client.pid.flatMap { facts.launchdLabels[$0] }
                owners.append(Owner(function: function, process: process, launchdLabel: label))
                break
            }
        }
        let profile = USBDeviceProfile(
            schemaVersion: 2, productType: facts.productType, osBuild: facts.osBuild,
            stockSourcePath: stockSourcePath,
            stockSourceSHA256: facts.stockSource.map(sha256),
            stockSourceSize: facts.stockSource?.count,
            liveDescriptionFieldCount: live.count,
            usbVendorID: try int("vendorID"), usbProductID: try int("productID"),
            healthyBcdUSB: try int("BcdUSBVersion"), healthyMPS0: try int("MPS0"),
            functions: functions, hostDependentFunctions: hostDependent, owners: owners)
        try profile.validate()
        return profile
    }

    func validate() throws {
        func check(_ value: String, _ pattern: String, _ what: String) throws {
            guard value.range(of: pattern, options: .regularExpression) != nil else {
                throw Failure.invalid(what)
            }
        }
        guard schemaVersion == 2 else { throw Failure.invalid("schema") }
        try check(productType, "^[A-Za-z]+[0-9]+,[0-9]+$", "productType")
        try check(osBuild, "^[0-9]{2}[A-Z][0-9]{1,5}[a-z]?$", "osBuild")
        if let digest = stockSourceSHA256 { try check(digest, "^[0-9a-f]{64}$", "stockSourceSHA256") }
        guard (stockSourceSHA256 == nil) == (stockSourceSize == nil),
              (4...64).contains(liveDescriptionFieldCount),
              (1...0xFFFF).contains(usbVendorID), (0...0xFFFF).contains(usbProductID),
              !functions.isEmpty, functions.count <= 64,
              Set(functions).count == functions.count,
              Set(hostDependentFunctions).isSubset(of: functions) else {
            throw Failure.invalid("counts")
        }
        try functions.forEach { try check($0, "^[A-Za-z0-9][A-Za-z0-9_+ .,-]{0,63}$", "function") }
        for owner in owners {
            guard functions.contains(owner.function) else { throw Failure.invalid("owner function") }
            try check(owner.process, "^[A-Za-z0-9._-]{1,32}$", "owner process")
            if let label = owner.launchdLabel {
                try check(label, "^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$", "launchdLabel")
            }
        }
    }

    func healPolicy() -> USBFunctionHealPolicy {
        var policy = USBFunctionHealPolicy()
        policy.hostDependentFunctions = Set(hostDependentFunctions)
        // The healer keys owners by an opaque restart token: the launchd label
        // when known, else the process name (restarted by SIGKILL).
        policy.owners = Dictionary(owners.map { ($0.function, $0.launchdLabel ?? $0.process) },
                                   uniquingKeysWith: { first, _ in first })
        return policy
    }

    // restart token -> process name, the only processes the broker may restart.
    var ownerProcesses: [String: String] {
        Dictionary(owners.map { ($0.launchdLabel ?? $0.process, $0.process) },
                   uniquingKeysWith: { first, _ in first })
    }

    func json() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(self)
    }
}

// Private on-device store: one root-owned 0600 file in the broker state directory.
struct USBDeviceProfileStore {
    let path: String
    var requireRootOwner = true

    func load() -> USBDeviceProfile? {
        var info = stat()
        guard lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_size <= 65_536, info.st_mode & 0o077 == 0,
              !requireRootOwner || info.st_uid == 0,
              let data = FileManager.default.contents(atPath: path),
              let profile = try? JSONDecoder().decode(USBDeviceProfile.self, from: data),
              (try? profile.validate()) != nil else { return nil }
        return profile
    }

    func save(_ profile: USBDeviceProfile) throws {
        let data = try profile.json()
        let temporary = path + ".new"
        _ = unlink(temporary)
        let fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw USBDeviceProfile.Failure.invalid("store") }
        let written = data.withUnsafeBytes { write(fd, $0.baseAddress, data.count) }
        let synced = fsync(fd) == 0
        close(fd)
        guard written == data.count, synced, rename(temporary, path) == 0 else {
            _ = unlink(temporary)
            throw USBDeviceProfile.Failure.invalid("store")
        }
        let directory = open((path as NSString).deletingLastPathComponent, O_RDONLY)
        if directory >= 0 { _ = fsync(directory); close(directory) }
    }
}

private func sha256(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}
