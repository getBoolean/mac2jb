import CryptoKit
import Darwin
import Foundation
import MAC2JBUSBRestoreShim

// Read-only target capture for the entitled watchdog. The fixed source digest
// and build tuple are guards; no private serial/description bytes are logged.
enum TargetUSBRestoreSnapshotError: Error {
    case changedTarget, unavailable
}

struct TargetUSBRestoreSnapshot {
    static let stockSource = "/System/Library/AppleUSBDevice/USBDeviceConfiguration.plist"
    static let expectedSourceSHA256 =
        "a0f63c8c2372ebd1ed4e49492344a5c1290c530ae8e5c66d88e9ba481792c5fa"

    let identity: USBRestoreIdentity
    let liveDescription: Data

    static func captureIdentity() throws -> USBRestoreIdentity {
        let product = try sysctlString("hw.machine")
        let build = try sysctlString("kern.osversion")
        guard product == "iPad14,5", build == "21A329" else {
            throw TargetUSBRestoreSnapshotError.changedTarget
        }
        let source = try Data(contentsOf: URL(fileURLWithPath: stockSource))
        guard source.count == 5_319,
              digest(source) == expectedSourceSHA256 else {
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
            bootSession: digest(boot), sourceSHA256: expectedSourceSHA256)
    }

    static func capture() throws -> Self {
        let snapshot = try captureRaw()
        guard var plist = try PropertyListSerialization.propertyList(
            from: snapshot.liveDescription, options: [], format: nil) as? [String: Any],
              (plist.count == 16 || plist.count == 17) else {
            throw TargetUSBRestoreSnapshotError.unavailable
        }
        if plist.count == 16, plist["AllowMultipleCreates"] == nil {
            return snapshot
        }
        #if MAC2JB_U2_POST_CLONE
        // A successful replacement leaves this permission marker in the live
        // registry. It is not a USB descriptor field. Journal the complete
        // current description with only that marker removed, so a later
        // no-op or fault trial can still restore every function and scalar.
        guard plist.count == 17,
              let flag = plist.removeValue(forKey: "AllowMultipleCreates") as? Bool,
              flag, plist.count == 16,
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
