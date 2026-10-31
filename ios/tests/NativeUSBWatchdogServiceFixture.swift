import CryptoKit
import Darwin
import Foundation

// Mac-only service fixture. This file is never linked into the iPad package.
// It substitutes a file-backed live snapshot and an append-only event counter
// for the USB controller, so the real socket/launch/restart path can be fault
// tested without contacting a device or calling SetDescription.
private struct FixtureFailure: Error {}

struct TargetUSBRestoreSnapshot {
    let identity: USBRestoreIdentity
    let liveDescription: Data

    static func captureIdentity() throws -> USBRestoreIdentity {
        throw FixtureFailure()
    }

    static func capture() throws -> Self {
        throw FixtureFailure()
    }

    static func captureForVerification() throws -> Self {
        throw FixtureFailure()
    }

    static func activeProfile() throws -> USBDeviceProfile {
        throw FixtureFailure()
    }
}

struct TargetUSBRestoreController: USBRestoreController {
    init(identity: USBRestoreIdentity, cycleBus: Bool) throws {
        throw FixtureFailure()
    }

    func validateInMemory(_ description: Data) throws {
        throw FixtureFailure()
    }

    func publish(_ description: Data) throws {
        throw FixtureFailure()
    }

    func isConfigured() throws -> Bool {
        throw FixtureFailure()
    }

    func unservedFunctions() throws -> Set<String> {
        throw FixtureFailure()
    }
}

private struct FileBackedController: USBRestoreController {
    let eventPath: String

    func publish(_ description: Data) throws {
        let fd = open(eventPath, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw FixtureFailure() }
        defer { _ = close(fd) }
        let byte: UInt8 = 80  // 'P': one fake publication or restoration.
        guard write(fd, [byte], 1) == 1, fsync(fd) == 0 else {
            throw FixtureFailure()
        }
    }
}

@main
enum NativeUSBWatchdogServiceFixture {
    static func main() throws {
        guard CommandLine.arguments.count == 5,
              CommandLine.arguments[1] == "--fixture-server" else {
            throw FixtureFailure()
        }
        let state = CommandLine.arguments[2]
        let livePath = CommandLine.arguments[3]
        let events = CommandLine.arguments[4]
        let identity = USBRestoreIdentity(
            productType: "iPad14,5", osBuild: "21A329",
            controllerIdentity: "fixture-controller",
            bootSession: "fixture-boot",
            sourceSHA256: String(repeating: "a", count: 64))
        let snapshot: () throws -> TargetUSBRestoreSnapshot = {
            let live = try Data(contentsOf: URL(fileURLWithPath: livePath))
            return TargetUSBRestoreSnapshot(identity: identity,
                                            liveDescription: live)
        }
        let readinessPath = ProcessInfo.processInfo.environment["MAC2JB_U2_FIXTURE_READINESS_FILE"]
        let unservedPath = ProcessInfo.processInfo.environment["MAC2JB_U2_FIXTURE_UNSERVED_QUEUE"]
        let restartPath = ProcessInfo.processInfo.environment["MAC2JB_U2_FIXTURE_RESTART_LOG"]
        let healOnRestart = ProcessInfo.processInfo.environment["MAC2JB_U2_FIXTURE_HEAL_ON_RESTART"] == "1"
        let service = try NativeUSBWatchdogService(
            publicationEnabled: true, stateDirectory: state,
            expectedOwner: geteuid(), currentIdentity: identity,
            controller: FileBackedController(eventPath: events),
            snapshotProvider: snapshot,
            verificationSnapshotProvider: snapshot,
            validateInMemory: { data in
                guard data.starts(with: Data("bplist00".utf8)) else {
                    throw FixtureFailure()
                }
            }, beforeRecovery: {
                if let readinessPath {
                    try NativeUSBWatchdogService.waitForConfigured {
                        try Data(contentsOf: URL(fileURLWithPath: readinessPath)) ==
                            Data("1".utf8)
                    }
                }
            }, controllerConfigured: {
                guard let readinessPath else { return false }
                return try Data(contentsOf: URL(fileURLWithPath: readinessPath)) ==
                    Data("1".utf8)
            }, unservedFunctions: unservedPath.map { path in {
                // Line N of the queue = unserved functions after publication N
                // (publication count = bytes in the event file).
                let lines = try String(contentsOfFile: path, encoding: .utf8)
                    .split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
                let published = (try? Data(contentsOf: URL(fileURLWithPath: events)).count) ?? 0
                let line = lines[min(max(published - 1, 0), lines.count - 1)]
                return Set(line.split(separator: ",").map(String.init))
            } }, restartOwner: unservedPath.map { _ in { label in
                let log = (restartPath ?? "/dev/null")
                let fd = open(log, O_WRONLY | O_APPEND | O_CREAT, 0o600)
                if fd >= 0 { _ = label.withCString { write(fd, $0, strlen($0)) }; _ = write(fd, "\n", 1); _ = close(fd) }
                if healOnRestart, let readinessPath {
                    try Data("1".utf8).write(to: URL(fileURLWithPath: readinessPath))
                }
            } }, healPolicy: {
                var policy = USBFunctionHealPolicy()
                policy.owners = ["Valeria": "com.apple.audiomxd"]
                policy.settleSeconds = 1
                policy.pollSeconds = 0.1
                return policy
            }(), leaseNanoseconds: 1_000_000_000)
        try service.run()
    }
}
