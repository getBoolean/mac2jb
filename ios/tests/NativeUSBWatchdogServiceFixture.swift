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

    func selectedConfiguration() throws -> Int {
        throw FixtureFailure()
    }
}

private struct FileBackedController: USBRestoreController {
    let eventPath: String
    // Makes the additive controller call fail with nothing written, the way a
    // refused SetDescription does: the dry run passes, the journal is already
    // published, and the live description still has no appended function.
    let failAppendingPublish: Bool
    // The description this fake controller currently has on the bus. Present
    // only when a test asks for it; the counter-only tests leave it nil and see
    // the original event-recording behaviour.
    let publishedPath: String?

    // Mac stand-in for the shim's clone-equality precondition: the backend
    // proves the live description equal to the one being published before it
    // writes, so a restore that does not account for an appended function is
    // refused here exactly as the controller refuses it.
    func publish(_ description: Data) throws {
        if let live = try currentlyPublished(), live != description {
            throw FixtureFailure()
        }
        try store(description)
        try record()
    }

    // Mac stand-in for the shim's restore after an additive publication: the
    // live description still carries the appended function, so the restore has
    // to name the one function it strips, that name must be last in the given
    // configuration, and what is left has to be the journaled original.
    func publish(_ description: Data, strippingFunction function: String,
                 configuration: Int) throws {
        guard let live = try currentlyPublished(),
              var plist = Self.fields(live),
              var configurations = plist["ConfigurationDescriptors"] as? [[String: Any]],
              (1...configurations.count).contains(configuration),
              var interfaces = configurations[configuration - 1]["Interfaces"] as? [String],
              interfaces.last == function else {
            // Exactly what the controller backend reports when the named
            // function is not the last interface of that configuration, or is
            // not there at all.
            throw USBRestoreCoordinatorError.appendedFunctionRejected
        }
        interfaces.removeLast()
        configurations[configuration - 1]["Interfaces"] = interfaces
        plist["ConfigurationDescriptors"] = configurations
        guard let original = Self.fields(description),
              NSDictionary(dictionary: plist).isEqual(to: original) else {
            throw FixtureFailure()
        }
        // The journaled original goes back byte for byte, never a re-encoding.
        try store(description)
        try record()
    }

    func validateAppending(_ description: Data, function: String, configuration: Int) throws {
        _ = try Self.appended(description, function: function, configuration: configuration)
    }

    // Mac stand-in for the shim's additive publication: append the name last
    // in the selected configuration's Interfaces and write the resulting
    // description where the test can compare it with the journaled original.
    // This file is never linked against the C shim, so the append is done with
    // plist serialization here.
    func publishAppending(_ description: Data, function: String, configuration: Int) throws {
        guard publishedPath != nil else { throw FixtureFailure() }
        let appended = try Self.appended(description, function: function,
                                         configuration: configuration)
        guard !failAppendingPublish else { throw FixtureFailure() }
        try store(appended)
        try record()
    }

    private static func fields(_ data: Data) -> [String: Any]? {
        (try? PropertyListSerialization.propertyList(
            from: data, options: [], format: nil)) as? [String: Any]
    }

    private static func appended(_ description: Data, function: String,
                                 configuration: Int) throws -> Data {
        guard var plist = fields(description),
              var configurations = plist["ConfigurationDescriptors"] as? [[String: Any]],
              (1...configurations.count).contains(configuration),
              !configurations.contains(where: {
                  ($0["Interfaces"] as? [String])?.contains(function) ?? false
              }) else {
            throw FixtureFailure()
        }
        var interfaces = configurations[configuration - 1]["Interfaces"] as? [String] ?? []
        interfaces.append(function)
        configurations[configuration - 1]["Interfaces"] = interfaces
        plist["ConfigurationDescriptors"] = configurations
        return try PropertyListSerialization.data(
            fromPropertyList: plist, format: .binary, options: 0)
    }

    private func currentlyPublished() throws -> Data? {
        guard let publishedPath else { return nil }
        return try? Data(contentsOf: URL(fileURLWithPath: publishedPath))
    }

    private func store(_ description: Data) throws {
        guard let publishedPath else { return }
        try description.write(to: URL(fileURLWithPath: publishedPath))
    }

    private func record() throws {
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
        let publishedPath = ProcessInfo.processInfo.environment["MAC2JB_U3_FIXTURE_APPENDED_FILE"]
        let selected = ProcessInfo.processInfo.environment["MAC2JB_U3_FIXTURE_SELECTED_CONFIGURATION"]
            .flatMap(Int.init)
        let service = try NativeUSBWatchdogService(
            publicationEnabled: true, stateDirectory: state,
            expectedOwner: geteuid(), currentIdentity: identity,
            controller: FileBackedController(
                eventPath: events,
                failAppendingPublish: ProcessInfo.processInfo
                    .environment["MAC2JB_FIXTURE_FAIL_APPENDING_PUBLISH"] == "1",
                publishedPath: publishedPath),
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
            }, selectedConfiguration: selected.map { value in { value } },
            unservedFunctions: unservedPath.map { path in {
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
