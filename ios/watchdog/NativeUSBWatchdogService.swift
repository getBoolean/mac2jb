import CryptoKit
import Darwin
import Foundation

// The launchd-supervised native process is the only U2 controller/journal
// writer. Its socket is root-only, the no-op trial lease is 15 seconds, and
// publication is disabled unless the launch argument explicitly enables it.
// It never edits the stock USB configuration or SSH files.
enum NativeUSBWatchdogError: Error {
    case unsafeState, unavailable, invalidRequest, disabled
}

private struct NativeClock: USBMonotonicClock {
    var uptimeNanoseconds: UInt64 {
        UInt64(ProcessInfo.processInfo.systemUptime * 1_000_000_000)
    }
}

private final class NativeExternalVerifier: USBExternalRestoreVerifier {
    var suppliedProof: String?
    let snapshotProvider: () throws -> TargetUSBRestoreSnapshot

    init(snapshotProvider: @escaping () throws -> TargetUSBRestoreSnapshot) {
        self.snapshotProvider = snapshotProvider
    }

    func verifyRestored(_ recipe: USBRestoreRecipe) throws -> String {
        let current = try snapshotProvider()
        try recipe.validateAgainst(current.identity)
        guard Self.originalFieldsMatch(current.liveDescription,
                                       recipe.originalDescription),
              let suppliedProof,
              USBRestoreRecipe.isDigest(suppliedProof) else {
            throw NativeUSBWatchdogError.unavailable
        }
        return suppliedProof
    }

    private static func originalFieldsMatch(_ live: Data, _ original: Data) -> Bool {
        guard var current = (try? PropertyListSerialization.propertyList(
                    from: live, options: [], format: nil)) as? [String: Any],
              let saved = (try? PropertyListSerialization.propertyList(
                    from: original, options: [], format: nil)) as? [String: Any],
              saved.count == 16, saved["AllowMultipleCreates"] == nil else {
            return false
        }
        if current.count == 17 {
            guard let flag = current.removeValue(forKey: "AllowMultipleCreates") as? Bool,
                  flag else { return false }
        } else if current.count != 16 {
            return false
        }
        return NSDictionary(dictionary: current).isEqual(to: saved)
    }
}

final class NativeUSBWatchdogService {
    static let stateDirectory = "/var/jb/var/lib/mac2jb-u2-native"
    private static let leaseNanoseconds: UInt64 = 15_000_000_000

    private let stateDirectory: String
    private var socketPath: String { stateDirectory + "/broker.sock" }
    private let journal: USBRestoreJournal
    private let coordinator: USBRestoreCoordinator
    private let verifier: NativeExternalVerifier
    private let clock = NativeClock()
    private let publicationEnabled: Bool
    private let leaseNanoseconds: UInt64
    private let snapshotProvider: () throws -> TargetUSBRestoreSnapshot
    private let validateInMemory: (Data) throws -> Void
    private let controllerConfigured: (() throws -> Bool)?
    private let unservedFunctions: (() throws -> Set<String>)?
    private let restartOwner: ((String) throws -> Void)?
    private let healPolicy: USBFunctionHealPolicy
    private var lastHeal = "none"
    private var worker: Int32 = -1
    private var singleton: Int32 = -1
    private var listener: Int32 = -1

    convenience init(publicationEnabled: Bool) throws {
        guard geteuid() == 0 else { throw NativeUSBWatchdogError.unsafeState }
        let identity = try TargetUSBRestoreSnapshot.captureIdentity()
        #if MAC2JB_U2_CONTROLLER_CLONE
        #if MAC2JB_U2_NO_INITIAL_CYCLE
        let controller = try TargetUSBRestoreController(
            identity: identity, cycleBus: false, useControllerClone: true)
        let recoveryController = try TargetUSBRestoreController(
            identity: identity, cycleBus: true, useControllerClone: true)
        #else
        let controller = try TargetUSBRestoreController(
            identity: identity, cycleBus: true, useControllerClone: true)
        let recoveryController = controller
        #endif
        #elseif MAC2JB_U2_EXPLICIT_BUS_CYCLE
        let controller = try TargetUSBRestoreController(
            identity: identity, cycleBus: true)
        let recoveryController = controller
        #else
        let controller = try TargetUSBRestoreController(
            identity: identity, cycleBus: false)
        let recoveryController = controller
        #endif
        try self.init(
            publicationEnabled: publicationEnabled,
            stateDirectory: Self.stateDirectory, expectedOwner: 0,
            currentIdentity: identity, controller: controller,
            recoveryController: recoveryController,
            snapshotProvider: { try TargetUSBRestoreSnapshot.capture() },
            verificationSnapshotProvider: {
                try TargetUSBRestoreSnapshot.captureForVerification()
            },
            validateInMemory: { try controller.validateInMemory($0) },
            beforeRecovery: {
                try Self.waitForConfigured { try controller.isConfigured() }
            },
            controllerConfigured: { try controller.isConfigured() },
            unservedFunctions: { try controller.unservedFunctions() },
            restartOwner: { try USBFunctionOwnerRestarter.restart($0) },
            leaseNanoseconds: Self.leaseNanoseconds)
    }

    // Dependency injection is used by the separate Mac fixture executable.
    // The installed entry point above always binds root, the exact iPad
    // identity and the real controller backend.
    init(publicationEnabled: Bool, stateDirectory: String,
         expectedOwner: uid_t, currentIdentity: USBRestoreIdentity,
         controller: USBRestoreController,
         recoveryController: USBRestoreController? = nil,
         snapshotProvider: @escaping () throws -> TargetUSBRestoreSnapshot,
         verificationSnapshotProvider: @escaping () throws -> TargetUSBRestoreSnapshot,
         validateInMemory: @escaping (Data) throws -> Void,
         beforeRecovery: @escaping () throws -> Void,
         controllerConfigured: (() throws -> Bool)? = nil,
         unservedFunctions: (() throws -> Set<String>)? = nil,
         restartOwner: ((String) throws -> Void)? = nil,
         healPolicy: USBFunctionHealPolicy = USBFunctionHealPolicy(),
         leaseNanoseconds: UInt64) throws {
        guard geteuid() == expectedOwner else {
            throw NativeUSBWatchdogError.unsafeState
        }
        try Self.checkPrivateDirectory(stateDirectory, owner: expectedOwner)
        self.stateDirectory = stateDirectory
        self.snapshotProvider = snapshotProvider
        self.validateInMemory = validateInMemory
        self.controllerConfigured = controllerConfigured
        self.unservedFunctions = unservedFunctions
        self.restartOwner = restartOwner
        self.healPolicy = healPolicy
        verifier = NativeExternalVerifier(snapshotProvider: verificationSnapshotProvider)
        journal = USBRestoreJournal(directory: stateDirectory, expectedOwner: expectedOwner)
        coordinator = USBRestoreCoordinator(
            journal: journal, currentIdentity: currentIdentity,
            controller: controller, recoveryController: recoveryController,
            externalVerifier: verifier, clock: clock,
            beforeRecovery: beforeRecovery)
        self.publicationEnabled = publicationEnabled
        guard leaseNanoseconds > 0,
              leaseNanoseconds <= Self.leaseNanoseconds else {
            throw NativeUSBWatchdogError.unsafeState
        }
        self.leaseNanoseconds = leaseNanoseconds
    }

    private static func checkPrivateDirectory(_ path: String, owner: uid_t) throws {
        var info = stat()
        guard lstat(path, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == owner, info.st_mode & 0o777 == 0o700 else {
            throw NativeUSBWatchdogError.unsafeState
        }
    }

    private func currentRecord() throws -> USBRestoreRecord? {
        do {
            return try journal.read()
        } catch USBRestoreJournalError.io(ENOENT) {
            return nil
        }
    }

    private func phase() throws -> String {
        try currentRecord()?.phase.rawValue ?? "absent"
    }

    private func recoverAtStart() throws {
        guard let record = try currentRecord() else {
            clearStartHealCount()
            return
        }
        if record.phase == .recoveryRequired {
            // A previous instance died or gave up mid-recovery (for example a
            // jetsam kill during re-publication). Heal, bounded across restarts.
            autoHealAtStart()
            return
        }
        // A failed external comparison requires an explicit recovery decision.
        // A successful controller call awaiting proof must not be reissued on
        // a routine service restart. Only uncertain or pre-call phases recover.
        if record.phase != .restored && record.phase != .awaitingVerification &&
                record.phase != .recoveryRequired {
            settleBeforeRecovery(record.phase)
            do {
                try coordinator.recover()
            } catch {
                // Watchdog restart after a publication that never enumerated.
                autoHealAtStart()
            }
        }
    }

    // Persisted per journal so a crashing broker cannot re-publish forever.
    private var startHealPath: String { stateDirectory + "/heal-at-start.count" }

    private func clearStartHealCount() { _ = unlink(startHealPath) }

    private func autoHealAtStart() {
        let previous = (try? String(contentsOfFile: startHealPath, encoding: .utf8))
            .flatMap { Int($0.trimmingCharacters(in: .whitespacesAndNewlines)) } ?? 0
        guard previous < 3 else {
            lastHeal = "start-heal-limit-reached"
            return
        }
        try? String(previous + 1).write(toFile: startHealPath, atomically: true, encoding: .utf8)
        autoHeal()
    }

    private func settleBeforeRecovery(_ phase: USBRestorePhase) {
        #if MAC2JB_U2_SETTLED_RECOVERY
        // SetDescription and GoOffAndOnBus may return before the host has
        // finished the first enumeration. An immediately dead worker must
        // not overlap the restore cycle with that first cycle. This bound
        // also applies after launchd restarts a killed watchdog.
        if phase == .published {
            Thread.sleep(forTimeInterval: 5)
        }
        #endif
    }

    // A successful off/on-bus API return does not mean the host has completed
    // enumeration. Wait long enough to avoid reading a stale pre-cycle state,
    // then require three consecutive configured/on-bus registry snapshots.
    // A timeout prevents a second controller write and preserves the journal
    // for a deliberate recovery decision.
    static func waitForConfigured(check: () throws -> Bool) throws {
        Thread.sleep(forTimeInterval: 5)
        let deadline = ProcessInfo.processInfo.systemUptime + 10
        var consecutive = 0
        while ProcessInfo.processInfo.systemUptime < deadline {
            if (try? check()) == true {
                consecutive += 1
                if consecutive == 3 { return }
            } else {
                consecutive = 0
            }
            Thread.sleep(forTimeInterval: 0.25)
        }
        throw NativeUSBWatchdogError.unavailable
    }

    private func handle(_ command: String) throws -> String {
        if command == "status" {
            return "phase=\(try phase()) publication=" +
                (publicationEnabled ? "enabled" : "disabled")
        }
        #if MAC2JB_U2_CONTROLLER_CLONE
        if command == "validate-only" {
            guard publicationEnabled, try currentRecord() == nil else {
                throw NativeUSBWatchdogError.unsafeState
            }
            let snapshot = try snapshotProvider()
            try validateInMemory(snapshot.liveDescription)
            return "validated-in-memory"
        }
        #endif
        if command == "prepare" {
            guard publicationEnabled else { throw NativeUSBWatchdogError.disabled }
            let snapshot = try snapshotProvider()
            let digest = SHA256.hash(data: snapshot.liveDescription)
                .map { String(format: "%02x", $0) }.joined()
            let recipe = USBRestoreRecipe(
                schemaVersion: 1,
                productType: snapshot.identity.productType,
                osBuild: snapshot.identity.osBuild,
                controllerIdentity: snapshot.identity.controllerIdentity,
                bootSession: snapshot.identity.bootSession,
                sourceSHA256: snapshot.identity.sourceSHA256,
                originalDescription: snapshot.liveDescription,
                plannedDescriptionSHA256: digest)
            try validateInMemory(snapshot.liveDescription)
            let deadline = clock.uptimeNanoseconds + leaseNanoseconds
            try coordinator.prepare(recipe, leaseDeadlineUptime: deadline)
            return "prepared"
        }
        if command == "publish-noop" {
            guard publicationEnabled, worker >= 0 else {
                throw NativeUSBWatchdogError.disabled
            }
            guard let record = try currentRecord() else {
                throw NativeUSBWatchdogError.invalidRequest
            }
            try coordinator.publish(record.recipe.originalDescription)
            return "published"
        }
        if command == "restore" {
            guard let record = try currentRecord() else { return "already-clear" }
            if record.phase == .awaitingVerification {
                return "awaiting-verification"
            }
            try coordinator.recover()
            return "restore-issued"
        }
        // Host-requested one-shot re-publication after the Mac observed that
        // USB did not return (for example over pinned Wi-Fi SSH). Refused
        // unless publication is enabled, a configured-state reader exists and
        // the controller is not configured.
        if command == "restore-after-failure" {
            guard publicationEnabled, let controllerConfigured else {
                throw NativeUSBWatchdogError.disabled
            }
            try coordinator.recoverAfterExternalFailure(
                controllerConfigured: controllerConfigured)
            return "restore-after-failure-issued " + autoHeal()
        }
        // Host-requested heal without an initial publication: restart owners
        // and/or re-publish (bounded) until every function registers.
        if command == "heal" {
            guard publicationEnabled, let record = try currentRecord(),
                  record.phase == .awaitingVerification || record.phase == .recoveryRequired else {
                throw NativeUSBWatchdogError.invalidRequest
            }
            return autoHeal()
        }
        if command == "heal-status" {
            return "last-heal " + lastHeal
        }
        if command.hasPrefix("confirm ") {
            let proof = String(command.dropFirst("confirm ".count))
            guard USBRestoreRecipe.isDigest(proof) else {
                throw NativeUSBWatchdogError.invalidRequest
            }
            verifier.suppliedProof = proof
            defer { verifier.suppliedProof = nil }
            try coordinator.confirmExternalRestore()
            clearStartHealCount()
            return "verified-and-cleared"
        }
        throw NativeUSBWatchdogError.invalidRequest
    }

    private func workerClosed(neutral: Bool) {
        defer { worker = -1 }
        guard let record = try? currentRecord(),
              record.phase == .prepared || record.phase == .published else {
            return
        }
        do {
            settleBeforeRecovery(record.phase)
            try coordinator.recover()
        } catch {
            // The first publication did not enumerate (readiness gate timed
            // out, journal recoveryRequired). Heal automatically; the journal
            // remains for recovery on the next launch if healing gives up.
            _ = autoHeal()
        }
        _ = neutral  // U3 will verify the actual neutral HID report.
    }

    // Bounded automatic recovery (see USBFunctionRegistrationHealer). Never
    // confirms or clears the journal. Returns and records a one-line summary.
    @discardableResult
    private func autoHeal() -> String {
        guard publicationEnabled, let controllerConfigured, let unservedFunctions,
              let restartOwner else {
            lastHeal = "unavailable"
            return lastHeal
        }
        struct Probe: USBFunctionHealProbe {
            let configured: () throws -> Bool
            let unserved: () throws -> Set<String>
            let publish: () throws -> Void
            let restart: (String) throws -> Void
            func controllerConfigured() throws -> Bool { try configured() }
            func unservedFunctions() throws -> Set<String> { try unserved() }
            func republish() throws { try publish() }
            func restartOwner(_ label: String) throws { try restart(label) }
            func sleep(seconds: Double) { Thread.sleep(forTimeInterval: seconds) }
        }
        let coordinator = self.coordinator
        let probe = Probe(configured: controllerConfigured, unserved: unservedFunctions,
                          publish: { try coordinator.recoverAfterExternalFailure(
                              controllerConfigured: controllerConfigured) },
                          restart: restartOwner)
        do {
            let outcome = try USBFunctionRegistrationHealer(probe: probe, policy: healPolicy).heal()
            if case .configured = outcome, let record = try? currentRecord(),
               record.phase == .recoveryRequired {
                try coordinator.acceptConfiguredOriginal(controllerConfigured: controllerConfigured)
            }
            lastHeal = outcome.summary
        } catch {
            lastHeal = "heal-error"
        }
        NSLog("mac2jb-u2 %@", lastHeal)
        return lastHeal
    }

    private func takeSingleton() throws {
        let path = stateDirectory + "/broker.lock"
        singleton = open(path, O_RDWR | O_CREAT | O_NOFOLLOW, 0o600)
        guard singleton >= 0 else { throw NativeUSBWatchdogError.unsafeState }
        var info = stat()
        guard fstat(singleton, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == journal.expectedOwner, info.st_nlink == 1,
              info.st_mode & 0o777 == 0o600,
              flock(singleton, LOCK_EX | LOCK_NB) == 0 else {
            throw NativeUSBWatchdogError.unsafeState
        }
    }

    private func openSocket() throws {
        var info = stat()
        if lstat(socketPath, &info) == 0 {
            guard (info.st_mode & S_IFMT) == S_IFSOCK,
                  info.st_uid == journal.expectedOwner,
                  info.st_mode & 0o777 == 0o600 else {
                throw NativeUSBWatchdogError.unsafeState
            }
            guard unlink(socketPath) == 0 else {
                throw NativeUSBWatchdogError.unavailable
            }
        } else if errno != ENOENT {
            throw NativeUSBWatchdogError.unavailable
        }
        listener = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard listener >= 0 else { throw NativeUSBWatchdogError.unavailable }
        var address = sockaddr_un()
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(socketPath.utf8) + [0]
        guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
            throw NativeUSBWatchdogError.unavailable
        }
        withUnsafeMutableBytes(of: &address.sun_path) { destination in
            destination.copyBytes(from: bytes)
        }
        let oldMask = umask(0o177)
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        _ = umask(oldMask)
        guard result == 0,
              chmod(socketPath, 0o600) == 0,
              listen(listener, 4) == 0 else {
            throw NativeUSBWatchdogError.unavailable
        }
    }

    private func sendLine(_ line: String, to fd: Int32) {
        let bytes = Array((line + "\n").utf8)
        bytes.withUnsafeBytes { buffer in
            _ = Darwin.send(fd, buffer.baseAddress, buffer.count, 0)
        }
    }

    private func readLine(from fd: Int32) -> String? {
        var timeout = timeval(tv_sec: 1, tv_usec: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                       socklen_t(MemoryLayout<timeval>.size))
        var buffer = [UInt8](repeating: 0, count: 257)
        let count = buffer.withUnsafeMutableBytes {
            Darwin.recv(fd, $0.baseAddress, $0.count, 0)
        }
        guard count > 0, count <= 256,
              buffer[Int(count) - 1] == 10,
              let text = String(bytes: buffer[..<(Int(count) - 1)],
                                encoding: .ascii) else {
            return nil
        }
        return text
    }

    func run() throws -> Never {
        signal(SIGPIPE, SIG_IGN)
        try takeSingleton()
        try recoverAtStart()
        try openSocket()
        defer {
            if worker >= 0 { _ = close(worker) }
            if listener >= 0 { _ = close(listener) }
            _ = unlink(socketPath)
            if singleton >= 0 { _ = close(singleton) }
        }
        while true {
            var descriptors = [pollfd(fd: listener, events: Int16(POLLIN), revents: 0)]
            if worker >= 0 {
                descriptors.append(pollfd(fd: worker, events: Int16(POLLIN | POLLHUP),
                                          revents: 0))
            }
            let pollResult = descriptors.withUnsafeMutableBufferPointer {
                Darwin.poll($0.baseAddress, nfds_t($0.count), 250)
            }
            if pollResult < 0 && errno != EINTR {
                throw NativeUSBWatchdogError.unavailable
            }
            if worker >= 0 && descriptors.count == 2 && descriptors[1].revents != 0 {
                let message = readLine(from: worker)
                workerClosed(neutral: message == "neutral")
                _ = close(descriptors[1].fd)
            }
            if descriptors[0].revents & Int16(POLLIN) != 0 {
                let client = accept(listener, nil, nil)
                if client >= 0 {
                    let request = readLine(from: client)
                    if request == "watch",
                       worker < 0,
                       publicationEnabled,
                       (try? phase()) == USBRestorePhase.prepared.rawValue {
                        worker = client
                        sendLine("OK watching", to: client)
                    } else {
                        let response = (try? request.map(handle)) ?? nil
                        sendLine(response.map { "OK " + $0 } ?? "ERR rejected",
                                 to: client)
                        _ = close(client)
                    }
                }
            }
            if let record = try? currentRecord(),
               record.phase == .prepared || record.phase == .published {
                do {
                    _ = try coordinator.recoverIfLeaseExpired()
                } catch {
                    autoHeal()  // lease expired and the readiness gate timed out
                }
            }
        }
    }
}
