import Darwin
import CryptoKit
import Foundation

private struct Failure: Error {}

private func require(_ condition: Bool) throws {
    if !condition { throw Failure() }
}

private let fixtureDescription: Data = {
    let fields: [String: Any] = [
        "Attributes": 192, "BcdUSBVersion": 768, "ConfigurationDescriptors":
            (0..<9).map { ["Description": "fixture-\($0)", "Interfaces": []] },
        "DefaultBcdUSBVersion": 768, "MPS0": 9, "MaxPower": 112,
        "deviceClass": 0, "deviceID": 1, "deviceProtocol": 0,
        "deviceSubClass": 0, "manufacturerString": "fixture",
        "productID": 1, "productString": "fixture", "serialNumber": "fixture",
        "uniqueDeviceID": "fixture", "vendorID": 1,
    ]
    return try! PropertyListSerialization.data(
        fromPropertyList: fields, format: .binary, options: 0)
}()

private func recipe(boot: String = "boot-a") -> USBRestoreRecipe {
    let original = fixtureDescription
    let plannedHash = SHA256.hash(data: original)
        .map { String(format: "%02x", $0) }.joined()
    return USBRestoreRecipe(
        schemaVersion: 1,
        productType: "iPad14,5",
        osBuild: "21A329",
        controllerIdentity: "test-controller",
        bootSession: boot,
        sourceSHA256: String(repeating: "a", count: 64),
        originalDescription: original,
        plannedDescriptionSHA256: plannedHash
    )
}

private final class FakeController: USBRestoreController {
    var descriptions: [Data] = []
    func publish(_ description: Data) throws { descriptions.append(description) }
}

private final class CycleRecordingController: USBRestoreController {
    let explicitCycle: Bool
    let events: NSMutableArray

    init(explicitCycle: Bool, events: NSMutableArray) {
        self.explicitCycle = explicitCycle
        self.events = events
    }

    func publish(_ description: Data) throws {
        events.add("SetDescription")
        if explicitCycle { events.add("GoOffAndOnBus") }
    }
}

// Records every controller call in order, so a test can tell the three
// publication shapes apart: the bare original, the original plus one appended
// function, and the one-call re-publication of that same intended description.
private final class AppendingController: USBRestoreController {
    var calls: [String] = []
    var refuseIntended = false

    func publish(_ description: Data) throws { calls.append("publish") }

    func publish(_ description: Data, strippingFunction function: String,
                 configuration: Int) throws {
        calls.append("strip \(function)@\(configuration)")
    }

    func validateAppending(_ description: Data, function: String, configuration: Int) throws {
        calls.append("validate \(function)@\(configuration)")
    }

    func publishAppending(_ description: Data, function: String, configuration: Int) throws {
        calls.append("append \(function)@\(configuration)")
    }

    func republishAppending(_ description: Data, function: String, configuration: Int) throws {
        guard !refuseIntended else {
            throw USBRestoreCoordinatorError.additivePublicationUnsupported
        }
        calls.append("republish-append \(function)@\(configuration)")
    }
}

private final class FakeVerifier: USBExternalRestoreVerifier {
    var fails = false
    func verifyRestored(_ recipe: USBRestoreRecipe) throws -> String {
        if fails { throw Failure() }
        return String(repeating: "c", count: 64)
    }
}

private final class FakeClock: USBMonotonicClock {
    var uptimeNanoseconds: UInt64
    init(uptimeNanoseconds: UInt64) { self.uptimeNanoseconds = uptimeNanoseconds }
}

private func identity() -> USBRestoreIdentity {
    USBRestoreIdentity(productType: "iPad14,5", osBuild: "21A329",
                       controllerIdentity: "test-controller", bootSession: "boot-a",
                       sourceSHA256: String(repeating: "a", count: 64))
}

private func record(boot: String = "boot-a") -> USBRestoreRecord {
    USBRestoreRecord(recipe: recipe(boot: boot), phase: .prepared,
                     leaseDeadlineUptime: 100, externalVerificationSHA256: nil)
}

private func next(_ record: USBRestoreRecord, _ phase: USBRestorePhase) -> USBRestoreRecord {
    USBRestoreRecord(
        recipe: record.recipe, phase: phase,
        leaseDeadlineUptime: record.leaseDeadlineUptime,
        externalVerificationSHA256: phase == .restored ? String(repeating: "c", count: 64) : nil
    )
}

private func temporaryDirectory() throws -> String {
    var template = Array("/tmp/mac2jb-journal-XXXXXX".utf8CString)
    guard let path = mkdtemp(&template) else { throw Failure() }
    return String(cString: path)
}

@main
enum USBRestoreJournalTests {
    static func main() throws {
        try canonicalAndValidation()
        try identityBinding()
        try createAndRead()
        try transitionAndRemoval()
        try preparedRecoveryMakesNoControllerWrite()
        try recoveryWaitsForReadiness()
        try noInitialCycleFailsClosedWithoutArrival()
        try leaseExpiryRestores()
        try renewalIsItsOwnJournalOperation()
        try renewalMovesForwardAndIsCapped()
        try healingALivePublicationKeepsTheAppendedFunction()
        try coordinatorRestoresAndRetainsFailure()
        try rejectUnsafeFile()
        try rejectSymlinkFile()
        try rejectUnsafeDirectory()
        try rejectCorruption()
        print("PASS USBRestoreJournal tests")
    }

    private static func canonicalAndValidation() throws {
        let first = try USBRestoreJournal.canonical(record())
        try require(first == USBRestoreJournal.canonical(record()))
        do {
            _ = try USBRestoreJournal.canonical(record(boot: ""))
            throw Failure()
        } catch USBRestoreJournalError.invalidRecipe {}
        let malformed = USBRestoreRecipe(
            schemaVersion: 1, productType: "iPad14,5", osBuild: "21A329",
            controllerIdentity: "test-controller", bootSession: "boot-a",
            sourceSHA256: String(repeating: "a", count: 64),
            originalDescription: Data("bplist00broken".utf8),
            plannedDescriptionSHA256: String(repeating: "b", count: 64))
        do { try malformed.validate(); throw Failure() }
        catch USBRestoreJournalError.invalidRecipe {}
    }

    private static func identityBinding() throws {
        let current = USBRestoreIdentity(
            productType: "iPad14,5", osBuild: "21A329",
            controllerIdentity: "test-controller", bootSession: "boot-a",
            sourceSHA256: String(repeating: "a", count: 64)
        )
        try recipe().validateAgainst(current)
        do { try recipe(boot: "old-boot").validateAgainst(current); throw Failure() }
        catch USBRestoreJournalError.identityMismatch {}
        let wrongBuild = USBRestoreIdentity(
            productType: current.productType, osBuild: "other-build",
            controllerIdentity: current.controllerIdentity,
            bootSession: current.bootSession, sourceSHA256: current.sourceSHA256)
        do { try recipe().validateAgainst(wrongBuild); throw Failure() }
        catch USBRestoreJournalError.identityMismatch {}
        let wrongController = USBRestoreIdentity(
            productType: current.productType, osBuild: current.osBuild,
            controllerIdentity: "other-controller",
            bootSession: current.bootSession, sourceSHA256: current.sourceSHA256)
        do { try recipe().validateAgainst(wrongController); throw Failure() }
        catch USBRestoreJournalError.identityMismatch {}
    }

    private static func createAndRead() throws {
        let path = try temporaryDirectory()
        defer { _ = unlink(path + "/" + USBRestoreJournal.filename); _ = rmdir(path) }
        let journal = USBRestoreJournal(directory: path, expectedOwner: getuid())
        try journal.create(record())
        try require(try journal.read() == record())
        do {
            try journal.create(record(boot: "boot-b"))
            throw Failure()
        } catch USBRestoreJournalError.alreadyExists {}
        try require(try journal.read() == record())
    }

    private static func transitionAndRemoval() throws {
        let path = try temporaryDirectory()
        defer {
            _ = unlink(path + "/" + USBRestoreJournal.filename)
            _ = unlink(path + "/.restore-journal.lock")
            _ = rmdir(path)
        }
        let journal = USBRestoreJournal(directory: path, expectedOwner: getuid())
        let prepared = record()
        let published = next(prepared, .published)
        let restoring = next(prepared, .restoring)
        let awaiting = next(prepared, .awaitingVerification)
        let restored = next(prepared, .restored)
        try journal.create(prepared)
        do { try journal.transition(from: prepared, to: restored); throw Failure() }
        catch USBRestoreJournalError.invalidTransition {}
        try journal.transition(from: prepared, to: published)
        do { try journal.transition(from: prepared, to: restoring); throw Failure() }
        catch USBRestoreJournalError.changed {}
        try journal.transition(from: published, to: restoring)
        do { try journal.transition(from: restoring, to: restored); throw Failure() }
        catch USBRestoreJournalError.invalidTransition {}
        try journal.transition(from: restoring, to: awaiting)
        try journal.transition(from: awaiting, to: restored)
        try require(try journal.read() == restored)
        try journal.removeAfterVerification(restored)
        do { _ = try journal.read(); throw Failure() }
        catch USBRestoreJournalError.io(ENOENT) {}
    }

    private static func coordinatorRestoresAndRetainsFailure() throws {
        let path = try temporaryDirectory()
        defer {
            _ = unlink(path + "/" + USBRestoreJournal.filename)
            _ = unlink(path + "/.restore-journal.lock")
            _ = rmdir(path)
        }
        let journal = USBRestoreJournal(directory: path, expectedOwner: getuid())
        let controller = FakeController()
        let verifier = FakeVerifier()
        let coordinator = USBRestoreCoordinator(
            journal: journal, currentIdentity: identity(),
            controller: controller, externalVerifier: verifier,
            clock: FakeClock(uptimeNanoseconds: 10), beforeRecovery: {}
        )
        try coordinator.prepare(recipe(), leaseDeadlineUptime: 100)
        do { try coordinator.publish(Data("wrong".utf8)); throw Failure() }
        catch USBRestoreCoordinatorError.plannedDescriptionMismatch {}
        try require(controller.descriptions.isEmpty)
        try coordinator.publish(recipe().originalDescription)
        try coordinator.recover()
        try require(try journal.read().phase == .awaitingVerification)
        try coordinator.recover()
        try require(controller.descriptions.count == 2)
        verifier.fails = true
        do { try coordinator.confirmExternalRestore(); throw Failure() }
        catch is Failure {}
        try require(try journal.read().phase == .recoveryRequired)
        verifier.fails = false
        try coordinator.recover()
        try require(try journal.read().phase == .awaitingVerification)
        try coordinator.confirmExternalRestore()
        try require(controller.descriptions.count == 3)
        try require(controller.descriptions[1] == recipe().originalDescription)
        do { _ = try journal.read(); throw Failure() }
        catch USBRestoreJournalError.io(ENOENT) {}
    }

    private static func preparedRecoveryMakesNoControllerWrite() throws {
        let path = try temporaryDirectory()
        defer {
            _ = unlink(path + "/" + USBRestoreJournal.filename)
            _ = unlink(path + "/.restore-journal.lock")
            _ = rmdir(path)
        }
        let journal = USBRestoreJournal(directory: path, expectedOwner: getuid())
        let controller = FakeController()
        let coordinator = USBRestoreCoordinator(
            journal: journal, currentIdentity: identity(),
            controller: controller, externalVerifier: FakeVerifier(),
            clock: FakeClock(uptimeNanoseconds: 10), beforeRecovery: {}
        )
        try coordinator.prepare(recipe(), leaseDeadlineUptime: 100)
        try coordinator.recover()
        try require(controller.descriptions.isEmpty)
        try require(try journal.read().phase == .awaitingVerification)
        try coordinator.confirmExternalRestore()
    }

    private static func recoveryWaitsForReadiness() throws {
        let path = try temporaryDirectory()
        defer {
            _ = unlink(path + "/" + USBRestoreJournal.filename)
            _ = unlink(path + "/.restore-journal.lock")
            _ = rmdir(path)
        }
        let journal = USBRestoreJournal(directory: path, expectedOwner: getuid())
        let controller = FakeController()
        var ready = false
        let coordinator = USBRestoreCoordinator(
            journal: journal, currentIdentity: identity(),
            controller: controller, externalVerifier: FakeVerifier(),
            clock: FakeClock(uptimeNanoseconds: 10),
            beforeRecovery: { if !ready { throw Failure() } }
        )
        try coordinator.prepare(recipe(), leaseDeadlineUptime: 100)
        try coordinator.publish(recipe().originalDescription)
        do { try coordinator.recover(); throw Failure() }
        catch is Failure {}
        try require(controller.descriptions.count == 1)
        try require(try journal.read().phase == .recoveryRequired)
        ready = true
        try coordinator.recover()
        try require(controller.descriptions.count == 2)
        try require(try journal.read().phase == .awaitingVerification)
    }

    private static func noInitialCycleFailsClosedWithoutArrival() throws {
        let path = try temporaryDirectory()
        defer {
            _ = unlink(path + "/" + USBRestoreJournal.filename)
            _ = unlink(path + "/.restore-journal.lock")
            _ = rmdir(path)
        }
        let journal = USBRestoreJournal(directory: path, expectedOwner: getuid())
        let events = NSMutableArray()
        let initial = CycleRecordingController(explicitCycle: false, events: events)
        let recovery = CycleRecordingController(explicitCycle: true, events: events)
        var firstArrivalObserved = false
        let coordinator = USBRestoreCoordinator(
            journal: journal, currentIdentity: identity(), controller: initial,
            recoveryController: recovery, externalVerifier: FakeVerifier(),
            clock: FakeClock(uptimeNanoseconds: 10),
            beforeRecovery: { if !firstArrivalObserved { throw Failure() } }
        )
        try coordinator.prepare(recipe(), leaseDeadlineUptime: 100)
        try coordinator.publish(recipe().originalDescription)
        try require(events as? [String] == ["SetDescription"])
        do { try coordinator.recover(); throw Failure() }
        catch is Failure {}
        try require(events as? [String] == ["SetDescription"])
        try require(try journal.read().phase == .recoveryRequired)
        do { try coordinator.confirmExternalRestore(); throw Failure() }
        catch USBRestoreCoordinatorError.recoveryRequired {}
        try require(try journal.read().phase == .recoveryRequired)
        firstArrivalObserved = true
        try coordinator.recover()
        try require(events as? [String] == [
            "SetDescription", "SetDescription", "GoOffAndOnBus"
        ])
        try require(try journal.read().phase == .awaitingVerification)
    }

    private static func leaseExpiryRestores() throws {
        let path = try temporaryDirectory()
        defer {
            _ = unlink(path + "/" + USBRestoreJournal.filename)
            _ = unlink(path + "/.restore-journal.lock")
            _ = rmdir(path)
        }
        let journal = USBRestoreJournal(directory: path, expectedOwner: getuid())
        let controller = FakeController()
        let clock = FakeClock(uptimeNanoseconds: 10)
        let coordinator = USBRestoreCoordinator(
            journal: journal, currentIdentity: identity(),
            controller: controller, externalVerifier: FakeVerifier(), clock: clock,
            beforeRecovery: {}
        )
        try coordinator.prepare(recipe(), leaseDeadlineUptime: 100)
        try coordinator.publish(recipe().originalDescription)
        try require(try !coordinator.recoverIfLeaseExpired())
        clock.uptimeNanoseconds = 100
        try require(try coordinator.recoverIfLeaseExpired())
        try require(controller.descriptions.count == 2)
        try require(try journal.read().phase == .awaitingVerification)
        try coordinator.confirmExternalRestore()
    }

    // Renewal is the only change to a live record that is not a phase change,
    // and it has to stay that way: transition() must keep refusing any change
    // to the deadline, and the renewal operation must change nothing else.
    private static func renewalIsItsOwnJournalOperation() throws {
        let path = try temporaryDirectory()
        defer {
            _ = unlink(path + "/" + USBRestoreJournal.filename)
            _ = unlink(path + "/.restore-journal.lock")
            _ = rmdir(path)
        }
        let journal = USBRestoreJournal(directory: path, expectedOwner: getuid())
        let prepared = record()
        try journal.create(prepared)
        // A phase change that also moves the deadline is still refused.
        do {
            try journal.transition(from: prepared, to: USBRestoreRecord(
                recipe: prepared.recipe, phase: .published,
                leaseDeadlineUptime: 200, externalVerificationSHA256: nil))
            throw Failure()
        } catch USBRestoreJournalError.invalidTransition {}
        // Only forward.
        for deadline in [UInt64(99), 100] {
            do { try journal.extendLease(from: prepared, to: deadline); throw Failure() }
            catch USBRestoreJournalError.invalidTransition {}
        }
        try journal.extendLease(from: prepared, to: 200)
        let renewed = try journal.read()
        try require(renewed.leaseDeadlineUptime == 200)
        try require(renewed.recipe == prepared.recipe)
        try require(renewed.phase == .prepared)
        try require(renewed.externalVerificationSHA256 == nil)
        try require(renewed.appendedFunctionName == nil)
        // A stale expectation cannot renew: the record it read is gone.
        do { try journal.extendLease(from: prepared, to: 300); throw Failure() }
        catch USBRestoreJournalError.changed {}
        // A published record renews too, and keeps the function it appended.
        let published = USBRestoreRecord(
            recipe: renewed.recipe, phase: .published,
            leaseDeadlineUptime: renewed.leaseDeadlineUptime,
            externalVerificationSHA256: nil,
            appendedFunctionName: "Mac2jbCanary", appendedFunctionConfiguration: 5)
        try journal.transition(from: renewed, to: published)
        try journal.extendLease(from: published, to: 400)
        let again = try journal.read()
        try require(again.leaseDeadlineUptime == 400)
        try require(again.appendedFunctionName == "Mac2jbCanary")
        try require(again.appendedFunctionConfiguration == 5)
        try require(again.phase == .published)
        // No lease applies once the original is going back.
        let restoring = USBRestoreRecord(
            recipe: again.recipe, phase: .restoring,
            leaseDeadlineUptime: again.leaseDeadlineUptime,
            externalVerificationSHA256: nil,
            appendedFunctionName: again.appendedFunctionName,
            appendedFunctionConfiguration: again.appendedFunctionConfiguration)
        try journal.transition(from: again, to: restoring)
        do { try journal.extendLease(from: restoring, to: 500); throw Failure() }
        catch USBRestoreJournalError.invalidTransition {}
        try require(try journal.read().leaseDeadlineUptime == 400)
    }

    private static func renewalMovesForwardAndIsCapped() throws {
        let path = try temporaryDirectory()
        defer {
            _ = unlink(path + "/" + USBRestoreJournal.filename)
            _ = unlink(path + "/.restore-journal.lock")
            _ = rmdir(path)
        }
        let second: UInt64 = 1_000_000_000
        let journal = USBRestoreJournal(directory: path, expectedOwner: getuid())
        let clock = FakeClock(uptimeNanoseconds: second)
        let coordinator = USBRestoreCoordinator(
            journal: journal, currentIdentity: identity(),
            controller: FakeController(), externalVerifier: FakeVerifier(),
            clock: clock, beforeRecovery: {})
        let quantum = USBRestoreCoordinator.maxLeaseQuantumNanoseconds
        let granted = clock.uptimeNanoseconds
        let cap = granted + USBRestoreCoordinator.maxPublicationLifeNanoseconds
        try coordinator.prepare(recipe(), leaseDeadlineUptime: granted + quantum)
        // Nothing has elapsed, so the deadline cannot move: a renewal that
        // would not extend anything is refused rather than rewritten.
        do {
            _ = try coordinator.renewLease(grantedUptime: granted, quantum: quantum)
            throw Failure()
        } catch USBRestoreCoordinatorError.leaseCapReached {}
        // A quantum larger than one lease is refused however it is asked for.
        clock.uptimeNanoseconds = 11 * second
        do {
            _ = try coordinator.renewLease(grantedUptime: granted, quantum: quantum + 1)
            throw Failure()
        } catch USBRestoreCoordinatorError.leaseExpired {}
        do {
            _ = try coordinator.renewLease(grantedUptime: granted, quantum: 0)
            throw Failure()
        } catch USBRestoreCoordinatorError.leaseExpired {}
        try require(try journal.read().leaseDeadlineUptime == granted + quantum)
        // A live worker moves the deadline out, one quantum at a time.
        try require(try coordinator.renewLease(grantedUptime: granted,
                                               quantum: quantum) == 11 * second + quantum)
        try require(try journal.read().leaseDeadlineUptime == 11 * second + quantum)
        try require(try !coordinator.recoverIfLeaseExpired())
        // However many renewals arrive, the total life of one publication is
        // capped, and the last renewal lands exactly on the cap.
        var last = 11 * second + quantum
        for step in stride(from: UInt64(36), through: 161, by: 25) {
            clock.uptimeNanoseconds = step * second
            try require(clock.uptimeNanoseconds < last)  // renewed before expiry
            last = try coordinator.renewLease(grantedUptime: granted, quantum: quantum)
            try require(last == min(step * second + quantum, cap))
            try require(last <= cap)
        }
        try require(last == cap)
        clock.uptimeNanoseconds = 170 * second
        for _ in 0..<3 {
            do {
                _ = try coordinator.renewLease(grantedUptime: granted, quantum: quantum)
                throw Failure()
            } catch USBRestoreCoordinatorError.leaseCapReached {}
        }
        try require(try journal.read().leaseDeadlineUptime == cap)
        // A lease that has run out is not renewable: the watchdog is entitled
        // to be restoring it already.
        clock.uptimeNanoseconds = cap
        do {
            _ = try coordinator.renewLease(grantedUptime: granted, quantum: quantum)
            throw Failure()
        } catch USBRestoreCoordinatorError.leaseExpired {}
        try require(try coordinator.recoverIfLeaseExpired())
        // And no lease applies once the original is going back.
        do {
            _ = try coordinator.renewLease(grantedUptime: granted, quantum: quantum)
            throw Failure()
        } catch USBRestoreCoordinatorError.leaseExpired {}
        try coordinator.confirmExternalRestore()
        // With no journal at all there is nothing to renew.
        do {
            _ = try coordinator.renewLease(grantedUptime: granted, quantum: quantum)
            throw Failure()
        } catch USBRestoreJournalError.io(ENOENT) {}
    }

    // A heal that is bringing the bus back during a live publication must put
    // the intended description back, not the bare original: the appended
    // function is the thing the publication exists to make observable. Every
    // path that is genuinely restoring still strips it.
    private static func healingALivePublicationKeepsTheAppendedFunction() throws {
        let path = try temporaryDirectory()
        defer {
            _ = unlink(path + "/" + USBRestoreJournal.filename)
            _ = unlink(path + "/.restore-journal.lock")
            _ = rmdir(path)
        }
        let journal = USBRestoreJournal(directory: path, expectedOwner: getuid())
        let controller = AppendingController()
        let clock = FakeClock(uptimeNanoseconds: 10)
        let deadline: UInt64 = 10 + USBRestoreCoordinator.maxLeaseQuantumNanoseconds
        let coordinator = USBRestoreCoordinator(
            journal: journal, currentIdentity: identity(), controller: controller,
            externalVerifier: FakeVerifier(), clock: clock, beforeRecovery: {})
        try coordinator.prepare(recipe(), leaseDeadlineUptime: deadline)
        try coordinator.publishAdditive(function: "Mac2jbCanary", configuration: 5)
        try require(controller.calls == ["validate Mac2jbCanary@5",
                                         "append Mac2jbCanary@5"])
        // Never over a working connection, the same rule every other
        // re-publication applies.
        do {
            try coordinator.republishIntended(controllerConfigured: { true })
            throw Failure()
        } catch USBRestoreCoordinatorError.recoveryRequired {}
        try coordinator.republishIntended(controllerConfigured: { false })
        try require(controller.calls.last == "republish-append Mac2jbCanary@5")
        // It is not a restore: the phase, the deadline and the recorded
        // function are all untouched, so a crash here still restores.
        let live = try journal.read()
        try require(live.phase == .published)
        try require(live.leaseDeadlineUptime == deadline)
        try require(live.appendedFunctionName == "Mac2jbCanary")
        // A backend that cannot re-publish the intended description says so
        // and changes nothing, so the caller can fall back to restoring.
        controller.refuseIntended = true
        do {
            try coordinator.republishIntended(controllerConfigured: { false })
            throw Failure()
        } catch USBRestoreCoordinatorError.additivePublicationUnsupported {}
        try require(try journal.read() == live)
        controller.refuseIntended = false
        // Once the lease is gone the intended description is refused and the
        // bare original goes back.
        clock.uptimeNanoseconds = deadline
        do {
            try coordinator.republishIntended(controllerConfigured: { false })
            throw Failure()
        } catch USBRestoreCoordinatorError.recoveryRequired {}
        try require(try coordinator.recoverIfLeaseExpired())
        try require(controller.calls.last == "strip Mac2jbCanary@5")
        try require(try journal.read().phase == .awaitingVerification)
        try require(try journal.read().appendedFunctionName == nil)
    }

    private static func rejectUnsafeFile() throws {
        let path = try temporaryDirectory()
        defer { _ = unlink(path + "/" + USBRestoreJournal.filename); _ = rmdir(path) }
        let journal = USBRestoreJournal(directory: path, expectedOwner: getuid())
        try journal.create(record())
        try require(chmod(path + "/" + USBRestoreJournal.filename, 0o644) == 0)
        do { _ = try journal.read(); throw Failure() }
        catch USBRestoreJournalError.unsafeFile {}
    }

    private static func rejectSymlinkFile() throws {
        let path = try temporaryDirectory()
        let outside = try temporaryDirectory()
        defer {
            _ = unlink(path + "/" + USBRestoreJournal.filename)
            _ = rmdir(path)
            _ = unlink(outside + "/target")
            _ = rmdir(outside)
        }
        let target = outside + "/target"
        try Data("private".utf8).write(to: URL(fileURLWithPath: target))
        try require(symlink(target, path + "/" + USBRestoreJournal.filename) == 0)
        let journal = USBRestoreJournal(directory: path, expectedOwner: getuid())
        do { _ = try journal.read(); throw Failure() }
        catch USBRestoreJournalError.io(ELOOP) {}
        do { try journal.create(record()); throw Failure() }
        catch USBRestoreJournalError.alreadyExists {}
    }

    private static func rejectUnsafeDirectory() throws {
        let path = try temporaryDirectory()
        defer { _ = chmod(path, 0o700); _ = rmdir(path) }
        let wrongOwner = USBRestoreJournal(directory: path,
                                           expectedOwner: getuid() &+ 1)
        do { try wrongOwner.create(record()); throw Failure() }
        catch USBRestoreJournalError.unsafeDirectory {}
        let journal = USBRestoreJournal(directory: path, expectedOwner: getuid())
        try require(chmod(path, 0o755) == 0)
        do { try journal.create(record()); throw Failure() }
        catch USBRestoreJournalError.unsafeDirectory {}
    }

    private static func rejectCorruption() throws {
        let path = try temporaryDirectory()
        defer { _ = unlink(path + "/" + USBRestoreJournal.filename); _ = rmdir(path) }
        let journal = USBRestoreJournal(directory: path, expectedOwner: getuid())
        try journal.create(record())
        let file = path + "/" + USBRestoreJournal.filename
        let data = try Data(contentsOf: URL(fileURLWithPath: file))
        try Data(data.dropLast()).write(to: URL(fileURLWithPath: file))
        do { _ = try journal.read(); throw Failure() }
        catch USBRestoreJournalError.corrupt {}
    }
}
