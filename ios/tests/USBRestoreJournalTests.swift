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
