import CryptoKit
import Foundation

// This is the watchdog's state machine. The controller and external verifier
// are injected so the fault path can be exercised without a USB mutation.
protocol USBRestoreController {
    func publish(_ description: Data) throws
    // Publish the journaled original after an additive publication: the live
    // description still carries the appended function, so the restore names the
    // one function the backend must strip before it can prove the description
    // it is about to publish is the journaled original.
    func publish(_ description: Data, strippingFunction: String, configuration: Int) throws
    // Build and check the appended description without writing the controller
    // or the bus, so a refused name or configuration costs nothing.
    func validateAppending(_ description: Data, function: String, configuration: Int) throws
    // Publish the journaled original with one named function appended last in
    // the given configuration. The appended description is built from live
    // controller state inside the controller backend, so it never exists as
    // bytes here.
    func publishAppending(_ description: Data, function: String, configuration: Int) throws
}

extension USBRestoreController {
    // Only the device controller backend can build an appended description or
    // take one apart again. Every other conformer refuses rather than
    // publishing something unchecked.
    func publish(_ description: Data, strippingFunction: String, configuration: Int) throws {
        throw USBRestoreCoordinatorError.additivePublicationUnsupported
    }

    func validateAppending(_ description: Data, function: String, configuration: Int) throws {
        throw USBRestoreCoordinatorError.additivePublicationUnsupported
    }

    func publishAppending(_ description: Data, function: String, configuration: Int) throws {
        throw USBRestoreCoordinatorError.additivePublicationUnsupported
    }
}

protocol USBExternalRestoreVerifier {
    // Return a digest of the independent host-side comparison evidence only
    // after the original descriptors, functions, and connections match.
    func verifyRestored(_ recipe: USBRestoreRecipe) throws -> String
}

protocol USBMonotonicClock {
    var uptimeNanoseconds: UInt64 { get }
}

enum USBRestoreCoordinatorError: Error {
    case leaseExpired, plannedDescriptionMismatch, recoveryRequired
    case additivePublicationUnsupported
    // The backend would not take the recorded appended function off the live
    // description: it is not the last interface of that configuration, or it
    // is not there at all because the publication never reached the bus.
    case appendedFunctionRejected
}

struct USBRestoreCoordinator {
    let journal: USBRestoreJournal
    let currentIdentity: USBRestoreIdentity
    let controller: USBRestoreController
    let recoveryController: USBRestoreController
    let externalVerifier: USBExternalRestoreVerifier
    let clock: USBMonotonicClock
    let beforeRecovery: () throws -> Void

    init(journal: USBRestoreJournal, currentIdentity: USBRestoreIdentity,
         controller: USBRestoreController, recoveryController: USBRestoreController? = nil,
         externalVerifier: USBExternalRestoreVerifier, clock: USBMonotonicClock,
         beforeRecovery: @escaping () throws -> Void) {
        self.journal = journal
        self.currentIdentity = currentIdentity
        self.controller = controller
        self.recoveryController = recoveryController ?? controller
        self.externalVerifier = externalVerifier
        self.clock = clock
        self.beforeRecovery = beforeRecovery
    }

    func prepare(_ recipe: USBRestoreRecipe, leaseDeadlineUptime: UInt64) throws {
        try recipe.validateAgainst(currentIdentity)
        let originalDigest = SHA256.hash(data: recipe.originalDescription)
            .map { String(format: "%02x", $0) }.joined()
        guard recipe.plannedDescriptionSHA256 == originalDigest else {
            throw USBRestoreCoordinatorError.plannedDescriptionMismatch
        }
        let now = clock.uptimeNanoseconds
        guard now < leaseDeadlineUptime,
              leaseDeadlineUptime - now <= 30_000_000_000 else {
            throw USBRestoreCoordinatorError.leaseExpired
        }
        try journal.create(USBRestoreRecord(
            recipe: recipe, phase: .prepared,
            leaseDeadlineUptime: leaseDeadlineUptime,
            externalVerificationSHA256: nil
        ))
    }

    func publish(_ plannedDescription: Data) throws {
        let prepared = try journal.read()
        try prepared.recipe.validateAgainst(currentIdentity)
        guard prepared.phase == .prepared,
              clock.uptimeNanoseconds < prepared.leaseDeadlineUptime else {
            throw USBRestoreCoordinatorError.leaseExpired
        }
        let digest = SHA256.hash(data: plannedDescription)
            .map { String(format: "%02x", $0) }.joined()
        guard digest == prepared.recipe.plannedDescriptionSHA256 else {
            throw USBRestoreCoordinatorError.plannedDescriptionMismatch
        }
        guard plannedDescription == prepared.recipe.originalDescription else {
            throw USBRestoreCoordinatorError.plannedDescriptionMismatch
        }
        // The durable phase change precedes the controller call. A crash at
        // either side of that call therefore leads the watchdog to restore.
        try journal.transition(from: prepared, to: changed(prepared, .published))
        do {
            try controller.publish(plannedDescription)
        } catch {
            try? recover()
            throw error
        }
    }

    // Publish the original plus one appended function. The recipe's
    // plannedDescriptionSHA256 stays the digest of the unmodified original and
    // the journal keeps byte-equal original bytes: for an additive publication
    // that field is the restore target, not the bytes on the bus, because the
    // appended description is built inside the shim from live controller state
    // and never materializes as bytes in Swift. Every failure path restores
    // recipe.originalDescription exactly as the no-op path does.
    func publishAdditive(function: String, configuration: Int) throws {
        let prepared = try journal.read()
        try prepared.recipe.validateAgainst(currentIdentity)
        guard prepared.phase == .prepared,
              clock.uptimeNanoseconds < prepared.leaseDeadlineUptime else {
            throw USBRestoreCoordinatorError.leaseExpired
        }
        // A name or configuration the backend refuses writes nothing, so it
        // must be refused before the durable phase change: a published record
        // forces a full restore swap, and that swap re-runs the function
        // registration race the no-op trials characterised.
        try controller.validateAppending(prepared.recipe.originalDescription,
                                        function: function,
                                        configuration: configuration)
        // The appended function is recorded in the same durable write that
        // moves the phase to published, so a watchdog that dies either side of
        // the controller call still knows what restore has to strip.
        try journal.transition(from: prepared, to: USBRestoreRecord(
            recipe: prepared.recipe, phase: .published,
            leaseDeadlineUptime: prepared.leaseDeadlineUptime,
            externalVerificationSHA256: nil,
            appendedFunctionName: function,
            appendedFunctionConfiguration: configuration))
        do {
            try controller.publishAppending(prepared.recipe.originalDescription,
                                            function: function,
                                            configuration: configuration)
        } catch {
            try? recover()
            throw error
        }
    }

    // Restore the journaled original, stating the one appended function when
    // the record carries one. A record with no appended function publishes
    // exactly as it always has.
    //
    // One bounded fallback, no loop: the function is recorded before the
    // controller call, so a call that failed with nothing written leaves a
    // record naming a function the bus does not have, and the strip is refused.
    // Publishing the original unchanged then recovers, and it recovers whether
    // or not a failed write can ever have partially applied, which nothing here
    // can know. It cannot lose an interface either: a plain publication is
    // refused unless the live description already is the journaled original.
    private func restoreOriginal(_ record: USBRestoreRecord) throws {
        guard let function = record.appendedFunctionName,
              let configuration = record.appendedFunctionConfiguration else {
            try recoveryController.publish(record.recipe.originalDescription)
            return
        }
        do {
            try recoveryController.publish(record.recipe.originalDescription,
                                           strippingFunction: function,
                                           configuration: configuration)
        } catch USBRestoreCoordinatorError.appendedFunctionRejected {
            NSLog("mac2jb restore: appended function not on the bus, retrying without it")
            try recoveryController.publish(record.recipe.originalDescription)
            NSLog("mac2jb restore: published the journaled original unchanged")
        }
    }

    @discardableResult
    func recoverIfLeaseExpired() throws -> Bool {
        let current = try journal.read()
        try current.recipe.validateAgainst(currentIdentity)
        guard current.phase == .prepared || current.phase == .published,
              clock.uptimeNanoseconds >= current.leaseDeadlineUptime else {
            return false
        }
        try recover()
        return true
    }

    func recover() throws {
        let current = try journal.read()
        try current.recipe.validateAgainst(currentIdentity)
        let publicationMayHaveStarted = current.phase != .prepared
        switch current.phase {
        case .restored, .awaitingVerification:
            return
        case .prepared, .published, .recoveryRequired:
            try journal.transition(from: current, to: changed(current, .restoring))
        case .restoring:
            break
        }
        // The journal enters published before the controller call, so a
        // prepared record cannot represent a controller write by this broker.
        if !publicationMayHaveStarted {
            let restoring = try journal.read()
            try journal.transition(from: restoring,
                                   to: changed(restoring, .awaitingVerification))
            return
        }
        // An API success is not proof that the first USB enumeration has
        // completed. Every path to a second controller publication, including
        // worker death, lease expiry, explicit restore and launchd restart,
        // must pass the same readiness gate.
        do {
            try beforeRecovery()
        } catch {
            if let latest = try? journal.read(), latest.phase == .restoring {
                try? journal.transition(from: latest, to: changed(latest, .recoveryRequired))
            }
            throw error
        }
        do {
            try restoreOriginal(current)
            let restoring = try journal.read()
            try journal.transition(from: restoring,
                                   to: changed(restoring, .awaitingVerification))
        } catch {
            if let latest = try? journal.read(), latest.phase == .restoring {
                try? journal.transition(from: latest, to: changed(latest, .recoveryRequired))
            }
            throw error
        }
    }

    // Operator-requested re-publication after the host has observed that USB
    // did not return. The readiness gate cannot apply: it waits for a first
    // enumeration that has already failed. The controller must read as not
    // configured, so a working connection is never republished. The journal
    // still ends in awaitingVerification and needs independent host proof.
    func recoverAfterExternalFailure(controllerConfigured: () throws -> Bool) throws {
        var current = try journal.read()
        try current.recipe.validateAgainst(currentIdentity)
        guard current.phase == .awaitingVerification || current.phase == .recoveryRequired else {
            throw USBRestoreCoordinatorError.recoveryRequired
        }
        guard try !controllerConfigured() else {
            throw USBRestoreCoordinatorError.recoveryRequired
        }
        if current.phase == .awaitingVerification {
            try journal.transition(from: current, to: changed(current, .recoveryRequired))
            current = try journal.read()
        }
        try journal.transition(from: current, to: changed(current, .restoring))
        do {
            try restoreOriginal(current)
            let restoring = try journal.read()
            try journal.transition(from: restoring,
                                   to: changed(restoring, .awaitingVerification))
        } catch {
            if let latest = try? journal.read(), latest.phase == .restoring {
                try? journal.transition(from: latest, to: changed(latest, .recoveryRequired))
            }
            throw error
        }
    }

    // After an automatic heal brought the controller on bus without a further
    // publication, the description on the bus is the journaled original (the
    // no-op published exactly it). Record that as awaiting external proof;
    // never confirms. Refused unless the controller reads configured.
    func acceptConfiguredOriginal(controllerConfigured: () throws -> Bool) throws {
        let current = try journal.read()
        try current.recipe.validateAgainst(currentIdentity)
        // A record that still names an appended function has not had the
        // original put back: healing may have brought the bus up carrying that
        // function. Refusing keeps the name in the journal for a real restore
        // instead of forgetting it and claiming the original is back.
        guard current.phase == .recoveryRequired, current.appendedFunctionName == nil,
              try controllerConfigured() else {
            throw USBRestoreCoordinatorError.recoveryRequired
        }
        try journal.transition(from: current, to: changed(current, .restoring))
        let restoring = try journal.read()
        try journal.transition(from: restoring, to: changed(restoring, .awaitingVerification))
    }

    // The watchdog may restore without a host connection. The journal stays
    // pending until an independent observer can prove the original state.
    func confirmExternalRestore() throws {
        let awaiting = try journal.read()
        try awaiting.recipe.validateAgainst(currentIdentity)
        guard awaiting.phase == .awaitingVerification else {
            throw USBRestoreCoordinatorError.recoveryRequired
        }
        do {
            let proof = try externalVerifier.verifyRestored(awaiting.recipe)
            guard USBRestoreRecipe.isDigest(proof) else {
                throw USBRestoreCoordinatorError.recoveryRequired
            }
            let verified = USBRestoreRecord(
                recipe: awaiting.recipe, phase: .restored,
                leaseDeadlineUptime: awaiting.leaseDeadlineUptime,
                externalVerificationSHA256: proof
            )
            try journal.transition(from: awaiting, to: verified)
            try journal.removeAfterVerification(verified)
        } catch {
            if let latest = try? journal.read(), latest.phase == .awaitingVerification {
                try? journal.transition(from: latest, to: changed(latest, .recoveryRequired))
            }
            throw error
        }
    }

    private func changed(_ record: USBRestoreRecord, _ phase: USBRestorePhase) -> USBRestoreRecord {
        // awaitingVerification is only ever reached with the journaled original
        // back on the bus, so nothing is left to strip. Every other phase keeps
        // the appended function: a restart in between still has to restore.
        let restored = phase == .awaitingVerification
        return USBRestoreRecord(
            recipe: record.recipe, phase: phase,
            leaseDeadlineUptime: record.leaseDeadlineUptime,
            externalVerificationSHA256: nil,
            appendedFunctionName: restored ? nil : record.appendedFunctionName,
            appendedFunctionConfiguration: restored ? nil : record.appendedFunctionConfiguration
        )
    }
}
