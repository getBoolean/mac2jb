import CryptoKit
import Foundation

// This is the watchdog's state machine. The controller and external verifier
// are injected so the fault path can be exercised without a USB mutation.
protocol USBRestoreController {
    func publish(_ description: Data) throws
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
            try recoveryController.publish(current.recipe.originalDescription)
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
        USBRestoreRecord(
            recipe: record.recipe, phase: phase,
            leaseDeadlineUptime: record.leaseDeadlineUptime,
            externalVerificationSHA256: nil
        )
    }
}
