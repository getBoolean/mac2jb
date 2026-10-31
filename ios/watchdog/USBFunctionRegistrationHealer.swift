import Foundation

// Automatic same-boot USB recovery after a USB device description swap.
//
// Mechanism (target M2 iPad, iPadOS 17, 2026-10-31): after
// IOUSBDeviceControllerSetDescription the controller recreates every function
// nub and goes on bus only once *every* function has registered
// (kernel `IOUSBDeviceController::gated_registerFunction`). Each swap races
// the old function instances still held by their owners, so a random one or
// two functions never register and the controller stays off bus forever.
// A function that failed to register has no IOService client under its nub.
//
// Remedy, in bounded rounds: if every unserved function has a user-space
// owner, restart that owner so it re-opens and registers its function;
// otherwise re-publish the original description to recreate all nubs.
// This file is policy only; the probe supplies IOKit, publication and process
// control, so it can be embedded in the watchdog, a TrollStore root helper or
// a tweak. See docs/ipad/usb-auto-recovery.md.

protocol USBFunctionHealProbe {
    func controllerConfigured() throws -> Bool
    // Function names (USBDeviceFunction) whose interface nub has no client.
    func unservedFunctions() throws -> Set<String>
    func republish() throws
    func restartOwner(_ label: String) throws
    func sleep(seconds: Double)
}

struct USBFunctionHealPolicy {
    var maxRepublications = 5  // v9 hardware trial needed 3
    var maxRestartsPerOwner = 2
    var settleSeconds = 6.0
    var pollSeconds = 0.25
    // Clients that exist only while a host is connected (ptpd waits 10 s for
    // a host, then exits), so their absence is an effect, not the cause.
    var hostDependentFunctions: Set<String> = ["PTP"]
    // User-space owners whose restart re-registers the function.
    var owners: [String: String] = ["Valeria": "com.apple.audiomxd"]
}

enum USBFunctionHealOutcome: Equatable {
    case configured(republications: Int, ownerRestarts: [String])
    case gaveUp(missing: [String], republications: Int, ownerRestarts: [String])
}

struct USBFunctionRegistrationHealer {
    let probe: USBFunctionHealProbe
    let policy: USBFunctionHealPolicy

    func heal() throws -> USBFunctionHealOutcome {
        var republications = 0
        var restarts: [String] = []
        while true {
            if try waitForConfigured() {
                return .configured(republications: republications, ownerRestarts: restarts)
            }
            let missing = try probe.unservedFunctions().subtracting(policy.hostDependentFunctions)
            let owners = Set(missing.compactMap { policy.owners[$0] })
            let ownerFixable = !missing.isEmpty &&
                missing.allSatisfy { policy.owners[$0] != nil } &&
                owners.allSatisfy { label in
                    restarts.filter { $0 == label }.count < policy.maxRestartsPerOwner
                }
            if ownerFixable {
                for label in owners.sorted() {
                    try probe.restartOwner(label)
                    restarts.append(label)
                }
                continue
            }
            if republications < policy.maxRepublications {
                try probe.republish()
                republications += 1
                continue
            }
            return .gaveUp(missing: missing.sorted(), republications: republications,
                           ownerRestarts: restarts)
        }
    }

    private func waitForConfigured() throws -> Bool {
        var waited = 0.0
        while true {
            if try probe.controllerConfigured() { return true }
            if waited >= policy.settleSeconds { return false }
            probe.sleep(seconds: policy.pollSeconds)
            waited += policy.pollSeconds
        }
    }
}

extension USBFunctionHealOutcome {
    var summary: String {
        switch self {
        case let .configured(republications, restarts):
            return "healed republications=\(republications) owner-restarts=" +
                (restarts.isEmpty ? "none" : restarts.joined(separator: ","))
        case let .gaveUp(missing, republications, restarts):
            return "heal-gave-up missing=" + (missing.isEmpty ? "none" : missing.joined(separator: ",")) +
                " republications=\(republications) owner-restarts=" +
                (restarts.isEmpty ? "none" : restarts.joined(separator: ","))
        }
    }
}
