import Foundation

// Mac-only policy tests for USBFunctionRegistrationHealer. Each scenario
// replays a registration pattern observed in the 2026-10-31 iPad syslog.

private struct Failure: Error { let message: String }

private func require(_ condition: Bool, _ message: String) throws {
    if !condition { throw Failure(message: message) }
}

private final class FakeProbe: USBFunctionHealProbe {
    // Unserved sets after each publication (index = publication count).
    var afterPublication: [Set<String>]
    var publications = 0
    var restarted: [String] = []
    var missing: Set<String>
    var ownerFixes: [String: Set<String>]

    init(_ publications: [Set<String>], ownerFixes: [String: Set<String>] = [:]) {
        afterPublication = publications
        missing = publications[0]
        self.ownerFixes = ownerFixes
    }

    func controllerConfigured() throws -> Bool { missing.subtracting(["PTP"]).isEmpty }
    func unservedFunctions() throws -> Set<String> { missing }
    func republish() throws {
        publications += 1
        missing = afterPublication[min(publications, afterPublication.count - 1)]
    }
    func restartOwner(_ label: String) throws {
        restarted.append(label)
        missing.subtract(ownerFixes[label] ?? [])
    }
    func sleep(seconds: Double) {}
}

@main
enum USBFunctionRegistrationHealerTests {
    static func main() throws {
        let policy = USBFunctionHealPolicy()
        // Observed: loop attempt 2 left only Valeria; restarting audiomxd healed it.
        var probe = FakeProbe([["Valeria", "PTP"]], ownerFixes: ["com.apple.audiomxd": ["Valeria"]])
        var outcome = try USBFunctionRegistrationHealer(probe: probe, policy: policy).heal()
        try require(outcome == .configured(republications: 0, ownerRestarts: ["com.apple.audiomxd"]),
                    "Valeria-only must heal by one owner restart: \(outcome)")
        try require(probe.publications == 0, "no republication needed for Valeria-only")

        // Observed: trial left IapOverUsbHid + USBAudio2StreamIN (kernel owners),
        // republications then left one function, finally only Valeria.
        probe = FakeProbe([["IapOverUsbHid", "USBAudio2StreamIN"], ["USBAudio2StreamOUT"], ["Valeria"]],
                          ownerFixes: ["com.apple.audiomxd": ["Valeria"]])
        outcome = try USBFunctionRegistrationHealer(probe: probe, policy: policy).heal()
        try require(outcome == .configured(republications: 2, ownerRestarts: ["com.apple.audiomxd"]),
                    "kernel-owned gaps must republish until owner-fixable: \(outcome)")

        // PTP alone is host-dependent: never restart ptpd or republish for it.
        probe = FakeProbe([["PTP"]])
        outcome = try USBFunctionRegistrationHealer(probe: probe, policy: policy).heal()
        try require(outcome == .configured(republications: 0, ownerRestarts: []), "PTP-only is configured")

        // Bounded: persistent kernel gap gives up after maxRepublications.
        probe = FakeProbe([["USBAudio2StreamOUT"]])
        outcome = try USBFunctionRegistrationHealer(probe: probe, policy: policy).heal()
        try require(outcome == .gaveUp(missing: ["USBAudio2StreamOUT"], republications: 3, ownerRestarts: []),
                    "must give up after 3 republications: \(outcome)")

        // Bounded: an owner restart that does not help is retried at most twice,
        // then the healer falls back to republication.
        probe = FakeProbe([["Valeria"]])
        outcome = try USBFunctionRegistrationHealer(probe: probe, policy: policy).heal()
        try require(outcome == .gaveUp(missing: ["Valeria"], republications: 3,
                                       ownerRestarts: ["com.apple.audiomxd", "com.apple.audiomxd"]),
                    "owner restarts must be bounded: \(outcome)")

        // Already configured: no action at all.
        probe = FakeProbe([[]])
        outcome = try USBFunctionRegistrationHealer(probe: probe, policy: policy).heal()
        try require(outcome == .configured(republications: 0, ownerRestarts: []) && probe.restarted.isEmpty,
                    "configured controller must be left alone")
        print("PASS USBFunctionRegistrationHealer policy tests (6 scenarios)")
    }
}
