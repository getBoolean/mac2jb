import Foundation

// Mac-only golden tests for the canary's HID model, its configuration plan and
// its exit behaviour. Every descriptor value here is the corrected value from
// the macOS sender, not the upstream example: the report length is derived from
// the real report descriptor, and no device-level identity is configured.
// The report sink and the lease are injected, so the exit paths are observed
// without the canary growing a test-only mode.

private struct Failure: Error { let message: String }

private func require(_ condition: Bool, _ message: String) throws {
    if !condition { throw Failure(message: message) }
}

private final class RecordingSink: HIDReportSink {
    private let outcomes: [HIDReportWriteOutcome]
    var written: [[UInt8]] = []

    // outcomes is consumed per write; the last one repeats forever.
    init(_ outcomes: [HIDReportWriteOutcome] = [.delivered]) {
        self.outcomes = outcomes
    }

    func write(_ report: [UInt8]) -> HIDReportWriteOutcome {
        written.append(report)
        return outcomes[min(written.count - 1, outcomes.count - 1)]
    }

    var neutralWrites: Int {
        written.filter { $0 == HIDKeyboard.neutralReport }.count
    }
}

private final class FakeLease: CanaryLease {
    private let heldChecks: Int
    private(set) var checks = 0
    private(set) var released = false
    private(set) var releasedNeutral: Bool?

    // Held for the first heldChecks queries, gone from then on.
    init(heldChecks: Int) { self.heldChecks = heldChecks }

    func isHeld() -> Bool {
        checks += 1
        return checks <= heldChecks
    }

    func release(neutralDelivered: Bool) {
        released = true
        releasedNeutral = neutralDelivered
    }
}

@main
enum HIDReportTests {
    static func main() throws {
        let expectedReportDescriptor: [UInt8] = [
            0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25, 0x01,
            0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08, 0x81, 0x01, 0x95, 0x03, 0x75, 0x01,
            0x05, 0x08, 0x19, 0x01, 0x29, 0x03, 0x91, 0x02, 0x95, 0x05, 0x75, 0x01, 0x91, 0x01, 0x95, 0x06,
            0x75, 0x08, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x05, 0x07, 0x19, 0x00, 0x2A, 0xFF, 0x00, 0x81, 0x00, 0xC0,
        ]

        // 1. The 9-byte HID descriptor, with the report length derived from the
        // descriptor that is actually appended (65 bytes -> 41 00).
        try require(HIDKeyboard.hidDescriptor == [0x09, 0x21, 0x11, 0x01, 0x00, 0x01, 0x22, 0x41, 0x00],
                    "HID descriptor golden: \(HIDKeyboard.hidDescriptor)")
        try require(HIDKeyboard.hidDescriptor.count == 9, "HID descriptor must be 9 bytes")
        try require(Int(HIDKeyboard.hidDescriptor[7]) |
                    Int(HIDKeyboard.hidDescriptor[8]) << 8 == HIDKeyboard.reportDescriptor.count,
                    "report length bytes must be derived from the report descriptor")

        // 2. The 65-byte boot-keyboard report descriptor, byte for byte.
        try require(HIDKeyboard.reportDescriptor == expectedReportDescriptor,
                    "report descriptor golden")
        try require(HIDKeyboard.reportDescriptor.count == 65, "report descriptor must be 65 bytes")

        // 3. Boot-keyboard tuple and the interrupt-IN endpoint.
        try require(HIDKeyboard.interfaceClass == 3 && HIDKeyboard.interfaceSubClass == 1 &&
                    HIDKeyboard.interfaceProtocol == 1, "interface tuple must be 3/1/1")
        try require(HIDKeyboard.endpoint == HIDEndpointPlan(transferType: 3, direction: 1,
                                                            maxPacketSize: 8, interval: 10),
                    "endpoint must be interrupt IN, 8 bytes, interval 10: \(HIDKeyboard.endpoint)")

        // 4. No device-level identity anywhere in the plan's vocabulary: the
        // device keeps the vendor ID, product ID, version and strings it
        // reports, so an external stock-value check stays meaningful.
        let identityTokens = ["vendor", "product", "version", "serial", "string", "manufacturer", "device"]
        for kind in HIDFunctionConfigurationStep.kindNames {
            for token in identityTokens {
                try require(!kind.lowercased().contains(token),
                            "configuration step \(kind) names a device-level identity field")
            }
        }

        // 5. The reference backend's operation order, made explicit: the pipe
        // when the endpoint is added, then the buffers, the commit and only
        // then the class-command callbacks, as its finalize step does them.
        try require(HIDFunctionConfigurationPlan.steps.map(\.kindName) == [
            "interfaceOpen", "setClass", "setSubClass", "setProtocol",
            "appendStandardDescriptor", "appendNonstandardDescriptor",
            "createPipe", "createBuffer", "commit", "setClassCommandCallbacks",
        ], "plan order: \(HIDFunctionConfigurationPlan.steps.map(\.kindName))")
        try require(HIDFunctionConfigurationPlan.steps.contains(
            .appendStandardDescriptor(type: 0x21, bytes: HIDKeyboard.hidDescriptor)),
                    "standard append must carry type 0x21 and the HID descriptor")
        try require(HIDFunctionConfigurationPlan.steps.contains(
            .appendNonstandardDescriptor(type: 0x22, bytes: HIDKeyboard.reportDescriptor)),
                    "nonstandard append must carry type 0x22 and the report descriptor")

        // 6. Report validation, ported from the keyboard forwarder.
        let valid: [UInt8] = [0x02, 0, 0x04, 0x05, 0, 0, 0, 0]
        try require(HIDKeyboard.isValidReport(valid), "a valid report must be accepted")
        try require(HIDKeyboard.isValidReport([0x02, 0, 0, 0, 0, 0, 0, 0]),
                    "a modifiers-only report must be accepted")
        try require(HIDKeyboard.isValidReport(HIDKeyboard.neutralReport),
                    "the neutral report must be valid")
        try require(!HIDKeyboard.isValidReport([0, 0x01, 0x04, 0, 0, 0, 0, 0]),
                    "a non-zero reserved byte must be rejected")
        try require(!HIDKeyboard.isValidReport([0, 0, 0x04, 0, 0x05, 0, 0, 0]),
                    "a keycode after an empty slot must be rejected")
        try require(!HIDKeyboard.isValidReport([0, 0, 0x03, 0, 0, 0, 0, 0]),
                    "a keycode below 4 must be rejected")
        try require(!HIDKeyboard.isValidReport([0, 0, 0x74, 0, 0, 0, 0, 0]),
                    "a keycode above 0x73 must be rejected")
        try require(!HIDKeyboard.isValidReport([0, 0, 0x04, 0x04, 0, 0, 0, 0]),
                    "a duplicate keycode must be rejected")
        try require(!HIDKeyboard.isValidReport([0, 0, 0x04, 0, 0, 0, 0]),
                    "a report that is not 8 bytes must be rejected")

        // 7. A controlled exit emits exactly one neutral report.
        var sink = RecordingSink()
        var lease = FakeLease(heldChecks: .max)
        var summary = HIDCanaryRun(sink: sink, lease: lease,
                                   reports: [valid, HIDKeyboard.neutralReport]).run()
        try require(summary.stop == .completed, "a delivered run completes: \(summary)")
        try require(summary.reportsWritten == 2, "both reports must be written: \(summary)")
        try require(summary.neutralAttempts == 1,
                    "a controlled exit writes the neutral report exactly once: \(summary)")
        try require(sink.written.last == HIDKeyboard.neutralReport,
                    "the last write must be the neutral report")
        try require(summary.neutralDelivered && lease.released && lease.releasedNeutral == true,
                    "a delivered neutral must be reported and the lease given up: \(summary)")

        // 8. Once the lease is gone nothing more is written, not even neutral:
        // the broker cannot protect the description against a late write.
        sink = RecordingSink()
        lease = FakeLease(heldChecks: 0)
        summary = HIDCanaryRun(sink: sink, lease: lease, reports: [valid]).run()
        try require(summary.stop == .leaseLost && summary.reportsWritten == 0 &&
                    summary.neutralAttempts == 0 && sink.written.isEmpty,
                    "no write is allowed without the lease: \(summary)")
        try require(lease.released && lease.releasedNeutral == false,
                    "the lease must still be given up: \(summary)")
        sink = RecordingSink()
        lease = FakeLease(heldChecks: 1)
        summary = HIDCanaryRun(sink: sink, lease: lease, reports: [valid, valid, valid]).run()
        try require(summary.stop == .leaseLost && summary.reportsWritten == 1 &&
                    summary.neutralAttempts == 0 && sink.written == [valid],
                    "writes must stop the moment the lease expires: \(summary)")

        // 9. A disconnect bounds the neutral attempts at three.
        sink = RecordingSink([.failed])
        lease = FakeLease(heldChecks: .max)
        summary = HIDCanaryRun(sink: sink, lease: lease, reports: [valid]).run()
        try require(summary.stop == .writeFailed && summary.reportsWritten == 0,
                    "a refused write stops the run: \(summary)")
        try require(summary.neutralAttempts == 3 && !summary.neutralDelivered,
                    "a failing sink must be retried at most three times: \(summary)")
        try require(sink.neutralWrites == 3, "exactly three neutral writes: \(sink.neutralWrites)")
        sink = RecordingSink([.disconnected])
        lease = FakeLease(heldChecks: .max)
        summary = HIDCanaryRun(sink: sink, lease: lease, reports: [valid]).run()
        try require(summary.stop == .disconnected && summary.neutralAttempts <= 3 &&
                    !summary.neutralDelivered,
                    "a disconnect stops retrying within the bound: \(summary)")

        // A signal during the report loop stops it at the next write rather
        // than after the list is exhausted, and is still a controlled exit:
        // one neutral report goes out while the lease is held.
        sink = RecordingSink()
        lease = FakeLease(heldChecks: .max)
        var writesBeforeStop = 0
        var run = HIDCanaryRun(sink: sink, lease: lease, reports: [valid, valid, valid])
        run.shouldStop = { writesBeforeStop >= 1 }
        let interrupted = run.run()
        writesBeforeStop = 0
        try require(interrupted.stop == .completed && interrupted.reportsWritten == 3,
                    "a predicate that never fires must not change the outcome: \(interrupted)")
        sink = RecordingSink()
        lease = FakeLease(heldChecks: .max)
        var seen = 0
        run = HIDCanaryRun(sink: sink, lease: lease, reports: [valid, valid, valid])
        run.shouldStop = { seen += 1; return seen > 2 }
        let signalled = run.run()
        try require(signalled.stop == .interrupted,
                    "a signal during the loop must report an interrupt: \(signalled)")
        try require(signalled.reportsWritten < 3,
                    "an interrupt must stop before the list is exhausted: \(signalled)")
        try require(signalled.neutralAttempts == 1 && signalled.neutralDelivered,
                    "an interrupt is a controlled exit, so exactly one neutral report: \(signalled)")
        try require(signalled.leaseReleased && lease.released,
                    "the lease must be given up after an interrupt: \(signalled)")

        // 10. An invalid report is refused before it reaches the sink.
        sink = RecordingSink()
        lease = FakeLease(heldChecks: .max)
        summary = HIDCanaryRun(sink: sink, lease: lease,
                               reports: [valid, [0, 0x01, 0, 0, 0, 0, 0, 0]]).run()
        try require(summary.stop == .invalidReport && summary.reportsWritten == 1 &&
                    sink.written == [valid, HIDKeyboard.neutralReport],
                    "an invalid report must never be written: \(sink.written)")

        // 11. The fixed canary string: a press and a release per character,
        // every one of them a valid boot-keyboard report.
        let canary = HIDKeyboard.canaryReports()
        try require(canary.count == HIDKeyboard.canaryText.count * 2,
                    "one press and one release per character: \(canary.count)")
        try require(canary.allSatisfy { HIDKeyboard.isValidReport($0) },
                    "every canary report must be valid")
        try require(stride(from: 1, to: canary.count, by: 2)
                        .allSatisfy { canary[$0] == HIDKeyboard.neutralReport },
                    "every press must be followed by a release")
        // The accepted string is upper case, so a shifted character is the only
        // thing that exercises the modifier byte at all.
        try require(HIDKeyboard.canaryText == HIDKeyboard.canaryText.uppercased(),
                    "the canary string must be upper case: \(HIDKeyboard.canaryText)")
        try require(zip(HIDKeyboard.canaryKeystrokes, stride(from: 0, to: canary.count, by: 2))
                        .allSatisfy { canary[$0.1][0] == ($0.0.character.isLetter
                                                          ? HIDKeyboard.leftShift : 0) },
                    "a shifted character must carry left shift and a digit must not")
        // 12. The pipe transport: delivery needs both a successful call and a
        // transferred count equal to the report length.
        var submitted: [UInt32] = []
        func transport(_ ioReturn: Int32, _ transferred: UInt64,
                       staged: Bool = true) -> PipeReportTransport {
            PipeReportTransport(stage: { _ in staged },
                                submit: { length in
                                    submitted.append(length)
                                    return (ioReturn, transferred)
                                })
        }
        try require(transport(0, 8).write(valid) == .delivered,
                    "a full transfer with a successful call is delivered")
        try require(submitted == [8], "the submit must carry the report length: \(submitted)")
        try require(transport(0, 4).write(valid) == .failed,
                    "a short write is not delivered even when the call succeeded")
        try require(transport(0, 0).write(valid) == .failed,
                    "a zero-byte transfer is not delivered")
        try require(transport(Int32(bitPattern: 0xE00002D6), 0).write(valid) == .failed,
                    "a refused write is a failure, not a disconnect")
        try require(transport(PipeReportTransport.notEnumerated, 0).write(valid) == .disconnected,
                    "a host that is not enumerated reads as a disconnect")
        try require(transport(0, 8, staged: false).write(valid) == .failed,
                    "a payload that cannot be staged is never submitted")

        // 13. The staged gates. Each mode answers one question, so the modes
        // are selected by an argument and an absent argument is still the full
        // run: existing callers must be unchanged.
        try require(HIDCanaryMode(argument: nil) == .full,
                    "no mode argument must still mean the full run")
        try require(HIDCanaryMode(argument: "full") == .full, "full mode spelling")
        try require(HIDCanaryMode(argument: "open-only") == .openOnly,
                    "stop-after-open mode spelling")
        try require(HIDCanaryMode(argument: "configure-only") == .configureOnly,
                    "configure-and-stop mode spelling")
        for unknown in ["", "openonly", "open", "configure", "Full", "configure-only "] {
            try require(HIDCanaryMode(argument: unknown) == nil,
                        "an unknown mode must be refused rather than guessed: \(unknown)")
        }

        // The three answers of the stop-after-open gate are three different
        // facts - the open succeeded, the interface never appeared, the
        // interface appeared and the open was denied - and a shared exit code
        // would destroy the gate. The usage refusal already owns 2.
        let openOutcomes: [HIDCanaryOpenOutcome] = [.opened, .interfaceAbsent,
                                                    .openDenied, .failed]
        try require(Set(openOutcomes.map(\.exitCode)).count == openOutcomes.count,
                    "each open outcome needs its own exit code: " +
                    "\(openOutcomes.map(\.exitCode))")
        try require(Set(openOutcomes.map(\.label)).count == openOutcomes.count,
                    "each open outcome needs its own label: \(openOutcomes.map(\.label))")
        try require(HIDCanaryOpenOutcome.opened.exitCode == 0,
                    "an opened interface is the only success")
        try require(openOutcomes.dropFirst().allSatisfy { $0.exitCode != 0 },
                    "no refusal may exit zero: \(openOutcomes.map(\.exitCode))")
        try require(openOutcomes.allSatisfy { $0.exitCode != 2 },
                    "2 is the usage refusal, so no gate answer may reuse it")
        try require(HIDCanaryOpenOutcome(resultRawValue: 0) == .opened,
                    "the shim's success must read as an opened interface")
        try require(HIDCanaryOpenOutcome(
            resultRawValue: HIDCanaryOpenOutcome.serviceAbsentResult) == .interfaceAbsent,
                    "the shim's service-absent must read as an absent interface")
        try require(HIDCanaryOpenOutcome(
            resultRawValue: HIDCanaryOpenOutcome.openDeniedResult) == .openDenied,
                    "the shim's open-denied must read as a denied open")
        try require(HIDCanaryOpenOutcome.serviceAbsentResult !=
                    HIDCanaryOpenOutcome.openDeniedResult,
                    "an absent interface and a denied open are different answers")
        for other: Int32 in [1, 2, 3, 4, 7, 8, 9] {
            try require(HIDCanaryOpenOutcome(resultRawValue: other) == .failed,
                        "any other shim result is neither answer: \(other)")
        }

        // The stop-after-open gate configures nothing at all: a refusal has to
        // be attributable to the open and not to some later selector.
        try require(!HIDCanaryMode.openOnly.configuresInterface,
                    "the stop-after-open gate must configure nothing")
        try require(HIDCanaryMode.configureOnly.configuresInterface &&
                    HIDCanaryMode.full.configuresInterface,
                    "both other modes walk the configuration sequence")
        // Typing is a separate question from configuring, and a host is not
        // necessarily watching, so only the full run writes the canary string.
        try require(HIDCanaryMode.full.reportsToWrite == HIDKeyboard.canaryReports(),
                    "the full run types the canary string")
        try require(HIDCanaryMode.configureOnly.reportsToWrite.isEmpty,
                    "the configure-and-stop gate writes no reports")
        try require(HIDCanaryMode.openOnly.reportsToWrite.isEmpty,
                    "the stop-after-open gate writes no reports")

        // 14. The configure-and-stop gate's exit: no reports, and the lease
        // rules unchanged - one neutral report on a controlled exit and the
        // lease handed back.
        sink = RecordingSink()
        lease = FakeLease(heldChecks: .max)
        summary = HIDCanaryRun(sink: sink, lease: lease,
                               reports: HIDCanaryMode.configureOnly.reportsToWrite).run()
        try require(summary.reportsWritten == 0 && summary.stop == .completed,
                    "a reportless gate writes nothing and still completes: \(summary)")
        try require(summary.neutralAttempts == 1 && summary.neutralDelivered,
                    "a controlled exit still writes exactly one neutral report: \(summary)")
        try require(sink.written == [HIDKeyboard.neutralReport],
                    "the neutral report is the only write: \(sink.written)")
        try require(lease.released && lease.releasedNeutral == true,
                    "the lease must be handed back: \(summary)")
        // Without the lease not even the neutral report is allowed.
        sink = RecordingSink()
        lease = FakeLease(heldChecks: 0)
        summary = HIDCanaryRun(sink: sink, lease: lease,
                               reports: HIDCanaryMode.configureOnly.reportsToWrite).run()
        try require(sink.written.isEmpty && summary.neutralAttempts == 0 && lease.released,
                    "a reportless gate writes nothing once the lease is gone: \(summary)")
        print("PASS HID canary report, plan, gate-mode and exit-path tests (14 scenarios)")
    }
}
