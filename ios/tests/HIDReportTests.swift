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
    // A raw return that is neither not-enumerated nor the write timeout, so a
    // plain .failed answer reads as a real refusal rather than "keep waiting".
    static let refusedRawReturn = Int32(bitPattern: 0xE00002C0)

    private let answers: [HIDReportWrite]
    var written: [[UInt8]] = []

    // answers is consumed per write; the last one repeats forever.
    init(_ outcomes: [HIDReportWriteOutcome] = [.delivered]) {
        answers = outcomes.map { outcome in
            switch outcome {
            case .delivered: return HIDReportWrite(outcome: .delivered, rawReturn: 0)
            case .failed: return HIDReportWrite(outcome: .failed,
                                                rawReturn: RecordingSink.refusedRawReturn)
            case .disconnected:
                return HIDReportWrite(outcome: .disconnected,
                                      rawReturn: PipeReportTransport.notEnumerated)
            }
        }
    }

    init(answers: [HIDReportWrite]) { self.answers = answers }

    func write(_ report: [UInt8]) -> HIDReportWrite {
        written.append(report)
        return answers[min(written.count - 1, answers.count - 1)]
    }

    var neutralWrites: Int {
        written.filter { $0 == HIDKeyboard.neutralReport }.count
    }

    var keystrokes: [[UInt8]] {
        written.filter { $0 != HIDKeyboard.neutralReport }
    }
}

// The pipe's answers to the wait's visibility query, scripted. Zero is "the
// host has not selected a configuration containing this interface yet" and the
// endpoint's size is "it has"; the last answer repeats forever. Nothing here
// writes a report, which is the point: the wait's mechanism is no longer the
// mechanism of typing.
private final class FakeVisibility: HIDPipeVisibility {
    // A shim result that is not success, for a query the build will not answer.
    static let refusedResult: Int32 = 9
    // A raw return that is neither zero nor one of the reference's "not yet"
    // values, so it reads as a real refusal rather than "keep waiting".
    static let refusedRawReturn = Int32(bitPattern: 0xE00002C0)

    static let visible = HIDPipeSizeProbe(result: HIDPipeSizeProbe.success,
                                          rawReturn: 0, maxPacketSize: 8)
    static let notYet = HIDPipeSizeProbe(result: HIDPipeSizeProbe.success,
                                         rawReturn: PipeReportTransport.notEnumerated,
                                         maxPacketSize: 0)
    static let quiet = HIDPipeSizeProbe(result: HIDPipeSizeProbe.success,
                                        rawReturn: 0, maxPacketSize: 0)

    private let answers: [HIDPipeSizeProbe]
    private(set) var polls = 0

    init(_ answers: [HIDPipeSizeProbe] = [FakeVisibility.visible]) {
        self.answers = answers
    }

    func currentMaxPacketSize() -> HIDPipeSizeProbe {
        polls += 1
        return answers[min(polls - 1, answers.count - 1)]
    }
}

// A clock the wait's deadline can be driven from without waiting on a real one.
// Every pause advances it, which is what the production pause does too.
private final class FakeClock {
    private(set) var nanoseconds: UInt64 = 0
    let step: UInt64

    init(stepMilliseconds: UInt64) { step = stepMilliseconds * 1_000_000 }

    func now() -> UInt64 { nanoseconds }
    func pause() { nanoseconds += step }
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
        var visible = FakeVisibility()
        var summary = HIDCanaryRun(sink: sink, lease: lease,
                                   reports: [valid, HIDKeyboard.neutralReport],
                                   visibility: visible).run()
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
        visible = FakeVisibility()
        summary = HIDCanaryRun(sink: sink, lease: lease, reports: [valid],
                               visibility: visible).run()
        try require(summary.stop == .leaseLost && summary.reportsWritten == 0 &&
                    summary.neutralAttempts == 0 && sink.written.isEmpty,
                    "no write is allowed without the lease: \(summary)")
        try require(visible.polls == 0,
                    "the wait may not even look without the lease: \(visible.polls)")
        try require(lease.released && lease.releasedNeutral == false,
                    "the lease must still be given up: \(summary)")
        // The enumeration wait takes the first lease check, so one report needs
        // two: the wait's poll and the loop's own check before the write. The
        // poll itself writes nothing, so the first write is the first report.
        sink = RecordingSink()
        lease = FakeLease(heldChecks: 2)
        summary = HIDCanaryRun(sink: sink, lease: lease, reports: [valid, valid, valid],
                               visibility: FakeVisibility()).run()
        try require(summary.stop == .leaseLost && summary.reportsWritten == 1 &&
                    summary.neutralAttempts == 0 && sink.written == [valid],
                    "writes must stop the moment the lease expires: \(summary)")

        // 9. A disconnect bounds the neutral attempts at three. The wait does
        // not consume a sink answer any more, so the first answer is the first
        // report's.
        sink = RecordingSink([.failed])
        lease = FakeLease(heldChecks: .max)
        summary = HIDCanaryRun(sink: sink, lease: lease, reports: [valid],
                               visibility: FakeVisibility()).run()
        try require(summary.stop == .writeFailed && summary.reportsWritten == 0,
                    "a refused write stops the run: \(summary)")
        try require(summary.neutralAttempts == 3 && !summary.neutralDelivered,
                    "a failing sink must be retried at most three times: \(summary)")
        try require(sink.neutralWrites == 3,
                    "three teardown neutral writes and nothing from the wait: " +
                    "\(sink.neutralWrites)")
        sink = RecordingSink([.disconnected])
        lease = FakeLease(heldChecks: .max)
        summary = HIDCanaryRun(sink: sink, lease: lease, reports: [valid],
                               visibility: FakeVisibility()).run()
        try require(summary.stop == .disconnected && summary.neutralAttempts <= 3 &&
                    !summary.neutralDelivered,
                    "a disconnect stops retrying within the bound: \(summary)")

        // A signal during the report loop stops it at the next write rather
        // than after the list is exhausted, and is still a controlled exit:
        // one neutral report goes out while the lease is held.
        sink = RecordingSink()
        lease = FakeLease(heldChecks: .max)
        var writesBeforeStop = 0
        var run = HIDCanaryRun(sink: sink, lease: lease, reports: [valid, valid, valid],
                               visibility: FakeVisibility())
        run.shouldStop = { writesBeforeStop >= 1 }
        let interrupted = run.run()
        writesBeforeStop = 0
        try require(interrupted.stop == .completed && interrupted.reportsWritten == 3,
                    "a predicate that never fires must not change the outcome: \(interrupted)")
        sink = RecordingSink()
        lease = FakeLease(heldChecks: .max)
        var seen = 0
        run = HIDCanaryRun(sink: sink, lease: lease, reports: [valid, valid, valid],
                           visibility: FakeVisibility())
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
                               reports: [valid, [0, 0x01, 0, 0, 0, 0, 0, 0]],
                               visibility: FakeVisibility()).run()
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
        try require(transport(0, 8).write(valid).outcome == .delivered,
                    "a full transfer with a successful call is delivered")
        try require(submitted == [8], "the submit must carry the report length: \(submitted)")
        try require(transport(0, 4).write(valid).outcome == .failed,
                    "a short write is not delivered even when the call succeeded")
        try require(transport(0, 0).write(valid).outcome == .failed,
                    "a zero-byte transfer is not delivered")
        try require(transport(PipeReportTransport.writeTimedOut, 0).write(valid).outcome
                    == .failed,
                    "a refused write is a failure, not a disconnect")
        try require(transport(PipeReportTransport.notEnumerated, 0).write(valid).outcome
                    == .disconnected,
                    "a host that is not enumerated reads as a disconnect")
        try require(transport(0, 8, staged: false).write(valid).outcome == .failed,
                    "a payload that cannot be staged is never submitted")
        // The raw IOReturn comes back beside the outcome, because the wait for
        // host enumeration reports the last one verbatim and a staging refusal
        // has no raw return of its own.
        try require(transport(RecordingSink.refusedRawReturn, 0).write(valid).rawReturn
                    == RecordingSink.refusedRawReturn,
                    "the raw IOReturn must be reported verbatim")
        try require(transport(0, 8, staged: false).write(valid).rawReturn == 0,
                    "a payload that cannot be staged has no raw return")
        // The two raw returns that mean "the host has not finished enumerating"
        // rather than "the host is gone", as the reference's wait treats them.
        try require(PipeReportTransport.notYetEnumerated ==
                    [PipeReportTransport.notEnumerated, PipeReportTransport.writeTimedOut],
                    "not-enumerated and the write timeout are the only waitable returns")
        try require(!PipeReportTransport.notYetEnumerated.contains(0) &&
                    !PipeReportTransport.notYetEnumerated.contains(
                        RecordingSink.refusedRawReturn),
                    "no other raw return may be waited on")

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
                               reports: HIDCanaryMode.configureOnly.reportsToWrite,
                               visibility: FakeVisibility()).run()
        try require(summary.reportsWritten == 0 && summary.stop == .completed,
                    "a reportless gate writes nothing and still completes: \(summary)")
        try require(summary.neutralAttempts == 1 && summary.neutralDelivered,
                    "a controlled exit still writes exactly one neutral report: \(summary)")
        try require(sink.keystrokes.isEmpty && sink.written.count == 1,
                    "the teardown neutral and nothing else: \(sink.written)")
        try require(lease.released && lease.releasedNeutral == true,
                    "the lease must be handed back: \(summary)")
        // The configure-and-stop gate reports the wait's answer too: configured
        // and enumerated by the host is a strictly stronger result.
        try require(summary.enumeration.state == .enumerated &&
                    summary.enumeration.polls == 1,
                    "the reportless gate still waits for the host: \(summary.enumeration)")
        // Without the lease not even the neutral report is allowed.
        sink = RecordingSink()
        lease = FakeLease(heldChecks: 0)
        summary = HIDCanaryRun(sink: sink, lease: lease,
                               reports: HIDCanaryMode.configureOnly.reportsToWrite,
                               visibility: FakeVisibility()).run()
        try require(sink.written.isEmpty && summary.neutralAttempts == 0 && lease.released,
                    "a reportless gate writes nothing once the lease is gone: \(summary)")

        // 15. The bounded wait for host enumeration. Committing the
        // configuration makes the device re-present itself, so the host needs a
        // moment to read the new descriptors and select a configuration. The
        // wait asks the pipe for its current maximum packet size, which is zero
        // until the host has selected a configuration containing this
        // interface and the endpoint's size once it has. It writes nothing at
        // all, so no amount of waiting can type into the host.
        let notYet = FakeVisibility.notYet
        let quiet = FakeVisibility.quiet
        let timedOut = HIDPipeSizeProbe(result: HIDPipeSizeProbe.success,
                                        rawReturn: PipeReportTransport.writeTimedOut,
                                        maxPacketSize: 0)
        let refusedRaw = HIDPipeSizeProbe(result: HIDPipeSizeProbe.success,
                                          rawReturn: FakeVisibility.refusedRawReturn,
                                          maxPacketSize: 0)
        let unavailable = HIDPipeSizeProbe(result: FakeVisibility.refusedResult,
                                           rawReturn: 0, maxPacketSize: 0)
        let selected = FakeVisibility.visible

        // A host that has already selected the configuration answers the first
        // poll with the endpoint's size, and nothing was written to find out.
        sink = RecordingSink()
        lease = FakeLease(heldChecks: .max)
        visible = FakeVisibility([selected])
        summary = HIDCanaryRun(sink: sink, lease: lease, reports: [valid],
                               visibility: visible).run()
        try require(summary.enumeration.state == .enumerated &&
                    summary.enumeration.polls == 1 &&
                    summary.enumeration.lastMaxPacketSize == 8 &&
                    summary.enumeration.lastRawReturn == 0,
                    "a selected configuration answers the first poll: \(summary.enumeration)")
        try require(summary.stop == .completed && summary.reportsWritten == 1,
                    "an enumerated host is typed to: \(summary)")
        try require(sink.written == [valid, HIDKeyboard.neutralReport],
                    "the wait must put nothing on the bus: \(sink.written)")

        // A host that needs a moment answers a later poll. A size of zero means
        // "not yet" whether the raw return is one of the reference's waited-on
        // values or plain success, and nothing is typed until the size appears.
        var clock = FakeClock(stepMilliseconds: 250)
        sink = RecordingSink()
        lease = FakeLease(heldChecks: .max)
        visible = FakeVisibility([notYet, quiet, timedOut, selected])
        run = HIDCanaryRun(sink: sink, lease: lease, reports: [valid],
                           visibility: visible)
        run.now = clock.now
        run.pause = clock.pause
        summary = run.run()
        try require(summary.enumeration.state == .enumerated &&
                    summary.enumeration.polls == 4 &&
                    summary.enumeration.lastMaxPacketSize == 8,
                    "a zero size means keep waiting: \(summary.enumeration)")
        try require(sink.keystrokes == [valid] && summary.reportsWritten == 1,
                    "typing starts only once the size appears: \(sink.written)")
        try require(sink.neutralWrites == 1,
                    "the only neutral report is the teardown's: \(sink.written)")

        // A host that never selects the configuration is bounded, and it is not
        // a disconnect: the two point at completely different causes, so the
        // stop reason and the exit code are its own.
        clock = FakeClock(stepMilliseconds: 500)
        sink = RecordingSink()
        lease = FakeLease(heldChecks: .max)
        visible = FakeVisibility([notYet])
        run = HIDCanaryRun(sink: sink, lease: lease, reports: [valid],
                           visibility: visible)
        run.now = clock.now
        run.pause = clock.pause
        summary = run.run()
        try require(summary.enumeration.state == .neverEnumerated,
                    "an unenumerated host must be reported as such: \(summary.enumeration)")
        try require(summary.stop == .hostNeverEnumerated && summary.stop != .disconnected,
                    "never enumerated is not a disconnect: \(summary)")
        try require(summary.enumeration.polls == 30,
                    "the wait is bounded at the reference's attempts: \(summary.enumeration)")
        try require(summary.enumeration.lastRawReturn == PipeReportTransport.notEnumerated &&
                    summary.enumeration.lastMaxPacketSize == 0,
                    "the last size and raw return must be kept verbatim: \(summary.enumeration)")
        try require(summary.reportsWritten == 0 && sink.keystrokes.isEmpty,
                    "an unenumerated host is never typed to: \(sink.written)")
        try require(HIDCanaryStop.hostNeverEnumerated.exitCode !=
                    HIDCanaryStop.disconnected.exitCode,
                    "the two causes need their own exit codes")
        try require(HIDCanaryStop.hostNeverEnumerated.exitCode != 0 &&
                    ![1, 2, 3, 4, 5].contains(HIDCanaryStop.hostNeverEnumerated.exitCode),
                    "the never-enumerated exit code must be unused elsewhere: " +
                    "\(HIDCanaryStop.hostNeverEnumerated.exitCode)")
        try require(HIDCanaryStop.completed.exitCode == 0 &&
                    HIDCanaryStop.disconnected.exitCode == 1 &&
                    HIDCanaryStop.writeFailed.exitCode == 1,
                    "every other stop keeps the generic refusal code")
        // The lease is the real bound, so the backstop cannot outlive it.
        try require(HIDCanaryRun.enumerationWaitSeconds <= BrokerSocketLease.maximumLeaseSeconds,
                    "the wait must not be able to outlive the lease")

        // Any other raw return is a real failure: it stops the wait at once and
        // is recorded verbatim, with no retry and no interpretation. It is not
        // a write failure, because the wait writes nothing.
        sink = RecordingSink()
        lease = FakeLease(heldChecks: .max)
        summary = HIDCanaryRun(sink: sink, lease: lease, reports: [valid],
                               visibility: FakeVisibility([refusedRaw])).run()
        try require(summary.enumeration.state == .waitFailed &&
                    summary.enumeration.polls == 1 &&
                    summary.enumeration.lastRawReturn == FakeVisibility.refusedRawReturn,
                    "a real refusal stops the wait at once: \(summary.enumeration)")
        try require(summary.stop == .enumerationWaitFailed && summary.reportsWritten == 0 &&
                    sink.keystrokes.isEmpty,
                    "a refused wait never types: \(summary)")

        // A query the build will not answer at all is a third fact: the wait
        // could not look, which is not the same statement as looking and seeing
        // nothing, so it keeps its own state and its own exit code.
        sink = RecordingSink()
        lease = FakeLease(heldChecks: .max)
        summary = HIDCanaryRun(sink: sink, lease: lease, reports: [valid],
                               visibility: FakeVisibility([unavailable])).run()
        try require(summary.enumeration.state == .probeUnavailable &&
                    summary.enumeration.polls == 1,
                    "an unanswerable query is its own answer: \(summary.enumeration)")
        try require(summary.stop == .enumerationProbeUnavailable &&
                    summary.reportsWritten == 0 && sink.keystrokes.isEmpty,
                    "an unanswerable query never types: \(summary)")
        try require(HIDCanaryStop.enumerationProbeUnavailable.exitCode !=
                    HIDCanaryStop.hostNeverEnumerated.exitCode,
                    "could not look and never enumerated need their own exit codes")
        try require(![0, 1, 2, 3, 4, 5, 6].contains(
                        HIDCanaryStop.enumerationProbeUnavailable.exitCode),
                    "the unanswerable-query exit code must be unused elsewhere: " +
                    "\(HIDCanaryStop.enumerationProbeUnavailable.exitCode)")
        // A controlled exit still writes exactly one neutral report, whatever
        // the wait found, and the lease still goes back.
        try require(summary.neutralAttempts == 1 && summary.neutralDelivered &&
                    sink.written == [HIDKeyboard.neutralReport] && lease.released,
                    "the lease rules do not change with the wait's answer: \(summary)")

        // The lease disappearing mid-wait stops the wait, and nothing is
        // written: a write after the lease has gone is the one thing the broker
        // cannot restore from.
        clock = FakeClock(stepMilliseconds: 250)
        sink = RecordingSink()
        lease = FakeLease(heldChecks: 2)
        visible = FakeVisibility([notYet])
        run = HIDCanaryRun(sink: sink, lease: lease, reports: [valid],
                           visibility: visible)
        run.now = clock.now
        run.pause = clock.pause
        summary = run.run()
        try require(summary.enumeration.state == .leaseLost &&
                    summary.enumeration.polls == 2,
                    "the lease is checked before every poll: \(summary.enumeration)")
        try require(summary.stop == .leaseLost && sink.written.isEmpty &&
                    summary.neutralAttempts == 0 && summary.reportsWritten == 0,
                    "nothing is written once the lease is gone: \(summary)")
        try require(lease.released && lease.releasedNeutral == false,
                    "the lease must still be given up: \(summary)")

        // A signal during the wait is a controlled exit like any other.
        sink = RecordingSink()
        lease = FakeLease(heldChecks: .max)
        visible = FakeVisibility([notYet])
        run = HIDCanaryRun(sink: sink, lease: lease, reports: [valid],
                           visibility: visible)
        run.shouldStop = { true }
        summary = run.run()
        try require(summary.enumeration.state == .interrupted &&
                    summary.enumeration.polls == 0 && summary.stop == .interrupted,
                    "a signal stops the wait before it polls: \(summary)")
        try require(visible.polls == 0,
                    "a signal stops the wait before it looks: \(visible.polls)")
        print("PASS HID canary report, plan, gate-mode, enumeration-wait and " +
              "exit-path tests (15 scenarios)")
    }
}
