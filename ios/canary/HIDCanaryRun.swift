import Darwin

// The canary's wait for host enumeration, its report loop and its exit paths.
// The report sink, the lease and the clock are injected, so the Mac tests
// observe the exit behaviour without this file growing a mode that only a test
// uses.

enum HIDReportWriteOutcome: Equatable {
    case delivered
    case failed        // the pipe refused the write
    case disconnected  // the host is not there; a further attempt cannot reach it
}

// The outcome and the raw IOReturn that produced it, kept apart: the same raw
// return means "not yet" before the host has enumerated and "gone" during
// typing, so the phase decides what it means and the raw value is reported
// verbatim either way.
struct HIDReportWrite: Equatable {
    let outcome: HIDReportWriteOutcome
    let rawReturn: Int32
}

protocol HIDReportSink {
    func write(_ report: [UInt8]) -> HIDReportWrite
}

// The production sink. The reference backend's write copies the payload into
// the mapped buffer that create-buffer returned and then submits the buffer's
// token, not a pointer. The raw IOReturn and the transferred count come back
// separately and both matter: a call that returned success having moved fewer
// than the report's bytes has not delivered the report, and conflating the two
// makes a short write look like an error code. The staging copy and the submit
// are injected so this rule is testable without a device.
struct PipeReportTransport: HIDReportSink {
    // The raw IOReturn the reference reports when the host is not enumerated,
    // and the one it reports when a write waited out its timeout.
    static let notEnumerated = Int32(bitPattern: 0xE0000001)
    static let writeTimedOut = Int32(bitPattern: 0xE00002D6)

    // The two raw returns the reference's enumeration wait keeps waiting on:
    // the host has not finished reading the new descriptors and selecting a
    // configuration, so it has not collected the report. Neither says the host
    // is gone, and no other raw return is waited on.
    static let notYetEnumerated: Set<Int32> = [notEnumerated, writeTimedOut]

    let stage: ([UInt8]) -> Bool
    let submit: (UInt32) -> (ioReturn: Int32, transferred: UInt64)

    func write(_ report: [UInt8]) -> HIDReportWrite {
        guard stage(report) else { return HIDReportWrite(outcome: .failed, rawReturn: 0) }
        let answer = submit(UInt32(report.count))
        if answer.ioReturn == Self.notEnumerated {
            return HIDReportWrite(outcome: .disconnected, rawReturn: answer.ioReturn)
        }
        guard answer.ioReturn == 0,
              answer.transferred == UInt64(report.count) else {
            return HIDReportWrite(outcome: .failed, rawReturn: answer.ioReturn)
        }
        return HIDReportWrite(outcome: .delivered, rawReturn: answer.ioReturn)
    }
}

enum HIDCanaryStop: Equatable {
    case completed
    case invalidReport
    case writeFailed
    case disconnected
    case hostNeverEnumerated
    case leaseLost
    case interrupted

    // A host that never enumerated this interface and a host that went away
    // mid-typing point at completely different causes, so a trial has to be
    // able to tell them apart from the exit status alone. 1 is the generic
    // refusal, 2 the usage refusal and 3 to 5 the stop-after-open gate's
    // answers, so the unenumerated host takes 6.
    var exitCode: Int32 {
        switch self {
        case .completed: return 0
        case .hostNeverEnumerated: return 6
        case .invalidReport, .writeFailed, .disconnected, .leaseLost, .interrupted:
            return 1
        }
    }
}

// What the wait for host enumeration found, and how long it took to find it:
// the poll count is the diagnostic a trial reader needs to tell "enumerated
// after a moment" from "never enumerated".
enum HIDHostEnumeration: Equatable {
    case enumerated
    case neverEnumerated  // the bound ran out: not a disconnect
    case waitFailed       // a raw return that is not waited on
    case leaseLost
    case interrupted

    var label: String {
        switch self {
        case .enumerated: return "enumerated"
        case .neverEnumerated: return "never-enumerated"
        case .waitFailed: return "wait-failed"
        case .leaseLost: return "lease-lost"
        case .interrupted: return "interrupted"
        }
    }
}

struct HIDEnumerationResult: Equatable {
    let state: HIDHostEnumeration
    let polls: Int
    let lastRawReturn: Int32
}

struct HIDCanarySummary: Equatable {
    let reportsWritten: Int
    let stop: HIDCanaryStop
    let neutralAttempts: Int
    let neutralDelivered: Bool
    let leaseReleased: Bool
    let enumeration: HIDEnumerationResult
}

struct HIDCanaryRun {
    // The reference teardown's bound: three attempts at the neutral report,
    // abandoned early once the host is gone.
    static let neutralAttemptLimit = 3

    // The reference's enumeration wait allows roughly 30 attempts at a 500 ms
    // write timeout, so about 15 seconds for the host to read the new
    // descriptors and select a configuration after the commit re-presents the
    // device. That is also the broker's lease ceiling, which is the point: the
    // lease check before every poll is the real bound and this deadline is
    // only the backstop, so the wait cannot outlive the lease it borrows.
    static let enumerationWaitSeconds: Double = 15
    static let enumerationPollMicroseconds: UInt32 = 500_000

    let sink: HIDReportSink
    let lease: CanaryLease
    let reports: [[UInt8]]
    // A requested stop, asked before every write rather than only once the
    // list runs out: a signal must take effect during the writing, not after
    // it. Defaulted, so a caller that cannot be interrupted says nothing.
    var shouldStop: () -> Bool = { false }
    // The clock and the pause the enumeration wait is bounded by, injected so
    // the Mac tests observe the bound without waiting on a real one.
    var now: () -> UInt64 = { clock_gettime_nsec_np(CLOCK_UPTIME_RAW) }
    var pause: () -> Void = { usleep(HIDCanaryRun.enumerationPollMicroseconds) }

    func run() -> HIDCanarySummary {
        // Committing the configuration makes the device re-present itself, so
        // the host needs a moment before it collects anything. Nothing is
        // typed until a write gets through.
        let enumeration = waitForHostEnumeration()
        guard enumeration.state == .enumerated else {
            return finish(reportsWritten: 0, stop: Self.stop(for: enumeration.state),
                          enumeration: enumeration)
        }
        var written = 0
        var stop = HIDCanaryStop.completed
        for report in reports {
            // A requested stop is a controlled exit: the neutral report and
            // the lease release below still happen.
            guard !shouldStop() else { stop = .interrupted; break }
            // Checked before every write: a write after the lease has gone is
            // the one thing the broker cannot restore from.
            guard lease.isHeld() else { stop = .leaseLost; break }
            guard HIDKeyboard.isValidReport(report) else { stop = .invalidReport; break }
            switch sink.write(report).outcome {
            case .delivered: written += 1
            case .failed: stop = .writeFailed
            case .disconnected: stop = .disconnected
            }
            if stop != .completed { break }
        }
        return finish(reportsWritten: written, stop: stop, enumeration: enumeration)
    }

    // The bounded wait for host enumeration, as the reference does it: poll by
    // writing the neutral report, which is all zeros, so a host that is
    // already watching sees "no keys pressed" and repeating it is harmless.
    // Not-enumerated and a write timeout mean the host has not finished
    // enumerating; any other raw return is a real failure and stops the wait
    // at once, recorded verbatim.
    private func waitForHostEnumeration() -> HIDEnumerationResult {
        let budget = UInt64(Self.enumerationWaitSeconds * 1_000_000_000)
        let start = now()
        var polls = 0
        var last: Int32 = 0
        func result(_ state: HIDHostEnumeration) -> HIDEnumerationResult {
            HIDEnumerationResult(state: state, polls: polls, lastRawReturn: last)
        }
        while true {
            guard !shouldStop() else { return result(.interrupted) }
            // Checked before every poll, exactly as the report loop does: a
            // write after the lease has gone is the one thing the broker
            // cannot restore from.
            guard lease.isHeld() else { return result(.leaseLost) }
            // The deadline only ends a wait that has already asked once, so a
            // clock that is already past it cannot skip the single poll that
            // tells an enumerated host from an absent one.
            guard polls == 0 || now() - start < budget else {
                return result(.neverEnumerated)
            }
            polls += 1
            let answer = sink.write(HIDKeyboard.neutralReport)
            last = answer.rawReturn
            if answer.outcome == .delivered { return result(.enumerated) }
            guard PipeReportTransport.notYetEnumerated.contains(last) else {
                return result(.waitFailed)
            }
            pause()
        }
    }

    private static func stop(for state: HIDHostEnumeration) -> HIDCanaryStop {
        switch state {
        case .enumerated: return .completed
        case .neverEnumerated: return .hostNeverEnumerated
        case .waitFailed: return .writeFailed
        case .leaseLost: return .leaseLost
        case .interrupted: return .interrupted
        }
    }

    // Every exit path ends here: one neutral report while the lease is held,
    // then the lease goes back. A lost lease is the exception, and the reason
    // is the same one that stops the loop above: without the lease the canary
    // may not write at all, so it releases and leaves the held keys to the
    // broker's restore path.
    private func finish(reportsWritten: Int, stop: HIDCanaryStop,
                        enumeration: HIDEnumerationResult) -> HIDCanarySummary {
        var attempts = 0
        var delivered = false
        if stop != .leaseLost && lease.isHeld() {
            attempts: while attempts < Self.neutralAttemptLimit {
                attempts += 1
                switch sink.write(HIDKeyboard.neutralReport).outcome {
                case .delivered: delivered = true; break attempts
                case .disconnected: break attempts
                case .failed: continue
                }
            }
        }
        lease.release(neutralDelivered: delivered)
        return HIDCanarySummary(reportsWritten: reportsWritten, stop: stop,
                                neutralAttempts: attempts, neutralDelivered: delivered,
                                leaseReleased: true, enumeration: enumeration)
    }
}
