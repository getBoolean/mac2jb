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
    // The pipe was aborted by a bus reset or configuration change.
    static let aborted = Int32(bitPattern: 0xE00002EB)
    // What the host-polling readiness wait treats as "not polling yet".
    static let reenumerating: Set<Int32> = [notEnumerated, writeTimedOut, aborted]

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

// What the pipe says its current maximum packet size is. The reference exposes
// this as a live property of the pipe, not as the value that was asked for: it
// is zero until a host has selected a configuration containing the interface
// and becomes the endpoint's size once it has. Reading it is therefore a
// complete answer to "is my interface in the host's active configuration", and
// it produces no host-visible traffic at all - which is why the wait polls it
// instead of writing a report. The shim's own result and the raw IOReturn are
// kept apart from the size, because a refused query and a query that answered
// zero are different facts.
struct HIDPipeSizeProbe: Equatable {
    // The shim's success result. Named here because this file is built for the
    // Mac tests too, where the shim header is not imported.
    static let success: Int32 = 0

    let result: Int32
    let rawReturn: Int32
    let maxPacketSize: UInt64
}

protocol HIDPipeVisibility {
    func currentMaxPacketSize() -> HIDPipeSizeProbe
}

// The production probe, with the shim call injected so this file stays free of
// the shim header and the Mac tests can exercise the wait without a device.
struct PipeSizeVisibility: HIDPipeVisibility {
    let probe: () -> HIDPipeSizeProbe

    func currentMaxPacketSize() -> HIDPipeSizeProbe { probe() }
}

enum HIDCanaryStop: Equatable {
    case completed
    case invalidReport
    case writeFailed
    case disconnected
    case hostNeverEnumerated
    case enumerationProbeUnavailable
    // The visibility query answered with a raw return that is not one of the
    // reference's "not yet" values. Not a write failure: the wait writes
    // nothing, so calling it one would describe something that never happened.
    case enumerationWaitFailed
    case leaseLost
    case interrupted

    // A host that never enumerated this interface and a host that went away
    // mid-typing point at completely different causes, so a trial has to be
    // able to tell them apart from the exit status alone. 1 is the generic
    // refusal, 2 the usage refusal and 3 to 5 the stop-after-open gate's
    // answers, so the unenumerated host takes 6. A pipe that would not answer
    // the visibility query at all is a third fact - the wait could not look,
    // rather than looked and saw nothing - so it takes 7.
    var exitCode: Int32 {
        switch self {
        case .completed: return 0
        case .hostNeverEnumerated: return 6
        case .enumerationProbeUnavailable: return 7
        case .invalidReport, .writeFailed, .disconnected, .leaseLost, .interrupted,
             .enumerationWaitFailed:
            return 1
        }
    }
}

// What the wait for host enumeration found, and how long it took to find it:
// the poll count is the diagnostic a trial reader needs to tell "enumerated
// after a moment" from "never enumerated".
enum HIDHostEnumeration: Equatable {
    case enumerated
    case neverEnumerated   // the bound ran out: not a disconnect
    case waitFailed        // a raw return that is not waited on
    case probeUnavailable  // the pipe would not answer at all: nothing was seen
    case leaseLost
    case interrupted

    var label: String {
        switch self {
        case .enumerated: return "enumerated"
        case .neverEnumerated: return "never-enumerated"
        case .waitFailed: return "wait-failed"
        case .probeUnavailable: return "probe-unavailable"
        case .leaseLost: return "lease-lost"
        case .interrupted: return "interrupted"
        }
    }
}

struct HIDEnumerationResult: Equatable {
    let state: HIDHostEnumeration
    let polls: Int
    let lastRawReturn: Int32
    // The last size the pipe reported. Zero is the whole signal for "not in the
    // host's active configuration yet", so it is kept beside the raw return
    // rather than folded into it.
    let lastMaxPacketSize: UInt64
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
    // Must outlast the device's own return to the bus. Publishing a
    // description takes the controller off bus and it comes back 29-72 s
    // later, so a wait shorter than that ends before the host has had any
    // chance to enumerate and reports "not enumerated" about a device that was
    // not yet present. 120 s covers the slowest measured return with room for
    // the host to read descriptors, and stays inside the lease above.
    // Must also outlast the *host's* sequence after the bus cycle - the
    // reattach, the report collection and the descriptor read - because this
    // wait ending is what releases the lease, and the broker restores the
    // original the moment the worker goes. A wait that ends first makes the
    // capture read a restored device, which is a void observation.
    static let enumerationWaitSeconds: Double = 560
    static let enumerationPollMicroseconds: UInt32 = 500_000

    // Selecting the configuration (max-packet > 0) does not mean the host's HID
    // driver is polling the interrupt IN endpoint yet: it still has to read the
    // report descriptor and start its reads. The 2026-11-17 sole-configuration
    // trial enumerated and then timed out every report (0xE00002D6) within a
    // second, before any poll. So typing waits until one neutral report - all
    // zeros, which types nothing - is actually collected, retrying only on
    // that timeout, lease-checked before every attempt, bounded here.
    static let hostPollingWaitSeconds: Double = 60
    // Polling starts before the host's input system has attached to the new
    // keyboard: in trial 5 macOS published the keyboard service to
    // WindowServer only for the ~6 s before the restore, and reports typed in
    // the first milliseconds of polling never appeared as keystrokes. So after
    // the first collected neutral report the canary keeps offering neutral
    // reports for this long, paces the typed reports, and holds the neutral
    // state briefly before exiting (its exit is what triggers the restore).
    static let hostSettleSeconds: Double = 3
    static let interReportMicroseconds: UInt32 = 30_000
    static let postTypingHoldSeconds: Double = 1
    // Upper bound on the event-driven hold: the caller releases the canary as
    // soon as its own measurements are done; this only bounds a caller that
    // never does.
    static let releaseWaitSeconds: Double = 120

    let sink: HIDReportSink
    let lease: CanaryLease
    let reports: [[UInt8]]
    // The wait's only instrument. Injected and required: the wait must have a
    // way to ask about host visibility that is not the way it types, so there
    // is no fallback to the report sink and no default that could reintroduce
    // one.
    let visibility: HIDPipeVisibility
    // A requested stop, asked before every write rather than only once the
    // list runs out: a signal must take effect during the writing, not after
    // it. Defaulted, so a caller that cannot be interrupted says nothing.
    var shouldStop: () -> Bool = { false }
    // Wait for the host to collect one neutral report before typing (see
    // hostPollingWaitSeconds). The device entry point turns it on.
    var awaitHostPolling = false
    // Event-driven post-typing hold: when set, the canary keeps the keyboard
    // neutral until this reports true (the caller closed the canary's input),
    // instead of for a fixed postTypingHoldSeconds.
    var released: (() -> Bool)? = nil
    // The clock and the pause the enumeration wait is bounded by, injected so
    // the Mac tests observe the bound without waiting on a real one.
    var now: () -> UInt64 = { clock_gettime_nsec_np(CLOCK_UPTIME_RAW) }
    var pause: () -> Void = { usleep(HIDCanaryRun.enumerationPollMicroseconds) }
    var interReportPause: () -> Void = { usleep(HIDCanaryRun.interReportMicroseconds) }

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
        if awaitHostPolling, !reports.isEmpty {
            if let notPolling = waitForHostPolling() {
                return finish(reportsWritten: 0, stop: notPolling, enumeration: enumeration)
            }
            if let settleStop = holdNeutral(seconds: Self.hostSettleSeconds) {
                return finish(reportsWritten: 0, stop: settleStop, enumeration: enumeration)
            }
        }
        for report in reports {
            // A requested stop is a controlled exit: the neutral report and
            // the lease release below still happen.
            guard !shouldStop() else { stop = .interrupted; break }
            // Checked before every write: a write after the lease has gone is
            // the one thing the broker cannot restore from.
            guard lease.isHeld() else { stop = .leaseLost; break }
            guard HIDKeyboard.isValidReport(report) else { stop = .invalidReport; break }
            if awaitHostPolling && written > 0 { interReportPause() }
            switch sink.write(report).outcome {
            case .delivered: written += 1
            case .failed: stop = .writeFailed
            case .disconnected: stop = .disconnected
            }
            if stop != .completed { break }
        }
        if awaitHostPolling, stop == .completed, written > 0 {
            let holdStop = released.map { holdNeutral(seconds: Self.releaseWaitSeconds, until: $0) }
                ?? holdNeutral(seconds: Self.postTypingHoldSeconds)
            if let holdStop { stop = holdStop }
        }
        return finish(reportsWritten: written, stop: stop, enumeration: enumeration)
    }

    // The bounded wait for host enumeration. It polls the pipe's current
    // maximum packet size, which is zero until a host has selected a
    // configuration containing this interface and the endpoint's size once it
    // has. That is a complete answer to the question the wait is asking, it
    // puts nothing on the bus, and - the reason it replaced polling by writing
    // the neutral report - it means the mechanism of the wait is not the
    // mechanism of typing, so no amount of waiting can type into the
    // operator's machine.
    //
    // The raw IOReturn is kept as the secondary signal it was: zero, or either
    // of the reference's two "not yet" values, is a size of zero that means
    // the host has not finished enumerating. Any other raw return is a real
    // failure and stops the wait at once, recorded verbatim. A query the shim
    // itself refuses is a third answer - the wait could not look at all - and
    // never a report that nothing was seen.
    private func waitForHostEnumeration() -> HIDEnumerationResult {
        let budget = UInt64(Self.enumerationWaitSeconds * 1_000_000_000)
        let start = now()
        var polls = 0
        var last: Int32 = 0
        var size: UInt64 = 0
        func result(_ state: HIDHostEnumeration) -> HIDEnumerationResult {
            HIDEnumerationResult(state: state, polls: polls, lastRawReturn: last,
                                 lastMaxPacketSize: size)
        }
        while true {
            guard !shouldStop() else { return result(.interrupted) }
            // Checked before every poll, exactly as the report loop does. The
            // poll writes nothing, but the lease is what authorizes touching
            // the interface at all, so the rule does not relax.
            guard lease.isHeld() else { return result(.leaseLost) }
            // The deadline only ends a wait that has already asked once, so a
            // clock that is already past it cannot skip the single poll that
            // tells an enumerated host from an absent one.
            guard polls == 0 || now() - start < budget else {
                return result(.neverEnumerated)
            }
            polls += 1
            let answer = visibility.currentMaxPacketSize()
            last = answer.rawReturn
            size = answer.maxPacketSize
            guard answer.result == HIDPipeSizeProbe.success else {
                return result(.probeUnavailable)
            }
            // A size the host has selected a configuration for: the interface
            // is in that configuration, which is the whole question.
            if size > 0 { return result(.enumerated) }
            guard last == 0 || PipeReportTransport.notYetEnumerated.contains(last) else {
                return result(.waitFailed)
            }
            pause()
        }
    }

    private static func stop(for state: HIDHostEnumeration) -> HIDCanaryStop {
        switch state {
        case .enumerated: return .completed
        case .neverEnumerated: return .hostNeverEnumerated
        case .probeUnavailable: return .enumerationProbeUnavailable
        case .waitFailed: return .enumerationWaitFailed
        case .leaseLost: return .leaseLost
        case .interrupted: return .interrupted
        }
    }

    // Offers the neutral report until the host collects one. Returns nil once
    // delivered, or the stop that ended the wait: only a timed-out write is
    // retried; a refusal, a disconnect, a lost lease or the deadline end it.
    private func waitForHostPolling() -> HIDCanaryStop? {
        let budget = UInt64(Self.hostPollingWaitSeconds * 1_000_000_000)
        let start = now()
        while true {
            guard !shouldStop() else { return .interrupted }
            guard lease.isHeld() else { return .leaseLost }
            let answer = sink.write(HIDKeyboard.neutralReport)
            switch answer.outcome {
            case .delivered: return nil
            case .disconnected, .failed:
                // The runner's bus cycle re-presents the device after the
                // commit, which aborts the pipe (0xE00002EB) and leaves it
                // unenumerated (0xE0000001) until the host selects the
                // configuration again. The second sole-configuration trial
                // exited on exactly that while the Mac's HID driver was already
                // sending SET_IDLE/SET_PROTOCOL. Those, and a timeout, are
                // waited out within the same budget; anything else stops.
                guard PipeReportTransport.reenumerating.contains(answer.rawReturn),
                      now() - start < budget else {
                    return answer.outcome == .disconnected ? .disconnected : .writeFailed
                }
                if answer.rawReturn != PipeReportTransport.writeTimedOut { pause() }
            }
        }
    }

    // Keeps the host's view neutral for a while: offers the neutral report,
    // paced, until the time is up. A timed-out offer just means the host did
    // not poll in that slice; a refusal, a disconnect or a lost lease ends it.
    private func holdNeutral(seconds: Double,
                             until done: () -> Bool = { false }) -> HIDCanaryStop? {
        let budget = UInt64(seconds * 1_000_000_000)
        let start = now()
        while now() - start < budget && !done() {
            guard !shouldStop() else { return .interrupted }
            guard lease.isHeld() else { return .leaseLost }
            let answer = sink.write(HIDKeyboard.neutralReport)
            switch answer.outcome {
            case .delivered: break
            case .disconnected: return .disconnected
            case .failed:
                guard answer.rawReturn == PipeReportTransport.writeTimedOut else { return .writeFailed }
            }
            interReportPause()
        }
        return nil
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
