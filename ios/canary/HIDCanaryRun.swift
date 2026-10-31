// The canary's report loop and its exit paths. The report sink and the lease
// are injected, so the Mac tests observe the exit behaviour without this file
// growing a mode that only a test uses.

enum HIDReportWriteOutcome {
    case delivered
    case failed        // the pipe refused the write
    case disconnected  // the host is gone; a further attempt cannot reach it
}

protocol HIDReportSink {
    func write(_ report: [UInt8]) -> HIDReportWriteOutcome
}

// The production sink. The reference backend's write copies the payload into
// the mapped buffer that create-buffer returned and then submits the buffer's
// token, not a pointer. The raw IOReturn and the transferred count come back
// separately and both matter: a call that returned success having moved fewer
// than the report's bytes has not delivered the report, and conflating the two
// makes a short write look like an error code. The staging copy and the submit
// are injected so this rule is testable without a device.
struct PipeReportTransport: HIDReportSink {
    // The raw IOReturn the reference reports when the host is not enumerated.
    // A further attempt cannot reach a host that is gone.
    static let notEnumerated = Int32(bitPattern: 0xE0000001)

    let stage: ([UInt8]) -> Bool
    let submit: (UInt32) -> (ioReturn: Int32, transferred: UInt64)

    func write(_ report: [UInt8]) -> HIDReportWriteOutcome {
        guard stage(report) else { return .failed }
        let answer = submit(UInt32(report.count))
        if answer.ioReturn == Self.notEnumerated { return .disconnected }
        guard answer.ioReturn == 0,
              answer.transferred == UInt64(report.count) else { return .failed }
        return .delivered
    }
}

enum HIDCanaryStop: Equatable {
    case completed
    case invalidReport
    case writeFailed
    case disconnected
    case leaseLost
}

struct HIDCanarySummary: Equatable {
    let reportsWritten: Int
    let stop: HIDCanaryStop
    let neutralAttempts: Int
    let neutralDelivered: Bool
    let leaseReleased: Bool
}

struct HIDCanaryRun {
    // The reference teardown's bound: three attempts at the neutral report,
    // abandoned early once the host is gone.
    static let neutralAttemptLimit = 3

    let sink: HIDReportSink
    let lease: CanaryLease
    let reports: [[UInt8]]

    func run() -> HIDCanarySummary {
        var written = 0
        var stop = HIDCanaryStop.completed
        for report in reports {
            // Checked before every write: a write after the lease has gone is
            // the one thing the broker cannot restore from.
            guard lease.isHeld() else { stop = .leaseLost; break }
            guard HIDKeyboard.isValidReport(report) else { stop = .invalidReport; break }
            switch sink.write(report) {
            case .delivered: written += 1
            case .failed: stop = .writeFailed
            case .disconnected: stop = .disconnected
            }
            if stop != .completed { break }
        }
        return finish(reportsWritten: written, stop: stop)
    }

    // Every exit path ends here: one neutral report while the lease is held,
    // then the lease goes back. A lost lease is the exception, and the reason
    // is the same one that stops the loop above: without the lease the canary
    // may not write at all, so it releases and leaves the held keys to the
    // broker's restore path.
    private func finish(reportsWritten: Int, stop: HIDCanaryStop) -> HIDCanarySummary {
        var attempts = 0
        var delivered = false
        if stop != .leaseLost && lease.isHeld() {
            attempts: while attempts < Self.neutralAttemptLimit {
                attempts += 1
                switch sink.write(HIDKeyboard.neutralReport) {
                case .delivered: delivered = true; break attempts
                case .disconnected: break attempts
                case .failed: continue
                }
            }
        }
        lease.release(neutralDelivered: delivered)
        return HIDCanarySummary(reportsWritten: reportsWritten, stop: stop,
                                neutralAttempts: attempts, neutralDelivered: delivered,
                                leaseReleased: true)
    }
}
