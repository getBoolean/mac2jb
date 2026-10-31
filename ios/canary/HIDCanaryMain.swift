import Darwin
import MAC2JBUSBDeviceFunctionShim

// The canary entry point: a separate, least-privileged process that holds a
// lease from the broker, configures one already-published gadget function into
// a USB boot keyboard and writes reports. It is signed with
// platform-application plus the IOUSBDeviceInterfaceUserClient exception and
// nothing else: it cannot publish a description, it never links the
// publication shim and it never opens the journal. Publication authority and
// the single-writer invariant stay with the broker.
//
// Every raw IOReturn is printed verbatim and the sequence stops at the first
// refusal: the first failing operation is the result worth having, so there is
// no retry, no suppression and no alternative selector here.

private let identifier = "U3_HID_CANARY"

// Plain POSIX and Darwin only, as the watchdog does: no Foundation, hence a
// local hex formatter for the raw IOReturn values.
private func hex(_ value: Int32) -> String {
    let digits = Array("0123456789abcdef")
    var raw = UInt32(bitPattern: value)
    var text = ""
    for _ in 0..<8 {
        text = String(digits[Int(raw & 0xF)]) + text
        raw >>= 4
    }
    return "0x" + text
}

private func line(_ text: String) {
    print(identifier + " " + text)
    fflush(stdout)
}

// What the commit step leaves behind for the transmit path: the pipe the
// reports go to and the shared buffer they are staged in.
private struct PipeHandles {
    var pipeID: UInt64 = 0
    var bufferAddress: UInt64 = 0
    var bufferSize: UInt64 = 0
    var bufferToken: UInt64 = 0
}

// The reference's write timeout for a keyboard report.
private let writeTimeoutMilliseconds: UInt64 = 250

// The appended interface cannot exist until the broker's publication lands,
// and the broker will not publish until this process holds the lease, so the
// interface is expected to be absent for a moment after the lease is taken.
// The shim makes one match-and-open attempt per call and leaves the waiting to
// its caller, so the waiting is done here: a call that reports no such service
// opened nothing, and the first call that finds the interface is the single
// open attempt.
private let interfaceWaitSeconds: Double = 10
private let interfacePollMicroseconds: UInt32 = 100_000

private struct Arguments {
    let function: String
    let controllerRegistryID: UInt64
    let socketPath: String
    let leaseSeconds: Double

    // --function <name> --controller <registry entry id> [--socket <path>]
    // [--lease-seconds <n>]. The controller id is a parameter so that nothing
    // device-specific is compiled in.
    init?(_ arguments: [String]) {
        var values: [String: String] = [:]
        var index = 0
        while index + 1 < arguments.count {
            values[arguments[index]] = arguments[index + 1]
            index += 2
        }
        guard index == arguments.count,
              let function = values["--function"],
              let controller = values["--controller"],
              let registryID = UInt64(controller), registryID > 0 else { return nil }
        self.function = function
        controllerRegistryID = registryID
        socketPath = values["--socket"] ?? BrokerSocketLease.defaultSocketPath
        leaseSeconds = Double(values["--lease-seconds"] ?? "")
            ?? BrokerSocketLease.maximumLeaseSeconds
    }
}

// A signal must not skip the neutral report and the lease release, so it only
// records that the run should stop; the normal exit path does the rest.
private var interrupted: sig_atomic_t = 0

private func noteInterrupt(_ signal: Int32) { interrupted = 1 }

private func describe(_ ledger: MAC2JBUSBFunctionLedger) -> String {
    let names = ["interface-open", "set-class", "set-subclass", "set-protocol",
                 "append-standard", "append-nonstandard", "class-callbacks",
                 "create-pipe", "commit", "create-buffer", "interface-close",
                 "write-pipe", "pipe-max-packet"]
    // The shim's fixed-size arrays arrive in Swift as tuples.
    let calls = withUnsafeBytes(of: ledger.calls) { Array($0.bindMemory(to: Int32.self)) }
    let attempts = withUnsafeBytes(of: ledger.attempts) { Array($0.bindMemory(to: UInt32.self)) }
    var parts: [String] = []
    for (index, name) in names.enumerated()
    where ledger.attempted & (1 << UInt32(index)) != 0 {
        // A repeatable cell holds its most recent raw return, so its attempt
        // count is reported beside it.
        let repeatable = MAC2JBUSBFunctionOperationIsRepeatable(
            MAC2JBUSBFunctionOperation(UInt32(index)))
        parts.append(name + "=" + hex(calls[index]) +
                     (repeatable ? "/\(attempts[index])" : ""))
    }
    return parts.joined(separator: " ")
}

@main
enum HIDCanaryMain {
    static func main() {
        signal(SIGPIPE, SIG_IGN)
        signal(SIGINT, noteInterrupt)
        signal(SIGTERM, noteInterrupt)
        guard let arguments = Arguments(Array(CommandLine.arguments.dropFirst())) else {
            line("rejected reason=usage")
            exit(2)
        }
        // The lease comes first: no interface is touched without it.
        let lease: BrokerSocketLease
        do {
            lease = try BrokerSocketLease(socketPath: arguments.socketPath,
                                          leaseSeconds: arguments.leaseSeconds)
        } catch {
            line("rejected reason=no-lease")
            exit(1)
        }
        // Said as soon as the lease is held, because the host runner waits for
        // exactly this before it asks the broker to publish: the broker
        // refuses to publish with no worker registered.
        line("lease=held function=\(arguments.function)")
        var session: OpaquePointer?
        var matchReturn: Int32 = 0
        var openReturn: Int32 = 0
        var opened = MAC2JBUSBFunctionServiceAbsent
        var waits = 0
        let deadline = clock_gettime_nsec_np(CLOCK_UPTIME_RAW) +
            UInt64(interfaceWaitSeconds * 1_000_000_000)
        while true {
            opened = MAC2JBUSBFunctionOpen(arguments.controllerRegistryID,
                                           arguments.function,
                                           MAC2JBUSBFunctionReferenceUserClientType,
                                           &session, &matchReturn, &openReturn)
            guard opened == MAC2JBUSBFunctionServiceAbsent,
                  lease.isHeld(), interrupted == 0,
                  clock_gettime_nsec_np(CLOCK_UPTIME_RAW) < deadline else { break }
            waits += 1
            usleep(interfacePollMicroseconds)
        }
        line("open result=\(opened.rawValue) " +
             "match=" + hex(matchReturn) +
             " open=" + hex(openReturn) +
             " waits=\(waits)")
        guard opened == MAC2JBUSBFunctionSuccess, let session else {
            lease.release(neutralDelivered: false)
            exit(1)
        }
        // exit() runs no defers, so each exit path below closes the session.
        var handles = PipeHandles()
        let configured = configure(session, lease: lease, handles: &handles)
        var ledger = MAC2JBUSBFunctionLedger()
        MAC2JBUSBFunctionLedgerInit(&ledger)
        _ = MAC2JBUSBFunctionCopyLedger(session, &ledger)
        line("operations " + describe(ledger) +
             " aborted-by=\(ledger.abortedBy)")
        guard configured else {
            MAC2JBUSBFunctionClose(session)
            lease.release(neutralDelivered: false)
            exit(1)
        }
        let summary = HIDCanaryRun(sink: transport(session, handles: handles),
                                   lease: lease, reports: HIDKeyboard.canaryReports(),
                                   shouldStop: { interrupted != 0 }).run()
        // Counts only: the keys themselves never reach the log.
        line("reports written=\(summary.reportsWritten) stop=\(summary.stop) " +
             "neutral-attempts=\(summary.neutralAttempts) " +
             "neutral=\(summary.neutralDelivered ? "delivered" : "undelivered") " +
             "transport=pipe-write")
        MAC2JBUSBFunctionClose(session)
        exit(summary.stop == .completed ? 0 : 1)
    }

    // The production report sink: stage the bytes in the mapped shared buffer
    // and submit that buffer's token. The raw IOReturn and the transferred
    // count are kept apart deliberately, so a short write is not read as an
    // error code; every raw return is printed.
    private static func transport(_ session: OpaquePointer,
                                  handles: PipeHandles) -> PipeReportTransport {
        PipeReportTransport(
            stage: { report in
                guard handles.bufferAddress != 0,
                      UInt64(report.count) <= handles.bufferSize,
                      let destination = UnsafeMutableRawPointer(
                            bitPattern: UInt(handles.bufferAddress)) else {
                    return false
                }
                report.withUnsafeBytes { destination.copyMemory(from: $0.baseAddress!,
                                                                byteCount: $0.count) }
                return true
            },
            submit: { length in
                var transferred: UInt64 = 0
                var callReturn: Int32 = 0
                let result = MAC2JBUSBFunctionWritePipe(
                    session, UInt32(MAC2JBUSBFunctionSelectorWritePipe.rawValue),
                    handles.pipeID, handles.bufferToken, UInt64(length),
                    writeTimeoutMilliseconds, &transferred, &callReturn)
                line("write result=\(result.rawValue) io=" + hex(callReturn) +
                     " transferred=\(transferred)")
                guard result == MAC2JBUSBFunctionSuccess else { return (callReturn, 0) }
                return (callReturn, transferred)
            })
    }

    // Drives the plan in the reference order, recording every raw IOReturn and
    // stopping at the first refusal. The pipe id and the buffer the plan's
    // later steps produce are kept for the transmit path.
    private static func configure(_ session: OpaquePointer, lease: CanaryLease,
                                  handles: inout PipeHandles) -> Bool {
        // The reference's class/pipe configuration id, and its undocumented
        // scalars, which that backend passes as zero.
        let configurationID: UInt64 = 0
        let unexplainedScalar: UInt64 = 0
        let descriptorSecondArgument: UInt8 = 0x0F  // the reference's value
        for step in HIDFunctionConfigurationPlan.steps {
            guard lease.isHeld(), interrupted == 0 else {
                line("stopped before=\(step.kindName) reason=" +
                     (interrupted != 0 ? "signal" : "lease-lost"))
                return false
            }
            var callReturn: Int32 = 0
            var result = MAC2JBUSBFunctionSuccess
            switch step {
            case .interfaceOpen:
                result = MAC2JBUSBFunctionInterfaceOpen(
                    session, UInt32(MAC2JBUSBFunctionSelectorInterfaceOpen.rawValue),
                    0, &callReturn)
            case .setClass(let value):
                result = MAC2JBUSBFunctionSetClass(
                    session, UInt32(MAC2JBUSBFunctionSelectorSetClass.rawValue),
                    value, configurationID, &callReturn)
            case .setSubClass(let value):
                result = MAC2JBUSBFunctionSetSubClass(
                    session, UInt32(MAC2JBUSBFunctionSelectorSetSubClass.rawValue),
                    value, configurationID, &callReturn)
            case .setProtocol(let value):
                result = MAC2JBUSBFunctionSetProtocol(
                    session, UInt32(MAC2JBUSBFunctionSelectorSetProtocol.rawValue),
                    value, configurationID, &callReturn)
            case .appendStandardDescriptor(let type, let bytes):
                result = bytes.withUnsafeBufferPointer {
                    MAC2JBUSBFunctionAppendStandardDescriptor(
                        session,
                        UInt32(MAC2JBUSBFunctionSelectorAppendStandardDescriptor.rawValue),
                        type, descriptorSecondArgument, $0.baseAddress, $0.count,
                        &callReturn)
                }
            case .appendNonstandardDescriptor(let type, let bytes):
                result = bytes.withUnsafeBufferPointer {
                    MAC2JBUSBFunctionAppendNonstandardDescriptor(
                        session,
                        UInt32(MAC2JBUSBFunctionSelectorAppendNonstandardDescriptor.rawValue),
                        type, descriptorSecondArgument, $0.baseAddress, $0.count,
                        &callReturn)
                }
            case .setClassCommandCallbacks(let flagA, let flagB, let flagC):
                // The kernel needs a port to deliver class commands to and a
                // reference block to carry back. The canary runs no run loop,
                // so it hands over a bare receive port and a zero callout: the
                // registration is what is being configured here, not callback
                // handling.
                var port: mach_port_t = 0
                guard mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE,
                                         &port) == KERN_SUCCESS else {
                    line("stopped before=class-callbacks reason=no-port")
                    return false
                }
                var reference = [UInt64](repeating: 0, count: 8)
                reference[0] = UInt64(port)
                result = reference.withUnsafeBufferPointer {
                    MAC2JBUSBFunctionSetClassCommandCallbacks(
                        session,
                        UInt32(MAC2JBUSBFunctionSelectorSetClassCommandCallbacks.rawValue),
                        port, $0.baseAddress, UInt32($0.count),
                        flagA, flagB, flagC, &callReturn)
                }
            case .createPipe(let endpoint):
                var pipeID: UInt64 = 0
                result = MAC2JBUSBFunctionCreatePipe(
                    session, UInt32(MAC2JBUSBFunctionSelectorCreatePipe.rawValue),
                    endpoint.transferType, endpoint.direction, endpoint.maxPacketSize,
                    endpoint.interval, unexplainedScalar, configurationID, &pipeID,
                    &callReturn)
                handles.pipeID = pipeID
                line("pipe id=\(pipeID)")
                // Ask the pipe what it actually is, so the run carries its own
                // evidence of an 8-byte endpoint rather than only what was
                // asked for. A refusal here is a recorded observation, not a
                // reason to stop: it says nothing about whether reports flow.
                if result == MAC2JBUSBFunctionSuccess && callReturn == 0 {
                    var maxPacketSize: UInt64 = 0
                    var queryReturn: Int32 = 0
                    let query = MAC2JBUSBFunctionPipeMaxPacketSize(
                        session,
                        UInt32(MAC2JBUSBFunctionSelectorPipeMaxPacketSize.rawValue),
                        pipeID, &maxPacketSize, &queryReturn)
                    line("pipe max-packet=\(maxPacketSize) result=\(query.rawValue) " +
                         "io=" + hex(queryReturn) +
                         " expected=\(endpoint.maxPacketSize)")
                }
            case .createBuffer(let size):
                var address: UInt64 = 0
                var bufferSize: UInt64 = 0
                var token: UInt64 = 0
                result = MAC2JBUSBFunctionCreateBuffer(
                    session, UInt32(MAC2JBUSBFunctionSelectorCreateBuffer.rawValue),
                    size, &address, &bufferSize, &token, &callReturn)
                handles.bufferAddress = address
                handles.bufferSize = bufferSize
                handles.bufferToken = token
                line("buffer size=\(bufferSize) mapped=\(address != 0)")
            case .commit:
                result = MAC2JBUSBFunctionCommit(
                    session, UInt32(MAC2JBUSBFunctionSelectorCommit.rawValue), &callReturn)
            }
            if result != MAC2JBUSBFunctionSuccess || callReturn != 0 {
                line("refused step=\(step.kindName) result=\(result.rawValue) " +
                     "io=" + hex(callReturn))
                return false
            }
        }
        return true
    }
}
