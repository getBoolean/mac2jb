// The canary's staged gates. Each gate answers one question, and a conflated
// failure is expensive to diagnose on hardware, so the questions are asked
// separately: does the appended name materialize as an interface whose user
// client opens at all, which configuration operations does this build
// authorize, and do reports reach a host. Pure values and pure functions, so
// the Mac tests observe the mapping without a device.

enum HIDCanaryMode: String, Equatable {
    case full = "full"
    case openOnly = "open-only"
    case configureOnly = "configure-only"

    // An absent argument is the full run: callers that predate the gates must
    // be unchanged. An unrecognised spelling is refused rather than guessed,
    // because silently running the full run would type into a host that may be
    // nobody's idea of a target.
    init?(argument: String?) {
        guard let argument else { self = .full; return }
        guard let mode = HIDCanaryMode(rawValue: argument) else { return nil }
        self = mode
    }

    // The stop-after-open gate configures nothing: a refusal has to be
    // attributable to the open and not to some later selector.
    var configuresInterface: Bool { self != .openOnly }

    // Typing is a separate question from configuring, and a host is not
    // necessarily watching, so only the full run writes the canary string. The
    // single neutral report of a controlled exit is not one of these: the lease
    // rules are unchanged whatever the mode.
    var reportsToWrite: [[UInt8]] { self == .full ? HIDKeyboard.canaryReports() : [] }
}

// The three answers of the stop-after-open gate, which are three different
// facts: the interface appeared and its user client opened; the interface never
// appeared; the interface appeared and the open was denied. The first is a stop
// gate for the whole approach and the last two point at different causes, so
// each carries its own exit code. 2 belongs to the usage refusal and 1 to a
// run that never got a lease.
enum HIDCanaryOpenOutcome: Equatable {
    case opened
    case interfaceAbsent
    case openDenied
    case failed  // anything else: no controller, no API, bad input

    // The shim's result codes for the two refusals this gate separates. Named
    // here because the Mac test build cannot import the shim header; the test
    // suite checks these against the header, since reporting one refusal as the
    // other is exactly what the gate exists to prevent.
    static let serviceAbsentResult: Int32 = 5
    static let openDeniedResult: Int32 = 6

    init(resultRawValue: Int32) {
        switch resultRawValue {
        case 0: self = .opened
        case Self.serviceAbsentResult: self = .interfaceAbsent
        case Self.openDeniedResult: self = .openDenied
        default: self = .failed
        }
    }

    var exitCode: Int32 {
        switch self {
        case .opened: return 0
        case .interfaceAbsent: return 3
        case .openDenied: return 4
        case .failed: return 5
        }
    }

    var label: String {
        switch self {
        case .opened: return "opened"
        case .interfaceAbsent: return "interface-absent"
        case .openDenied: return "open-denied"
        case .failed: return "open-failed"
        }
    }
}
