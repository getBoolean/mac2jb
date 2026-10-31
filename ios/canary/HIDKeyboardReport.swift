// The canary's USB HID boot-keyboard model and the configuration plan it
// drives through the interface shim. Pure values and pure functions: nothing
// here opens a service, publishes a description or touches the journal.
//
// Every value is the corrected one from the macOS sender, not the upstream
// libusbd example: the HID descriptor's report length is derived from the
// report descriptor that is actually appended (the example declared 93 bytes
// for a 65-byte descriptor), and no device-level identity is configured at
// all. The device keeps the vendor ID, product ID, version and strings it
// already reports, because hosts bind keyboards by interface class and an
// external check compares those device scalars against the stock values.

struct HIDEndpointPlan: Equatable {
    let transferType: UInt8   // USB transfer type: 3 is interrupt
    let direction: UInt8      // 1 is IN (device to host)
    let maxPacketSize: UInt32
    let interval: UInt8
}

enum HIDKeyboard {
    static let interfaceClass: UInt8 = 3     // HID
    static let interfaceSubClass: UInt8 = 1  // boot interface
    static let interfaceProtocol: UInt8 = 1  // keyboard

    static let reportLength = 8
    static let neutralReport = [UInt8](repeating: 0, count: reportLength)

    static let endpoint = HIDEndpointPlan(transferType: 3, direction: 1,
                                          maxPacketSize: 8, interval: 10)

    // Boot-keyboard report descriptor, 65 bytes, byte-identical to the sender's.
    static let reportDescriptor: [UInt8] = [
        0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25, 0x01,
        0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08, 0x81, 0x01, 0x95, 0x03, 0x75, 0x01,
        0x05, 0x08, 0x19, 0x01, 0x29, 0x03, 0x91, 0x02, 0x95, 0x05, 0x75, 0x01, 0x91, 0x01, 0x95, 0x06,
        0x75, 0x08, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x05, 0x07, 0x19, 0x00, 0x2A, 0xFF, 0x00, 0x81, 0x00, 0xC0,
    ]

    // bLength, HID, bcdHID 1.11, country 0, one descriptor, report type 0x22,
    // then the report length little-endian, derived rather than declared.
    static let hidDescriptor: [UInt8] = [
        0x09, 0x21, 0x11, 0x01, 0x00, 0x01, 0x22,
        UInt8(reportDescriptor.count & 0xFF),
        UInt8((reportDescriptor.count >> 8) & 0xFF),
    ]

    // One fixed string, with its keycodes written out beside each character.
    // Text encoding, indentation and bootstrap belong to later work; proving
    // that reports reach a host needs nothing more than this.
    static let leftShift: UInt8 = 0x02

    // Upper case on purpose: the accepted canary string is upper case, and a
    // shifted character is the only thing that puts a non-zero value in the
    // modifier byte, so a run that typed lower case would never exercise it.
    static let canaryKeystrokes: [(character: Character, modifiers: UInt8, keycode: UInt8)] = [
        ("M", leftShift, 0x10), ("A", leftShift, 0x04), ("C", leftShift, 0x06),
        ("2", 0, 0x1F), ("J", leftShift, 0x0D), ("B", leftShift, 0x05),
    ]

    static var canaryText: String { String(canaryKeystrokes.map(\.character)) }

    // A press and its release for each character: a held key that is never
    // released is exactly the failure the neutral report exists to prevent.
    static func canaryReports() -> [[UInt8]] {
        canaryKeystrokes.flatMap {
            [report(modifiers: $0.modifiers, keycode: $0.keycode), neutralReport]
        }
    }

    static func report(modifiers: UInt8, keycode: UInt8) -> [UInt8] {
        [modifiers, 0, keycode, 0, 0, 0, 0, 0]
    }

    // Ported from the keyboard forwarder's report check: the reserved byte is
    // zero, keycodes live in bytes 2..7, no keycode follows an empty slot, each
    // keycode is in range and no keycode repeats.
    static func isValidReport(_ report: [UInt8]) -> Bool {
        guard report.count == reportLength, report[1] == 0 else { return false }
        var empty = false
        for index in 2..<reportLength {
            let key = report[index]
            if key == 0 { empty = true; continue }
            if empty || key < 4 || key > 0x73 { return false }
            if report[2..<index].contains(key) { return false }
        }
        return true
    }
}

// One step of the interface configuration, with the arguments it carries. The
// cases are the vocabulary of what the canary is allowed to configure, so the
// absence of any device-level identity case is checkable rather than asserted
// in a comment.
enum HIDFunctionConfigurationStep: Equatable {
    case interfaceOpen
    case setClass(UInt8)
    case setSubClass(UInt8)
    case setProtocol(UInt8)
    case appendStandardDescriptor(type: UInt8, bytes: [UInt8])
    case appendNonstandardDescriptor(type: UInt8, bytes: [UInt8])
    case setClassCommandCallbacks(flagA: Bool, flagB: Bool, flagC: Bool)
    case createPipe(HIDEndpointPlan)
    case createBuffer(size: UInt32)
    case commit

    static let kindNames = [
        "interfaceOpen", "setClass", "setSubClass", "setProtocol",
        "appendStandardDescriptor", "appendNonstandardDescriptor",
        "createPipe", "createBuffer", "commit", "setClassCommandCallbacks",
    ]

    var kindName: String {
        switch self {
        case .interfaceOpen: return "interfaceOpen"
        case .setClass: return "setClass"
        case .setSubClass: return "setSubClass"
        case .setProtocol: return "setProtocol"
        case .appendStandardDescriptor: return "appendStandardDescriptor"
        case .appendNonstandardDescriptor: return "appendNonstandardDescriptor"
        case .setClassCommandCallbacks: return "setClassCommandCallbacks"
        case .createPipe: return "createPipe"
        case .createBuffer: return "createBuffer"
        case .commit: return "commit"
        }
    }
}

enum HIDFunctionConfigurationPlan {
    // The reference backend's size for the setup and endpoint buffers.
    static let bufferSize: UInt32 = 0x1000

    // The order is the macOS reference backend's, step for step: the
    // interface open first (the only order the shim's ledger enforces), then
    // the class triple and the two descriptor appends, then the pipe, which
    // that backend creates when the endpoint is added, and finally what its
    // finalize step does in this sequence - create the buffers, commit the
    // configuration, and only then register the class-command callbacks.
    // Order matters because this is a probe: it stops at the first refusal and
    // records raw returns, so an operation attempted out of the reference's
    // order can be refused for the wrong reason and be read as this build
    // refusing the operation itself.
    static let steps: [HIDFunctionConfigurationStep] = [
        .interfaceOpen,
        .setClass(HIDKeyboard.interfaceClass),
        .setSubClass(HIDKeyboard.interfaceSubClass),
        .setProtocol(HIDKeyboard.interfaceProtocol),
        .appendStandardDescriptor(type: 0x21, bytes: HIDKeyboard.hidDescriptor),
        .appendNonstandardDescriptor(type: 0x22, bytes: HIDKeyboard.reportDescriptor),
        .createPipe(HIDKeyboard.endpoint),
        .createBuffer(size: bufferSize),
        .commit,
        .setClassCommandCallbacks(flagA: true, flagB: false, flagC: false),
    ]
}
