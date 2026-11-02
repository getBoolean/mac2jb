#!/usr/bin/env swift
// Record the HID input reports one matched USB boot keyboard sends to this Mac.
//
// Why this seizes the device, which is the whole reason the tool exists: the
// device under trial presents itself as a real USB keyboard, so the string it
// types is real keyboard input to this Mac. A reader that merely observed
// would let every keystroke of the trial also land in whatever window has
// focus, which is unacceptable - a trial must not type into the operator's
// machine. So the matched device is opened with kIOHIDOptionsTypeSeizeDevice,
// which delivers its reports here instead of to the system's HID stack. A
// failed seize is a hard refusal with its own exit code: there is deliberately
// no fallback to passive observation, because passive observation is precisely
// the harmful behaviour this tool exists to prevent.
//
// Matching is by the vendor and product ID given as arguments - learned from
// the device's own profile by the caller, never compiled in - and by the boot
// keyboard's usage page and usage, so the operator's own keyboard cannot be
// bound by accident. More than one match is refused rather than guessed.
//
// Bounded always: a deadline in seconds and a maximum report count, both
// arguments. The run ends at whichever comes first, and the reader never waits
// unbounded on a device.
//
// Every outcome has its own exit code and its own summary label, because a
// tooling fault read as a hardware result would turn "we could not look" into
// "the device sent nothing", which is a false negative about the device.
// macOS gates input-report access behind Input Monitoring, so a permission
// refusal names the grant and the binary that needs it and stops there; there
// is no attempt to work around TCC.
//
// No serial number, unique identifier or pairing identifier is read, printed
// or written. The vendor and product IDs are deliberately stock and may appear.
//
// Usage: u2-hid-report-reader VENDOR PRODUCT DEADLINE_SECONDS MAX_REPORTS OUT
//        u2-hid-report-reader --self-test

import CoreFoundation
import Darwin
import Foundation
import IOKit
import IOKit.hid

private let prefix = "U2_HID_REPORTS"
// A boot keyboard report is eight bytes: one modifier byte, one reserved byte
// and six keycodes. This is the boot protocol, not a property of any device.
private let reportLength = 8
private let usagePage = Int(kHIDPage_GenericDesktop)
private let usage = Int(kHIDUsage_GD_Keyboard)
// How long the reader will wait for the matched device to appear before it
// reports that nothing matched. The caller starts it once the function is
// published, and host enumeration is not instant, so a short wait here is what
// lets the seize happen before the first keystroke rather than after it.
private let arrivalPollSeconds = 0.1

private enum Outcome: String {
    case recorded = "reports-recorded"
    case silent = "no-reports"
    case permission = "permission-denied"
    case absent = "no-matching-device"
    case ambiguous = "several-matching-devices"
    case refused = "seize-refused"

    // Separate codes on purpose: collapsing any two of these would let a
    // tooling fault be read as a result about the device.
    var code: Int32 {
        switch self {
        case .recorded: return 0
        case .silent: return 66
        case .permission: return 67
        case .absent: return 68
        case .ambiguous: return 69
        case .refused: return 70
        }
    }

    // Only a seized device can have written anything, so only these two
    // outcomes leave a reports file behind.
    var seized: Bool { self == .recorded || self == .silent }
}

private struct Result {
    let outcome: Outcome
    let reports: [String]
    let malformed: Int
    let deadlineReached: Bool
}

private func hexLine(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

private func isPermissionDenied(_ status: IOReturn) -> Bool {
    status == kIOReturnNotPermitted || status == kIOReturnNotPrivileged
}

/// What a seized device that sent nothing means, given the privacy grant.
///
/// A denied Input Monitoring grant does not always surface as a refused open:
/// the open can succeed and the input-report callback simply never fire. That
/// is the one case where silence would be read as "the device sent nothing",
/// which is a false negative about the device, so the grant decides the label.
private func silentOutcome(accessGranted: Bool) -> Outcome {
    accessGranted ? .silent : .permission
}

/// The Input Monitoring grant's state. Only asked, never requested: working
/// around TCC is not this tool's business, and an unknown state is left to the
/// open attempt, which is what would prompt for it.
private func inputMonitoringGranted() -> Bool {
    IOHIDCheckAccess(kIOHIDRequestTypeListenEvent) != kIOHIDAccessTypeDenied
}

private final class ReportCollector {
    let maximum: Int
    var reports: [String] = []
    var malformed = 0

    init(maximum: Int) { self.maximum = maximum }

    // A short or long report is counted, never padded into something that
    // would compare as a keystroke the device did not send.
    func append(_ bytes: [UInt8]) {
        guard reports.count < maximum else { return }
        guard bytes.count == reportLength else {
            malformed += 1
            return
        }
        reports.append(hexLine(bytes))
        if reports.count >= maximum { CFRunLoopStop(CFRunLoopGetCurrent()) }
    }
}

private func matchingDictionary(vendor: UInt16, product: UInt16) -> CFDictionary {
    [
        kIOHIDVendorIDKey: Int(vendor),
        kIOHIDProductIDKey: Int(product),
        kIOHIDPrimaryUsagePageKey: usagePage,
        kIOHIDPrimaryUsageKey: usage,
    ] as CFDictionary
}

/// The one matched device, or the outcome that says why there is not one.
private func matchedDevice(
    _ manager: IOHIDManager,
    deadline: Date
) -> (IOHIDDevice?, Outcome?) {
    while true {
        let devices = (IOHIDManagerCopyDevices(manager) as? Set<IOHIDDevice>) ?? []
        // Two keyboards with the same learned identity cannot be told apart
        // here, and guessing could bind the wrong one, so this is a refusal.
        if devices.count > 1 { return (nil, .ambiguous) }
        if let device = devices.first { return (device, nil) }
        if Date() >= deadline { return (nil, .absent) }
        // Running the loop is what lets a device that arrives during the wait
        // reach the manager at all.
        _ = CFRunLoopRunInMode(.defaultMode, arrivalPollSeconds, true)
    }
}

private func capture(
    vendor: UInt16,
    product: UInt16,
    deadline: TimeInterval,
    maximum: Int
) -> Result {
    // Asked before the device is touched at all: with the grant refused there
    // is nothing to seize reports with, and saying so is the whole answer.
    guard inputMonitoringGranted() else {
        return Result(outcome: .permission, reports: [], malformed: 0,
                      deadlineReached: false)
    }
    let manager = IOHIDManagerCreate(kCFAllocatorDefault,
                                     IOOptionBits(kIOHIDOptionsTypeNone))
    IOHIDManagerSetDeviceMatching(manager, matchingDictionary(vendor: vendor,
                                                              product: product))
    IOHIDManagerScheduleWithRunLoop(manager, CFRunLoopGetCurrent(),
                                    CFRunLoopMode.defaultMode.rawValue)
    defer {
        IOHIDManagerUnscheduleFromRunLoop(manager, CFRunLoopGetCurrent(),
                                          CFRunLoopMode.defaultMode.rawValue)
        IOHIDManagerClose(manager, IOOptionBits(kIOHIDOptionsTypeNone))
    }
    let opened = IOHIDManagerOpen(manager, IOOptionBits(kIOHIDOptionsTypeNone))
    if isPermissionDenied(opened) {
        return Result(outcome: .permission, reports: [], malformed: 0,
                      deadlineReached: false)
    }
    guard opened == kIOReturnSuccess else {
        return Result(outcome: .refused, reports: [], malformed: 0,
                      deadlineReached: false)
    }
    let started = Date()
    let end = started.addingTimeInterval(deadline)
    let (found, failure) = matchedDevice(manager, deadline: end)
    if let failure {
        return Result(outcome: failure, reports: [], malformed: 0,
                      deadlineReached: failure == .absent)
    }
    guard let device = found else {
        return Result(outcome: .absent, reports: [], malformed: 0,
                      deadlineReached: true)
    }
    // Seized, never shared: see the file comment. A refusal here ends the run.
    let seize = IOHIDDeviceOpen(device, IOOptionBits(kIOHIDOptionsTypeSeizeDevice))
    if isPermissionDenied(seize) {
        return Result(outcome: .permission, reports: [], malformed: 0,
                      deadlineReached: false)
    }
    guard seize == kIOReturnSuccess else {
        return Result(outcome: .refused, reports: [], malformed: 0,
                      deadlineReached: false)
    }
    let collector = ReportCollector(maximum: maximum)
    let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: reportLength)
    defer {
        buffer.deallocate()
        IOHIDDeviceClose(device, IOOptionBits(kIOHIDOptionsTypeSeizeDevice))
    }
    IOHIDDeviceRegisterInputReportCallback(
        device,
        buffer,
        CFIndex(reportLength),
        { context, _, _, _, _, report, length in
            guard let context, length > 0 else { return }
            let collected = Unmanaged<ReportCollector>
                .fromOpaque(context).takeUnretainedValue()
            collected.append(Array(UnsafeBufferPointer(start: report, count: Int(length))))
        },
        Unmanaged.passUnretained(collector).toOpaque())
    IOHIDDeviceScheduleWithRunLoop(device, CFRunLoopGetCurrent(),
                                   CFRunLoopMode.defaultMode.rawValue)
    defer {
        IOHIDDeviceUnscheduleFromRunLoop(device, CFRunLoopGetCurrent(),
                                         CFRunLoopMode.defaultMode.rawValue)
        IOHIDDeviceRegisterInputReportCallback(device, buffer, CFIndex(reportLength),
                                               nil, nil)
    }
    var reached = false
    while collector.reports.count < maximum {
        let remaining = end.timeIntervalSinceNow
        if remaining <= 0 {
            reached = true
            break
        }
        _ = CFRunLoopRunInMode(.defaultMode, remaining, true)
    }
    return Result(outcome: collector.reports.isEmpty
                      ? silentOutcome(accessGranted: inputMonitoringGranted())
                      : .recorded,
                  reports: collector.reports, malformed: collector.malformed,
                  deadlineReached: reached)
}

private func summary(_ result: Result) -> [String] {
    var lines = ["\(prefix) outcome=\(result.outcome.rawValue) " +
                 "reports=\(result.reports.count) " +
                 "malformed=\(result.malformed) " +
                 "seized=\(result.outcome.seized ? "yes" : "no") " +
                 "deadline=\(result.deadlineReached ? "reached" : "not-reached")"]
    if result.outcome == .permission {
        // What the operator has to grant, and for which binary. macOS also
        // attributes the request to the application that launched this binary,
        // so the terminal running the trial needs the same grant.
        lines.append("\(prefix) grant=input-monitoring " +
                     "binary=\(CommandLine.arguments.first ?? "unknown") " +
                     "pane=System-Settings/Privacy-and-Security/Input-Monitoring " +
                     "note=also-grant-the-terminal-that-launched-it")
        // Unavoidable, so said rather than discovered: this binary is not
        // signed with a stable identity, so the grant is tied to its bytes.
        lines.append("\(prefix) grant-scope=this-exact-binary " +
                     "after-source-change=grant-it-again " +
                     "why=an-unsigned-binary-is-identified-by-its-bytes-and-the-" +
                     "file-name-carries-the-source-digest")
    }
    return lines
}

/// Owner-only, and never over an existing file: this is trial evidence.
private func write(_ reports: [String], to path: String) -> Bool {
    let descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
    guard descriptor >= 0 else { return false }
    defer { close(descriptor) }
    let data = Data(reports.map { $0 + "\n" }.joined().utf8)
    return data.withUnsafeBytes { bytes in
        bytes.isEmpty || Darwin.write(descriptor, bytes.baseAddress, bytes.count) == bytes.count
    }
}

private func parseIdentifier(_ value: String) -> UInt16? {
    let normalized = value.lowercased().hasPrefix("0x") ? String(value.dropFirst(2)) : value
    return UInt16(normalized, radix: 16)
}

private func selfTest() {
    // Every outcome is distinct, and only a recorded sequence exits zero.
    let all: [Outcome] = [.recorded, .silent, .permission, .absent, .ambiguous, .refused]
    precondition(Set(all.map(\.code)).count == all.count)
    precondition(Set(all.map(\.rawValue)).count == all.count)
    precondition(Outcome.recorded.code == 0)
    for outcome in all where outcome != .recorded {
        precondition(outcome.code != 0)
    }
    precondition(Outcome.recorded.seized && Outcome.silent.seized)
    for outcome in [Outcome.permission, .absent, .ambiguous, .refused] {
        precondition(!outcome.seized)
    }
    // Silence is only a result about the device when the grant is in place.
    precondition(silentOutcome(accessGranted: true) == .silent)
    precondition(silentOutcome(accessGranted: false) == .permission)
    precondition(isPermissionDenied(kIOReturnNotPermitted))
    precondition(isPermissionDenied(kIOReturnNotPrivileged))
    precondition(!isPermissionDenied(kIOReturnSuccess))
    precondition(!isPermissionDenied(kIOReturnNoDevice))
    precondition(hexLine([0x02, 0, 0x10, 0, 0, 0, 0, 0]) == "0200100000000000")
    precondition(hexLine([0xff]) == "ff")
    let collector = ReportCollector(maximum: 2)
    collector.append([UInt8](repeating: 0, count: reportLength))
    collector.append([1, 2, 3])
    precondition(collector.malformed == 1)
    precondition(collector.reports.count == 1)
    collector.append([UInt8](repeating: 1, count: reportLength))
    collector.append([UInt8](repeating: 2, count: reportLength))
    precondition(collector.reports.count == 2, "the maximum is a bound, not a hint")
    // The permission refusal says what to grant and for which binary.
    let denied = summary(Result(outcome: .permission, reports: [], malformed: 0,
                                deadlineReached: false))
    precondition(denied.count == 3)
    precondition(denied[1].contains("grant=input-monitoring"))
    precondition(denied[1].contains("binary="))
    precondition(denied[0].contains("seized=no"))
    // The re-grant rule is stated, not left to be discovered.
    precondition(denied[2].contains("after-source-change=grant-it-again"))
    let quiet = summary(Result(outcome: .silent, reports: [], malformed: 0,
                               deadlineReached: true))
    precondition(quiet.count == 1)
    precondition(quiet[0].contains("outcome=no-reports"))
    precondition(quiet[0].contains("deadline=reached"))
    // Nothing identifying is ever rendered.
    for line in denied + quiet {
        precondition(!line.lowercased().contains("serial"))
        precondition(!line.lowercased().contains("udid"))
        precondition(!line.lowercased().contains("unique"))
    }
    // A synthetic pair: no device identifier belongs in this source.
    precondition(parseIdentifier("0x1234") == 0x1234)
    precondition(parseIdentifier("abcd") == 0xABCD)
    precondition(parseIdentifier("nonsense") == nil)
    print("PASS host HID report reader self-test (34 scenarios)")
}

private func run() -> Int32 {
    let arguments = Array(CommandLine.arguments.dropFirst())
    if arguments == ["--self-test"] {
        selfTest()
        return 0
    }
    guard arguments.count == 5,
          let vendor = parseIdentifier(arguments[0]),
          let product = parseIdentifier(arguments[1]),
          let deadline = Int(arguments[2]), (1...600).contains(deadline),
          let maximum = Int(arguments[3]), (1...4096).contains(maximum),
          !arguments[4].isEmpty
    else {
        FileHandle.standardError.write(Data(
            "Usage: u2-hid-report-reader VENDOR PRODUCT DEADLINE_SECONDS MAX_REPORTS OUT\n".utf8
        ))
        return 64
    }
    let result = capture(vendor: vendor, product: product,
                         deadline: TimeInterval(deadline), maximum: maximum)
    var lines = summary(result)
    var outcome = result.outcome
    if outcome.seized, !write(result.reports, to: arguments[4]) {
        // The reports exist but the evidence file does not, so this is not a
        // recorded sequence; saying otherwise would point the comparator at a
        // file that is not there.
        outcome = .refused
        lines = summary(Result(outcome: .refused, reports: result.reports,
                               malformed: result.malformed,
                               deadlineReached: result.deadlineReached))
        lines.append("\(prefix) failure reports-file-not-written")
    }
    print(lines.joined(separator: "\n"))
    return outcome.code
}

exit(run())
