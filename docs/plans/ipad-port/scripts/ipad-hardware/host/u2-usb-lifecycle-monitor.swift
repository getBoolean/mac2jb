#!/usr/bin/env swift
// Generic-host USB arrival/termination monitor for the U1 read-only gate.
//
// What this code does:
// 1. Subscribes to macOS IOKit first-match and termination notifications for
//    IOUSBHostDevice services. It never opens a device user client and never
//    sends a USB request.
// 2. Before arming the observation window, requires exactly one currently
//    attached device with the operator-supplied vendor/product IDs and a usable
//    host location ID. The USB serial property is never read, printed, or
//    written.
// 3. Emits newline-delimited JSON to stdout: a ready record, any target
//    termination/re-arrival records, and a final summary. Location is emitted
//    only as a SHA-256 digest. Any target event makes the summary fail.
// 4. Runs for a bounded 1...600 second window and writes no file. The future
//    operator starts the monitor, waits for the ready record, runs the reviewed
//    probe batch inside the window, and retains the private stdout capture.
//
// `--self-test` exercises only synthetic identities and never calls IOKit. The
// source must pass review before a real monitoring window is used as evidence.

import CryptoKit
import Dispatch
import Foundation
import IOKit

private let schemaVersion = 1
private let usbHostDeviceClass = "IOUSBHostDevice"
private let observationScope = "IOUSBHostDevice lifecycle notifications plus final registry presence"
private let maximumStoredEvents = 64

private enum MonitorError: Error {
    case invalidArguments
    case iokit(String)
    case selection(String)
}

private struct DeviceIdentity: Equatable {
    let registryID: UInt64
    let vendorID: UInt16?
    let productID: UInt16?
    let locationID: UInt32?
}

private struct TargetIdentity {
    let registryID: UInt64
    let vendorID: UInt16
    let productID: UInt16
    let locationID: UInt32

    var locationDigest: String {
        let value = "mac2jb-host-usb-location:\(locationID)"
        return SHA256.hash(data: Data(value.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
    }

    func matchesTermination(_ device: DeviceIdentity) -> Bool {
        if device.registryID == registryID { return true }
        return device.vendorID == vendorID && device.locationID == locationID
    }

    func matchesArrival(_ device: DeviceIdentity) -> Bool {
        device.vendorID == vendorID && device.locationID == locationID
    }
}

private struct LifecycleEvent {
    let elapsedNanoseconds: UInt64
    let kind: String
    let productID: String
    let vendorID: String
}

private func matchesLifecycleEvent(
    kind: String,
    target: TargetIdentity,
    device: DeviceIdentity
) -> Bool {
    kind == "terminated"
        ? target.matchesTermination(device)
        : target.matchesArrival(device)
}

private func lifecycleObservationPassed(
    eventCount: Int,
    windowCompleted: Bool,
    targetStillPresent: Bool
) -> Bool {
    eventCount == 0 && windowCompleted && targetStillPresent
}

private func selectTarget(
    from devices: [DeviceIdentity],
    vendorID: UInt16,
    productID: UInt16
) throws -> TargetIdentity {
    let matches = devices.filter {
        $0.vendorID == vendorID && $0.productID == productID
    }
    if matches.isEmpty { throw MonitorError.selection("target-not-found") }
    guard matches.count == 1 else {
        throw MonitorError.selection("target-ambiguous")
    }
    let device = matches[0]
    guard let deviceVendor = device.vendorID,
          let deviceProduct = device.productID,
          let deviceLocation = device.locationID,
          deviceLocation != 0
    else {
        throw MonitorError.selection("target-location-unavailable")
    }
    return TargetIdentity(
        registryID: device.registryID,
        vendorID: deviceVendor,
        productID: deviceProduct,
        locationID: deviceLocation
    )
}

private func integerProperty(_ service: io_service_t, _ key: String) -> UInt64? {
    guard let property = IORegistryEntryCreateCFProperty(
        service,
        key as CFString,
        kCFAllocatorDefault,
        0
    )?.takeRetainedValue() else {
        return nil
    }
    guard CFGetTypeID(property) == CFNumberGetTypeID() else { return nil }
    return (property as? NSNumber)?.uint64Value
}

private func deviceIdentity(_ service: io_service_t) -> DeviceIdentity? {
    var registryID: UInt64 = 0
    guard IORegistryEntryGetRegistryEntryID(service, &registryID) == KERN_SUCCESS else {
        return nil
    }
    let rawVendor = integerProperty(service, "idVendor")
    let rawProduct = integerProperty(service, "idProduct")
    let rawLocation = integerProperty(service, "locationID")
    let vendor = rawVendor.flatMap { $0 <= UInt16.max ? UInt16($0) : nil }
    let product = rawProduct.flatMap { $0 <= UInt16.max ? UInt16($0) : nil }
    let location = rawLocation.flatMap { $0 <= UInt32.max ? UInt32($0) : nil }
    return DeviceIdentity(
        registryID: registryID,
        vendorID: vendor,
        productID: product,
        locationID: location
    )
}

private func drain(_ iterator: io_iterator_t) -> [DeviceIdentity] {
    var devices: [DeviceIdentity] = []
    while true {
        let service = IOIteratorNext(iterator)
        if service == 0 { break }
        if let device = deviceIdentity(service) { devices.append(device) }
        IOObjectRelease(service)
    }
    return devices
}

private func currentDevices() throws -> [DeviceIdentity] {
    var iterator: io_iterator_t = 0
    let status = IOServiceGetMatchingServices(
        kIOMainPortDefault,
        IOServiceMatching(usbHostDeviceClass),
        &iterator
    )
    guard status == KERN_SUCCESS else {
        throw MonitorError.iokit("current-device-enumeration")
    }
    defer { IOObjectRelease(iterator) }
    return drain(iterator)
}

private func timestamp() -> String {
    ISO8601DateFormatter().string(from: Date())
}

private func emit(_ object: [String: Any]) throws {
    let data = try JSONSerialization.data(
        withJSONObject: object,
        options: [.sortedKeys, .withoutEscapingSlashes]
    )
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data([0x0a]))
}

private final class USBMonitor {
    let vendorID: UInt16
    let productID: UInt16
    let duration: TimeInterval
    let startedAt = timestamp()
    let startedUptime = DispatchTime.now().uptimeNanoseconds
    var target: TargetIdentity?
    var initialDevices: [DeviceIdentity] = []
    var pendingTerminations: [DeviceIdentity] = []
    var armed = false
    var eventCount = 0
    var events: [LifecycleEvent] = []
    var eventsTruncated = false
    var notificationPort: IONotificationPortRef?
    var matchedIterator: io_iterator_t = 0
    var terminatedIterator: io_iterator_t = 0

    init(vendorID: UInt16, productID: UInt16, duration: TimeInterval) {
        self.vendorID = vendorID
        self.productID = productID
        self.duration = duration
    }

    deinit {
        if matchedIterator != 0 { IOObjectRelease(matchedIterator) }
        if terminatedIterator != 0 { IOObjectRelease(terminatedIterator) }
        if let notificationPort { IONotificationPortDestroy(notificationPort) }
    }

    func record(_ kind: String, devices: [DeviceIdentity]) {
        guard armed, let target else {
            if kind == "terminated" {
                pendingTerminations.append(contentsOf: devices)
            } else {
                initialDevices.append(contentsOf: devices)
            }
            return
        }
        for device in devices {
            let matches = matchesLifecycleEvent(
                kind: kind,
                target: target,
                device: device
            )
            if !matches { continue }
            let now = DispatchTime.now().uptimeNanoseconds
            appendEvent(LifecycleEvent(
                elapsedNanoseconds: now >= startedUptime ? now - startedUptime : 0,
                kind: kind,
                productID: device.productID.map { String(format: "0x%04x", $0) } ?? "unavailable",
                vendorID: device.vendorID.map { String(format: "0x%04x", $0) } ?? "unavailable"
            ))
        }
    }

    func appendEvent(_ event: LifecycleEvent) {
        if eventCount < Int.max { eventCount += 1 }
        if events.count < maximumStoredEvents {
            events.append(event)
        } else {
            eventsTruncated = true
        }
    }

    func recordSyntheticEvent(_ kind: String, target: TargetIdentity) {
        let now = DispatchTime.now().uptimeNanoseconds
        appendEvent(LifecycleEvent(
            elapsedNanoseconds: now >= startedUptime ? now - startedUptime : 0,
            kind: kind,
            productID: String(format: "0x%04x", target.productID),
            vendorID: String(format: "0x%04x", target.vendorID)
        ))
    }

    func start() throws -> Bool {
        guard let port = IONotificationPortCreate(kIOMainPortDefault) else {
            throw MonitorError.iokit("notification-port")
        }
        notificationPort = port
        let context = Unmanaged.passUnretained(self).toOpaque()
        let terminatedStatus = IOServiceAddMatchingNotification(
            port,
            kIOTerminatedNotification,
            IOServiceMatching(usbHostDeviceClass),
            { reference, iterator in
                guard let reference else { return }
                let monitor = Unmanaged<USBMonitor>.fromOpaque(reference).takeUnretainedValue()
                monitor.record("terminated", devices: drain(iterator))
            },
            context,
            &terminatedIterator
        )
        guard terminatedStatus == KERN_SUCCESS else {
            throw MonitorError.iokit("termination-notification")
        }
        record("terminated", devices: drain(terminatedIterator))

        let matchedStatus = IOServiceAddMatchingNotification(
            port,
            kIOFirstMatchNotification,
            IOServiceMatching(usbHostDeviceClass),
            { reference, iterator in
                guard let reference else { return }
                let monitor = Unmanaged<USBMonitor>.fromOpaque(reference).takeUnretainedValue()
                monitor.record("arrived", devices: drain(iterator))
            },
            context,
            &matchedIterator
        )
        guard matchedStatus == KERN_SUCCESS else {
            throw MonitorError.iokit("first-match-notification")
        }
        record("arrived", devices: drain(matchedIterator))

        target = try selectTarget(
            from: initialDevices,
            vendorID: vendorID,
            productID: productID
        )
        guard let target else { throw MonitorError.selection("target-not-selected") }
        record("terminated", devices: drain(terminatedIterator))
        guard !pendingTerminations.contains(where: target.matchesTermination) else {
            throw MonitorError.selection("target-terminated-before-ready")
        }
        initialDevices.removeAll(keepingCapacity: false)
        pendingTerminations.removeAll(keepingCapacity: false)
        guard let source = IONotificationPortGetRunLoopSource(port)?.takeUnretainedValue() else {
            throw MonitorError.iokit("run-loop-source")
        }
        CFRunLoopAddSource(CFRunLoopGetCurrent(), source, .defaultMode)
        armed = true
        try emit([
            "observationScope": observationScope,
            "schemaVersion": schemaVersion,
            "startedAt": startedAt,
            "target": [
                "locationSha256": target.locationDigest,
                "productID": String(format: "0x%04x", target.productID),
                "vendorID": String(format: "0x%04x", target.vendorID),
            ],
            "type": "ready",
            "windowSeconds": Int(duration),
        ])
        let runResult = CFRunLoopRunInMode(.defaultMode, duration, false)
        record("arrived", devices: drain(matchedIterator))
        record("terminated", devices: drain(terminatedIterator))
        let stillPresent = try currentDevices().contains {
            $0.registryID == target.registryID
        }
        if !stillPresent {
            recordSyntheticEvent("missing-at-window-end", target: target)
        }
        let windowCompleted = runResult == .timedOut
        if !windowCompleted {
            recordSyntheticEvent("observation-window-incomplete", target: target)
        }
        armed = false
        let lifecyclePassed = lifecycleObservationPassed(
            eventCount: eventCount,
            windowCompleted: windowCompleted,
            targetStillPresent: stillPresent
        )
        for event in events {
            try emit([
                "elapsedNanoseconds": event.elapsedNanoseconds,
                "kind": event.kind,
                "productID": event.productID,
                "schemaVersion": schemaVersion,
                "type": "event",
                "vendorID": event.vendorID,
            ])
        }
        try emit([
            "eventCount": eventCount,
            "eventsTruncated": eventsTruncated,
            "finishedAt": timestamp(),
            "lifecycleObservationPassed": lifecyclePassed,
            "observationScope": observationScope,
            "schemaVersion": schemaVersion,
            "type": "summary",
            "windowCompleted": windowCompleted,
        ])
        return lifecyclePassed
    }
}

private func parseIdentifier(_ value: String) -> UInt16? {
    let normalized = value.lowercased().hasPrefix("0x")
        ? String(value.dropFirst(2))
        : value
    return UInt16(normalized, radix: 16)
}

private func selfTest() throws {
    let candidate = DeviceIdentity(
        registryID: 11,
        vendorID: 0x05ac,
        productID: 0x12ab,
        locationID: 0x12340000
    )
    let unrelated = DeviceIdentity(
        registryID: 22,
        vendorID: 0x1234,
        productID: 0xabcd,
        locationID: 0x98760000
    )
    let target = try selectTarget(
        from: [candidate, unrelated],
        vendorID: 0x05ac,
        productID: 0x12ab
    )
    precondition(target.matchesTermination(candidate))
    precondition(target.matchesArrival(DeviceIdentity(
        registryID: 33,
        vendorID: 0x05ac,
        productID: 0x12ac,
        locationID: 0x12340000
    )))
    precondition(target.matchesTermination(DeviceIdentity(
        registryID: candidate.registryID,
        vendorID: nil,
        productID: nil,
        locationID: nil
    )))
    precondition(!target.matchesArrival(unrelated))
    precondition(matchesLifecycleEvent(kind: "terminated", target: target, device: candidate))
    precondition(matchesLifecycleEvent(kind: "arrived", target: target, device: DeviceIdentity(
        registryID: 44,
        vendorID: 0x05ac,
        productID: 0x12ff,
        locationID: 0x12340000
    )))
    precondition(lifecycleObservationPassed(
        eventCount: 0,
        windowCompleted: true,
        targetStillPresent: true
    ))
    precondition(!lifecycleObservationPassed(
        eventCount: 1,
        windowCompleted: true,
        targetStillPresent: true
    ))
    precondition(!lifecycleObservationPassed(
        eventCount: 0,
        windowCompleted: false,
        targetStillPresent: true
    ))
    precondition(!lifecycleObservationPassed(
        eventCount: 0,
        windowCompleted: true,
        targetStillPresent: false
    ))
    do {
        _ = try selectTarget(from: [], vendorID: 0x05ac, productID: 0x12ab)
        preconditionFailure("missing target accepted")
    } catch MonitorError.selection("target-not-found") {}
    do {
        _ = try selectTarget(
            from: [candidate, candidate],
            vendorID: 0x05ac,
            productID: 0x12ab
        )
        preconditionFailure("ambiguous target accepted")
    } catch MonitorError.selection("target-ambiguous") {}
    let ready: [String: Any] = [
        "locationSha256": target.locationDigest,
        "productID": String(format: "0x%04x", target.productID),
        "vendorID": String(format: "0x%04x", target.vendorID),
    ]
    let encoded = try JSONSerialization.data(withJSONObject: ready, options: [.sortedKeys])
    let output = String(decoding: encoded, as: UTF8.self)
    precondition(!output.contains("305397760"))
    precondition(!output.contains("12340000"))
    let buffer = USBMonitor(vendorID: 0x05ac, productID: 0x12ab, duration: 1)
    for index in 0..<(maximumStoredEvents + 2) {
        buffer.appendEvent(LifecycleEvent(
            elapsedNanoseconds: UInt64(index),
            kind: "synthetic",
            productID: "0x12ab",
            vendorID: "0x05ac"
        ))
    }
    precondition(buffer.eventCount == maximumStoredEvents + 2)
    precondition(buffer.events.count == maximumStoredEvents)
    precondition(buffer.eventsTruncated)
    print("PASS host USB event monitor self-test (17 scenarios)")
}

private func run() -> Int32 {
    let arguments = Array(CommandLine.arguments.dropFirst())
    if arguments == ["--self-test"] {
        do {
            try selfTest()
            return 0
        } catch {
            return 65
        }
    }
    guard arguments.count == 3,
          let vendorID = parseIdentifier(arguments[0]),
          let productID = parseIdentifier(arguments[1]),
          let durationValue = Int(arguments[2]),
          (1...600).contains(durationValue)
    else {
        FileHandle.standardError.write(Data(
            "Usage: u1-usb-event-monitor VENDOR_ID PRODUCT_ID DURATION_SECONDS\n".utf8
        ))
        return 64
    }
    do {
        let monitor = USBMonitor(
            vendorID: vendorID,
            productID: productID,
            duration: TimeInterval(durationValue)
        )
        return try monitor.start() ? 0 : 65
    } catch {
        FileHandle.standardError.write(Data(
            "Host USB event monitor rejected the observation window.\n".utf8
        ))
        return 65
    }
}

exit(run())
