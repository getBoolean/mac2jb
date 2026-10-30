import CryptoKit
import Darwin
import Foundation
import MAC2JBProbeShim

private enum ProbeError: Error, CustomStringConvertible {
    case usage(String)
    case iokit(String, Int32)
    case reportWrite(Int32)
    case standardOutputWrite(Int32)
    case unsafe([String])

    var description: String {
        switch self {
        case .usage(let message): return message
        case .iokit(let operation, let status):
            return "\(operation) failed: 0x\(String(format: "%08x", UInt32(bitPattern: status)))"
        case .reportWrite(let status): return "exclusive report write failed: errno \(status)"
        case .standardOutputWrite(let status): return "stdout write failed: errno \(status)"
        case .unsafe(let violations): return violations.joined(separator: "; ")
        }
    }
}

#if MAC2JB_DIAGNOSTIC
private enum DiagnosticPhase: String {
    case launch
    case identity
    case controllerMatch = "controller-match"
    case controllerMetadata = "controller-metadata"
    case controllerOpen = "controller-open"
    case interfaceMatch = "interface-match"
    case interfaceMetadata = "interface-metadata"
    case interfaceOpen = "interface-open"
    case configurationFile = "configuration-file"
    case deviceTree = "device-tree"
    case symbols
    case mutationSymbols = "mutation-symbols"
    case privateReadback = "private-readback"
    case entitlements
    case serialization
    case fullNoReport = "full-no-report"

    static func parse(_ arguments: [String]) throws -> DiagnosticPhase {
        guard arguments.count == 2,
              arguments[0] == "--diagnostic-phase",
              let phase = DiagnosticPhase(rawValue: arguments[1]) else {
            throw ProbeError.usage("Invalid diagnostic invocation")
        }
        return phase
    }
}
#endif

private struct RegistryInventory {
    var controllers: [ControllerService] = []
    var functions: [FunctionService] = []
    var operations: [OperationObservation] = []
}

private enum ProbeCollector {
    static func collect(options: ProbeOptions) throws -> ProbeResult {
        var inventory = try collectRegistry(clientTypes: options.clientTypes)
        let readback = collectPrivateReadback()
        inventory.operations.append(
            OperationObservation(
                name: "IOUSBDeviceControllerCreate",
                kind: .readOnly,
                ioReturn: readback.controllerCreateStatus,
                outcome: privateReadbackOutcome(readback)
            )
        )
        inventory.operations.append(OperationObservation(
            name: "IOUSBDeviceControllerGetTypeID",
            kind: .readOnly,
            outcome: !readback.controllerTypeIDAvailable ? "missing-symbol" :
                (!readback.controllerCreated ? "not-invoked" : (readback.controllerTypeMatches ? "type-match" : "abi-mismatch"))
        ))
        inventory.operations.append(OperationObservation(
            name: "IOUSBDeviceDescriptionCreateFromController",
            kind: .readOnly,
            outcome: !readback.descriptionCreateAvailable ? "missing-symbol" :
                (!readback.controllerCreated ? "not-invoked" : (readback.descriptionCreated ? "description-created" : "description-unavailable"))
        ))
        inventory.operations.append(OperationObservation(
            name: "IOUSBDeviceDescriptionGetTypeID",
            kind: .readOnly,
            outcome: !readback.descriptionTypeIDAvailable ? "missing-symbol" :
                (!readback.descriptionCreated ? "not-invoked" : (readback.descriptionTypeMatches ? "type-match" : "abi-mismatch"))
        ))

        let result = ProbeResult(
            schemaVersion: 1,
            capturedAt: ISO8601DateFormatter().string(from: Date()),
            target: TargetIdentity(
                productType: sysctlString("hw.machine") ?? "unknown",
                boardIdentifier: sysctlString("hw.model") ?? "unknown",
                soc: options.soc,
                portFamily: options.portFamily,
                osVersion: ProcessInfo.processInfo.operatingSystemVersionString,
                osBuild: sysctlString("kern.osversion") ?? "unknown",
                dopamineBuild: options.dopamineBuild,
                trollStoreBuild: options.trollStoreBuild
            ),
            role: RoleObservation(
                peerKind: options.peerKind,
                peerIdentity: HashedIdentifier(options.peerIdentity),
                cableIdentity: HashedIdentifier(options.cableIdentity),
                orientation: options.orientation.lowercased(),
                controllerPresent: !inventory.controllers.isEmpty,
                powerState: options.powerState
            ),
            controllers: inventory.controllers,
            functions: inventory.functions,
            configuration: configurationSource(),
            symbols: symbolObservations(readback: readback),
            entitlements: entitlementObservations(),
            operations: inventory.operations
        )
        let violations = result.readOnlyViolations()
        if !violations.isEmpty { throw ProbeError.unsafe(violations) }
        return result
    }

#if MAC2JB_DIAGNOSTIC
    static func emitDiagnosticProcessMarker() {
        emitDiagnosticLine("MAC2JB_DIAG_PROCESS v1")
    }

    static func runDiagnostic(_ phase: DiagnosticPhase) throws {
        emitDiagnosticLine("MAC2JB_DIAG_BEGIN v1 \(phase.rawValue)")
        switch phase {
        case .launch:
            break
        case .identity:
            diagnosticStep(phase, "identity") {
                _ = sysctlString("hw.machine")
                _ = sysctlString("hw.model")
                _ = sysctlString("kern.osversion")
                _ = ProcessInfo.processInfo.operatingSystemVersionString
                _ = HashedIdentifier("mac2jb-diagnostic")
            }
        case .controllerMatch:
            try withDiagnosticServices(matching: "IOUSBDeviceController", phase: phase) { _ in }
        case .controllerMetadata:
            try withDiagnosticServices(matching: "IOUSBDeviceController", phase: phase) { entries in
                diagnosticStep(phase, "inspect") {
                    for entry in entries {
                        _ = registryID(entry)
                        _ = registryName(entry)
                        _ = registryClass(entry)
                        _ = ancestry(entry)
                        _ = userClientClasses(entry)
                        _ = safeProperties(entry, keys: [
                            "idVendor", "idProduct", "bcdDevice", "bDeviceClass",
                            "bDeviceSubClass", "bDeviceProtocol", "USB Vendor Name",
                            "USB Product Name", "USBDeviceConfiguration", "current-available",
                            "max-current"
                        ])
                    }
                }
            }
        case .controllerOpen:
            try withDiagnosticServices(matching: "IOUSBDeviceController", phase: phase) { entries in
                diagnosticStep(phase, "open-close") {
                    var operations: [OperationObservation] = []
                    for entry in entries {
                        _ = openResults(
                            for: entry,
                            serviceKind: "controller",
                            clientTypes: [0],
                            operations: &operations
                        )
                    }
                }
            }
        case .interfaceMatch:
            try withDiagnosticServices(matching: "IOUSBDeviceInterface", phase: phase) { _ in }
        case .interfaceMetadata:
            try withDiagnosticServices(matching: "IOUSBDeviceInterface", phase: phase) { entries in
                diagnosticStep(phase, "inspect") {
                    for entry in entries {
                        _ = registryID(entry)
                        _ = registryName(entry)
                        _ = registryClass(entry)
                        _ = stringProperty(entry, "USBDeviceFunction")
                        _ = parentControllerID(entry)
                        _ = userClientClasses(entry)
                        _ = safeProperties(entry, keys: [
                            "USBDeviceFunction", "bInterfaceClass", "bInterfaceSubClass",
                            "bInterfaceProtocol", "USBConfigurationValue"
                        ])
                    }
                }
            }
        case .interfaceOpen:
            try withDiagnosticServices(matching: "IOUSBDeviceInterface", phase: phase) { entries in
                diagnosticStep(phase, "open-close") {
                    var operations: [OperationObservation] = []
                    for entry in entries {
                        _ = openResults(
                            for: entry,
                            serviceKind: "function",
                            clientTypes: [0],
                            operations: &operations
                        )
                    }
                }
            }
        case .configurationFile:
            diagnosticStep(phase, "read-file") {
                let path = "/System/Library/AppleUSBDevice/USBDeviceConfiguration.plist"
                if let data = try? Data(contentsOf: URL(fileURLWithPath: path)) {
                    _ = SHA256.hash(data: data)
                }
            }
        case .deviceTree:
            diagnosticStep(phase, "read-tree") {
                let root = IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/")
                if root != 0 {
                    _ = stringProperty(root, "configuration-string")
                    IOObjectRelease(root)
                }
            }
        case .symbols:
            diagnosticStep(phase, "resolve") {
                _ = symbolObservations(readback: MAC2JBPrivateAPIReadback())
            }
        case .mutationSymbols:
            diagnosticStep(phase, "resolve-only") {
                for name in [
                    "IOUSBDeviceControllerSetDescription",
                    "IOUSBDeviceControllerSendCommand",
                    "IOUSBDeviceControllerGoOffAndOnBus",
                    "IOUSBDeviceControllerForceOffBus",
                    "IORegistryEntrySetCFProperty",
                    "IORegistryEntrySetCFProperties"
                ] {
                    _ = MAC2JBSymbolAvailable(name)
                }
            }
        case .privateReadback:
            diagnosticStep(phase, "readback") { _ = collectPrivateReadback() }
        case .entitlements:
            diagnosticStep(phase, "read") { _ = entitlementObservations() }
        case .serialization:
            try diagnosticStep(phase, "encode") {
                _ = try diagnosticResult().canonicalJSON()
            }
        case .fullNoReport:
            try diagnosticStep(phase, "collect-encode") {
                let options = ProbeOptions(
                    soc: "T8112",
                    portFamily: "thunderbolt-usb4",
                    dopamineBuild: "unknown",
                    trollStoreBuild: "unknown",
                    peerKind: "capture-host",
                    peerIdentity: "mac2jb-diagnostic-peer",
                    cableIdentity: "mac2jb-diagnostic-cable",
                    orientation: "a",
                    powerState: "diagnostic",
                    clientTypes: [0],
                    output: nil
                )
                _ = try collect(options: options).canonicalJSON()
            }
        }
        emitDiagnosticLine("MAC2JB_DIAG_END v1 \(phase.rawValue) ok")
    }

    private static func diagnosticResult() -> ProbeResult {
        ProbeResult(
            schemaVersion: 1,
            capturedAt: "diagnostic",
            target: TargetIdentity(
                productType: "diagnostic",
                boardIdentifier: "diagnostic",
                soc: "diagnostic",
                portFamily: "diagnostic",
                osVersion: "diagnostic",
                osBuild: "diagnostic",
                dopamineBuild: "diagnostic",
                trollStoreBuild: "diagnostic"
            ),
            role: RoleObservation(
                peerKind: "capture-host",
                peerIdentity: HashedIdentifier("mac2jb-diagnostic-peer"),
                cableIdentity: HashedIdentifier("mac2jb-diagnostic-cable"),
                orientation: "a",
                controllerPresent: false,
                powerState: "diagnostic"
            ),
            controllers: [],
            functions: [],
            configuration: ConfigurationSource(path: "diagnostic", sha256: nil, deviceTreeConfiguration: nil),
            symbols: [],
            entitlements: [],
            operations: []
        )
    }

    private static func withDiagnosticServices(
        matching className: String,
        phase: DiagnosticPhase,
        body: ([io_object_t]) throws -> Void
    ) throws {
        var operations: [OperationObservation] = []
        let entries = try diagnosticStep(phase, "match") {
            try services(matching: className, operations: &operations)
        }
        defer { entries.forEach { IOObjectRelease($0) } }
        try body(entries)
    }

    private static func diagnosticStep<T>(
        _ phase: DiagnosticPhase,
        _ step: String,
        body: () throws -> T
    ) rethrows -> T {
        emitDiagnosticLine("MAC2JB_DIAG_STEP v1 \(phase.rawValue) \(step) begin")
        let result = try body()
        emitDiagnosticLine("MAC2JB_DIAG_STEP v1 \(phase.rawValue) \(step) ok")
        return result
    }

    private static func emitDiagnosticLine(_ line: String) {
        let bytes = Array("\(line)\n".utf8)
        bytes.withUnsafeBufferPointer { buffer in
            guard let baseAddress = buffer.baseAddress else { exit(74) }
            var offset = 0
            while offset < buffer.count {
                let address = UnsafeRawPointer(baseAddress.advanced(by: offset))
                let count = Darwin.write(STDOUT_FILENO, address, buffer.count - offset)
                if count > 0 {
                    offset += count
                } else if count < 0 && errno == EINTR {
                    continue
                } else {
                    exit(74)
                }
            }
        }
    }
#endif

    private static func collectRegistry(clientTypes: [UInt32]) throws -> RegistryInventory {
        var result = RegistryInventory()
        let controllerEntries = try services(matching: "IOUSBDeviceController", operations: &result.operations)
        defer { controllerEntries.forEach { IOObjectRelease($0) } }
        result.controllers = controllerEntries.map { entry in
            let openResults = openResults(
                for: entry,
                serviceKind: "controller",
                clientTypes: clientTypes,
                operations: &result.operations
            )
            return ControllerService(
                registryID: registryID(entry),
                name: registryName(entry),
                className: registryClass(entry),
                ancestry: ancestry(entry),
                userClientClasses: userClientClasses(entry),
                openResults: openResults,
                restoreProperties: safeProperties(entry, keys: [
                    "idVendor", "idProduct", "bcdDevice", "bDeviceClass",
                    "bDeviceSubClass", "bDeviceProtocol", "USB Vendor Name",
                    "USB Product Name", "USBDeviceConfiguration", "current-available",
                    "max-current"
                ])
            )
        }

        let functionEntries = try services(matching: "IOUSBDeviceInterface", operations: &result.operations)
        defer { functionEntries.forEach { IOObjectRelease($0) } }
        result.functions = functionEntries.map { entry in
            let openResults = openResults(
                for: entry,
                serviceKind: "function",
                clientTypes: clientTypes,
                operations: &result.operations
            )
            return FunctionService(
                registryID: registryID(entry),
                name: registryName(entry),
                className: registryClass(entry),
                functionName: stringProperty(entry, "USBDeviceFunction") ?? "unknown",
                controllerRegistryID: parentControllerID(entry),
                userClientClasses: userClientClasses(entry),
                openResults: openResults,
                restoreProperties: safeProperties(entry, keys: [
                    "USBDeviceFunction", "bInterfaceClass", "bInterfaceSubClass",
                    "bInterfaceProtocol", "USBConfigurationValue"
                ])
            )
        }
        return result
    }

    private static func openResults(
        for entry: io_service_t,
        serviceKind: String,
        clientTypes: [UInt32],
        operations: inout [OperationObservation]
    ) -> [OpenResult] {
        clientTypes.map { clientType in
            var connection: io_connect_t = 0
            let status = IOServiceOpen(entry, mach_task_self_, clientType, &connection)
            operations.append(OperationObservation(
                name: "IOServiceOpen(\(serviceKind):\(registryID(entry)),type:\(clientType))",
                kind: .readOnly,
                ioReturn: status,
                outcome: iokitOutcome(status)
            ))
            if status == KERN_SUCCESS {
                let closeStatus = IOServiceClose(connection)
                operations.append(OperationObservation(
                    name: "IOServiceClose(\(serviceKind):\(registryID(entry)),type:\(clientType))",
                    kind: .readOnly,
                    ioReturn: closeStatus,
                    outcome: iokitOutcome(closeStatus)
                ))
            }
            return OpenResult(clientType: clientType, ioReturn: status, outcome: iokitOutcome(status))
        }
    }

    private static func services(matching className: String, operations: inout [OperationObservation]) throws -> [io_object_t] {
        guard let matching = IOServiceMatching(className) else {
            throw ProbeError.iokit("IOServiceMatching(\(className))", Int32(bitPattern: 0xe00002bd))
        }
        var iterator: io_iterator_t = 0
        let status = IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator)
        operations.append(OperationObservation(
            name: "IOServiceGetMatchingServices(\(className))",
            kind: .readOnly,
            ioReturn: status,
            outcome: iokitOutcome(status)
        ))
        guard status == KERN_SUCCESS else { throw ProbeError.iokit("IOServiceGetMatchingServices(\(className))", status) }
        defer { IOObjectRelease(iterator) }
        var entries: [io_object_t] = []
        while true {
            let entry = IOIteratorNext(iterator)
            if entry == 0 { break }
            entries.append(entry)
        }
        operations.append(OperationObservation(
            name: "IOServiceMatch(\(className))",
            kind: .readOnly,
            outcome: entries.isEmpty ? "missing-service" : "service-present"
        ))
        return entries
    }

    private static func registryID(_ entry: io_registry_entry_t) -> UInt64 {
        var value: UInt64 = 0
        return IORegistryEntryGetRegistryEntryID(entry, &value) == KERN_SUCCESS ? value : 0
    }

    private static func registryClass(_ entry: io_object_t) -> String {
        IOObjectCopyClass(entry)?.takeRetainedValue() as String? ?? "unknown"
    }

    private static func registryName(_ entry: io_registry_entry_t) -> String {
        guard let path = IORegistryEntryCopyPath(entry, kIOServicePlane)?.takeRetainedValue() as String? else {
            return "unknown"
        }
        return path.split(separator: "/").last.map(String.init) ?? path
    }

    private static func stringProperty(_ entry: io_registry_entry_t, _ key: String) -> String? {
        guard let value = IORegistryEntryCreateCFProperty(entry, key as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() else {
            return nil
        }
        if let string = value as? String { return string }
        if let data = value as? Data {
            return String(decoding: data.prefix { $0 != 0 }, as: UTF8.self)
        }
        return nil
    }

    private static func stringListProperty(_ entry: io_registry_entry_t, _ key: String) -> [String] {
        guard let value = IORegistryEntryCreateCFProperty(entry, key as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() else {
            return []
        }
        if let string = value as? String { return [string] }
        if let strings = value as? [String] { return strings }
        if let dictionary = value as? [String: Any] { return dictionary.keys.sorted() }
        return []
    }

    private static func safeProperties(_ entry: io_registry_entry_t, keys: [String]) -> [String: String] {
        var result: [String: String] = [:]
        for key in keys {
            guard let value = IORegistryEntryCreateCFProperty(entry, key as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() else {
                continue
            }
            if let string = value as? String {
                result[key] = string
            } else if let number = value as? NSNumber {
                result[key] = number.stringValue
            } else if let data = value as? Data, data.count <= 64 {
                result[key] = data.map { String(format: "%02x", $0) }.joined()
            }
        }
        return result
    }

    private static func userClientClasses(_ entry: io_registry_entry_t) -> [String] {
        Array(Set(
            stringListProperty(entry, "IOUserClientClass") +
            stringListProperty(entry, "IOUserClientClassNames")
        )).sorted()
    }

    private static func ancestry(_ entry: io_registry_entry_t) -> [String] {
        var result: [String] = []
        var current = entry
        var ownsCurrent = false
        for _ in 0..<24 {
            result.append(registryClass(current))
            var parent: io_registry_entry_t = 0
            let status = IORegistryEntryGetParentEntry(current, kIOServicePlane, &parent)
            if ownsCurrent { IOObjectRelease(current) }
            guard status == KERN_SUCCESS, parent != 0 else { return result }
            current = parent
            ownsCurrent = true
        }
        if ownsCurrent { IOObjectRelease(current) }
        return result
    }

    private static func parentControllerID(_ entry: io_registry_entry_t) -> UInt64? {
        var current = entry
        var ownsCurrent = false
        for _ in 0..<24 {
            if registryClass(current) == "IOUSBDeviceController" {
                let identifier = registryID(current)
                if ownsCurrent { IOObjectRelease(current) }
                return identifier
            }
            var parent: io_registry_entry_t = 0
            let status = IORegistryEntryGetParentEntry(current, kIOServicePlane, &parent)
            if ownsCurrent { IOObjectRelease(current) }
            guard status == KERN_SUCCESS, parent != 0 else { return nil }
            current = parent
            ownsCurrent = true
        }
        if ownsCurrent { IOObjectRelease(current) }
        return nil
    }

    private static func configurationSource() -> ConfigurationSource {
        let path = "/System/Library/AppleUSBDevice/USBDeviceConfiguration.plist"
        let digest = try? Data(contentsOf: URL(fileURLWithPath: path))
        let sha256 = digest.map { SHA256.hash(data: $0).map { String(format: "%02x", $0) }.joined() }
        let root = IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/")
        var configuration: String?
        if root != 0 {
            configuration = stringProperty(root, "configuration-string")
            IOObjectRelease(root)
        }
        return ConfigurationSource(path: path, sha256: sha256, deviceTreeConfiguration: configuration)
    }

    private static func collectPrivateReadback() -> MAC2JBPrivateAPIReadback {
        var result = MAC2JBPrivateAPIReadback()
        MAC2JBProbePrivateAPI(&result)
        return result
    }

    private static func privateReadbackOutcome(_ readback: MAC2JBPrivateAPIReadback) -> String {
        if !readback.controllerCreateAvailable { return "missing-symbol" }
        if readback.controllerCreateStatus != KERN_SUCCESS { return iokitOutcome(readback.controllerCreateStatus) }
        if !readback.controllerTypeIDAvailable || !readback.controllerTypeMatches { return "controller-abi-mismatch" }
        if !readback.descriptionCreateAvailable || !readback.descriptionCreated { return "description-unavailable" }
        if !readback.descriptionTypeIDAvailable || !readback.descriptionTypeMatches { return "description-abi-mismatch" }
        return "read-only-description-validated"
    }

    private static func symbolObservations(readback: MAC2JBPrivateAPIReadback) -> [SymbolObservation] {
        let readOnly = [
            "IOUSBDeviceControllerCreate",
            "IOUSBDeviceControllerCreateWithService",
            "IOUSBDeviceControllerGetTypeID",
            "IOUSBDeviceDescriptionCreateFromController",
            "IOUSBDeviceDescriptionCreateFromDefaultsAndController",
            "IOUSBDeviceDescriptionCopyInterfaces",
            "IOUSBDeviceDescriptionGetTypeID"
        ]
#if MAC2JB_DIAGNOSTIC
        return readOnly.map {
            SymbolObservation(name: $0, available: MAC2JBSymbolAvailable($0), kind: .readOnly, invoked: readOnlySymbolInvoked($0, readback: readback))
        }
#else
        let mutation = [
            "IOUSBDeviceControllerSetDescription",
            "IOUSBDeviceControllerSendCommand",
            "IOUSBDeviceControllerGoOffAndOnBus",
            "IOUSBDeviceControllerForceOffBus",
            "IORegistryEntrySetCFProperty",
            "IORegistryEntrySetCFProperties"
        ]
        return readOnly.map {
            SymbolObservation(name: $0, available: MAC2JBSymbolAvailable($0), kind: .readOnly, invoked: readOnlySymbolInvoked($0, readback: readback))
        } + mutation.map {
            SymbolObservation(name: $0, available: MAC2JBSymbolAvailable($0), kind: .mutation, invoked: false)
        }
#endif
    }

    private static func readOnlySymbolInvoked(_ name: String, readback: MAC2JBPrivateAPIReadback) -> Bool {
        switch name {
        case "IOUSBDeviceControllerCreate": return readback.controllerCreateAvailable
        case "IOUSBDeviceControllerGetTypeID": return readback.controllerCreated && readback.controllerTypeIDAvailable
        case "IOUSBDeviceDescriptionCreateFromController": return readback.controllerCreated && readback.descriptionCreateAvailable
        case "IOUSBDeviceDescriptionGetTypeID": return readback.descriptionCreated && readback.descriptionTypeIDAvailable
        default: return false
        }
    }

    private static func entitlementObservations() -> [EntitlementObservation] {
        let booleanEntitlements = [
            "com.apple.private.usbdevice.setdescription",
            "com.apple.security.exception.iokit-user-client-class",
            "com.apple.private.security.no-sandbox",
            "platform-application"
        ].map { EntitlementObservation(name: $0, present: MAC2JBHasEntitlement($0)) }
        let userClientEntitlement = "com.apple.security.exception.iokit-user-client-class"
        let expectedUserClientClasses: [String] = [
            "IOUSBDeviceControllerUserClient",
            "IOUSBDeviceInterfaceUserClient"
        ]
        let userClientClassEntitlements: [EntitlementObservation] = expectedUserClientClasses.map { className in
            EntitlementObservation(
                name: "\(userClientEntitlement):\(className)",
                present: MAC2JBEntitlementContainsString(userClientEntitlement, className)
            )
        }
        return booleanEntitlements + userClientClassEntitlements
    }

    private static func iokitOutcome(_ value: Int32) -> String {
        String(cString: MAC2JBIOReturnCategory(value))
    }

    private static func sysctlString(_ name: String) -> String? {
        var size = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return nil }
        var bytes = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &bytes, &size, nil, 0) == 0 else { return nil }
        return String(cString: bytes)
    }
}

#if MAC2JB_DIAGNOSTIC
do {
    ProbeCollector.emitDiagnosticProcessMarker()
    let phase = try DiagnosticPhase.parse(Array(CommandLine.arguments.dropFirst()))
    try ProbeCollector.runDiagnostic(phase)
} catch {
    fputs("mac2jb-ios-probe-diagnostic: phase failed\n", stderr)
    exit(2)
}
#else
#if MAC2JB_SPRINGBOARD_R2
// SpringBoard does not pass the probe's command-line options. This entry point
// records only authorization boundaries, with physical peer fields explicitly
// unattributed. It makes the same read-only IOKit calls as the CLI collector.
do {
    guard CommandLine.arguments.count == 1 else { throw ProbeError.usage("Unexpected app arguments") }
    let options = ProbeOptions(
        soc: "T8112",
        portFamily: "thunderbolt-usb4",
        dopamineBuild: "3.0.12",
        trollStoreBuild: "2.1.1",
        peerKind: "unattributed",
        peerIdentity: "springboard-admission-only",
        cableIdentity: "unattributed",
        orientation: "unknown",
        powerState: "unobserved",
        clientTypes: [0, 123],
        output: nil
    )
    let result = try ProbeCollector.collect(options: options)
    let data = try result.canonicalJSON()
    guard !data.isEmpty && data.count <= 1_048_576 else {
        throw ProbeError.usage("App report size outside bound")
    }
    guard let environmentTmp = ProcessInfo.processInfo.environment["TMPDIR"] else {
        throw ProbeError.usage("Missing app tmp directory")
    }
    let tmp = environmentTmp.hasSuffix("/") ? String(environmentTmp.dropLast()) : environmentTmp
    guard (tmp.hasPrefix("/var/mobile/Containers/Data/Application/") ||
           tmp.hasPrefix("/private/var/mobile/Containers/Data/Application/")),
          tmp.hasSuffix("/tmp"), !tmp.contains("/../"), !tmp.contains("/./") else {
        throw ProbeError.usage("Unsafe app tmp directory")
    }
    let status = data.withUnsafeBytes { bytes in
        tmp.withCString { directory in
            ".mac2jb-u1-r2-report.json".withCString { filename in
                MAC2JBWriteExclusiveReport(
                    directory,
                    filename,
                    bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    bytes.count
                )
            }
        }
    }
    guard status == 0 else { throw ProbeError.reportWrite(status) }
} catch {
    fputs("mac2jb-u1-springboard-r2: collection failed\n", stderr)
    exit(2)
}
#else
#if MAC2JB_STDOUT_ONLY
private func writeStandardOutput(_ data: Data) throws {
    var terminated = data
    terminated.append(0x0a)
    try terminated.withUnsafeBytes { bytes in
        guard let baseAddress = bytes.baseAddress else { return }
        var offset = 0
        while offset < bytes.count {
            let written = Darwin.write(
                STDOUT_FILENO,
                baseAddress.advanced(by: offset),
                bytes.count - offset
            )
            if written > 0 {
                offset += written
            } else if written < 0 && errno == EINTR {
                continue
            } else {
                throw ProbeError.standardOutputWrite(errno)
            }
        }
    }
}
#endif

do {
#if MAC2JB_STDOUT_ONLY
    let options = try ProbeOptions.parse(
        Array(CommandLine.arguments.dropFirst()),
        outputMode: .standardOutputOnly
    )
#else
    let options = try ProbeOptions.parse(
        Array(CommandLine.arguments.dropFirst()),
        outputMode: .exclusiveFile
    )
#endif
    let result = try ProbeCollector.collect(options: options)
    let data = try result.canonicalJSON()
#if MAC2JB_STDOUT_ONLY
    try writeStandardOutput(data)
    let reportFingerprint = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    fputs("MAC2JB_REPORT_SHA256 \(reportFingerprint)\n", stderr)
    fputs("MAC2JB_TOPOLOGY_SHA256 \(try result.topologyFingerprint())\n", stderr)
#else
    guard let output = options.output else { throw ProbeError.usage("Missing --output") }
    let outputDirectory = output.deletingLastPathComponent().path
    let outputFilename = output.lastPathComponent
    let reportWriteStatus = data.withUnsafeBytes { bytes in
        outputDirectory.withCString { directory in
            outputFilename.withCString { filename in
                MAC2JBWriteExclusiveReport(
                    directory,
                    filename,
                    bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    bytes.count
                )
            }
        }
    }
    guard reportWriteStatus == 0 else { throw ProbeError.reportWrite(reportWriteStatus) }
    let reportFingerprint = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    print("MAC2JB_PROBE_REPORT \(output.path)")
    print("MAC2JB_REPORT_SHA256 \(reportFingerprint)")
    print("MAC2JB_TOPOLOGY_SHA256 \(try result.topologyFingerprint())")
#endif
} catch {
    fputs("mac2jb-ios-probe: \(error)\n", stderr)
#if MAC2JB_STDOUT_ONLY
    fputs("Required: --soc --port-family --dopamine-build --trollstore-build --peer-kind --peer-id --cable-id --orientation --power-state [--client-type N]\n", stderr)
#else
    fputs("Required: --soc --port-family --dopamine-build --trollstore-build --peer-kind --peer-id --cable-id --orientation --power-state --output [--client-type N]\n", stderr)
#endif
    exit(2)
}
#endif
#endif
