import CryptoKit
import Darwin
import Foundation
import MAC2JBProbeShim

private struct ProbeOptions {
    let soc: String
    let portFamily: String
    let dopamineBuild: String
    let trollStoreBuild: String
    let peerKind: String
    let peerIdentity: String
    let cableIdentity: String
    let orientation: String
    let powerState: String
    let clientTypes: [UInt32]
    let output: URL

    static func parse(_ arguments: [String]) throws -> ProbeOptions {
        var values: [String: String] = [:]
        var clientTypes: [UInt32] = []
        var index = 0
        while index < arguments.count {
            let key = arguments[index]
            guard key.hasPrefix("--"), index + 1 < arguments.count else {
                throw ProbeError.usage("Expected --name value arguments")
            }
            let value = arguments[index + 1]
            if key == "--client-type" {
                guard let parsed = UInt32(value) else { throw ProbeError.usage("Invalid user-client type: \(value)") }
                clientTypes.append(parsed)
            } else {
                guard values.updateValue(value, forKey: key) == nil else {
                    throw ProbeError.usage("Duplicate option: \(key)")
                }
            }
            index += 2
        }

        func required(_ name: String) throws -> String {
            guard let value = values.removeValue(forKey: name), !value.isEmpty else {
                throw ProbeError.usage("Missing \(name)")
            }
            return value
        }

        let options = ProbeOptions(
            soc: try required("--soc"),
            portFamily: try required("--port-family"),
            dopamineBuild: try required("--dopamine-build"),
            trollStoreBuild: try required("--trollstore-build"),
            peerKind: try required("--peer-kind"),
            peerIdentity: try required("--peer-id"),
            cableIdentity: try required("--cable-id"),
            orientation: try required("--orientation"),
            powerState: try required("--power-state"),
            clientTypes: clientTypes.isEmpty ? [0] : Array(Set(clientTypes)).sorted(),
            output: URL(fileURLWithPath: try required("--output"))
        )
        guard values.isEmpty else { throw ProbeError.usage("Unknown option: \(values.keys.sorted()[0])") }
        guard ["capture-host", "switch"].contains(options.peerKind) else {
            throw ProbeError.usage("--peer-kind must be capture-host or switch")
        }
        guard ["a", "b"].contains(options.orientation.lowercased()) else {
            throw ProbeError.usage("--orientation must be a or b")
        }
        return options
    }
}

private enum ProbeError: Error, CustomStringConvertible {
    case usage(String)
    case iokit(String, Int32)
    case unsafe([String])

    var description: String {
        switch self {
        case .usage(let message): return message
        case .iokit(let operation, let status):
            return "\(operation) failed: 0x\(String(format: "%08x", UInt32(bitPattern: status)))"
        case .unsafe(let violations): return violations.joined(separator: "; ")
        }
    }
}

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
        [
            "com.apple.private.usbdevice.setdescription",
            "com.apple.security.exception.iokit-user-client-class",
            "com.apple.private.security.no-sandbox",
            "platform-application"
        ].map { EntitlementObservation(name: $0, present: MAC2JBHasEntitlement($0)) }
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

do {
    let options = try ProbeOptions.parse(Array(CommandLine.arguments.dropFirst()))
    let result = try ProbeCollector.collect(options: options)
    let data = try result.canonicalJSON()
    try FileManager.default.createDirectory(at: options.output.deletingLastPathComponent(), withIntermediateDirectories: true)
    try data.write(to: options.output, options: .atomic)
    print("MAC2JB_PROBE_REPORT \(options.output.path)")
    print("MAC2JB_TOPOLOGY_SHA256 \(try result.topologyFingerprint())")
} catch {
    fputs("mac2jb-ios-probe: \(error)\n", stderr)
    fputs("Required: --soc --port-family --dopamine-build --trollstore-build --peer-kind --peer-id --cable-id --orientation --power-state --output [--client-type N]\n", stderr)
    exit(2)
}
