import Foundation

private func expect(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    if !condition() { throw TestFailure(message) }
}

private struct TestFailure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

private func fixture(
    capturedAt: String = "2026-10-28T12:00:00Z",
    controllers: [ControllerService]? = nil,
    functions: [FunctionService]? = nil,
    symbols: [SymbolObservation]? = nil
) -> ProbeResult {
    ProbeResult(
        schemaVersion: 1,
        capturedAt: capturedAt,
        target: TargetIdentity(
            productType: "iPad14,5",
            boardIdentifier: "J620AP",
            soc: "T8112",
            portFamily: "thunderbolt-usb4",
            osVersion: "17.0",
            osBuild: "21A329",
            dopamineBuild: "2.4.5",
            trollStoreBuild: "2.2.2"
        ),
        role: RoleObservation(
            peerKind: "capture-host",
            peerIdentity: HashedIdentifier("peer-secret"),
            cableIdentity: HashedIdentifier("cable-secret"),
            orientation: "a",
            controllerPresent: true,
            powerState: "observed-vbus"
        ),
        controllers: controllers ?? [
            ControllerService(
                registryID: 42,
                name: "usb-drd0",
                className: "IOUSBDeviceController",
                ancestry: ["IOService", "AppleT8112USBXHCI"],
                userClientClasses: ["IOUSBDeviceControllerUserClient"],
                openResults: [OpenResult(clientType: 0, ioReturn: 0)]
            )
        ],
        functions: functions ?? [
            FunctionService(
                registryID: 84,
                name: "AppleUSBDeviceNCM",
                className: "IOUSBDeviceInterface",
                functionName: "NCM",
                controllerRegistryID: 42,
                userClientClasses: ["IOUSBDeviceInterfaceUserClient"],
                openResults: [OpenResult(clientType: 0, ioReturn: 0)]
            )
        ],
        configuration: ConfigurationSource(
            path: "/System/Library/AppleUSBDevice/USBDeviceConfiguration.plist",
            sha256: String(repeating: "a", count: 64),
            deviceTreeConfiguration: "standard"
        ),
        symbols: symbols ?? [
            SymbolObservation(name: "IOUSBDeviceDescriptionCreateFromController", available: true, kind: .readOnly, invoked: false),
            SymbolObservation(name: "IOUSBDeviceControllerSetDescription", available: true, kind: .mutation, invoked: false)
        ],
        entitlements: [
            EntitlementObservation(name: "com.apple.private.usbdevice.setdescription", present: false)
        ],
        operations: [
            OperationObservation(name: "IOServiceOpen", kind: .readOnly, ioReturn: 0)
        ]
    )
}

@main
enum ProbeResultTests {
    static func main() throws {
        try hashedIdentifiersNeverExposeRawValues()
        try topologyFingerprintIsStable()
        try topologyFingerprintDetectsMeaningfulChanges()
        try topologyFingerprintDetectsFunctionAuthorizationChanges()
        try topologyFingerprintDetectsAncestryOrderChanges()
        try mutationCallsFailTheReadOnlyAudit()
        print("PASS ProbeResult tests")
    }

    private static func hashedIdentifiersNeverExposeRawValues() throws {
        let identifier = HashedIdentifier("abc")
        try expect(identifier.algorithm == "sha256", "identifier algorithm")
        try expect(identifier.digest == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "identifier digest")

        let json = String(decoding: try fixture().canonicalJSON(), as: UTF8.self)
        try expect(!json.contains("peer-secret"), "peer identity leaked")
        try expect(!json.contains("cable-secret"), "cable identity leaked")
        try expect(json.contains(HashedIdentifier("peer-secret").digest), "peer digest missing")
    }

    private static func topologyFingerprintIsStable() throws {
        let controllerA = fixture().controllers[0]
        let controllerB = ControllerService(
            registryID: 7,
            name: "usb-drd1",
            className: "IOUSBDeviceController",
            ancestry: ["IOService"],
            userClientClasses: [],
            openResults: [OpenResult(clientType: 0, ioReturn: -536870201)]
        )
        let functionA = fixture().functions[0]
        let functionB = FunctionService(
            registryID: 9,
            name: "AppleUSBDeviceMux",
            className: "IOUSBDeviceInterface",
            functionName: "Mux",
            controllerRegistryID: 7,
            userClientClasses: [],
            openResults: [OpenResult(clientType: 0, ioReturn: -536870201)]
        )
        let first = fixture(controllers: [controllerA, controllerB], functions: [functionA, functionB])
        let second = fixture(
            capturedAt: "2026-10-28T12:05:00Z",
            controllers: [controllerB, controllerA],
            functions: [functionB, functionA],
            symbols: Array(first.symbols.reversed())
        )
        let firstFingerprint = try first.topologyFingerprint()
        let secondFingerprint = try second.topologyFingerprint()
        try expect(firstFingerprint == secondFingerprint, "equivalent topology produced a different fingerprint")
    }

    private static func topologyFingerprintDetectsMeaningfulChanges() throws {
        var changed = fixture().controllers[0]
        changed.openResults = [OpenResult(clientType: 0, ioReturn: -536870201)]
        let baselineFingerprint = try fixture().topologyFingerprint()
        let changedFingerprint = try fixture(controllers: [changed]).topologyFingerprint()
        try expect(baselineFingerprint != changedFingerprint, "authorization change was ignored")
    }

    private static func topologyFingerprintDetectsFunctionAuthorizationChanges() throws {
        let baseline = fixture()
        let function = baseline.functions[0]
        let denied = FunctionService(
            registryID: function.registryID,
            name: function.name,
            className: function.className,
            functionName: function.functionName,
            controllerRegistryID: function.controllerRegistryID,
            userClientClasses: function.userClientClasses,
            openResults: [OpenResult(clientType: 0, ioReturn: -536870201)]
        )

        let baselineFingerprint = try baseline.topologyFingerprint()
        let deniedFingerprint = try fixture(functions: [denied]).topologyFingerprint()
        try expect(baselineFingerprint != deniedFingerprint, "function authorization change was ignored")
    }

    private static func topologyFingerprintDetectsAncestryOrderChanges() throws {
        let baseline = fixture()
        let controller = baseline.controllers[0]
        let reordered = ControllerService(
            registryID: controller.registryID,
            name: controller.name,
            className: controller.className,
            ancestry: Array(controller.ancestry.reversed()),
            userClientClasses: controller.userClientClasses,
            openResults: controller.openResults,
            restoreProperties: controller.restoreProperties
        )

        let baselineFingerprint = try baseline.topologyFingerprint()
        let reorderedFingerprint = try fixture(controllers: [reordered]).topologyFingerprint()
        try expect(baselineFingerprint != reorderedFingerprint, "controller ancestry order was ignored")
    }

    private static func mutationCallsFailTheReadOnlyAudit() throws {
        try expect(fixture().readOnlyViolations().isEmpty, "valid read-only report failed audit")
        let invoked = SymbolObservation(name: "IOUSBDeviceControllerSetDescription", available: true, kind: .mutation, invoked: true)
        let violations = fixture(symbols: [invoked]).readOnlyViolations()
        try expect(violations == ["mutation symbol invoked: IOUSBDeviceControllerSetDescription"], "mutation invocation was not rejected")
    }
}
