import Foundation
import MAC2JBUSBRestoreShim

enum TargetUSBRestoreError: Error {
    case invalidControllerIdentity
    case operation(MAC2JBUSBResult, Int32, Int32)
}

// Link this type and the C publication shim only into the watchdog executable.
// The canary talks to the watchdog and never receives a controller writer.
struct TargetUSBRestoreController: USBRestoreController {
    let controllerRegistryID: UInt64
    let cycleBus: Bool
    let useControllerClone: Bool

    init(identity: USBRestoreIdentity, cycleBus: Bool,
         useControllerClone: Bool = false) throws {
        guard let registryID = UInt64(identity.controllerIdentity), registryID > 0 else {
            throw TargetUSBRestoreError.invalidControllerIdentity
        }
        self.controllerRegistryID = registryID
        self.cycleBus = cycleBus
        self.useControllerClone = useControllerClone
    }

    func validateInMemory(_ description: Data) throws {
        try invoke(description, publish: false)
    }

    func publish(_ description: Data) throws {
        try invoke(description, publish: true)
    }

    // After a successful additive publication the live description carries the
    // appended function, so the clone can only be proven equal to the journaled
    // original once that one name comes off. The shim refuses unless it is the
    // last interface of that configuration, so no other interface can be lost.
    func publish(_ description: Data, strippingFunction function: String,
                 configuration: Int) throws {
        try invoke(description, publish: true,
                   strippingFunction: function, configuration: configuration)
    }

    // The clone is proven byte-equal to the journaled original inside the shim
    // before the one named function is appended last in the given
    // configuration, so this still starts from exactly what restore puts back.
    func publishAppending(_ description: Data, function: String, configuration: Int) throws {
        try appending(description, function: function,
                      configuration: configuration, publish: true)
    }

    func validateAppending(_ description: Data, function: String, configuration: Int) throws {
        try appending(description, function: function,
                      configuration: configuration, publish: false)
    }

    // The continuing re-publication the healer uses while a lease is live: the
    // journaled original plus the appended function in one write, so the
    // mechanism that brings the bus back stops being the mechanism that
    // deletes the function being observed. Restoring still publishes the bare
    // original; only this path preserves what the trial is there to see.
    func republishAppending(_ description: Data, function: String, configuration: Int) throws {
        try appending(description, function: function,
                      configuration: configuration, publish: true,
                      republish: true)
    }

    private func appending(_ description: Data, function: String,
                           configuration: Int, publish: Bool,
                           republish: Bool = false) throws {
        guard let number = Int32(exactly: configuration), number > 0 else {
            throw TargetUSBRestoreError.operation(MAC2JBUSBFunctionRejected, 0, 0)
        }
        var setStatus: Int32 = 0
        var busStatus: Int32 = 0
        let result = description.withUnsafeBytes { bytes in
            let base = bytes.bindMemory(to: UInt8.self).baseAddress
            if republish {
                return MAC2JBUSBCloneRepublishAppendedFunctionOrPublish(
                    base, description.count, controllerRegistryID, function,
                    number, publish, publish && cycleBus, &setStatus, &busStatus)
            }
            return MAC2JBUSBCloneAppendFunctionOrPublish(
                base, description.count, controllerRegistryID, function, number,
                publish, publish && cycleBus, &setStatus, &busStatus)
        }
        guard result == MAC2JBUSBSuccess else {
            throw TargetUSBRestoreError.operation(result, setStatus, busStatus)
        }
    }

    // Publish the journaled original with the given configuration's interface
    // list replaced by exactly these names (parent plan U4). The clone is proven
    // byte-equal to the journaled original inside the shim before the list is
    // replaced, so restore still starts from exactly the stock bytes.
    func publishSettingInterfaces(_ description: Data, interfaces: [String],
                                  configuration: Int) throws {
        try settingInterfaces(description, interfaces: interfaces,
                              configuration: configuration, publish: true)
    }

    func validateSettingInterfaces(_ description: Data, interfaces: [String],
                                   configuration: Int) throws {
        try settingInterfaces(description, interfaces: interfaces,
                              configuration: configuration, publish: false)
    }

    private func settingInterfaces(_ description: Data, interfaces: [String],
                                   configuration: Int, publish: Bool) throws {
        guard let number = Int32(exactly: configuration), number > 0 else {
            throw TargetUSBRestoreError.operation(MAC2JBUSBFunctionRejected, 0, 0)
        }
        var setStatus: Int32 = 0
        var busStatus: Int32 = 0
        let cStrings = interfaces.map { strdup($0) }
        defer { cStrings.forEach { free($0) } }
        var pointers: [UnsafePointer<CChar>?] = cStrings.map { UnsafePointer($0) }
        let result = pointers.withUnsafeMutableBufferPointer { names in
            description.withUnsafeBytes { bytes -> MAC2JBUSBResult in
                let base = bytes.bindMemory(to: UInt8.self).baseAddress
                return MAC2JBUSBCloneSetInterfacesOrPublish(
                    base, description.count, controllerRegistryID,
                    names.baseAddress, interfaces.count, number,
                    publish, publish && cycleBus, &setStatus, &busStatus)
            }
        }
        guard result == MAC2JBUSBSuccess else {
            throw TargetUSBRestoreError.operation(result, setStatus, busStatus)
        }
    }

    // Restore a replaced-interface-list publication by pushing the exact stored
    // original bytes back through SetDescription. No clone-and-compare: the live
    // description no longer resembles the original, so nothing can be stripped
    // back to it; the stored bytes are the journaled original.
    func restoreStored(_ description: Data) throws {
        var setStatus: Int32 = 0
        var busStatus: Int32 = 0
        let result = description.withUnsafeBytes { bytes -> MAC2JBUSBResult in
            let base = bytes.bindMemory(to: UInt8.self).baseAddress
            return MAC2JBUSBSetStoredDescriptionOrPublish(
                base, description.count, controllerRegistryID, cycleBus,
                &setStatus, &busStatus)
        }
        guard result == MAC2JBUSBSuccess else {
            throw TargetUSBRestoreError.operation(result, setStatus, busStatus)
        }
    }

    // Cycle the bus and publish nothing. Publication already cycles the bus,
    // so the host read the configuration descriptor before the appended
    // interface had a class, descriptors or endpoints; configuring it
    // afterwards changes only the device's own state. This is what makes the
    // device re-present itself so the host reads a configuration descriptor
    // that includes the interface. Controller authority stays here in the
    // broker: the process that configures the interface cannot do this.
    func cycleBusOnly() throws -> Int32 {
        var busStatus: Int32 = 0
        let result = MAC2JBUSBCycleControllerBus(controllerRegistryID, &busStatus)
        // A cycle that the controller refused is still a reported observation,
        // so its raw return goes back to the caller rather than being
        // collapsed into an error. Only a call that never reached the cycle -
        // a missing symbol, the wrong controller - is an error here.
        guard result == MAC2JBUSBSuccess || result == MAC2JBUSBBusCycleFailed else {
            throw TargetUSBRestoreError.operation(result, 0, busStatus)
        }
        return busStatus
    }

    // The configuration the host currently selects; never assumed.
    func selectedConfiguration() throws -> Int {
        var number: Int32 = 0
        let result = MAC2JBUSBCopySelectedConfiguration(controllerRegistryID, &number)
        guard result == MAC2JBUSBSuccess, number > 0 else {
            throw TargetUSBRestoreError.operation(result, number, 0)
        }
        return Int(number)
    }

    func isConfigured() throws -> Bool {
        var configured = false
        let result = MAC2JBUSBCopyConfiguredState(controllerRegistryID, &configured)
        guard result == MAC2JBUSBSuccess else {
            throw TargetUSBRestoreError.operation(result, 0, 0)
        }
        return configured
    }

    // Read-only: functions whose interface nub has no client (failed to register).
    func unservedFunctions() throws -> Set<String> {
        var buffer = [CChar](repeating: 0, count: 1024)
        let result = MAC2JBUSBCopyUnservedFunctions(controllerRegistryID, &buffer, buffer.count)
        guard result == MAC2JBUSBSuccess else {
            throw TargetUSBRestoreError.operation(result, 0, 0)
        }
        let names = String(cString: buffer)
        return Set(names.split(separator: ",").map(String.init))
    }

    private func invoke(_ description: Data, publish: Bool,
                        strippingFunction function: String? = nil,
                        configuration: Int = 0) throws {
        // Only the clone path can strip: the reconstruct path never sees the
        // live description at all.
        let number = Int32(exactly: configuration) ?? 0
        guard function == nil || (useControllerClone && number > 0) else {
            throw TargetUSBRestoreError.operation(MAC2JBUSBFunctionRejected, 0, 0)
        }
        var setStatus: Int32 = 0
        var busStatus: Int32 = 0
        let result = description.withUnsafeBytes { bytes in
            let pointer = bytes.bindMemory(to: UInt8.self).baseAddress
            if useControllerClone {
                return MAC2JBUSBCloneOrPublish(
                    pointer, description.count, controllerRegistryID,
                    function, number,
                    publish, publish && cycleBus, &setStatus, &busStatus)
            }
            return MAC2JBUSBReconstructOrPublish(
                pointer, description.count, controllerRegistryID,
                publish, publish && cycleBus, &setStatus, &busStatus)
        }
        // A refused strip is reported as its own error: it is the one failure
        // the caller can answer by restoring the original unchanged instead.
        if function != nil, result == MAC2JBUSBFunctionRejected {
            throw USBRestoreCoordinatorError.appendedFunctionRejected
        }
        guard result == MAC2JBUSBSuccess else {
            throw TargetUSBRestoreError.operation(result, setStatus, busStatus)
        }
    }
}
