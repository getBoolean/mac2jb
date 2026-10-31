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

    private func invoke(_ description: Data, publish: Bool) throws {
        var setStatus: Int32 = 0
        var busStatus: Int32 = 0
        let result = description.withUnsafeBytes { bytes in
            let pointer = bytes.bindMemory(to: UInt8.self).baseAddress
            if useControllerClone {
                return MAC2JBUSBCloneOrPublish(
                    pointer, description.count, controllerRegistryID,
                    publish, publish && cycleBus, &setStatus, &busStatus)
            }
            return MAC2JBUSBReconstructOrPublish(
                pointer, description.count, controllerRegistryID,
                publish, publish && cycleBus, &setStatus, &busStatus)
        }
        guard result == MAC2JBUSBSuccess else {
            throw TargetUSBRestoreError.operation(result, setStatus, busStatus)
        }
    }
}
