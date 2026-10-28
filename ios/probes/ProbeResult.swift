import CryptoKit
import Foundation

struct HashedIdentifier: Codable, Equatable {
    let algorithm: String
    let digest: String

    init(_ value: String) {
        algorithm = "sha256"
        digest = SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}

struct TargetIdentity: Codable, Equatable {
    let productType: String
    let boardIdentifier: String
    let soc: String
    let portFamily: String
    let osVersion: String
    let osBuild: String
    let dopamineBuild: String
    let trollStoreBuild: String
}

struct RoleObservation: Codable, Equatable {
    let peerKind: String
    let peerIdentity: HashedIdentifier
    let cableIdentity: HashedIdentifier
    let orientation: String
    let controllerPresent: Bool
    let powerState: String
}

struct OpenResult: Codable, Equatable {
    let clientType: UInt32
    let ioReturn: Int32
    let outcome: String

    init(clientType: UInt32, ioReturn: Int32, outcome: String? = nil) {
        self.clientType = clientType
        self.ioReturn = ioReturn
        self.outcome = outcome ?? IOReturnClassification.describe(ioReturn)
    }
}

struct ControllerService: Codable, Equatable {
    let registryID: UInt64
    let name: String
    let className: String
    let ancestry: [String]
    let userClientClasses: [String]
    var openResults: [OpenResult]
    var restoreProperties: [String: String] = [:]
}

struct FunctionService: Codable, Equatable {
    let registryID: UInt64
    let name: String
    let className: String
    let functionName: String
    let controllerRegistryID: UInt64?
    let userClientClasses: [String]
    var restoreProperties: [String: String] = [:]
}

struct ConfigurationSource: Codable, Equatable {
    let path: String
    let sha256: String?
    let deviceTreeConfiguration: String?
}

enum APIKind: String, Codable {
    case readOnly
    case mutation
}

struct SymbolObservation: Codable, Equatable {
    let name: String
    let available: Bool
    let kind: APIKind
    let invoked: Bool
}

struct EntitlementObservation: Codable, Equatable {
    let name: String
    let present: Bool
}

struct OperationObservation: Codable, Equatable {
    let name: String
    let kind: APIKind
    let ioReturn: Int32?
    let outcome: String

    init(name: String, kind: APIKind, ioReturn: Int32? = nil, outcome: String? = nil) {
        self.name = name
        self.kind = kind
        self.ioReturn = ioReturn
        self.outcome = outcome ?? ioReturn.map(IOReturnClassification.describe) ?? "no-ioreturn"
    }
}

private enum IOReturnClassification {
    static func describe(_ value: Int32) -> String {
        if value == 0 { return "success" }
        return String(format: "iokit-error-0x%08x", UInt32(bitPattern: value))
    }
}

struct ProbeResult: Codable, Equatable {
    let schemaVersion: Int
    let capturedAt: String
    let target: TargetIdentity
    let role: RoleObservation
    let controllers: [ControllerService]
    let functions: [FunctionService]
    let configuration: ConfigurationSource
    let symbols: [SymbolObservation]
    let entitlements: [EntitlementObservation]
    let operations: [OperationObservation]

    func canonicalJSON() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        guard var object = try JSONSerialization.jsonObject(with: encoder.encode(self)) as? [String: Any] else {
            throw EncodingError.invalidValue(self, .init(codingPath: [], debugDescription: "Probe result was not a JSON object"))
        }
        object["topologyFingerprint"] = try topologyFingerprint()
        return try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
    }

    func topologyFingerprint() throws -> String {
        let snapshot = TopologySnapshot(
            schemaVersion: schemaVersion,
            target: target,
            controllers: controllers.map { controller in
                var normalized = controller
                normalized.openResults.sort { ($0.clientType, $0.ioReturn) < ($1.clientType, $1.ioReturn) }
                return ControllerService(
                    registryID: normalized.registryID,
                    name: normalized.name,
                    className: normalized.className,
                    ancestry: normalized.ancestry.sorted(),
                    userClientClasses: normalized.userClientClasses.sorted(),
                    openResults: normalized.openResults,
                    restoreProperties: normalized.restoreProperties
                )
            }.sorted { ($0.registryID, $0.name) < ($1.registryID, $1.name) },
            functions: functions.map { function in
                FunctionService(
                    registryID: function.registryID,
                    name: function.name,
                    className: function.className,
                    functionName: function.functionName,
                    controllerRegistryID: function.controllerRegistryID,
                    userClientClasses: function.userClientClasses.sorted(),
                    restoreProperties: function.restoreProperties
                )
            }.sorted { ($0.registryID, $0.name) < ($1.registryID, $1.name) },
            configuration: configuration,
            symbols: symbols.sorted { $0.name < $1.name },
            entitlements: entitlements.sorted { $0.name < $1.name },
            operations: operations.sorted { $0.name < $1.name }
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return SHA256.hash(data: try encoder.encode(snapshot)).map { String(format: "%02x", $0) }.joined()
    }

    func readOnlyViolations() -> [String] {
        let symbolViolations = symbols.compactMap { symbol -> String? in
            guard symbol.kind == .mutation && symbol.invoked else { return nil }
            return "mutation symbol invoked: \(symbol.name)"
        }
        let operationViolations = operations.compactMap { operation -> String? in
            guard operation.kind == .mutation else { return nil }
            return "mutation operation recorded: \(operation.name)"
        }
        return (symbolViolations + operationViolations).sorted()
    }
}

private struct TopologySnapshot: Codable {
    let schemaVersion: Int
    let target: TargetIdentity
    let controllers: [ControllerService]
    let functions: [FunctionService]
    let configuration: ConfigurationSource
    let symbols: [SymbolObservation]
    let entitlements: [EntitlementObservation]
    let operations: [OperationObservation]
}
