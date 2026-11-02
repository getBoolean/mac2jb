import Foundation

enum ProbeOutputMode {
    case exclusiveFile
    case standardOutputOnly
}

enum ProbeOptionError: Error, CustomStringConvertible {
    case usage(String)

    var description: String {
        switch self {
        case .usage(let message): return message
        }
    }
}

struct ProbeOptions {
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
    let output: URL?

    static func parse(_ arguments: [String], outputMode: ProbeOutputMode) throws -> ProbeOptions {
        var values: [String: String] = [:]
        var clientTypes: [UInt32] = []
        var index = 0
        while index < arguments.count {
            let key = arguments[index]
            guard key.hasPrefix("--"), index + 1 < arguments.count else {
                throw ProbeOptionError.usage("Expected --name value arguments")
            }
            let value = arguments[index + 1]
            if key == "--client-type" {
                guard let parsed = UInt32(value) else {
                    throw ProbeOptionError.usage("Invalid user-client type: \(value)")
                }
                clientTypes.append(parsed)
            } else {
                if key == "--output", outputMode == .standardOutputOnly {
                    throw ProbeOptionError.usage("--output is forbidden in stdout-only mode")
                }
                guard values.updateValue(value, forKey: key) == nil else {
                    throw ProbeOptionError.usage("Duplicate option: \(key)")
                }
            }
            index += 2
        }

        func required(_ name: String) throws -> String {
            guard let value = values.removeValue(forKey: name), !value.isEmpty else {
                throw ProbeOptionError.usage("Missing \(name)")
            }
            return value
        }

        let output: URL?
        switch outputMode {
        case .exclusiveFile:
            output = URL(fileURLWithPath: try required("--output"))
        case .standardOutputOnly:
            output = nil
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
            output: output
        )
        guard values.isEmpty else {
            throw ProbeOptionError.usage("Unknown option: \(values.keys.sorted()[0])")
        }
        guard ["capture-host", "switch"].contains(options.peerKind) else {
            throw ProbeOptionError.usage("--peer-kind must be capture-host or switch")
        }
        guard ["a", "b"].contains(options.orientation.lowercased()) else {
            throw ProbeOptionError.usage("--orientation must be a or b")
        }
        return options
    }
}
