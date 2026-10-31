import Darwin
import Foundation

// Mac-only tests for on-device profile learning. Facts replay the reference
// iPad's healthy census (2026-10-31): 16 functions and their direct clients.

private struct Failure: Error { let message: String }
private func require(_ condition: Bool, _ message: String) throws {
    if !condition { throw Failure(message: message) }
}

private typealias Client = (client: String, process: String?, pid: Int32?)

private func referenceClients() -> [String: [Client]] {
    func k(_ cls: String) -> [Client] { [(client: cls, process: nil, pid: nil)] }
    return [
        "PTP": [(client: "IOUSBDeviceInterfaceUserClient", process: "ptpd", pid: 412)],
        "USBAudioControl": k("AppleUSBMike"), "USBAudioStreaming": k("AppleUSBMike"),
        "IapOverUsbHid": k("IOAccessoryPortUSB"), "AppleUSBMux": k("AppleUSBDeviceMux"),
        "AppleUSBEthernet": k("AppleUSBEthernetDevice"),
        "AppleUSBNCMControl": k("AppleUSBDeviceNCMControl"), "AppleUSBNCMData": k("AppleUSBDeviceNCMData"),
        "AppleUSBNCMControlAux": k("AppleUSBDeviceNCMControl"), "AppleUSBNCMDataAux": k("AppleUSBDeviceNCMData"),
        "Valeria": [(client: "IOUSBDeviceInterfaceUserClient", process: "audiomxd", pid: 448)],
        "USBAudio2Control": k("AppleUSBDeviceAudioController"),
        "USBAudio2StreamIN": k("AppleUSBDeviceAudioController"),
        "USBAudio2StreamOUT": k("AppleUSBDeviceAudioController"),
        "IDAMInterface": k("AppleIDAMInterface"), "AppleUSBNCMControlDirect": k("AppleUSBDeviceNCMControl"),
    ]
}

private func live(flag: Bool = false) -> [String: Any] {
    var fields: [String: Any] = ["Attributes": 192, "BcdUSBVersion": 784, "ConfigurationDescriptors": [],
                                 "DefaultBcdUSBVersion": 528, "MPS0": 9, "MaxPower": -1, "deviceClass": 0,
                                 "deviceID": 5125, "deviceProtocol": 0, "deviceSubClass": 0,
                                 "manufacturerString": "Apple Inc.", "productID": 4779, "productString": "iPad",
                                 "serialNumber": "redacted", "uniqueDeviceID": "redacted", "vendorID": 1452]
    if flag { fields["AllowMultipleCreates"] = true }
    return fields
}

private func facts(configured: Bool = true, clients: [String: [Client]] = referenceClients(),
                   labels: [Int32: String] = [448: "com.apple.audiomxd", 412: "com.apple.ptpd"],
                   flag: Bool = false) -> USBDeviceProfile.Facts {
    USBDeviceProfile.Facts(productType: "iPad14,5", osBuild: "21A329", stockSource: Data("stock".utf8),
                           liveDescription: live(flag: flag), configured: configured,
                           functionClients: clients, launchdLabels: labels)
}

private func hid(name: String = "Mac2JBHID", selfOwned: Bool = true) -> USBDeviceProfile.AddedFunction {
    .init(name: name, configurationNumber: 1, selfOwned: selfOwned, ownerProcess: "mac2jbcanary",
          ownerLaunchdLabel: "dev.mac2jb.canary",
          selectorResults: [.init(operation: "class", selector: 0, ioReturn: 0),
                            .init(operation: "createPipe", selector: 7, ioReturn: -536_870_201)])
}

// Stored JSON a prior broker version could have written, by editing the
// encoded form: the decoder, not the writer, defines what still loads.
private func stored(_ profile: USBDeviceProfile,
                    _ edit: (inout [String: Any]) -> Void) throws -> Data {
    guard var object = try JSONSerialization.jsonObject(with: try profile.json()) as? [String: Any] else {
        throw Failure(message: "profile json")
    }
    edit(&object)
    return try JSONSerialization.data(withJSONObject: object)
}

@main
enum USBDeviceProfileTests {
    static func main() throws {
        // Reference: learns 16 functions, PTP host-dependent, only Valeria owned.
        let profile = try USBDeviceProfile.learn(facts())
        try require(profile.functions.count == 16 && profile.hostDependentFunctions == ["PTP"], "functions")
        try require(profile.owners == [.init(function: "Valeria", process: "audiomxd",
                                              launchdLabel: "com.apple.audiomxd")], "owners \(profile.owners)")
        try require(profile.liveDescriptionFieldCount == 16 && profile.usbVendorID == 1452 &&
                    profile.usbProductID == 4779 && profile.healthyBcdUSB == 784 && profile.healthyMPS0 == 9,
                    "scalars")
        try require(profile.healPolicy().owners == ["Valeria": "com.apple.audiomxd"], "policy owners")
        // A stock learn stays readable by the build a rollback returns to, so it
        // keeps the version that build requires.
        try require(profile.schemaVersion == 2 && profile.addedFunctions.isEmpty, "learned stock profile")
        try profile.validate()
        try require(!String(decoding: try profile.json(), as: UTF8.self).contains("redacted"),
                    "profile must not contain serial/UDID")

        // Post-publication live shape: the replacement flag is not a stock field.
        try require(try USBDeviceProfile.learn(facts(flag: true)).liveDescriptionFieldCount == 16, "flag strip")

        // TrollStore (no launchctl): owner keyed by process, restarted by SIGKILL.
        let troll = try USBDeviceProfile.learn(facts(labels: [:]))
        try require(troll.owners.first?.launchdLabel == nil &&
                    troll.healPolicy().owners == ["Valeria": "audiomxd"] &&
                    troll.ownerProcesses == ["audiomxd": "audiomxd"], "trollstore owners")

        // Never learn from an unhealthy or partially registered controller.
        for (name, bad) in [("unconfigured", facts(configured: false)),
                            ("unserved", { var c = referenceClients(); c["IapOverUsbHid"] = []
                                           return facts(clients: c) }())] {
            do { _ = try USBDeviceProfile.learn(bad); throw Failure(message: name + " learned") }
            catch USBDeviceProfile.Failure.notHealthy {}
        }

        // PTP without a client (no host) is still healthy.
        var noHost = referenceClients(); noHost["PTP"] = []
        try require(try USBDeviceProfile.learn(facts(clients: noHost)).functions.count == 16, "PTP host-dependent")

        // Validation rejects an unsafe owner process name.
        var evil = referenceClients()
        evil["Valeria"] = [(client: "IOUSBDeviceInterfaceUserClient", process: "a b;rm", pid: 1)]
        do { _ = try USBDeviceProfile.learn(facts(clients: evil)); throw Failure(message: "bad name") }
        catch USBDeviceProfile.Failure.invalid {}

        // An added function joins both lists, so `functions` stays the single
        // source of truth for what the published description carries.
        let added = hid()
        let extended = try profile.recording(added)
        try require(extended.addedFunctions == [added] && extended.functions.count == 17 &&
                    extended.functions.contains(added.name), "recording extends both lists")

        // A name already published cannot be added again.
        do { _ = try profile.recording(hid(name: "Valeria")); throw Failure(message: "duplicate added") }
        catch USBDeviceProfile.Failure.invalid {}

        // A self-owned added function is restartable like any stock owner,
        // alongside (not instead of) the stock owners.
        try require(extended.healPolicy().owners ==
                    ["Valeria": "com.apple.audiomxd", "Mac2JBHID": "dev.mac2jb.canary"] &&
                    extended.ownerProcesses ==
                    ["com.apple.audiomxd": "audiomxd", "dev.mac2jb.canary": "mac2jbcanary"],
                    "added owner \(extended.healPolicy().owners) \(extended.ownerProcesses)")

        // A function owned by something else must never be restarted by us.
        let foreign = try profile.recording(hid(name: "ForeignHID", selfOwned: false))
        try require(foreign.healPolicy().owners == ["Valeria": "com.apple.audiomxd"] &&
                    foreign.ownerProcesses == ["com.apple.audiomxd": "audiomxd"], "foreign owner")

        // An added function absent from the function list cannot be published.
        var orphaned = try JSONDecoder().decode(USBDeviceProfile.self, from: try stored(extended) {
            $0["functions"] = extended.functions.filter { $0 != added.name }
        })
        do { try orphaned.validate(); throw Failure(message: "orphan added function validated") }
        catch USBDeviceProfile.Failure.invalid {}

        // A profile predating added functions cannot describe one.
        orphaned = try JSONDecoder().decode(USBDeviceProfile.self,
                                            from: try stored(extended) { $0["schemaVersion"] = 2 })
        do { try orphaned.validate(); throw Failure(message: "v2 added function validated") }
        catch USBDeviceProfile.Failure.invalid {}

        // Store: private round trip; a group/other-readable file is refused.
        let directory = NSTemporaryDirectory() + "mac2jb-profile-\(getpid())"
        mkdir(directory, 0o700)
        defer { _ = try? FileManager.default.removeItem(atPath: directory) }
        let store = USBDeviceProfileStore(path: directory + "/device-profile.json", requireRootOwner: false)
        try store.save(profile)
        try require(store.load() == profile, "store round trip")
        try store.save(extended)
        try require(store.load() == extended, "added function store round trip")
        try require(!String(decoding: try extended.json(), as: UTF8.self).contains("redacted"),
                    "extended profile must not contain serial/UDID")

        // Only a profile that really describes an appended function announces the newer version.
        try require(extended.schemaVersion == 3 && extended.addedFunctions.count == 1, "recorded profile version")
        try extended.validate()

        // Rollback: the previous build accepted exactly version 2 and re-learning
        // is refused while a journal exists, so a stock profile this build saved
        // must still pass that check.
        func previousBuildAccepts(_ p: USBDeviceProfile) -> Bool { p.schemaVersion == 2 }
        try store.save(profile)
        let reloaded = store.load()
        try require(reloaded == profile && reloaded.map(previousBuildAccepts) == true,
                    "stock profile must stay loadable by the previous build")

        // A profile learned before added functions existed keeps loading, with
        // the section empty: no key, no re-learn.
        try (try stored(profile) { $0["schemaVersion"] = 2; $0.removeValue(forKey: "addedFunctions") })
            .write(to: URL(fileURLWithPath: store.path))
        chmod(store.path, 0o600)
        let legacy = store.load()
        try require(legacy?.schemaVersion == 2 && legacy?.addedFunctions.isEmpty == true &&
                    legacy?.functions == profile.functions && legacy?.owners == profile.owners,
                    "stored profile without the added section must still load")

        chmod(store.path, 0o644)
        try require(store.load() == nil, "readable profile must be refused")
        print("PASS USBDeviceProfile learning tests (18 scenarios)")
    }
}
