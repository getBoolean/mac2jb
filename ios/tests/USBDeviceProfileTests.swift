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

        // Store: private round trip; a group/other-readable file is refused.
        let directory = NSTemporaryDirectory() + "mac2jb-profile-\(getpid())"
        mkdir(directory, 0o700)
        defer { _ = try? FileManager.default.removeItem(atPath: directory) }
        let store = USBDeviceProfileStore(path: directory + "/device-profile.json", requireRootOwner: false)
        try store.save(profile)
        try require(store.load() == profile, "store round trip")
        chmod(store.path, 0o644)
        try require(store.load() == nil, "readable profile must be refused")
        print("PASS USBDeviceProfile learning tests (8 scenarios)")
    }
}
