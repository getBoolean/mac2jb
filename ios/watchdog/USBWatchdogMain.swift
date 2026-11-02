import Foundation

// Read-only target validation and publication-disabled service entry point.
// A guarded publication trial requires a later reviewed build and complete
// external descriptor/function baseline; this binary cannot enable it.
@main
enum USBWatchdogMain {
    static func main() {
        let arguments = Array(CommandLine.arguments.dropFirst())
        do {
            if arguments == ["--serve"] {
                let service = try NativeUSBWatchdogService(publicationEnabled: false)
                try service.run()
            }
#if MAC2JB_ENABLE_U2_NOOP_TRIAL
            // Only a separately built, signed trial executable includes this
            // entry point. The installed 0.1.0 package remains disabled.
            if arguments == ["--serve-noop-trial"] {
                let service = try NativeUSBWatchdogService(publicationEnabled: true)
                try service.run()
            }
#endif
            guard arguments == ["--snapshot"] else { exit(2) }
            let snapshot = try TargetUSBRestoreSnapshot.capture()
            let profile = try TargetUSBRestoreSnapshot.activeProfile()
            guard snapshot.identity.productType == profile.productType,
                  snapshot.identity.osBuild == profile.osBuild,
                  snapshot.liveDescription.count > 8 else {
                throw TargetUSBRestoreSnapshotError.changedTarget
            }
            print("U2_NATIVE_SNAPSHOT target=expected controller=one live=dict:\(profile.liveDescriptionFieldCount) source=expected")
        } catch {
            print("U2_NATIVE_SNAPSHOT rejected")
            exit(1)
        }
    }
}
