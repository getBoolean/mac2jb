import Darwin
import Foundation

// Restart the user-space owner of a USB function so it re-opens its nub.
// Jailbreak: `launchctl kickstart -k system/<label>` (rootless or rootful).
// TrollStore / no launchctl: SIGKILL the owner by process name as root;
// launchd relaunches the on-demand daemon when its Mach services are next used.
enum USBFunctionOwnerRestarter {
    enum Failure: Error { case notAllowed, failed }

    // `allowed` maps launchd label -> process name, from the active device
    // profile's owners (labels validated as com.apple.*).
    static func restart(_ label: String, allowed: [String: String]) throws {
        guard let process = allowed[label] else { throw Failure.notAllowed }
        // A learned launchd label (jailbreak) is kickstarted; a bare process
        // token (no launchctl, e.g. TrollStore) goes straight to SIGKILL.
        for launchctl in ["/var/jb/usr/bin/launchctl", "/var/jb/bin/launchctl", "/bin/launchctl"]
        where label != process && access(launchctl, X_OK) == 0 {
            if run([launchctl, "kickstart", "-k", "system/" + label]) == 0 { return }
        }
        guard killAll(named: process) > 0 else { throw Failure.failed }
    }

    private static func run(_ argv: [String]) -> Int32 {
        var pid: pid_t = 0
        var cArgs = argv.map { strdup($0) } + [nil]
        defer { cArgs.forEach { free($0) } }
        guard posix_spawn(&pid, argv[0], nil, nil, &cArgs, environ) == 0 else { return -1 }
        var status: Int32 = 0
        guard waitpid(pid, &status, 0) == pid else { return -1 }
        return (status & 0x7f) == 0 ? (status >> 8) & 0xff : -1
    }

    private static func killAll(named name: String) -> Int {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size = 0
        guard sysctl(&mib, 4, nil, &size, nil, 0) == 0, size > 0 else { return 0 }
        let count = size / MemoryLayout<kinfo_proc>.stride + 16
        var procs = [kinfo_proc](repeating: kinfo_proc(), count: count)
        size = count * MemoryLayout<kinfo_proc>.stride
        guard sysctl(&mib, 4, &procs, &size, nil, 0) == 0 else { return 0 }
        var killed = 0
        for index in 0..<(size / MemoryLayout<kinfo_proc>.stride) {
            var info = procs[index]
            let command = withUnsafePointer(to: &info.kp_proc.p_comm) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXCOMLEN) + 1) { String(cString: $0) }
            }
            let pid = info.kp_proc.p_pid
            if command == name, pid > 1, kill(pid, SIGKILL) == 0 { killed += 1 }
        }
        return killed
    }
}
