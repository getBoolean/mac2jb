import Darwin

// The canary's lease over the broker's unix socket. The broker is the single
// writer of the USB description and the journal; the canary only borrows the
// window in which a prepared description is published, and the broker restores
// the original as soon as this connection dies.
//
// Protocol, as the broker implements it: connect to the root-only socket, send
// `watch`, and a reply of `OK watching` means this process is the broker's
// worker. From then on the broker polls this connection; it reads one line and
// restores the original description the moment the connection closes, so
// closing the socket is how the lease is given back. A final `neutral` line
// tells the broker that the neutral report was delivered before the release.

protocol CanaryLease {
    func isHeld() -> Bool
    func release(neutralDelivered: Bool)
}

final class BrokerSocketLease: CanaryLease {
    enum Failure: Error { case unavailable, refused }

    // Matches the broker's total life cap for one publication, because the
    // broker - not this clock - decides when the window ends: on any restore it
    // closes this socket, and isHeld() below reads that as the lease being gone
    // within one poll. This value is the backstop for a broker that dies
    // without closing anything, so it must not be *shorter* than the broker's
    // cap either: at 15 s against a renewable 30 s quantum the worker always
    // killed itself first, which closed the socket, which made the broker
    // restore the original and delete the function under observation - no
    // amount of broker-side renewal could help, because the worker was the
    // thing expiring. Keep this and the host's BROKER_LEASE_CAP_SECONDS equal.
    static let maximumLeaseSeconds: Double = 600
    static let defaultSocketPath = "/var/jb/var/lib/mac2jb-u2-native/broker.sock"

    private var descriptor: Int32 = -1
    private let deadlineUptime: UInt64

    init(socketPath: String, leaseSeconds: Double) throws {
        guard leaseSeconds > 0 else { throw Failure.refused }
        let bytes = Array(socketPath.utf8) + [0]
        var address = sockaddr_un()
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        address.sun_family = sa_family_t(AF_UNIX)
        guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
            throw Failure.unavailable
        }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
        let socketDescriptor = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard socketDescriptor >= 0 else { throw Failure.unavailable }
        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(socketDescriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0 else {
            _ = Darwin.close(socketDescriptor)
            throw Failure.unavailable
        }
        descriptor = socketDescriptor
        var timeout = timeval(tv_sec: 2, tv_usec: 0)
        _ = setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                       socklen_t(MemoryLayout<timeval>.size))
        guard Self.send(line: "watch", to: descriptor),
              Self.readLine(from: descriptor) == "OK watching" else {
            _ = Darwin.close(descriptor)
            descriptor = -1
            throw Failure.refused
        }
        deadlineUptime = clock_gettime_nsec_np(CLOCK_UPTIME_RAW) +
            UInt64(min(leaseSeconds, Self.maximumLeaseSeconds) * 1_000_000_000)
    }

    // The lease is gone once its own budget runs out, and also as soon as the
    // broker closes or speaks on the connection: the broker says nothing to a
    // worker it is still watching, so anything readable means the window ended.
    func isHeld() -> Bool {
        guard descriptor >= 0,
              clock_gettime_nsec_np(CLOCK_UPTIME_RAW) < deadlineUptime else { return false }
        var descriptors = [pollfd(fd: descriptor, events: Int16(POLLIN | POLLHUP), revents: 0)]
        let ready = descriptors.withUnsafeMutableBufferPointer {
            Darwin.poll($0.baseAddress, nfds_t($0.count), 0)
        }
        if ready < 0 { return errno == EINTR }
        return ready == 0 || descriptors[0].revents == 0
    }

    func release(neutralDelivered: Bool) {
        guard descriptor >= 0 else { return }
        if neutralDelivered { _ = Self.send(line: "neutral", to: descriptor) }
        _ = Darwin.close(descriptor)
        descriptor = -1
    }

    @discardableResult
    private static func send(line: String, to descriptor: Int32) -> Bool {
        let bytes = Array((line + "\n").utf8)
        return bytes.withUnsafeBytes { buffer in
            Darwin.send(descriptor, buffer.baseAddress, buffer.count, 0) == buffer.count
        }
    }

    private static func readLine(from descriptor: Int32) -> String? {
        var buffer = [UInt8](repeating: 0, count: 65)
        let count = buffer.withUnsafeMutableBytes {
            Darwin.recv(descriptor, $0.baseAddress, $0.count, 0)
        }
        guard count > 0 else { return nil }
        var received = Array(buffer[..<Int(count)])
        if received.last == 10 { received.removeLast() }
        return String(decoding: received, as: UTF8.self)
    }
}
