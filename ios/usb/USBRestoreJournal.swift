import CryptoKit
import Darwin
import Foundation

// The watchdog is the only caller allowed to write this journal. Every controller
// publication must wait for create() to return; a failed fsync is a hard stop.
struct USBRestoreRecipe: Codable, Equatable {
    let schemaVersion: Int
    let productType: String
    let osBuild: String
    let controllerIdentity: String
    let bootSession: String
    let sourceSHA256: String
    let originalDescription: Data
    let plannedDescriptionSHA256: String

    func validate() throws {
        guard schemaVersion == 1,
              !productType.isEmpty, !osBuild.isEmpty,
              !controllerIdentity.isEmpty, !bootSession.isEmpty,
              Self.isDigest(sourceSHA256), Self.isDigest(plannedDescriptionSHA256),
              (1...1_048_576).contains(originalDescription.count),
              originalDescription.starts(with: Data("bplist00".utf8)),
              let plist = try? PropertyListSerialization.propertyList(
                  from: originalDescription, options: [], format: nil)
                  as? [String: Any],
              plist.count == 16,
              plist["AllowMultipleCreates"] == nil,
              let configurations = plist["ConfigurationDescriptors"] as? [Any],
              configurations.count == 9 else {
            throw USBRestoreJournalError.invalidRecipe
        }
    }

    func validateAgainst(_ current: USBRestoreIdentity) throws {
        try validate()
        guard productType == current.productType,
              osBuild == current.osBuild,
              controllerIdentity == current.controllerIdentity,
              bootSession == current.bootSession,
              sourceSHA256 == current.sourceSHA256 else {
            throw USBRestoreJournalError.identityMismatch
        }
    }

    static func isDigest(_ value: String) -> Bool {
        value.count == 64 && value.utf8.allSatisfy {
            (48...57).contains($0) || (97...102).contains($0)
        }
    }
}

struct USBRestoreIdentity {
    let productType: String
    let osBuild: String
    let controllerIdentity: String
    let bootSession: String
    let sourceSHA256: String
}

enum USBRestorePhase: String, Codable {
    case prepared, published, restoring, awaitingVerification, recoveryRequired, restored
}

struct USBRestoreRecord: Codable, Equatable {
    let recipe: USBRestoreRecipe
    let phase: USBRestorePhase
    let leaseDeadlineUptime: UInt64
    let externalVerificationSHA256: String?
    // The one function a successful additive publication appended to the live
    // description, and the 1-based configuration it went into. Restore has to
    // state both, because the description on the bus carries the function and
    // the backend refuses to publish a clone that is not the journaled
    // original. They live on the record, not the recipe: the recipe is the
    // immutable restore target that host tools parse. Both are absent again
    // once the original is back, and absent entirely for a record written
    // before additive publication existed.
    let appendedFunctionName: String?
    let appendedFunctionConfiguration: Int?

    init(recipe: USBRestoreRecipe, phase: USBRestorePhase,
         leaseDeadlineUptime: UInt64, externalVerificationSHA256: String?,
         appendedFunctionName: String? = nil,
         appendedFunctionConfiguration: Int? = nil) {
        self.recipe = recipe
        self.phase = phase
        self.leaseDeadlineUptime = leaseDeadlineUptime
        self.externalVerificationSHA256 = externalVerificationSHA256
        self.appendedFunctionName = appendedFunctionName
        self.appendedFunctionConfiguration = appendedFunctionConfiguration
    }

    func validate() throws {
        try recipe.validate()
        guard leaseDeadlineUptime > 0,
              externalVerificationSHA256.map(USBRestoreRecipe.isDigest) ?? true,
              (phase == .restored) == (externalVerificationSHA256 != nil),
              (appendedFunctionName != nil) == (appendedFunctionConfiguration != nil),
              appendedFunctionName.map(Self.isFunctionName) ?? true,
              appendedFunctionConfiguration.map({ (1...255).contains($0) }) ?? true,
              // A phase that means the original is back on the bus cannot still
              // owe a strip.
              appendedFunctionName == nil ||
                  (phase != .restored && phase != .awaitingVerification) else {
            throw USBRestoreJournalError.invalidRecipe
        }
    }

    // ^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$ , the single Swift mirror of the rule
    // in USBFunctionName.h. A name one side accepts and the other rejects
    // publishes a function that can never be found or stripped again.
    static func isFunctionName(_ name: String) -> Bool {
        guard (1...32).contains(name.utf8.count) else { return false }
        for (index, byte) in name.utf8.enumerated() {
            if (65...90).contains(byte) || (97...122).contains(byte) ||
                (48...57).contains(byte) { continue }
            guard index > 0, byte == 95 || byte == 46 || byte == 45 else { return false }
        }
        return true
    }
}

enum USBRestoreJournalError: Error {
    case invalidRecipe, corrupt, unsafeDirectory, unsafeFile, alreadyExists
    case identityMismatch, changed, invalidTransition, io(Int32)
}

private struct USBRestoreEnvelope: Codable {
    let payload: Data
    let sha256: String
}

struct USBRestoreJournal {
    let directory: String
    let expectedOwner: uid_t
    static let filename = "restore-journal.json"
    private static let maxFileSize = 2_000_000

    init(directory: String, expectedOwner: uid_t = 0) {
        self.directory = directory
        self.expectedOwner = expectedOwner
    }

    static func canonical(_ record: USBRestoreRecord) throws -> Data {
        try record.validate()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(record)
    }

    private static func sealed(_ record: USBRestoreRecord) throws -> Data {
        let payload = try canonical(record)
        let digest = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(USBRestoreEnvelope(payload: payload, sha256: digest))
    }

    private static func unseal(_ data: Data) throws -> USBRestoreRecord {
        let decoder = JSONDecoder()
        guard let envelope = try? decoder.decode(USBRestoreEnvelope.self, from: data),
              let canonicalEnvelope = try? JSONEncoder.sorted.encode(envelope),
              canonicalEnvelope == data,
              envelope.sha256 == SHA256.hash(data: envelope.payload)
                .map({ String(format: "%02x", $0) }).joined(),
              let record = try? decoder.decode(USBRestoreRecord.self, from: envelope.payload),
              let canonicalRecord = try? canonical(record),
              canonicalRecord == envelope.payload else {
            throw USBRestoreJournalError.corrupt
        }
        return record
    }

    func create(_ record: USBRestoreRecord) throws {
        let data = try Self.sealed(record)
        try withDirectory { dir in
            let temporary = ".restore-journal-\(UUID().uuidString)"
            let fd = openat(dir, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
            guard fd >= 0 else { throw USBRestoreJournalError.io(errno) }
            defer { _ = close(fd); _ = unlinkat(dir, temporary, 0) }
            try writeAll(data, to: fd)
            guard fsync(fd) == 0 else { throw USBRestoreJournalError.io(errno) }
            guard linkat(dir, temporary, dir, Self.filename, 0) == 0 else {
                if errno == EEXIST { throw USBRestoreJournalError.alreadyExists }
                throw USBRestoreJournalError.io(errno)
            }
            guard fsync(dir) == 0 else { throw USBRestoreJournalError.io(errno) }
        }
    }

    func transition(from expected: USBRestoreRecord, to next: USBRestoreRecord) throws {
        try next.validate()
        guard expected.recipe == next.recipe,
              expected.leaseDeadlineUptime == next.leaseDeadlineUptime,
              Self.allowed(expected.phase, next.phase) else {
            throw USBRestoreJournalError.invalidTransition
        }
        let data = try Self.sealed(next)
        try withDirectory { dir in
            try withWriterLock(dir) {
                guard try read() == expected else { throw USBRestoreJournalError.changed }
                let temporary = ".restore-journal-\(UUID().uuidString)"
                let fd = openat(dir, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
                guard fd >= 0 else { throw USBRestoreJournalError.io(errno) }
                defer { _ = close(fd); _ = unlinkat(dir, temporary, 0) }
                try writeAll(data, to: fd)
                guard fsync(fd) == 0 else { throw USBRestoreJournalError.io(errno) }
                guard renameat(dir, temporary, dir, Self.filename) == 0 else {
                    throw USBRestoreJournalError.io(errno)
                }
                guard fsync(dir) == 0 else { throw USBRestoreJournalError.io(errno) }
            }
        }
    }

    func removeAfterVerification(_ expected: USBRestoreRecord) throws {
        guard expected.phase == .restored,
              expected.externalVerificationSHA256 != nil else {
            throw USBRestoreJournalError.invalidTransition
        }
        try withDirectory { dir in
            try withWriterLock(dir) {
                guard try read() == expected else { throw USBRestoreJournalError.changed }
                guard unlinkat(dir, Self.filename, 0) == 0,
                      fsync(dir) == 0 else { throw USBRestoreJournalError.io(errno) }
            }
        }
    }

    private static func allowed(_ from: USBRestorePhase, _ to: USBRestorePhase) -> Bool {
        switch (from, to) {
        case (.prepared, .published), (.prepared, .restoring),
             (.published, .restoring), (.restoring, .awaitingVerification),
             (.awaitingVerification, .restored),
             (.recoveryRequired, .restoring):
            return true
        case (_, .recoveryRequired) where from != .restored:
            return true
        default:
            return false
        }
    }

    private func withWriterLock<T>(_ dir: Int32, _ body: () throws -> T) throws -> T {
        let fd = openat(dir, ".restore-journal.lock", O_RDWR | O_CREAT | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw USBRestoreJournalError.io(errno) }
        defer { _ = close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == expectedOwner, info.st_nlink == 1,
              info.st_mode & 0o777 == 0o600 else {
            throw USBRestoreJournalError.unsafeFile
        }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { throw USBRestoreJournalError.changed }
        defer { _ = flock(fd, LOCK_UN) }
        return try body()
    }

    func read() throws -> USBRestoreRecord {
        try withDirectory { dir in
            let fd = openat(dir, Self.filename, O_RDONLY | O_NOFOLLOW)
            guard fd >= 0 else { throw USBRestoreJournalError.io(errno) }
            defer { _ = close(fd) }
            var info = stat()
            guard fstat(fd, &info) == 0 else { throw USBRestoreJournalError.io(errno) }
            guard (info.st_mode & S_IFMT) == S_IFREG,
                  info.st_uid == expectedOwner, info.st_nlink == 1,
                  info.st_mode & 0o777 == 0o600,
                  info.st_size > 0, info.st_size <= Self.maxFileSize else {
                throw USBRestoreJournalError.unsafeFile
            }
            var bytes = [UInt8](repeating: 0, count: Int(info.st_size))
            var offset = 0
            let length = bytes.count
            while offset < length {
                let count = bytes.withUnsafeMutableBytes { buffer in
                    Darwin.read(fd, buffer.baseAddress!.advanced(by: offset), length - offset)
                }
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw USBRestoreJournalError.corrupt }
                offset += count
            }
            return try Self.unseal(Data(bytes))
        }
    }

    private func withDirectory<T>(_ body: (Int32) throws -> T) throws -> T {
        let fd = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard fd >= 0 else { throw USBRestoreJournalError.unsafeDirectory }
        defer { _ = close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == expectedOwner,
              info.st_mode & 0o777 == 0o700 else {
            throw USBRestoreJournalError.unsafeDirectory
        }
        return try body(fd)
    }
}

private extension JSONEncoder {
    static var sorted: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }
}

private func writeAll(_ data: Data, to fd: Int32) throws {
    try data.withUnsafeBytes { buffer in
        var offset = 0
        while offset < buffer.count {
            let count = Darwin.write(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw USBRestoreJournalError.io(errno) }
            offset += count
        }
    }
}
