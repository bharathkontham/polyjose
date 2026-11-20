import CryptoKit
import Foundation

/// One vector file read for a run: its vector id, its path under the vectors directory and the
/// raw bytes the runner parses (and hashes for `vectors_digest`, ADR 0060 §2).
struct VectorFile: Sendable {
    /// ADR 0034 §1 as amended by ADR 0045 §4: the path under `conformance/vectors/`, with `/`
    /// separators on every platform, then `#0` (one vector per file).
    let id: String
    /// The `/`-separated path under the vectors directory.
    let path: String
    /// The file's raw bytes, read once, with no conversion (ADR 0060 §2).
    let bytes: Data
}

/// A file that has a results entry but no bytes to run: a symbolic link, or a read failure. It is
/// a `fail` (ADR 0034 §3) and gets no digest line (ADR 0060 §2).
struct UnreadableVector: Sendable {
    let id: String
    let reason: String
}

/// The vector files under a directory standing in for `conformance/vectors/`
/// (conformance/README.md "Rules for every runner": every `*.json` file, recursively, never a
/// list of directories). For the conformance run the directory is the test bundle's copy
/// (`Bundle.module`), so the bytes are the bundled bytes the runner parses (ADR 0060 §2).
struct VectorCorpus: Sendable {
    var files: [VectorFile]
    var unreadable: [UnreadableVector]

    /// Reads every regular `*.json` file under `root`, recursively, hidden ones included. A
    /// symbolic link anywhere below `root` is reported in `unreadable` and never followed, as is a
    /// file that cannot be read. Other files (README.md, NOTICE.md, `.jwk` keys, generate.mjs) are
    /// not vectors and are ignored (ADR 0060 §2). `root` itself may be a link (the bundle path is
    /// resolved first).
    static func load(from root: URL) throws -> VectorCorpus {
        let base = root.resolvingSymlinksInPath().standardizedFileURL
        let baseComponents = base.pathComponents
        let keys: [URLResourceKey] = [.isSymbolicLinkKey, .isRegularFileKey]
        guard
            let enumerator = FileManager.default.enumerator(
                at: base, includingPropertiesForKeys: keys, options: [])
        else {
            throw CorpusError.cannotList(base.path)
        }
        var corpus = VectorCorpus(files: [], unreadable: [])
        for case let url as URL in enumerator {
            let components = url.standardizedFileURL.pathComponents
            guard components.count > baseComponents.count,
                Array(components.prefix(baseComponents.count)) == baseComponents
            else {
                throw CorpusError.outside(url.path)
            }
            let path = components.dropFirst(baseComponents.count).joined(separator: "/")
            let values = try url.resourceValues(forKeys: Set(keys))
            if values.isSymbolicLink == true {
                // ADR 0060 §2; the JS runner does the same for every link it finds.
                enumerator.skipDescendants()
                corpus.unreadable.append(
                    UnreadableVector(id: "\(path)#0", reason: "\(path): symbolic links are not allowed"))
                continue
            }
            guard values.isRegularFile == true, url.pathExtension == "json" else { continue }
            do {
                corpus.files.append(VectorFile(id: "\(path)#0", path: path, bytes: try Data(contentsOf: url)))
            } catch {
                corpus.unreadable.append(
                    UnreadableVector(id: "\(path)#0", reason: "\(path): cannot read: \(error.localizedDescription)"))
            }
        }
        return corpus
    }

    enum CorpusError: Error, CustomStringConvertible {
        case cannotList(String)
        case outside(String)

        var description: String {
            switch self {
            case .cannotList(let path): return "cannot list the vectors directory \(path)"
            case .outside(let path): return "the enumerator returned \(path), outside the vectors directory"
            }
        }
    }
}

/// `vectors_digest` (ADR 0060 §2-§3): lowercase hex SHA-256 over the lines
/// `<id> TAB <lowercase hex SHA-256 of the file's raw bytes> LF`, one per vector file read,
/// sorted by their UTF-8 bytes (unsigned, lexicographic, a shorter prefix first). The SHA-256 is
/// CryptoKit's, never polyjose's API under test (ADR 0060 §5).
enum VectorsDigest {
    /// The SHA-256 of the empty input, which is never a valid digest (ADR 0060 §3).
    static let emptyInput = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    struct EmptyCorpus: Error, CustomStringConvertible {
        var description: String { "no vector file was read; an empty corpus has no vectors_digest (ADR 0060 §3)" }
    }

    /// Lowercase hex of CryptoKit's SHA-256 of `data`.
    static func sha256Hex<D: DataProtocol>(_ data: D) -> String {
        hex(SHA256.hash(data: data))
    }

    /// The digest input lines, encoded as UTF-8 and sorted by their bytes (ADR 0060 §2). Sorting
    /// `[UInt8]` with `lexicographicallyPrecedes` compares unsigned bytes; Swift `String <` would
    /// compare canonically equivalent ids as equal, and UTF-16 order differs outside ASCII.
    static func sortedLines(_ files: [VectorFile]) -> [[UInt8]] {
        files.map { file in
            Array(file.id.utf8) + [0x09] + Array(sha256Hex(file.bytes).utf8) + [0x0a]
        }.sorted { $0.lexicographicallyPrecedes($1) }
    }

    /// `vectors_digest` over `files`; throws for an empty corpus (ADR 0060 §3).
    static func digest(of files: [VectorFile]) throws -> String {
        guard !files.isEmpty else { throw EmptyCorpus() }
        var hasher = SHA256()
        for line in sortedLines(files) { hasher.update(data: line) }
        return hex(hasher.finalize())
    }

    private static func hex<S: Sequence>(_ bytes: S) -> String where S.Element == UInt8 {
        let digits = Array("0123456789abcdef".utf8)
        var out = [UInt8]()
        for b in bytes {
            out.append(digits[Int(b >> 4)])
            out.append(digits[Int(b & 0x0f)])
        }
        return String(decoding: out, as: UTF8.self)
    }
}
