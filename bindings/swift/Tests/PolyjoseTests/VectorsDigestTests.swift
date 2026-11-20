import Foundation
import XCTest

/// ADR 0060 §2-§4: the vector corpus loader and `vectors_digest`, checked on the ADR's own worked
/// example (§4), built in a temporary directory that stands in for `conformance/vectors/`.
final class VectorsDigestTests: XCTestCase {
    private var root: URL!

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("polyjose-digest-\(UUID().uuidString)", isDirectory: true)
        try write("a.json", [0x7b, 0x7d])  // {}
        try write("jws/b.json", [0x7b, 0x7d, 0x0a])  // {} LF
        try write("jws-x/c.json", [0xef, 0xbb, 0xbf, 0x7b, 0x7d])  // UTF-8 BOM, {}
        try write("README.md", [0x6e, 0x6f, 0x74, 0x65, 0x73])  // "notes": not a vector
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: root)
    }

    private func write(_ path: String, _ bytes: [UInt8]) throws {
        let url = root.appendingPathComponent(path)
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data(bytes).write(to: url)
    }

    /// ADR 0060 §2: one entry per regular `*.json` file, found recursively, with `/`-separated ids
    /// `<path>#0`; README.md is not a vector. The bytes are the raw file bytes (the BOM stays).
    func testLoadsEveryJsonFileWithItsRawBytes() throws {
        let corpus = try VectorCorpus.load(from: root)
        XCTAssertEqual(corpus.files.map(\.id).sorted(), ["a.json#0", "jws-x/c.json#0", "jws/b.json#0"])
        XCTAssertTrue(corpus.unreadable.isEmpty)
        let c = try XCTUnwrap(corpus.files.first { $0.id == "jws-x/c.json#0" })
        XCTAssertEqual([UInt8](c.bytes), [0xef, 0xbb, 0xbf, 0x7b, 0x7d])
        XCTAssertEqual(c.path, "jws-x/c.json")
    }

    /// ADR 0060 §2, §4: the per-file hashes, the lines sorted by their UTF-8 bytes (`-` 0x2D before
    /// `/` 0x2F, so `jws-x/` before `jws/`), and the worked example's digest.
    func testWorkedExampleDigest() throws {
        let corpus = try VectorCorpus.load(from: root)
        let lines = VectorsDigest.sortedLines(corpus.files).map { String(decoding: $0, as: UTF8.self) }
        XCTAssertEqual(
            lines,
            [
                "a.json#0\t44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a\n",
                "jws-x/c.json#0\taa25e978046d680ef8740d837e6de5bc1e2a2dc6089dbda1012544b538d53f65\n",
                "jws/b.json#0\tca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356\n",
            ])
        XCTAssertEqual(
            try VectorsDigest.digest(of: corpus.files),
            "9a06f1efdd269176088cb0e6bfc6a7e4d4f74aa3d1b1b8fc6c879fdbb82ac7d1")
    }

    /// The order of the input files does not change the digest (§2: the lines are sorted).
    func testDigestIgnoresInputOrder() throws {
        let files = try VectorCorpus.load(from: root).files
        XCTAssertEqual(
            try VectorsDigest.digest(of: files.reversed()),
            "9a06f1efdd269176088cb0e6bfc6a7e4d4f74aa3d1b1b8fc6c879fdbb82ac7d1")
    }

    /// The order is by UTF-8 bytes (ADR 0060 §2), not by a platform string order:
    /// - Swift `String` compares canonically equivalent text as equal, so `é` (C3 A9) and `e` +
    ///   U+0301 (65 CC 81) have no order there; by bytes the decomposed form comes first;
    /// - UTF-16 order (JS, Kotlin) puts U+1F600 (D83D DE00) before U+FF21; by bytes U+FF21
    ///   (EF BC A1) comes before U+1F600 (F0 9F 98 80).
    func testLinesSortByUtf8Bytes() throws {
        let ids = ["\u{1F600}.json#0", "\u{E9}.json#0", "\u{FF21}.json#0", "e\u{301}.json#0"]
        let files = ids.map { VectorFile(id: $0, path: String($0.dropLast(2)), bytes: Data()) }
        let sorted = VectorsDigest.sortedLines(files).map { line in
            [UInt8](line.prefix { $0 != 0x09 })
        }
        XCTAssertEqual(sorted, ["e\u{301}.json#0", "\u{E9}.json#0", "\u{FF21}.json#0", "\u{1F600}.json#0"].map { Array($0.utf8) })
    }

    /// ADR 0060 §2: a symbolic link gets a `fail` result and no digest line.
    func testSymbolicLinkIsUnreadableAndNotHashed() throws {
        try FileManager.default.createSymbolicLink(
            at: root.appendingPathComponent("jws/link.json"),
            withDestinationURL: root.appendingPathComponent("a.json"))
        let corpus = try VectorCorpus.load(from: root)
        XCTAssertEqual(corpus.files.count, 3)
        XCTAssertEqual(corpus.unreadable.map(\.id), ["jws/link.json#0"])
        XCTAssertEqual(
            try VectorsDigest.digest(of: corpus.files),
            "9a06f1efdd269176088cb0e6bfc6a7e4d4f74aa3d1b1b8fc6c879fdbb82ac7d1")
    }

    /// ADR 0060 §3: an empty corpus is invalid; the empty-input SHA-256 is never a digest.
    func testEmptyCorpusHasNoDigest() throws {
        XCTAssertThrowsError(try VectorsDigest.digest(of: []))
        XCTAssertEqual(
            VectorsDigest.sha256Hex(Data()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        let empty = root.appendingPathComponent("empty", isDirectory: true)
        try FileManager.default.createDirectory(at: empty, withIntermediateDirectories: true)
        XCTAssertTrue(try VectorCorpus.load(from: empty).files.isEmpty)
    }
}
