# Shared Kotlin test sources

`kotlin/` is a source directory of both test source sets: `:polyjose-jvm`'s `test` (JUnit 5, on the
host JVM) and `:polyjose`'s `androidTest` (instrumented, on the emulator). Code here uses no
JVM-only API (no `java.nio.file`, no `java.io.File`) and no test framework, so it compiles in both.

## The conformance runner (`dev.polyjose.conformance`)

The Kotlin runner of ADR 0034: it runs every file of `conformance/vectors/` through the generated
Kotlin API, following the "Binding runners" rules and operation mapping of
[`conformance/README.md`](../../../conformance/README.md), and returns the results document,
`vectors_digest` included (ADR 0060).

| File | Does |
|---|---|
| `Runner.kt` | `Runner.run(runner, inputs, schemaJson)`: validates, skips (only `feature:` reasons, ADR 0034 §3, ADR 0056), runs and compares each vector; returns a `ResultsDocument` whose `toJson()` is the results file |
| `Operations.kt` | one handler per vector `operation`, calling the generated API; outcomes compare by `PolyjoseException.code()` (ADR 0030 §5) |
| `VectorsDigest.kt` | the ADR 0060 digest, with `java.security.MessageDigest` |
| `Json.kt`, `Schema.kt` | a strict RFC 8259 scan (duplicate members fail, value spans kept) over `org.json` values, and the `schema.json` keyword subset |
| `VectorInput.kt` | what a host hands in: `VectorBytes(path, bytes)` per regular `*.json` file, or `VectorUnreadable(path, problem)` for a symbolic link or an unreadable file |

A host:

1. finds every regular `*.json` file under the vectors (recursively), reads each **once** as raw
   bytes and passes `VectorBytes("<path relative to conformance/vectors, / separators>", bytes)`;
   links and unreadable files go in as `VectorUnreadable` (a `fail`, no digest line);
2. passes the text of `conformance/schema.json` (the runner validates every vector against it);
3. calls `Runner.run("jvm" | "android-emulator", inputs, schema)` and writes `toJson()` to
   `target/conformance/<runner>.json`, then fails on any entry in `failures`.

The run throws, and the host must write no file, when no vector file was read (ADR 0060 §3).

- **JVM:** `polyjose-jvm/src/test/kotlin/dev/polyjose/ConformanceTest.kt` reads
  `polyjose.vectors` and its sibling `schema.json`, and writes `polyjose.conformanceResults`.
- **Android** (feature 0008 T03): the same runner over the test APK's assets. The bytes hashed must
  be the bundled bytes it parsed, so a bundle that differs from the checkout fails parity.
