package dev.polyjose.conformance

/**
 * A broken vector or a failed runner check: the vector fails with this message, without `actual`
 * (conformance/README.md `results[].actual`). Never an outcome, never a skip (ADR 0034 §3).
 */
internal class HarnessError(message: String) : Exception(message)

/** The library refused: the vector's outcome is this code, read from `PolyjoseException.code()` (ADR 0030 §5). */
internal class LibraryError(val code: String) : Exception(code)
