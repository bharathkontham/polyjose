package dev.polyjose

import dev.polyjose.conformance.VectorBytes
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Modifier
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.fail

/**
 * The binding's security properties on the JVM (feature 0008 T02): no input in errors (ADR 0030 §5,
 * ADR 0007), the error-code set (ADR 0030 §5, ADR 0034 §8), and allow-lists that a caller can't
 * leave out (RFC 8725 §3.1, ADR 0007, ADR 0030 §3).
 */
class SecurityTest {
    /**
     * ADR 0030 §5: a private key whose secret holds a marker, and other inputs holding it, passed
     * to failing calls of every family. The marker appears in neither the exception's `message`
     * nor its `toString()` (the core's `Display`, across the FFI), nor in `code()`.
     */
    @Test
    fun noFailingCallPutsTheMarkerInTheError() {
        val hs256 = JwsSignOptions(protectedHeader = """{"alg":"HS256"}""")
        val token = jwsSignCompact(PAYLOAD, MARKED_OCT, hs256)
        val a256kw = JweEncryptOptions(enc = "A256GCM", recipients = listOf(JweRecipient(alg = "A256KW", key = MARKED_OCT)))
        val jwe = jweEncryptCompact(PAYLOAD, a256kw)
        val jweOptions = JweDecryptOptions(allowedAlgs = listOf("A256KW"), allowedEnc = listOf("A256GCM"))
        val jwt = jwtSign("""{"sub":"$MARKER","exp":1}""", MARKED_OCT, JwtSignOptions(alg = "HS256"))
        val jwtOptions = JwtVerifyOptions(allowedAlgs = listOf("HS256"), now = 2_000_000_000L)
        val markedToken = listOf(MARKER, MARKER, MARKER).joinToString(".")
        val markedJwe = List(5) { MARKER }.joinToString(".")

        val cases: List<Pair<String, () -> Any>> = listOf(
            // Utilities (RFC 4648 §5).
            "base64url" to { base64urlDecode("$MARKER*") },
            // JWK (RFC 7517, RFC 7638, ADR 0054).
            "unparseable key" to { jwkParse(MARKED_UNPARSEABLE[0]) },
            "off-curve key" to { jwkParse(MARKED_UNPARSEABLE[1]) },
            "key syntax" to { jwkParse(MARKED_UNPARSEABLE[2]) },
            "public form" to { jwkToPublic(MARKED_UNPARSEABLE[0]) },
            "thumbprint hash" to { jwkThumbprint(MARKED_OCT, MARKER) },
            "thumbprint uri hash" to { jwkThumbprintUri(MARKED_OCT, MARKER) },
            "jwks selector" to { jwksSelect("""{"keys":[$MARKED_OCT]}""", JwkSelector(kid = MARKER)) },
            "jwks syntax" to { jwksSelect("""{"keys":[$MARKED_OCT] $MARKER}""", JwkSelector()) },
            // Keys (ADR 0018).
            "export oct" to { jwkToPem(MARKED_OCT, "pkcs8") },
            "export format" to { jwkToDer(MARKED_OCT, MARKER) },
            "import pem" to { jwkFromPem("-----BEGIN PRIVATE KEY-----\n$MARKER\n-----END PRIVATE KEY-----\n") },
            "import der" to { jwkFromDer(MARKER.toByteArray(), "pkcs8") },
            "generate alg" to { jwkGenerateForAlg(MARKER) },
            "generate curve" to { jwkGenerateEc(MARKER) },
            // JWS (RFC 7515).
            "sign key" to { jwsSignCompact(PAYLOAD, MARKED_UNPARSEABLE[0], hs256) },
            "sign alg" to { jwsSignCompact(PAYLOAD, MARKED_OCT, JwsSignOptions(protectedHeader = """{"alg":"$MARKER"}""")) },
            "sign header" to { jwsSignCompact(PAYLOAD, MARKED_OCT, JwsSignOptions(protectedHeader = """{"alg":"HS256","kid":"$MARKER" $MARKER}""")) },
            "sign json header" to { jwsSignFlattened(PAYLOAD, JwsSigner(key = MARKED_OCT, unprotectedHeader = """{"kid":"$MARKER" $MARKER}"""), false) },
            "verify allow-list" to { jwsVerifyCompact(token, MARKED_OCT, JwsVerifyOptions(allowedAlgs = listOf(MARKER))) },
            "verify token" to { jwsVerifyCompact(markedToken, MARKED_OCT, JwsVerifyOptions(allowedAlgs = listOf("HS256"))) },
            "verify wrong key" to { jwsVerifyCompact(token, OTHER_MARKED_OCT, JwsVerifyOptions(allowedAlgs = listOf("HS256"))) },
            "verify json" to { jwsVerifyJson("""{"payload":"$MARKER" $MARKER}""", MARKED_OCT, JwsVerifyOptions(allowedAlgs = listOf("HS256"))) },
            // JWE (RFC 7516).
            "encrypt enc" to { jweEncryptCompact(PAYLOAD, JweEncryptOptions(enc = MARKER, recipients = listOf(JweRecipient("A256KW", MARKED_OCT)))) },
            "encrypt alg" to { jweEncryptCompact(PAYLOAD, JweEncryptOptions(enc = "A256GCM", recipients = listOf(JweRecipient(MARKER, MARKED_OCT)))) },
            "encrypt header" to {
                jweEncryptJson(PAYLOAD, a256kw.copy(sharedUnprotectedHeader = """{"kid":"$MARKER" $MARKER}"""), "flattened")
            },
            "decrypt allow-lists" to {
                jweDecryptCompact(jwe, MARKED_OCT, JweDecryptOptions(allowedAlgs = listOf(MARKER), allowedEnc = listOf(MARKER)))
            },
            "decrypt token" to { jweDecryptCompact(markedJwe, MARKED_OCT, jweOptions) },
            "decrypt wrong key" to { jweDecryptCompact(jwe, OTHER_MARKED_OCT, jweOptions) },
            "decrypt crit" to { jweDecryptCompact(jwe, MARKED_UNPARSEABLE[0], jweOptions.copy(understoodCrit = listOf(MARKER))) },
            // JWT (RFC 7519, ADR 0027).
            "issue claims" to { jwtSign("""{"sub":"$MARKER" $MARKER}""", MARKED_OCT, JwtSignOptions(alg = "HS256")) },
            "issue key" to { jwtSign("""{"sub":"x"}""", MARKED_UNPARSEABLE[0], JwtSignOptions(alg = "HS256")) },
            "validate expired" to { jwtVerify(jwt, MARKED_OCT, jwtOptions) },
            "validate wrong key" to { jwtVerify(jwt, OTHER_MARKED_OCT, jwtOptions) },
            "validate jwks" to { jwtVerifyWithJwks(jwt, """{"keys":[$OTHER_MARKED_OCT]}""", jwtOptions) },
            "validate claim policy" to { jwtVerify(jwt, MARKED_OCT, jwtOptions.copy(issuers = listOf(MARKER), allowMissingExp = true)) },
            "nested" to { jwtDecryptNested(markedJwe, MARKED_OCT, jweOptions, MARKED_OCT, jwtOptions) },
        )
        for ((what, call) in cases) {
            val error = try {
                call()
                fail("$what: the call succeeded; the marker test needs a failing call")
            } catch (e: PolyjoseException) {
                e
            }
            for (rendered in listOf(error.code(), error.message.orEmpty(), error.toString(), error.localizedMessage.orEmpty())) {
                assertFalse(rendered.contains(MARKER)) { "$what (${error.code()}): the error shows the marker: $rendered" }
            }
        }
    }

    /**
     * `errorCodes()` is the inventory's code list in order (ADR 0030 §5, ADR 0034 §8), and the
     * sealed `PolyjoseException` has exactly one subclass per code, whose exported `code()` (a call
     * into Rust, ADR 0033 §3) is its variant name.
     */
    @Test
    fun theCodeSetIsTheInventoryAndEachSubclassReportsItsOwnCode() {
        val inventory = Files.readAllLines(pathProperty("polyjose.apiInventory"))
            .map { it.trim() }
            .filter { it.startsWith("code ") }
            .map { it.removePrefix("code ").trim() }
        assertFalse(inventory.isEmpty(), "no `code` lines in the API inventory")
        assertEquals(inventory, errorCodes())

        val base = PolyjoseException::class.java
        val subclasses = base.declaredClasses.filter { base.isAssignableFrom(it) && it != base }
        assertEquals(inventory.sorted(), subclasses.map { it.simpleName }.sorted())
        for (subclass in subclasses) {
            val error = subclass.getConstructor(String::class.java).newInstance("detail") as PolyjoseException
            assertEquals(subclass.simpleName, error.code(), "the code() of PolyjoseException.${subclass.simpleName}")
        }
    }

    /** ADR 0030 §5: every error code a vector expects is one the binding reports. */
    @Test
    fun everyExpectedVectorCodeIsInTheCodeSet() {
        val codes = errorCodes().toSet()
        val expected = loadVectorFiles(pathProperty("polyjose.vectors")).filterIsInstance<VectorBytes>().mapNotNull {
            val expect = JSONObject(String(it.bytes, Charsets.UTF_8)).optJSONObject("expect")
            if (expect?.opt("ok") == false) it.path to expect.getString("error") else null
        }
        assertTrue(expected.isNotEmpty(), "no failure vectors read")
        val unknown = expected.filter { (_, code) -> code !in codes }
        assertTrue(unknown.isEmpty()) { "vectors expect codes the binding lacks: $unknown" }
    }

    /**
     * RFC 8725 §3.1, ADR 0007, ADR 0030 §3: the allow-lists are required, with no default, so a call
     * site without them doesn't compile. Checked on the records' Kotlin default-argument constructor:
     * with every default requested, a field that has a default takes it, and one without passes the
     * null through to the primary constructor, which refuses it (a non-null parameter). A field
     * that has a default (`maxInputLen`) proves the check tells the two apart.
     */
    @Test
    fun allowListsHaveNoDefault() {
        for ((record, field) in listOf(
            JwsVerifyOptions::class.java to "allowedAlgs",
            JweDecryptOptions::class.java to "allowedAlgs",
            JweDecryptOptions::class.java to "allowedEnc",
            JwtVerifyOptions::class.java to "allowedAlgs",
        )) {
            assertFalse(hasDefault(record, field)) { "${record.simpleName}.$field has a default; an allow-list must be required" }
        }
        assertTrue(hasDefault(JwsVerifyOptions::class.java, "maxInputLen"), "the probe must see maxInputLen's default")
        assertTrue(hasDefault(JweDecryptOptions::class.java, "maxPbes2Count"), "the probe must see maxPbes2Count's default")
    }

    /** Whether [field] of the data class [record] has a default value (see [allowListsHaveNoDefault]). */
    private fun hasDefault(record: Class<*>, field: String): Boolean {
        val fields = record.declaredFields.filter { !Modifier.isStatic(it.modifiers) }
        val index = fields.indexOfFirst { it.name == field }
        assertTrue(index >= 0, "${record.simpleName} has no field $field")
        val primary = record.declaredConstructors.single { !it.isSynthetic && it.parameterCount == fields.size }
        assertEquals(fields.map { it.type }, primary.parameterTypes.toList(), "${record.simpleName}: fields in constructor order")
        // The default-argument constructor: the fields, one `int` mask (up to 32 fields), then the
        // marker. (A record with an inline-class field such as `UInt?` also has a name-mangled
        // constructor ending in the marker, without the mask.)
        val defaults = record.declaredConstructors.singleOrNull {
            val types = it.parameterTypes
            types.size == fields.size + 2 && types[fields.size] == Integer.TYPE &&
                types.last().name == "kotlin.jvm.internal.DefaultConstructorMarker"
        } ?: return false // no field of the record has a default
        assertTrue(fields.size <= 32, "${record.simpleName}: more than one mask word")
        val args = fields.mapIndexed { i, f -> if (i == index) null else filler(f.type) } + listOf(-1, null)
        return try {
            defaults.newInstance(*args.toTypedArray())
            true
        } catch (e: InvocationTargetException) {
            val cause = e.cause
            assertTrue(cause is NullPointerException && cause.message.orEmpty().contains(field)) {
                "${record.simpleName}.$field: expected the non-null check of $field, got $cause"
            }
            false
        }
    }

    /** A valid value of a required field's type, for the fields not under test. */
    private fun filler(type: Class<*>): Any? = when (type) {
        List::class.java -> emptyList<Any>()
        String::class.java -> ""
        java.lang.Boolean.TYPE -> false
        Integer.TYPE -> 0
        java.lang.Long.TYPE -> 0L
        else -> null
    }

    private fun pathProperty(name: String): Path = Paths.get(
        System.getProperty(name) ?: error("system property $name is not set (platforms/android/polyjose-jvm/build.gradle.kts)"),
    )

    private companion object {
        /** A distinctive value standing in for key material and other input (the core's marker style). */
        const val MARKER = "pj-SECRET-marker-7f3a"

        val PAYLOAD = "polyjose".toByteArray()

        /** A valid 256-bit `oct` key whose `k` holds the marker: 21 + 22 = 43 base64url characters, 32 octets. */
        val MARKED_OCT = """{"kty":"oct","k":"$MARKER${"A".repeat(22)}"}"""

        /** Another valid 256-bit key holding the marker, for wrong-key failures. */
        val OTHER_MARKED_OCT = """{"kty":"oct","k":"$MARKER${"B".repeat(21)}A"}"""

        /** Keys that fail to import with the marker in their secret (ADR 0030 §5). */
        val MARKED_UNPARSEABLE = listOf(
            // 21 base64url characters: no base64url text has that length.
            """{"kty":"oct","k":"$MARKER"}""",
            """{"kty":"EC","crv":"P-256","x":"$MARKER","y":"$MARKER","d":"$MARKER"}""",
            // A syntax error next to the marker, where a quoting parser would echo it.
            """{"kty":"oct","k":"$MARKER" $MARKER}""",
        )
    }
}
