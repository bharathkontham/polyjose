package dev.polyjose.gradle;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The deterministic, fail-closed patch the root project's {@code uniffiGenerate} task applies to
 * the UniFFI-generated {@code polyjose_ffi.kt} (feature 0008 F05; orchestrator decision
 * 2026-11-07: patching the generated Kotlin in 0008's generation step is approved). Plain Java
 * with no Gradle API, so the JVM tests load this class on its own and feed it mutated input.
 *
 * <p>Two changes, nothing else:
 *
 * <ol>
 *   <li><b>Loader (security audit M1, I3, I4).</b> The body of the generated {@code
 *       findLibraryName} (which returned the {@code uniffi.component.polyjose_ffi.libraryOverride}
 *       property, else the bare name {@code polyjose_ffi} that JNA resolves through {@code
 *       jna.library.path}, the working directory and the OS search paths before the jar) becomes
 *       a call to the hand-written {@code PolyjoseNativeLoader.libraryName} in {@code
 *       src/shared/kotlin} (ADR 0030 §1: a few hand-written members). On the JVM that returns the
 *       absolute path of the jar's own hash-checked library; on Android the bare name (I2).
 *   <li><b>Redaction (ADR 0065 decision 1, 2; ADR 0030 §7.5).</b> Each record of {@link
 *       #redactedFields()} gets an {@code override fun toString()} that prints every field as the
 *       generated {@code data class} would, except that the listed secret fields print as {@code
 *       <redacted, N bytes>}. JWT claims are not redacted (ADR 0058 decision 2, ADR 0065 decision
 *       3).
 * </ol>
 *
 * <p><b>Fail closed.</b> {@link #patch} throws {@link IllegalStateException}, failing the build,
 * when the input is not exactly what this patch was written against: the {@code findLibraryName}
 * text is not found exactly once; the two {@code Native.register} calls are not exactly the two
 * expected ones; any other loading call ({@code System.loadLibrary}, {@code Native.load}, {@code
 * NativeLibrary.getInstance}, ...) appears; a listed record or field is missing, has an
 * unsupported type, or already overrides {@code toString}; or the set of record fields whose
 * KDoc (from {@code bindings/ffi/src/records.rs}) calls them secret is not exactly {@link
 * #redactedFields()}. So a UniFFI upgrade cannot silently drop the hook, and a new secret field
 * in records.rs cannot print unredacted.
 */
public final class UniffiKotlinPatch {
    private static final String PREFIX = "uniffi Kotlin patch (feature 0008 F05): ";

    /**
     * ADR 0065 decision 1: the records whose printed form redacts secret fields, each with its
     * secret fields in declaration order. The decision's last bullet adds "any other field ADR
     * 0030 §7 lists as secret-bearing": ADR 0030 §7's values that live in a record field are
     * exactly these (private JWKs and passwords in {@code key}, JWS payloads, JWE plaintext and
     * {@code aad}), and they are exactly the fields records.rs marks "Secret" (checked by {@link
     * #patch}). Generated keys and {@code jwk_to_pem}/{@code jwk_to_der} output are function
     * results, never record fields.
     */
    private static final Map<String, List<String>> REDACTED;

    static {
        Map<String, List<String>> m = new LinkedHashMap<>();
        m.put("JweDecrypted", List.of("plaintext", "aad"));
        m.put("JweEncryptOptions", List.of("aad"));
        m.put("JweRecipient", List.of("key"));
        m.put("JwsSigner", List.of("key"));
        m.put("JwsVerified", List.of("payload"));
        m.put("JwsVerifyOptions", List.of("detachedPayload"));
        REDACTED = Collections.unmodifiableMap(m);
    }

    /** The generated loader function, exactly as UniFFI 0.32.2 writes it. */
    static final String LOADER_ORIGINAL = """
            @Synchronized
            private fun findLibraryName(componentName: String): String {
                val libOverride = System.getProperty("uniffi.component.$componentName.libraryOverride")
                if (libOverride != null) {
                    return libOverride
                }
                return "polyjose_ffi"
            }
            """;

    /** Its replacement (security audit M1). */
    static final String LOADER_PATCHED = """
            @Synchronized
            private fun findLibraryName(componentName: String): String =
                // Patched by the build (feature 0008 F05, security audit M1): no override property
                // and no bare name on the JVM, only the jar's own hash-checked library.
                PolyjoseNativeLoader.libraryName(componentName)
            """;

    /** The only two places the generated code loads the library, each exactly once. */
    static final List<String> REGISTER_CALLS = List.of(
            "Native.register(IntegrityCheckingUniffiLib::class.java, findLibraryName(componentName = \"polyjose_ffi\"))",
            "Native.register(UniffiLib::class.java, findLibraryName(componentName = \"polyjose_ffi\"))");

    /** Loading calls or settings that must not appear in the patched file at all. */
    static final List<String> FORBIDDEN = List.of(
            "libraryOverride",
            "jna.library.path",
            "System.loadLibrary",
            "System.load(",
            "Native.load(",
            "Native.loadLibrary(",
            "NativeLibrary.getInstance(",
            "NativeLibrary.addSearchPath(");

    /** The first line of the patched file. */
    static final String HEADER = """
            // Patched by platforms/android/build-logic UniffiKotlinPatch (feature 0008 F05): findLibraryName
            // loads only the jar's hash-checked library (security audit M1), and the ADR 0065 records
            // redact their secret fields in toString(). The unpatched file is build/generated/uniffi/raw.
            """;

    private static final Pattern DATA_CLASS = Pattern.compile("(?m)^data class (\\w+) \\(\\n");
    private static final Pattern FIELD = Pattern.compile("(?m)^    var `(\\w+)`: ([^\\n=]+?)(?: = [^\\n]*?)?\\s*$");
    private static final Pattern SECRET_DOC = Pattern.compile("\\b[Ss]ecret\\b");
    private static final String BODY_OPEN = "\n){\n";

    private UniffiKotlinPatch() {}

    /** ADR 0065's records and their redacted fields, as this patch applies them (read-only). */
    public static Map<String, List<String>> redactedFields() {
        return REDACTED;
    }

    /**
     * Patches the generated Kotlin. The same input always gives the same output.
     *
     * @throws IllegalStateException when the input is not what the patch expects (see the class
     *     comment); the message says what was not found
     */
    public static String patch(String source) {
        String s = source.replace("\r\n", "\n");
        s = patchLoader(s);
        s = patchRecords(s);
        for (String f : FORBIDDEN) {
            if (s.contains(f)) {
                throw fail("the patched file still contains `" + f + "`: a load path the patch does not route through PolyjoseNativeLoader");
            }
        }
        return HEADER + s;
    }

    private static String patchLoader(String s) {
        int n = count(s, LOADER_ORIGINAL);
        if (n != 1) {
            throw fail("expected the generated findLibraryName exactly once, found it " + n + " times (UniFFI changed its loader?)");
        }
        int registers = count(s, "Native.register(");
        if (registers != REGISTER_CALLS.size()) {
            throw fail("expected " + REGISTER_CALLS.size() + " Native.register calls, found " + registers);
        }
        for (String call : REGISTER_CALLS) {
            int c = count(s, call);
            if (c != 1) {
                throw fail("expected `" + call + "` exactly once, found it " + c + " times");
            }
        }
        String out = s.replace(LOADER_ORIGINAL, LOADER_PATCHED);
        // The declaration and the two calls, nothing else.
        int uses = count(out, "findLibraryName(");
        if (uses != 1 + REGISTER_CALLS.size()) {
            throw fail("expected findLibraryName to be declared once and called " + REGISTER_CALLS.size() + " times, found " + uses + " uses");
        }
        return out;
    }

    /** One field of a generated record declaration. */
    private record Field(String name, String type, boolean documentedSecret) {}

    private static String patchRecords(String s) {
        Map<String, Integer> declarations = new LinkedHashMap<>();
        Matcher m = DATA_CLASS.matcher(s);
        while (m.find()) {
            if (declarations.put(m.group(1), m.end()) != null) {
                throw fail("data class " + m.group(1) + " is declared twice");
            }
        }
        // Every field any record's KDoc calls secret must be redacted, and nothing else.
        Set<String> documented = new TreeSet<>();
        Map<String, List<Field>> fields = new LinkedHashMap<>();
        for (Map.Entry<String, Integer> d : declarations.entrySet()) {
            int end = s.indexOf(BODY_OPEN, d.getValue());
            if (end < 0) {
                throw fail("no `){` after data class " + d.getKey());
            }
            List<Field> list = parseFields(d.getKey(), s.substring(d.getValue(), end));
            fields.put(d.getKey(), list);
            for (Field f : list) {
                if (f.documentedSecret()) {
                    documented.add(d.getKey() + "." + f.name());
                }
            }
        }
        Set<String> expected = new TreeSet<>();
        REDACTED.forEach((record, names) -> names.forEach(n -> expected.add(record + "." + n)));
        if (!documented.equals(expected)) {
            throw fail("the record fields documented as secret " + documented
                    + " are not ADR 0065's redacted fields " + expected
                    + " (update UniffiKotlinPatch and ADR 0065 together with bindings/ffi/src/records.rs)");
        }

        StringBuilder out = new StringBuilder(s);
        // Insert from the end, so earlier offsets stay valid.
        List<String> records = new ArrayList<>(REDACTED.keySet());
        records.sort((a, b) -> Integer.compare(declarations.getOrDefault(b, -1), declarations.getOrDefault(a, -1)));
        for (String record : records) {
            Integer start = declarations.get(record);
            if (start == null) {
                throw fail("no `data class " + record + " (` in the generated file");
            }
            int open = s.indexOf(BODY_OPEN, start) + BODY_OPEN.length();
            int close = s.indexOf("\n}\n", open);
            if (close < 0 || s.substring(open, close).contains("fun toString(")) {
                throw fail("data class " + record + " has no body to patch or already overrides toString");
            }
            out.insert(open, renderToString(record, fields.get(record)));
        }
        return out.toString();
    }

    private static List<Field> parseFields(String record, String declaration) {
        List<Field> list = new ArrayList<>();
        Matcher f = FIELD.matcher(declaration);
        int previous = 0;
        while (f.find()) {
            String doc = declaration.substring(previous, f.start());
            int kdoc = doc.lastIndexOf("/**");
            boolean secret = kdoc >= 0 && SECRET_DOC.matcher(doc.substring(kdoc)).find();
            list.add(new Field(f.group(1), f.group(2).trim(), secret));
            previous = f.end();
        }
        long vars = declaration.lines().filter(l -> l.trim().startsWith("var ") || l.trim().startsWith("val ")).count();
        if (list.isEmpty() || vars != list.size()) {
            throw fail("cannot read the fields of data class " + record + " (" + list.size() + " of " + vars + " parsed)");
        }
        return list;
    }

    private static String renderToString(String record, List<Field> fields) {
        List<String> secret = REDACTED.get(record);
        for (String name : secret) {
            if (fields.stream().noneMatch(f -> f.name().equals(name))) {
                throw fail("data class " + record + " has no field `" + name + "`");
            }
        }
        StringBuilder b = new StringBuilder();
        b.append("    /**\n");
        b.append("     * The fields as the generated `data class` prints them, except that the secret ones (")
                .append(String.join(", ", secret.stream().map(n -> "`" + n + "`").toList()))
                .append(")\n");
        b.append("     * print as `<redacted, N bytes>` (ADR 0065 decision 1, 2; ADR 0030 §7.5). Written by the\n");
        b.append("     * build (feature 0008 F05, UniffiKotlinPatch), not by UniFFI.\n");
        b.append("     */\n");
        b.append("    override fun toString(): String =\n");
        b.append("        \"").append(record).append("(\" +\n");
        for (int i = 0; i < fields.size(); i++) {
            Field f = fields.get(i);
            String value;
            if (secret.contains(f.name())) {
                if (!f.type().equals("kotlin.String") && !f.type().equals("kotlin.ByteArray") && !f.type().equals("kotlin.ByteArray?")) {
                    throw fail("secret field " + record + "." + f.name() + " has type " + f.type() + ", which PolyjoseRedaction cannot redact");
                }
                value = "PolyjoseRedaction.redact(`" + f.name() + "`)";
            } else if (f.type().equals("kotlin.ByteArray") || f.type().equals("kotlin.ByteArray?")) {
                // As the data class: java.util.Arrays.toString.
                value = "`" + f.name() + "`.contentToString()";
            } else if (f.type().contains("ByteArray")) {
                throw fail("field " + record + "." + f.name() + " has type " + f.type() + ", which this patch does not print");
            } else {
                value = "`" + f.name() + "`";
            }
            b.append("            \"").append(f.name()).append("=${").append(value).append("}");
            b.append(i + 1 < fields.size() ? ", \" +\n" : ")\"\n");
        }
        return b.toString();
    }

    private static int count(String haystack, String needle) {
        int n = 0;
        for (int i = haystack.indexOf(needle); i >= 0; i = haystack.indexOf(needle, i + needle.length())) {
            n++;
        }
        return n;
    }

    private static IllegalStateException fail(String message) {
        return new IllegalStateException(PREFIX + message);
    }
}
