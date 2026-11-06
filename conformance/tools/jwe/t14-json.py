"""Generates the T14 JWE JSON conformance vectors.

Inputs (data only): the vendored ietf-jose cookbook (RFC 7520 §5) and the
RFC 7516 text (Appendix A.3-A.5). Outputs one file per vector.
"""
import base64, copy, json, os, re, sys

WT, RFC_TXT = sys.argv[1], sys.argv[2]
CB = os.path.join(WT, "crates/polyjose/tests/third_party/ietf-jose-cookbook/jwe")
OUT_OK = os.path.join(WT, "conformance/vectors/jwe/json")
OUT_NEG = os.path.join(WT, "conformance/vectors/jwe/negative-json")

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def unb64u(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def cook(name):
    for f in os.listdir(CB):
        if f.startswith(name + "."):
            return json.load(open(os.path.join(CB, f), encoding="utf-8"))
    raise SystemExit(name)

# ---- RFC 7516 A.4 / A.5 from the RFC text ---------------------------------
rfc = open(RFC_TXT, encoding="ascii").read()
def block(heading, nxt):
    sec = rfc[rfc.index(heading + "\n"):rfc.index(nxt + "\n")]
    sec = re.sub(r"\n\n\n*Jones & Hildebrand.*?\n\x0c?\nRFC 7516.*?\n", "\n", sec, flags=re.S)
    start = sec.index("\n     {\n")
    end = sec.index("\n     }\n", start) + len("\n     }\n")
    return json.loads(re.sub(r"\s+", "", sec[start:end]))
A4 = block("A.4.7.  Complete JWE JSON Serialization Representation", "A.5.  Example JWE Using Flattened JWE JSON Serialization")
A5 = block("A.5.  Example JWE Using Flattened JWE JSON Serialization", "Appendix B.  Example AES_128_CBC_HMAC_SHA_256 Computation")
assert '"k":"GawgguFyGrWKav7AX4VKUg"' in rfc.replace(" ", "").replace("\n", "")
A3_KEY = {"kty": "oct", "k": "GawgguFyGrWKav7AX4VKUg"}
assert "Live long and prosper." in rfc
A_PT = b64u(b"Live long and prosper.")
A2_RSA_PUBLIC = {"kty": "RSA", "n": None, "e": "AQAB"}
# A.2.3: the RSA key; only n and e (RFC 7516 App. A.2.3), from the text.
a23 = rfc[rfc.rindex("A.2.3.  "):rfc.rindex("A.2.4.  ")]
n = re.search(r'"n":"(.*?)"', re.sub(r"\s+", "", a23)).group(1)
A2_RSA_PUBLIC["n"] = n
A_ENC = ["A128CBC-HS256"]

files = {}
def vec(dirname, fname, source, description, operation, inp, expect, features=None):
    v = {"source": source, "description": description, "operation": operation,
         "input": inp, "expect": expect}
    if features:
        v["features"] = features
    path = os.path.join(dirname, fname + ".json")
    assert path not in files, path
    files[path] = v

def dec(jwe, key, algs, encs, extra=None):
    d = {"jwe": jwe, "key": key, "allowed_algs": algs, "allowed_enc": encs}
    d.update(extra or {})
    return d

def ok(pt, recipient=0): return {"ok": True, "plaintext_b64u": pt, "recipient": recipient}
def err(code): return {"ok": False, "error": code}

# ---- RFC 7520 cookbook examples -------------------------------------------
class Ex:
    def __init__(self, name, sec):
        d = cook(name)
        self.sec = sec
        self.key = d["input"]["key"]
        self.alg = d["input"]["alg"]
        self.enc = d["input"]["enc"]
        self.pt = b64u(d["input"]["plaintext"].encode("utf-8"))
        g = d.get("generated", {})
        self.rng = b64u((unb64u(g["cek"]) if "cek" in g else b"") + unb64u(g["iv"]))
        self.aad = g.get("aad_b64u")
        self.protected_b64 = d["encrypting_content"].get("protected_b64u")
        self.general = d["output"]["json"]
        self.flat = d["output"]["json_flat"]
    def dec(self, jwe, key=None, algs=None):
        return dec(jwe, key or self.key, algs or [self.alg], [self.enc])

c56 = Ex("5_6", "§5.6")
c58 = Ex("5_8", "§5.8")
c510 = Ex("5_10", "§5.10")
c511 = Ex("5_11", "§5.11")
c512 = Ex("5_12", "§5.12")

OMISSION = ("No jwe.encrypt vector reproduces it: polyjose's encryptor always puts alg in the "
            "protected header of a flattened JWE and in the recipient's header of a general one, "
            "never in the shared unprotected header (documented omission for 0.1.0, plan.md lead "
            "refinement 15; jwe_json.rs shows the output differs only in where alg sits)")
GENERAL_OMISSION = ("No exact jwe.encrypt vector for this general form: RFC 7520 keeps alg in the "
                    "protected header, where polyjose's general form puts it in each recipient's "
                    "header (plan.md, as RFC 7520 §5.13); the flattened form is reproduced exactly")

J = OUT_OK
# §5.6
g56 = copy.deepcopy(c56.flat); g56["recipients"] = [{}]
assert c56.general == c56.flat and "recipients" not in c56.general
vec(J, "rfc7520-5-6-dir-a128gcm-flattened-decrypt", "RFC 7520 §5.6",
    "The RFC 7520 §5.6 flattened JSON JWE (dir + A128GCM, kid in the protected header) decrypts with the §5.6 key to the Figure 72 plaintext (generated from the ietf-jose cookbook; RFC 7520 prints the same object as its general output, which without recipients is the RFC 7516 §7.2.2 flattened syntax)",
    "jwe.decrypt", c56.dec(c56.flat), ok(c56.pt))
vec(J, "rfc7520-5-6-dir-a128gcm-general-decrypt", "RFC 7520 §5.6",
    "The RFC 7520 §5.6 JWE in the RFC 7516 §7.2.1 general syntax decrypts as recipient 0: derived from the cookbook's flattened output by adding \"recipients\":[{}] (dir has no encrypted key and no per-recipient header), since RFC 7520 prints its general output without a recipients member. " + GENERAL_OMISSION,
    "jwe.decrypt", c56.dec(g56), ok(c56.pt))
vec(J, "rfc7520-5-6-dir-a128gcm-flattened-encrypt", "RFC 7520 §5.6",
    "Encrypting with the RFC 7520 §5.6 IV as the drawn bytes (dir draws no CEK) and its protected header (kid in the protected header) reproduces the RFC 7520 §5.6 flattened JSON JWE exactly",
    "jwe.encrypt",
    {"serialization": "flattened", "enc": c56.enc, "plaintext_b64u": c56.pt,
     "recipients": [{"alg": c56.alg, "key": c56.key}], "protected": {"kid": c56.key["kid"]},
     "protected_b64u": c56.protected_b64, "rng_b64u": c56.rng},
    {"ok": True, "jwe": c56.flat}, ["fixed-rng"])
# §5.8 and §5.10
for ex, slug, extra_desc in [(c58, "rfc7520-5-8-a128kw-a128gcm", ""),
                             (c510, "rfc7520-5-10-a128kw-a128gcm-aad", " with the §5.10 JWE AAD")]:
    vec(J, slug + "-general-decrypt", "RFC 7520 " + ex.sec,
        f"The RFC 7520 {ex.sec} general JSON JWE{extra_desc} (A128KW + A128GCM, alg and kid in the protected header) decrypts with the {ex.sec} key to the Figure 72 plaintext as recipient 0 (generated from the ietf-jose cookbook). " + GENERAL_OMISSION,
        "jwe.decrypt", ex.dec(ex.general), ok(ex.pt))
    vec(J, slug + "-flattened-decrypt", "RFC 7520 " + ex.sec,
        f"The RFC 7520 {ex.sec} flattened JSON JWE{extra_desc} (A128KW + A128GCM) decrypts with the {ex.sec} key to the Figure 72 plaintext (generated from the ietf-jose cookbook)",
        "jwe.decrypt", ex.dec(ex.flat), ok(ex.pt))
    inp = {"serialization": "flattened", "enc": ex.enc, "plaintext_b64u": ex.pt,
           "recipients": [{"alg": ex.alg, "key": ex.key}], "protected": {"kid": ex.key["kid"]},
           "protected_b64u": ex.protected_b64, "rng_b64u": ex.rng}
    if ex.aad:
        inp["aad_b64u"] = ex.aad
    vec(J, slug + "-flattened-encrypt", "RFC 7520 " + ex.sec,
        f"Encrypting with the RFC 7520 {ex.sec} random values as the drawn bytes (CEK, then IV){extra_desc} and its protected header (kid in the protected header) reproduces the RFC 7520 {ex.sec} flattened JSON JWE exactly",
        "jwe.encrypt", inp, {"ok": True, "jwe": ex.flat}, ["fixed-rng"])
# §5.11 and §5.12
for ex, slug, what in [(c511, "rfc7520-5-11-a128kw-a128gcm-protected-enc-only", "only enc in the protected header; alg and kid in the shared unprotected header"),
                       (c512, "rfc7520-5-12-a128kw-a128gcm-no-protected-header", "no protected header; alg, kid and enc in the shared unprotected header, so the AAD is empty (RFC 7516 §5.1 step 14)")]:
    for form, jwe in [("general", ex.general), ("flattened", ex.flat)]:
        vec(J, f"{slug}-{form}-decrypt", "RFC 7520 " + ex.sec,
            f"The RFC 7520 {ex.sec} {form} JSON JWE ({what}) decrypts with the {ex.sec} key to the Figure 72 plaintext (generated from the ietf-jose cookbook). " + OMISSION + (", and it always protects enc, which §5.12 leaves unprotected" if ex is c512 else ""),
            "jwe.decrypt", ex.dec(jwe), ok(ex.pt))

# ---- RFC 7516 A.4 / A.5 ----------------------------------------------------
vec(J, "rfc7516-a4-general-a128kw-recipient-1-decrypt", "RFC 7516 App. A.4",
    "The RFC 7516 A.4.7 general JWE (recipient 0 RSA1_5, recipient 1 A128KW) decrypts with the A.3 A128KW key as recipient 1: RSA1_5 is never a candidate (ADRs 0021, 0022), even when allowed. No encrypt vector: polyjose does not encrypt to RSA1_5",
    "jwe.decrypt", dec(A4, A3_KEY, ["RSA1_5", "A128KW"], A_ENC), ok(A_PT, 1))
k7 = dict(A3_KEY); k7 = {"kty": "oct", "kid": "7", "k": A3_KEY["k"]}
vec(J, "rfc7516-a4-general-kid-7-decrypt", "RFC 7516 App. A.4",
    "RFC 7516 §4.1.6: the A.3 key with A.4's kid \"7\" matches recipient 1 (kid \"7\") and decrypts the A.4.7 general JWE as recipient 1",
    "jwe.decrypt", dec(A4, k7, ["A128KW"], A_ENC), ok(A_PT, 1))
a4_swapped = copy.deepcopy(A4); a4_swapped["recipients"].reverse()
vec(J, "rfc7516-a4-general-recipients-swapped-decrypt", "RFC 7516 App. A.4",
    "Derived from RFC 7516 A.4.7 by swapping its two recipients (the recipients array is not integrity protected, §7.2.1): the A128KW key now decrypts as recipient 0",
    "jwe.decrypt", dec(a4_swapped, A3_KEY, ["RSA1_5", "A128KW"], A_ENC), ok(A_PT, 0))
a4_kids = copy.deepcopy(A4)
decoy = copy.deepcopy(A4["recipients"][1]); decoy["header"]["kid"] = "6"
a4_kids["recipients"].insert(1, decoy)
vec(J, "rfc7516-a4-general-kid-mismatch-skipped-decrypt", "RFC 7516 App. A.4",
    "Derived from RFC 7516 A.4.7 by inserting a copy of the A128KW recipient with kid \"6\" before it: with the kid-\"7\" key the copy is not a candidate (RFC 7516 §4.1.6, plan.md recipient selection), so the original decrypts as recipient 2 although the copy would decrypt",
    "jwe.decrypt", dec(a4_kids, k7, ["A128KW"], A_ENC), ok(A_PT, 2))
vec(J, "rfc7516-a4-general-kid-absent-first-candidate-decrypt", "RFC 7516 App. A.4",
    "The same three-recipient derivation of RFC 7516 A.4.7 with the A.3 key without a kid: every A128KW recipient is a candidate and the first that decrypts (recipient 1, the kid-\"6\" copy) wins (plan.md recipient selection)",
    "jwe.decrypt", dec(a4_kids, A3_KEY, ["A128KW"], A_ENC), ok(A_PT, 1))
a4_wrongkey_first = copy.deepcopy(A4)
bad = copy.deepcopy(A4["recipients"][1]); bad["encrypted_key"] = b64u(b"\x00" * 40)
a4_wrongkey_first["recipients"].insert(1, bad)
vec(J, "rfc7516-a4-general-failing-candidate-passed-over-decrypt", "RFC 7516 App. A.4",
    "Derived from RFC 7516 A.4.7 by inserting an A128KW recipient whose encrypted key fails the RFC 3394 integrity check: that candidate fails and the next one decrypts as recipient 2 (RFC 7516 §5.2 step 6, plan.md recipient selection)",
    "jwe.decrypt", dec(a4_wrongkey_first, A3_KEY, ["A128KW"], A_ENC), ok(A_PT, 2))
vec(J, "rfc7516-a5-flattened-decrypt", "RFC 7516 App. A.5",
    "The RFC 7516 A.5 flattened JWE (alg and kid in the per-recipient header, jku in the shared unprotected header) decrypts with the A.3 A128KW key. " + OMISSION.replace("never in the shared unprotected header", "never in the per-recipient header of a flattened JWE"),
    "jwe.decrypt", dec(A5, A3_KEY, ["A128KW"], A_ENC), ok(A_PT))

# ---- round trips (OS CSPRNG) ----------------------------------------------
K128 = {"kty": "oct", "k": b64u(bytes([0x11]) * 16)}
K192 = {"kty": "oct", "k": b64u(bytes([0x22]) * 24)}
K256 = {"kty": "oct", "k": b64u(bytes([0x33]) * 32)}
PT = b64u(b"Live long and prosper.")
three = [{"alg": "A128KW", "key": K128}, {"alg": "A256KW", "key": K256}, {"alg": "A192KW", "key": K192}]
for alg, key in [("A128KW", K128), ("A256KW", K256), ("A192KW", K192)]:
    vec(J, f"roundtrip-general-three-kw-{alg.lower()}-key", "polyjose",
        f"RFC 7516 §5.1 steps 2-8, §7.2.1: one CEK wrapped for A128KW, A256KW and A192KW recipients (RFC 7518 §4.4) in a general JWE with A256GCM on the OS CSPRNG has three recipients and decrypts with the {alg} key",
        "jwe.encrypt",
        {"serialization": "general", "enc": "A256GCM", "plaintext_b64u": PT, "recipients": three},
        {"ok": True, "decrypt_with": {"key": key, "allowed_algs": ["A128KW", "A192KW", "A256KW"], "allowed_enc": ["A256GCM"]}})
vec(J, "roundtrip-general-headers-and-aad", "polyjose",
    "RFC 7516 §7.2.1: a general JWE with a protected typ, a shared unprotected jku, per-recipient kids and a JWE AAD (A128KW and A192KW + A128CBC-HS256, OS CSPRNG) decrypts with the second recipient's key",
    "jwe.encrypt",
    {"serialization": "general", "enc": "A128CBC-HS256", "plaintext_b64u": PT,
     "recipients": [{"alg": "A128KW", "key": K128, "header": {"kid": "a"}},
                    {"alg": "A192KW", "key": K192, "header": {"kid": "b"}}],
     "protected": {"typ": "JOSE+JSON"}, "unprotected": {"jku": "https://example.com/keys"},
     "aad_b64u": b64u(b"bound, not encrypted")},
    {"ok": True, "decrypt_with": {"key": K192, "allowed_algs": ["A192KW"], "allowed_enc": ["A128CBC-HS256"]}})
vec(J, "roundtrip-flattened-a256kw-a256cbc-hs512-aad", "polyjose",
    "RFC 7516 §7.2.2: a flattened A256KW + A256CBC-HS512 JWE with a shared unprotected header, a per-recipient header and a JWE AAD on the OS CSPRNG decrypts with the same key",
    "jwe.encrypt",
    {"serialization": "flattened", "enc": "A256CBC-HS512", "plaintext_b64u": PT,
     "recipients": [{"alg": "A256KW", "key": K256, "header": {"kid": "c"}}],
     "unprotected": {"cty": "text/plain"}, "aad_b64u": b64u(b"[\"vcard\"]")},
    {"ok": True, "decrypt_with": {"key": K256, "allowed_algs": ["A256KW"], "allowed_enc": ["A256CBC-HS512"]}})
vec(J, "roundtrip-general-dir-a128gcm", "polyjose",
    "RFC 7516 §7.2.1, RFC 7518 §4.5: a general JWE to one dir recipient (no encrypted key) on the OS CSPRNG decrypts with the same key",
    "jwe.encrypt",
    {"serialization": "general", "enc": "A128GCM", "plaintext_b64u": PT, "recipients": [{"alg": "dir", "key": K128}]},
    {"ok": True, "decrypt_with": {"key": K128, "allowed_algs": ["dir"], "allowed_enc": ["A128GCM"]}})
vec(J, "roundtrip-flattened-empty-plaintext", "polyjose",
    "RFC 7516 §7.2.1 (ciphertext is always present), RFC 7518 §5.3: an empty plaintext under A128KW + A128GCM gives an empty ciphertext member and decrypts to the empty plaintext",
    "jwe.encrypt",
    {"serialization": "flattened", "enc": "A128GCM", "plaintext_b64u": "", "recipients": [{"alg": "A128KW", "key": K128}]},
    {"ok": True, "decrypt_with": {"key": K128, "allowed_algs": ["A128KW"], "allowed_enc": ["A128GCM"]}})

# ---- negatives -------------------------------------------------------------
N = OUT_NEG
def neg(fname, desc, jwe, code, key=None, algs=None, encs=None, extra=None, source="polyjose"):
    vec(N, fname, source, desc, "jwe.decrypt",
        dec(jwe, key or A3_KEY, algs or ["A128KW"], encs or A_ENC, extra), err(code))
def a5(**changes):
    j = copy.deepcopy(A5)
    for k, v in changes.items():
        if v is None: j.pop(k, None)
        else: j[k] = v
    return j
def a4(**changes):
    j = copy.deepcopy(A4)
    for k, v in changes.items():
        if v is None: j.pop(k, None)
        else: j[k] = v
    return j

neg("recipients-empty", "RFC 7516 §7.2.1: recipients must be a non-empty array (derived from RFC 7516 A.4.7 with recipients []): InvalidFormat", a4(recipients=[]), "InvalidFormat")
neg("recipients-not-an-array", "RFC 7516 §7.2.1: recipients \"MUST be an array of JSON objects\" (RFC 7516 A.4.7 with recipients an object): InvalidFormat", a4(recipients=A4["recipients"][1]), "InvalidFormat")
neg("recipient-not-an-object", "RFC 7516 §7.2.1: each recipients entry is a JSON object (RFC 7516 A.4.7 with a string entry): InvalidFormat", a4(recipients=[A4["recipients"][1], "A128KW"]), "InvalidFormat")
neg("flattened-with-recipients", "RFC 7516 §7.2.2: a flattened JWE \"MUST NOT\" have a recipients member (RFC 7516 A.5 with A.4.7's recipients added): InvalidFormat", a5(recipients=A4["recipients"]), "InvalidFormat")
neg("missing-ciphertext-general", "RFC 7516 §7.2.1: the ciphertext member MUST be present (RFC 7516 A.4.7 without it): InvalidFormat", a4(ciphertext=None), "InvalidFormat")
neg("missing-ciphertext-flattened", "RFC 7516 §7.2.1, §7.2.2: the ciphertext member MUST be present (RFC 7516 A.5 without it): InvalidFormat", a5(ciphertext=None), "InvalidFormat")
neg("ciphertext-not-a-string", "RFC 7516 §7.2.1: ciphertext is BASE64URL(JWE Ciphertext), a string (RFC 7516 A.5 with a number): InvalidFormat", a5(ciphertext=1), "InvalidFormat")
neg("unprotected-not-an-object", "RFC 7516 §7.2.1: unprotected is an unencoded JSON object, not a string (RFC 7516 A.5 with it encoded): InvalidFormat", a5(unprotected=b64u(json.dumps(A5["unprotected"]).encode())), "InvalidFormat")
neg("empty-aad-member", "RFC 7516 §7.2.1: aad MUST be absent when the JWE AAD is empty, so \"aad\":\"\" is malformed (it would change the AAD computation, §5.2 step 15): InvalidFormat", a5(aad=""), "InvalidFormat")
neg("empty-protected-member", "RFC 7516 §7.2.1: protected MUST be absent when the protected header is empty (RFC 7516 A.5 with \"protected\":\"\" and enc moved to the shared header): InvalidFormat",
    a5(protected="", unprotected={"jku": A5["unprotected"]["jku"], "enc": "A128CBC-HS256"}), "InvalidFormat")
neg("empty-unprotected-member", "RFC 7516 §7.2.1: unprotected MUST be absent when the shared unprotected header is empty (RFC 7516 A.5 with \"unprotected\":{}): InvalidFormat", a5(unprotected={}), "InvalidFormat")
neg("empty-encrypted-key-member", "RFC 7516 §7.2.1: encrypted_key MUST be absent when the encrypted key is empty (RFC 7516 A.5 with \"encrypted_key\":\"\"): InvalidFormat", a5(encrypted_key=""), "InvalidFormat")
neg("recipient-without-any-header", "RFC 7516 §7.2.1: at least one of header, protected and unprotected MUST be present for each recipient (RFC 7516 A.5 without all three): InvalidFormat", a5(protected=None, unprotected=None, header=None), "InvalidFormat")
neg("over-max-recipients", "ADR 0026 §7, plan.md limits: RFC 7516 A.4.7 has two recipients, more than a max_recipients of 1: InvalidFormat", copy.deepcopy(A4), "InvalidFormat", extra={"max_recipients": 1})
neg("over-max-input-len", "ADR 0026 §7: the RFC 7516 A.5 JWE text is longer than a max_input_len of 64 octets: InvalidFormat, before parsing", copy.deepcopy(A5), "InvalidFormat", extra={"max_input_len": 64})
neg("padded-base64url-iv", "RFC 7516 §5.2 step 2, RFC 7515 §2: the iv member must be unpadded base64url (RFC 7516 A.5 with \"=\" padding added): InvalidBase64", a5(iv=A5["iv"] + "=="), "InvalidBase64")
neg("standard-alphabet-encrypted-key", "RFC 7516 §5.2 step 2, RFC 7515 §2: the encrypted_key member must use the URL-safe alphabet (RFC 7516 A.5 with its first character replaced by the standard-alphabet \"+\"): InvalidBase64", a5(encrypted_key="+" + A5["encrypted_key"][1:]), "InvalidBase64")
neg("protected-header-not-an-object", "RFC 7516 §5.2 step 3, plan.md lead refinement 15: a protected header that is JSON but not an object (base64url of [\"enc\"]): InvalidJson", a5(protected=b64u(b'["enc"]')), "InvalidJson")
neg("protected-header-duplicate-member", "ADR 0041 §1, RFC 7516 §5.2 step 3: a duplicate member name in the protected header of a JSON JWE (\"enc\" twice): InvalidJson. A duplicate in the JWE JSON itself cannot be written as a vector object; tests/jwe_json.rs covers it", a5(protected=b64u(b'{"enc":"A128CBC-HS256","enc":"A128CBC-HS256"}')), "InvalidJson")
neg("alg-in-protected-and-recipient-header", "RFC 7516 §5.2 step 4, §7.2.1: the protected and per-recipient headers MUST be disjoint (RFC 7516 A.5 with alg also in the protected header): InvalidHeader, before any cryptography",
    a5(protected=b64u(b'{"enc":"A128CBC-HS256","alg":"A128KW"}')), "InvalidHeader")
a4_overlap = copy.deepcopy(A4); a4_overlap["recipients"][1]["header"]["jku"] = "https://server.example.com/keys.jwks"
neg("shared-and-recipient-header-overlap", "RFC 7516 §5.2 step 4, §7.2.1: the shared and per-recipient headers MUST be disjoint, checked for every recipient (RFC 7516 A.4.7 with jku also in recipient 1's header): InvalidHeader", a4_overlap, "InvalidHeader")
neg("zip-in-unprotected-header", "RFC 7516 §4.1.3: zip MUST occur only in the protected header (RFC 7516 A.5 with zip in the shared unprotected header): InvalidHeader",
    a5(unprotected={"jku": A5["unprotected"]["jku"], "zip": "DEF"}), "InvalidHeader")
neg("crit-in-unprotected-header", "RFC 7516 §4.1.13, RFC 7515 §4.1.11: crit MUST be integrity protected (RFC 7516 A.5 with crit in the per-recipient header): InvalidHeader",
    a5(header={"alg": "A128KW", "kid": "7", "crit": ["exp"], "exp": 1}), "InvalidHeader", extra={"understood_crit": ["exp"]})
a4_enc = copy.deepcopy(A4); a4_enc.pop("protected")
a4_enc["recipients"][0]["header"]["enc"] = "A128CBC-HS256"; a4_enc["recipients"][1]["header"]["enc"] = "A256GCM"
neg("recipients-disagree-on-enc", "RFC 7516 §5.2 step 4: one ciphertext has one enc, so recipients with different enc values are malformed (RFC 7516 A.4.7 with enc moved into each recipient's header, A128CBC-HS256 and A256GCM): InvalidHeader", a4_enc, "InvalidHeader", encs=["A128CBC-HS256", "A256GCM"])
a4_noalg = copy.deepcopy(A4); a4_noalg["recipients"][1].pop("header")
neg("recipient-without-alg", "RFC 7516 §4.1.1: every recipient's JOSE Header has alg (RFC 7516 A.4.7 with recipient 1's header removed; the protected header still conveys enc): InvalidHeader", a4_noalg, "InvalidHeader")
# §5.10 AAD
neg("tampered-aad", "RFC 7516 §5.2 steps 14-16: the JWE AAD is authenticated (the RFC 7520 §5.10 flattened JWE with its aad replaced): DecryptionFailed",
    dict(c510.flat, aad=b64u(b'["vcard",[]]')), "DecryptionFailed", key=c510.key, algs=["A128KW"], encs=["A128GCM"])
neg("aad-removed", "RFC 7516 §5.2 step 15: removing the aad member changes the AAD (the RFC 7520 §5.10 flattened JWE without it): DecryptionFailed",
    {k: v for k, v in c510.flat.items() if k != "aad"}, "DecryptionFailed", key=c510.key, algs=["A128KW"], encs=["A128GCM"])
compact = ".".join(c510.flat[m] for m in ["protected", "encrypted_key", "iv", "ciphertext", "tag"])
neg("aad-moved-to-compact", "RFC 7516 §7.1: the compact serialization has no JWE AAD, so the RFC 7520 §5.10 flattened JWE's parts as a compact JWE lose it and the tag fails (§5.2 step 15): DecryptionFailed",
    compact, "DecryptionFailed", key=c510.key, algs=["A128KW"], encs=["A128GCM"])
# tampered unprotected (§5.11: alg and kid unprotected)
def t511(**u):
    j = copy.deepcopy(c511.flat); j["unprotected"].update(u); return j
vec(N, "tampered-unprotected-jku-still-decrypts", "RFC 7520 §5.11",
    "RFC 7516 §7.2.1: the shared unprotected header is not integrity protected, so adding a jku to the RFC 7520 §5.11 flattened JWE plays no part in decryption and it still decrypts",
    "jwe.decrypt", c511.dec(t511(jku="https://attacker.example/keys")), ok(c511.pt))
neg("tampered-unprotected-alg-not-allowed", "plan.md error contract: the RFC 7520 §5.11 flattened JWE with its unprotected alg changed to A256KW, which the policy does not allow: AlgorithmNotAllowed",
    t511(alg="A256KW"), "AlgorithmNotAllowed", key=c511.key, algs=["A128KW"], encs=["A128GCM"])
neg("tampered-unprotected-alg-unsupported", "plan.md error contract, ADR 0022: the RFC 7520 §5.11 flattened JWE with its unprotected alg changed to RSA1_5: UnsupportedAlgorithm, even when allowed",
    t511(alg="RSA1_5"), "UnsupportedAlgorithm", key=c511.key, algs=["A128KW", "RSA1_5"], encs=["A128GCM"])
neg("tampered-unprotected-alg-key-mismatch", "RFC 7516 §5.2 step 7, RFC 7517 §4.4: the RFC 7520 §5.11 flattened JWE with its unprotected alg changed to A192KW, which the key's alg A128KW forbids: KeyAlgorithmMismatch",
    t511(alg="A192KW"), "KeyAlgorithmMismatch", key=c511.key, algs=["A128KW", "A192KW"], encs=["A128GCM"])
bare = {"kty": "oct", "k": c511.key["k"]}
neg("tampered-unprotected-alg-decryption-failed", "RFC 7518 §4.5, RFC 7516 §11.4: the RFC 7520 §5.11 flattened JWE with its unprotected alg changed to dir, for which the alg-less 16-octet key is a candidate under A128GCM: the non-empty encrypted key fails key management: DecryptionFailed",
    t511(alg="dir"), "DecryptionFailed", key=bare, algs=["A128KW", "dir"], encs=["A128GCM"])
# A.4 selection
neg("rfc7516-a4-rsa-key-only", "RFC 7516 App. A.4.7 with only the A.2 RSA public key: RSA1_5 is UnsupportedAlgorithm (ADRs 0021, 0022) and the A128KW recipient cannot use an RSA key (KeyAlgorithmMismatch), which ranks lower (plan.md recipient selection): UnsupportedAlgorithm",
    copy.deepcopy(A4), "UnsupportedAlgorithm", key=A2_RSA_PUBLIC, algs=["RSA1_5", "A128KW"], source="RFC 7516 App. A.4")
neg("rfc7516-a4-wrong-a128kw-key", "RFC 7516 App. A.4.7 with an A128KW key that is not A.3's: the one candidate fails key management: DecryptionFailed",
    copy.deepcopy(A4), "DecryptionFailed", key={"kty": "oct", "k": b64u(bytes(16))}, algs=["RSA1_5", "A128KW"], source="RFC 7516 App. A.4")
neg("rfc7516-a4-kid-mismatch", "RFC 7516 App. A.4.7 with the A.3 key under kid \"8\": recipient 1 (kid \"7\") is not a candidate (KeyAlgorithmMismatch) and recipient 0 is RSA1_5 (UnsupportedAlgorithm), which ranks higher: UnsupportedAlgorithm",
    copy.deepcopy(A4), "UnsupportedAlgorithm", key={"kty": "oct", "kid": "8", "k": A3_KEY["k"]}, source="RFC 7516 App. A.4")
def a4_algs(*algs):
    j = copy.deepcopy(A4)
    base = j["recipients"][1]
    j["recipients"] = []
    for alg in algs:
        r = copy.deepcopy(base); r["header"]["alg"] = alg; j["recipients"].append(r)
    return j
neg("no-candidate-not-allowed-ranks-first", "plan.md recipient selection: RFC 7516 A.4.7's A128KW recipient copied three times with alg RSA1_5 (unsupported), A192KW (allowed, but the 16-octet key cannot serve it) and A256KW (not allowed): with no candidate, AlgorithmNotAllowed ranks first",
    a4_algs("RSA1_5", "A192KW", "A256KW"), "AlgorithmNotAllowed", algs=["A128KW", "A192KW"])
neg("no-candidate-unsupported-ranks-second", "plan.md recipient selection: RFC 7516 A.4.7's A128KW recipient copied with alg A192KW (allowed, but the 16-octet key cannot serve it), RSA-OAEP-256 (not decrypted, ADR 0021) and A192KW: UnsupportedAlgorithm outranks KeyAlgorithmMismatch",
    a4_algs("A192KW", "RSA-OAEP-256", "A192KW"), "UnsupportedAlgorithm", algs=["A128KW", "A192KW", "RSA-OAEP-256"])
neg("no-candidate-key-mismatch", "plan.md recipient selection: RFC 7516 A.4.7's A128KW recipient copied twice with alg A192KW and A256KW, both allowed, neither servable by the 16-octet key: KeyAlgorithmMismatch",
    a4_algs("A192KW", "A256KW"), "KeyAlgorithmMismatch", algs=["A128KW", "A192KW", "A256KW"])
vec(J, "rfc7516-a4-general-one-candidate-among-failures-decrypt", "RFC 7516 App. A.4",
    "plan.md recipient selection: RFC 7516 A.4.7's A128KW recipient copied with alg A256KW (not allowed), RSA1_5 (unsupported) and its own A128KW: the one candidate decrypts as recipient 2",
    "jwe.decrypt", dec(a4_algs("A256KW", "RSA1_5", "A128KW"), A3_KEY, ["A128KW"], A_ENC), ok(A_PT, 2))
# encrypt negatives
def enc_neg(fname, desc, inp, code):
    vec(N, fname, "polyjose", desc, "jwe.encrypt", inp, err(code))
enc_neg("encrypt-flattened-two-recipients", "RFC 7516 §7.2.2: the flattened form carries one recipient, so encrypting to two is refused: InvalidFormat",
        {"serialization": "flattened", "enc": "A128GCM", "plaintext_b64u": PT, "recipients": three[:2]}, "InvalidFormat")
enc_neg("encrypt-general-dir-and-a128kw", "RFC 7516 §5.1 step 6: dir makes the shared key the CEK, so it allows no other recipient: InvalidFormat",
        {"serialization": "general", "enc": "A128GCM", "plaintext_b64u": PT, "recipients": [{"alg": "A128KW", "key": K128}, {"alg": "dir", "key": K128}]}, "InvalidFormat")
enc_neg("encrypt-general-ecdh-es-and-a128kw", "RFC 7516 §5.1 step 5: ECDH-ES (direct key agreement) determines the CEK, so it allows no other recipient; checked before the key: InvalidFormat",
        {"serialization": "general", "enc": "A128GCM", "plaintext_b64u": PT, "recipients": [{"alg": "A128KW", "key": K128}, {"alg": "ECDH-ES", "key": K128}]}, "InvalidFormat")
enc_neg("encrypt-empty-aad", "RFC 7516 §7.2.1: aad must be absent when the JWE AAD is empty, but an empty JWE AAD set by the caller is part of the AAD computation (§5.1 step 14), so the JSON output could not be decrypted and is refused: InvalidFormat",
        {"serialization": "general", "enc": "A128GCM", "plaintext_b64u": PT, "recipients": [{"alg": "A128KW", "key": K128}], "aad_b64u": ""}, "InvalidFormat")
enc_neg("encrypt-unprotected-alg", "RFC 7516 §4.1.1: polyjose sets alg itself, so a shared unprotected header with alg is refused: InvalidHeader",
        {"serialization": "general", "enc": "A128GCM", "plaintext_b64u": PT, "recipients": [{"alg": "A128KW", "key": K128}], "unprotected": {"alg": "A128KW"}}, "InvalidHeader")
enc_neg("encrypt-shared-and-recipient-overlap", "RFC 7516 §7.2.1: the shared and per-recipient headers must be disjoint (kid in both): InvalidHeader",
        {"serialization": "general", "enc": "A128GCM", "plaintext_b64u": PT, "recipients": [{"alg": "A128KW", "key": K128, "header": {"kid": "a"}}], "unprotected": {"kid": "a"}}, "InvalidHeader")

for d in (OUT_OK, OUT_NEG):
    os.makedirs(d, exist_ok=True)
for path, v in sorted(files.items()):
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(v, indent=2, ensure_ascii=False) + "\n")
print(len(files), "files;", sum(1 for p in files if "/json/" in p), "positive")
