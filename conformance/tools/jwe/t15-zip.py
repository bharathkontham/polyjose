"""0003 T15: write conformance/vectors/jwe/zip/*.json.

Usage: python3 -I t15-zip.py <repo-root> conformance/tools/jwe/t15-zip-tokens.txt
The tokens come from t15-zip-tokens.rs (historical; see conformance/README.md, Tools).
"""
import base64, json, sys
root, tokens_path = sys.argv[1], sys.argv[2]
out = root + "/conformance/vectors/jwe/zip/"
cb = json.load(open(root + "/crates/polyjose/tests/third_party/ietf-jose-cookbook/jwe/5_9.compressed_content.json"))
tok = dict(line.split(" ", 1) for line in open(tokens_path).read().splitlines())
b64u = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
dir_key = {"kty": "oct", "k": tok["key"]}
fig72 = cb["input"]["plaintext"].encode()

def write(name, source, desc, op, inp, expect):
    v = {"source": source, "description": desc, "operation": op, "input": inp, "expect": expect, "features": ["deflate"]}
    with open(out + name + ".json", "w") as f:
        f.write(json.dumps(v, indent=2, ensure_ascii=False) + "\n")

def dec(jwe, key=dir_key, algs=("dir",), encs=("A128GCM",), **policy):
    d = {"jwe": jwe, "key": key, "allowed_algs": list(algs), "allowed_enc": list(encs)}
    d.update(policy)
    return d

ok = lambda pt: {"ok": True, "plaintext_b64u": b64u(pt), "recipient": 0}
fail = lambda code: {"ok": False, "error": code}

c59 = cb["output"]["compact"]
k59 = cb["input"]["key"]
write("rfc7520-5-9-a128kw-a128gcm-def-decrypt", "RFC 7520 §5.9",
      "The RFC 7520 §5.9 compact JWE (A128KW + A128GCM, zip DEF) decrypts with the §5.9 key and inflates (RFC 7516 §5.2 step 17) to the Figure 72 plaintext (generated from the ietf-jose cookbook)",
      "jwe.decrypt", dec(c59, k59, ("A128KW",)), ok(fig72))
parts = c59.split(".")
tag = bytearray(base64.urlsafe_b64decode(parts[4] + "=="))
tag[15] ^= 1
parts[4] = b64u(bytes(tag))
write("rfc7520-5-9-bad-tag", "RFC 7520 §5.9",
      "RFC 7516 §5.2 steps 16-17: the §5.9 JWE with one tag bit flipped is DecryptionFailed; inflation never starts before the tag verifies (generated from the ietf-jose cookbook)",
      "jwe.decrypt", dec(".".join(parts), k59, ("A128KW",)), fail("DecryptionFailed"))
write("roundtrip-a128kw-a128gcm-def", "polyjose",
      "RFC 7516 §5.1 step 11: a compressed compact A128KW + A128GCM encryption of the Figure 72 plaintext carries zip DEF in the protected header and decrypts to the plaintext (byte-exact compression is not required, RFC 7520 erratum 7680)",
      "jwe.encrypt",
      {"serialization": "compact", "enc": "A128GCM", "plaintext_b64u": b64u(fig72), "compress": True,
       "recipients": [{"alg": "A128KW", "key": {"kty": "oct", "k": k59["k"]}}]},
      {"ok": True, "decrypt_with": {"key": {"kty": "oct", "k": k59["k"]}, "allowed_algs": ["A128KW"], "allowed_enc": ["A128GCM"]}})
pt64 = b"0123456789abcdef" * 4
write("bound-exact-decrypts", "polyjose",
      "ADR 0017 §1: a dir + A128GCM zip JWE whose plaintext inflates to 64 bytes decrypts under max_decompressed_len 64; the bound is inclusive",
      "jwe.decrypt", dec(tok["bound64"], max_decompressed_len=64), ok(pt64))
write("bound-plus-one-fails", "polyjose",
      "ADR 0017 §1, RFC 7516 §5.2 step 17: the same JWE under max_decompressed_len 63 is DecryptionFailed, as soon as the output would exceed the bound",
      "jwe.decrypt", dec(tok["bound64"], max_decompressed_len=63), fail("DecryptionFailed"))
write("empty-plaintext-decrypts", "polyjose",
      "RFC 7516 §5.2 step 17: a dir + A128GCM zip JWE of the empty plaintext decrypts under the default bound",
      "jwe.decrypt", dec(tok["empty"]), ok(b""))
write("bound-zero-rejects-empty", "polyjose",
      "ADR 0017 §3: max_decompressed_len 0 rejects every zip JWE, even one whose plaintext is empty and inflates to 0 bytes",
      "jwe.decrypt", dec(tok["empty"], max_decompressed_len=0), fail("DecryptionFailed"))
write("bomb-over-default-bound", "polyjose",
      "ADR 0017, CVE-2024-28180 class: an authenticated 1,015-byte DEFLATE stream that would inflate to 1,032,001 bytes (length 258 and distance 1 as one-bit codes) is DecryptionFailed under the default 250,000-byte bound",
      "jwe.decrypt", dec(tok["bomb"]), fail("DecryptionFailed"))
for name, what in [("reserved", "BTYPE 11, reserved (RFC 1951 §3.2.3)"),
                   ("truncated", "a fixed-Huffman block cut before its end-of-block code (RFC 1951 §3.2.3)"),
                   ("nlen", "a stored block whose NLEN is not the complement of LEN (RFC 1951 §3.2.4)")]:
    write("malformed-deflate-" + name, "polyjose",
          f"ADR 0017 §1, RFC 7516 §11.4: an authenticated dir + A128GCM zip JWE whose plaintext is {what} is DecryptionFailed, the same unit error as a bad tag",
          "jwe.decrypt", dec(tok[name]), fail("DecryptionFailed"))
