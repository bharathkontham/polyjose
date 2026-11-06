"""Write conformance/vectors/jwe/pbes2/*.json from the vendored cookbook and RFC 7517 App. C."""
import sys, json, base64, os
cookbook, appc_json, out = sys.argv[1], sys.argv[2], sys.argv[3]
def b64(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
def unb64(s): return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
cb = json.load(open(cookbook)); c = json.load(open(appc_json))
os.makedirs(out, exist_ok=True)
def write(name, v):
    with open(os.path.join(out, name + '.json'), 'w') as f:
        f.write(json.dumps(v, indent=2, ensure_ascii=False) + '\n')
pw53 = cb['input']['pwd'].encode()
key53 = {"kty": "oct", "k": b64(pw53)}
pwc = b'Thus from my lips, by yours, my sin is purged.'
keyc = {"kty": "oct", "k": b64(pwc)}
compact53 = cb['output']['compact']
p2s53 = cb['encrypting_key']['salt']
assert cb['encrypting_content']['protected']['p2s'] == p2s53
assert cb['encrypting_key']['iteration_count'] == 8192 == cb['encrypting_content']['protected']['p2c']
assert compact53.split('.')[0] == cb['encrypting_content']['protected_b64u']
assert json.loads(unb64(cb['encrypting_content']['protected_b64u'])) == cb['encrypting_content']['protected']
pt53 = cb['input']['plaintext'].encode()
S53 = 'RFC 7520 §5.3'
SC = 'RFC 7517 App. C'
A512, A256 = 'PBES2-HS512+A256KW', 'PBES2-HS256+A128KW'
CBC = 'A128CBC-HS256'
FAMILY = ['PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW']

write('rfc7520-5-3-pbes2-hs512-a256kw-a128cbc-hs256-decrypt', {
  "source": S53,
  "description": "The RFC 7520 §5.3 compact JWE (PBES2-HS512+A256KW + A128CBC-HS256, p2c 8192, inside the 10,000 default bound of ADR 0023) decrypts with the Figure 96 password as an oct key to the Figure 95 JWK Set (Figures 95-106; generated from the ietf-jose cookbook)",
  "operation": "jwe.decrypt",
  "input": {"jwe": compact53, "key": key53, "allowed_algs": [A512], "allowed_enc": [CBC]},
  "expect": {"ok": True, "plaintext_b64u": b64(pt53), "recipient": 0}})
rng53 = unb64(cb['generated']['cek']) + unb64(p2s53) + unb64(cb['generated']['iv'])
write('rfc7520-5-3-pbes2-hs512-a256kw-a128cbc-hs256-encrypt', {
  "source": S53,
  "description": "Encrypting with the RFC 7520 §5.3 random values as the drawn bytes (CEK, then the 16-octet p2s, then IV), p2c 8192 and its protected header (cty in the protected header) reproduces the RFC 7520 §5.3 compact JWE exactly (RFC 7518 §4.8)",
  "operation": "jwe.encrypt",
  "input": {"serialization": "compact", "enc": CBC, "plaintext_b64u": b64(pt53),
            "recipients": [{"alg": A512, "key": key53, "p2c": 8192, "p2s_len": 16}],
            "protected": {"cty": "jwk-set+json"},
            "protected_b64u": cb['encrypting_content']['protected_b64u'],
            "rng_b64u": b64(rng53)},
  "expect": {"ok": True, "jwe": compact53},
  "features": ["fixed-rng"]})
write('rfc7517-c-pbes2-hs256-a128kw-a128cbc-hs256-decrypt', {
  "source": SC,
  "description": "The RFC 7517 Appendix C.9 compact JWE (PBES2-HS256+A128KW + A128CBC-HS256, p2c 4096) decrypts with the C.4 passphrase as an oct key to the C.1 RSA private key JWK (values extracted from the RFC text, cross-checked between C.1-C.9)",
  "operation": "jwe.decrypt",
  "input": {"jwe": c['compact'], "key": keyc, "allowed_algs": [A256], "allowed_enc": [CBC]},
  "expect": {"ok": True, "plaintext_b64u": c['plaintext_b64u'], "recipient": 0}})
rngc = unb64(c['cek_b64u']) + unb64(c['p2s_b64u']) + unb64(c['iv_b64u'])
write('rfc7517-c-pbes2-hs256-a128kw-a128cbc-hs256-encrypt', {
  "source": SC,
  "description": "Encrypting with the RFC 7517 Appendix C random values as the drawn bytes (C.3 CEK, then the C.2 16-octet p2s, then the C.6 IV), p2c 4096 and its protected header (cty in the protected header) reproduces the C.9 compact JWE exactly (RFC 7518 §4.8)",
  "operation": "jwe.encrypt",
  "input": {"serialization": "compact", "enc": CBC, "plaintext_b64u": c['plaintext_b64u'],
            "recipients": [{"alg": A256, "key": keyc, "p2c": 4096}],
            "protected": {"cty": "jwk+json"},
            "protected_b64u": c['protected_b64u'],
            "rng_b64u": b64(rngc)},
  "expect": {"ok": True, "jwe": c['compact']},
  "features": ["fixed-rng"]})

# Round trips on the OS CSPRNG with the defaults (p2s 16 octets, p2c 10,000).
pw = b'Hunter2, but longer'
key = {"kty": "oct", "k": b64(pw)}
for alg, enc in [(FAMILY[0], 'A128GCM'), (FAMILY[1], 'A192CBC-HS384'), (FAMILY[2], 'A256GCM')]:
    slug = alg.lower().replace('+', '-')
    write('roundtrip-%s-%s' % (slug, enc.lower()), {
      "source": "polyjose",
      "description": "RFC 7516 §5.1/§5.2 with RFC 7518 §4.8: a compact %s + %s encryption on the OS CSPRNG with the default p2s (16 octets) and p2c (10,000, ADR 0023) decrypts with the same password under the default bound" % (alg, enc),
      "operation": "jwe.encrypt",
      "input": {"serialization": "compact", "enc": enc, "plaintext_b64u": b64(b'Live long and prosper.'),
                "recipients": [{"alg": alg, "key": key}]},
      "expect": {"ok": True, "decrypt_with": {"key": key, "allowed_algs": [alg], "allowed_enc": [enc]}}})
write('roundtrip-pbes2-hs256-a128kw-minimum-parameters', {
  "source": "polyjose",
  "description": "RFC 7518 §4.8.1.1-§4.8.1.2: the smallest parameters polyjose encrypts with, p2c 1000 and an 8-octet p2s, round-trip",
  "operation": "jwe.encrypt",
  "input": {"serialization": "compact", "enc": "A128CBC-HS256", "plaintext_b64u": b64(b'Live long and prosper.'),
            "recipients": [{"alg": FAMILY[0], "key": key, "p2c": 1000, "p2s_len": 8}]},
  "expect": {"ok": True, "decrypt_with": {"key": key, "allowed_algs": [FAMILY[0]], "allowed_enc": ["A128CBC-HS256"]}}})

write('roundtrip-pbes2-hs256-a128kw-p2s-len-256', {
  "source": "ADR 0050 §2",
  "description": "ADR 0050 §2, RFC 7518 §4.8.1.1: the longest Salt Input polyjose encrypts with, 256 octets (with p2c 1000), round-trips",
  "operation": "jwe.encrypt",
  "input": {"serialization": "compact", "enc": "A128GCM", "plaintext_b64u": b64(b'Live long and prosper.'),
            "recipients": [{"alg": FAMILY[0], "key": key, "p2c": 1000, "p2s_len": 256}]},
  "expect": {"ok": True, "decrypt_with": {"key": key, "allowed_algs": [FAMILY[0]], "allowed_enc": ["A128GCM"]}}})

# Encrypt negatives.
for name, rec, why in [
    ('encrypt-p2c-999', {"p2c": 999}, 'RFC 7518 §4.8.1.2 ("A minimum iteration count of 1000 is RECOMMENDED"): polyjose refuses to encrypt with p2c 999'),
    ('encrypt-p2s-len-7', {"p2s_len": 7}, 'RFC 7518 §4.8.1.1 ("A Salt Input value containing 8 or more octets MUST be used"): polyjose refuses to encrypt with a 7-octet p2s'),
    # F07, ADR 0050 §2: the upper limits, checked before any draw or derivation.
    ('encrypt-p2c-ceiling-plus-one', {"p2c": 1000001}, 'ADR 0050 §2: polyjose refuses to encrypt with p2c 1000001, above the 1,000,000 decrypt ceiling of ADR 0023 that no DecryptPolicy can exceed, before any draw or derivation'),
    ('encrypt-p2s-len-257', {"p2s_len": 257}, 'ADR 0050 §2: p2s_len is capped at 256 octets; polyjose refuses to encrypt with a 257-octet p2s, before any draw or derivation'),
]:
    r = {"alg": FAMILY[0], "key": key}; r.update(rec)
    source = 'ADR 0050 §2' if why.startswith('ADR 0050') else 'RFC 7518 §4.8.1'
    write(name, {"source": source, "description": why + ' (InvalidKey)', "operation": "jwe.encrypt",
      "input": {"serialization": "compact", "enc": "A128GCM", "plaintext_b64u": b64(b'x'), "recipients": [r]},
      "expect": {"ok": False, "error": "InvalidKey"}})

# Decrypt negatives: the §5.3 JWE with its protected header changed.
def forged(p2s, p2c, alg=A512):
    members = ['"alg":"%s"' % alg]
    if p2s is not None: members.append('"p2s":%s' % p2s)
    if p2c is not None: members.append('"p2c":%s' % p2c)
    members.append('"cty":"jwk-set+json","enc":"A128CBC-HS256"')
    h = '{' + ','.join(members) + '}'
    parts = compact53.split('.')
    parts[0] = b64(h.encode())
    return '.'.join(parts)
assert forged('"%s"' % p2s53, '8192') == compact53, 'forging must be identity on the RFC header'
P = '"%s"' % p2s53
seven = '"%s"' % b64(unb64(p2s53)[:7])
def neg(name, jwe, source, desc, error='DecryptionFailed', extra=None, key=key53, algs=FAMILY):
    inp = {"jwe": jwe, "key": key, "allowed_algs": list(algs), "allowed_enc": [CBC]}
    if extra: inp.update(extra)
    write(name, {"source": source, "description": desc, "operation": "jwe.decrypt", "input": inp,
                 "expect": {"ok": False, "error": error}})
neg('p2c-bound-plus-one', forged(P, '10001'), 'ADR 0023',
    'ADR 0023, RFC 7518 §8.8: the RFC 7520 §5.3 JWE with p2c 10001, one above the default max_pbes2_count, is DecryptionFailed before any PBKDF2 work (CVE-2022-36083)')
neg('p2c-2pow32-minus-1', forged(P, '4294967295'), 'RFC 7518 §8.8',
    'RFC 7518 §8.8, CVE-2022-36083/CVE-2023-52428/CVE-2023-51775: p2c 4294967295 is DecryptionFailed at once, even with the bound raised as far as the API allows (clamped to the 1,000,000 ceiling of ADR 0023)',
    extra={"max_pbes2_count": 4294967295})
neg('p2c-ceiling-plus-one', forged(P, '1000001'), 'ADR 0023',
    'ADR 0023: max_pbes2_count is clamped to the 1,000,000 ceiling, so p2c 1000001 is DecryptionFailed even with the bound set to 2000000',
    extra={"max_pbes2_count": 2000000})
neg('bound-below-count', compact53, 'ADR 0023',
    'ADR 0023: the unmodified RFC 7520 §5.3 JWE (p2c 8192) is DecryptionFailed when max_pbes2_count is lowered to 8191; the bound is inclusive',
    extra={"max_pbes2_count": 8191})
neg('p2c-missing', forged(P, None), 'RFC 7518 §4.8.1.2',
    'RFC 7518 §4.8.1.2: p2c "MUST be present" for PBES2; without it the RFC 7520 §5.3 JWE is DecryptionFailed')
neg('p2s-missing', forged(None, '8192'), 'RFC 7518 §4.8.1.1',
    'RFC 7518 §4.8.1.1: p2s "MUST be present" for PBES2; without it the RFC 7520 §5.3 JWE is DecryptionFailed')
neg('p2s-7-octets', forged(seven, '8192'), 'RFC 7518 §4.8.1.1',
    'RFC 7518 §4.8.1.1 ("A Salt Input value containing 8 or more octets MUST be used"): a canonical 7-octet p2s is DecryptionFailed')
neg('p2s-not-base64url', forged('"8Q1Szinas+3xchYz6ZZcHA"', '8192'), 'RFC 7518 §4.8.1.1',
    'RFC 7518 §4.8.1.1, RFC 7515 §2: a p2s that is not base64url (a "+") is DecryptionFailed')
neg('p2c-zero', forged(P, '0'), 'RFC 7518 §4.8.1.2',
    'RFC 7518 §4.8.1.2: p2c is "a positive JSON integer"; p2c 0 is a registered header parameter of the wrong type, refused while parsing the header (plan.md error contract, steps 3-4), so InvalidHeader',
    error='InvalidHeader')
neg('wrong-password', compact53, 'RFC 7516 §11.5',
    'RFC 7516 §11.5, RFC 3394 §2.2.3: the RFC 7520 §5.3 JWE with the password\'s en dashes replaced by hyphens fails the key unwrap integrity check: DecryptionFailed, the same error as a bad tag',
    key={"kty": "oct", "k": b64(b'entrap_o-peter_long-credit_tun')})
neg('alg-swapped-within-family', forged(P, '8192', alg='PBES2-HS256+A128KW'), 'RFC 7518 §4.8.1.1',
    'RFC 7518 §4.8.1.1: alg is part of the PBKDF2 salt and fixes the PRF and KW key size; the RFC 7520 §5.3 JWE relabelled PBES2-HS256+A128KW is DecryptionFailed')
