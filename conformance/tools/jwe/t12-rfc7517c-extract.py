"""Extract RFC 7517 Appendix C values from the RFC text, cross-checking sections."""
import sys, re, json, base64, hashlib
txt = open(sys.argv[1]).read()
lines = [l for l in txt.split('\n')
         if not re.match(r'^Jones\s+Standards Track\s+\[Page \d+\]$', l)
         and not re.match(r'^RFC 7517\s+JSON Web Key \(JWK\)\s+May 2015$', l)
         and '\f' not in l]
t = '\n'.join(lines)
app = t[t.index('Appendix C.  Example Encrypted RSA Private Key\n\n   This example'):t.index('\nAcknowledgements')]
def arr(after, before):
    seg = app[app.index(after):app.index(before)]
    seg = seg[seg.index('['):seg.index(']')+1]
    return bytes(int(x) for x in re.findall(r'\d+', seg))
def b64(s): return base64.urlsafe_b64encode(s).rstrip(b'=').decode()
def unb64(s): return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
def block(after, before):
    seg = app[app.index(after)+len(after):app.index(before)]
    return ''.join(seg.split())
pt = arr('The octets representing the plaintext used in this example', 'C.2.  JOSE Header')
p2s = arr('the Salt Input ("p2s") value is', 'the Iteration Count')
cek = arr('In this\n   example, the value (using JSON array notation) is:', 'C.4.  Key Derivation')
pwd = arr('The octets representing the passphrase are:', 'The Salt value')
salt = arr('The Salt value (UTF8(Alg) || 0x00 || Salt Input) is:', 'The resulting PBKDF2 Derived Key')
dk = arr('The resulting PBKDF2 Derived Key value is:', 'C.5.  Key Encryption')
ek = arr('The resulting JWE Encrypted Key value is:', 'Encoding this JWE Encrypted Key')
iv = arr('Generate a random 128-bit JWE Initialization Vector.', 'C.7.  Additional')
prot = block('Header)) gives this value (with line breaks for display purposes\n   only):', 'C.3.  Content Encryption Key')
ek_b64 = block('Encoding this JWE Encrypted Key as BASE64URL(JWE Encrypted Key) gives\n   this value:', 'C.6.  Initialization Vector')
iv_b64 = block('Initialization Vector) gives this value:', 'C.7.  Additional Authenticated Data')
tag_b64 = block('Tag) gives this value:', 'C.9.  Complete Representation')
compact = block('The final result in this example (with line breaks for display\n   purposes only) is:', '\x00') if False else None
seg = app[app.index('The final result in this example'):]
seg = seg[seg.index('is:')+3:]
compact = ''.join(seg.split())
# Cross-checks between sections.
parts = compact.split('.')
assert len(parts) == 5
assert parts[0] == prot, 'C.9 header != C.2'
assert parts[1] == ek_b64 == b64(ek), 'C.9 key != C.5'
assert parts[2] == iv_b64 == b64(iv), 'C.9 iv != C.6'
assert parts[4] == tag_b64, 'C.9 tag != C.8'
hdr = json.loads(unb64(prot))
assert hdr == {"alg":"PBES2-HS256+A128KW","p2s":b64(p2s),"p2c":4096,"enc":"A128CBC-HS256","cty":"jwk+json"}, hdr
assert pwd == b'Thus from my lips, by yours, my sin is purged.'
assert salt == b'PBES2-HS256+A128KW\x00' + p2s
assert hashlib.pbkdf2_hmac('sha256', pwd, salt, 4096, 16) == dk, 'C.4 dk'
assert len(cek) == 32 and len(iv) == 16 and len(p2s) == 16
jwk = json.loads(pt)
assert jwk['kty'] == 'RSA' and jwk['kid'] == 'juliet@capulet.lit'
print(json.dumps({"plaintext_b64u": b64(pt), "password_b64u": b64(pwd), "cek_b64u": b64(cek),
                  "p2s_b64u": b64(p2s), "iv_b64u": b64(iv), "protected_b64u": prot,
                  "compact": compact, "plaintext_len": len(pt)}, indent=1))
