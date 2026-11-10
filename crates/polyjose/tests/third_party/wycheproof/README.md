# Wycheproof (vendored)

- Upstream: https://github.com/C2SP/wycheproof
- Commit: `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9` (2026-10-23, "go.mod: bump go directive to 1.27.3")
- Vendored: 49 files from `testvectors_v1/` plus the repository `LICENSE`, byte for byte, on 2026-11-06
  (25 for JWS in feature 0002, 17 for JWE in feature 0003) and 2026-11-10 (7 for RSA signing and
  RSA-OAEP-256 decryption in feature 0020),
  from `https://raw.githubusercontent.com/C2SP/wycheproof/<commit>/testvectors_v1/<file>`.
- License: Apache-2.0. See `LICENSE` in this directory. The files are unmodified.

These are ADR 0008 layer 1 (Rust) vectors. The bindings don't run them, and
they are not part of `conformance/vectors/`.

`crates/polyjose/src/test_support/wycheproof.rs` (test builds only) loads them.
It checks each file against the table below before parsing it, and its
`vendored_files_match_the_readme` test checks the whole directory: every file
is listed, and every listed file has this size and SHA-256.

A test's `result` is `valid`, `invalid` or `acceptable`; `acceptable` means
a library may accept or reject it (upstream `doc/files.md`). Where polyjose's
outcome differs from `result`, or the result is `acceptable`, the family test
lists the `tcId` in its deviation list with an RFC or ADR reason.

| File | Bytes | SHA-256 |
|---|---|---|
| `LICENSE` | 11357 | `58d1e17ffe5109a7ae296caafcadfdbe6a7d176f0bc4ab01e12a689b0499d8bd` |
| `a128cbc_hs256_test.json` | 66551 | `ed844579d1ade7195bdcf67369fc2b2112029f185bd46b2d53076dddc607f464` |
| `a192cbc_hs384_test.json` | 71063 | `e795bad158298c87541bc1357ee8658b0e96849d40eb8e7654f1f137c1413865` |
| `a256cbc_hs512_test.json` | 75575 | `28fd47c8f3a353dd51e32956c3ab780f231805e7ffc01bf545e234ffd4219391` |
| `aes_gcm_test.json` | 213177 | `985e5ecc172e181eaf49e89508b9470dcf478002eb7e8559c707eb42dc97dfe7` |
| `aes_wrap_test.json` | 67737 | `2fdb3661fd8823d1ec50e03886b24066415018975677dff83d83e77f5a51562d` |
| `ecdh_secp256r1_ecpoint_test.json` | 200088 | `648f16d077caf2400d02331ca51f44744c72c799830c8d0595d0b18b6dd9f886` |
| `ecdh_secp256r1_webcrypto_test.json` | 307612 | `578ddbae7cba6ba89583ed539b15cb601fcbd78c9614480895b577199bc8c985` |
| `ecdh_secp384r1_ecpoint_test.json` | 549253 | `ffa7835fe1de359dff762c8f1272b98acebd5578e2f855d969051ff956c6dca3` |
| `ecdh_secp384r1_webcrypto_test.json` | 801350 | `4eff6afc6923dcf01a21ceb42eeb4bcca9512ad9f7135e775bd7b56eac042cfc` |
| `ecdh_secp521r1_ecpoint_test.json` | 553688 | `87aba8739c96de2bde8c75b60ffea09d0493192c4d9543d1d969e5e998931f35` |
| `ecdh_secp521r1_webcrypto_test.json` | 765237 | `58888e023292d60a52f53ceb26e0eb3eb88c3e2eed66852fb09493ec3a40e943` |
| `ecdsa_secp256k1_sha256_p1363_test.json` | 233029 | `7a339efc7134fb2495cd32afdbd692e0f86427d3c24e9073f6a7d858bb8788d2` |
| `ecdsa_secp256r1_sha256_p1363_test.json` | 242550 | `c60de693930e386c3a5472d08081623ef8504decc54b38ac01ec6b2a2575c986` |
| `ecdsa_secp384r1_sha384_p1363_test.json` | 283550 | `e27344bf6daae75fa19663620883809f91c79fc4b4420eff9eae8036b34476be` |
| `ecdsa_secp521r1_sha512_p1363_test.json` | 360316 | `d294cbe0485dff0a2c53f6b363103ddb81c444e7e5ee44df56549ea92b873840` |
| `ed25519_test.json` | 172628 | `ea80ffebac085e21cb9d3e903e7fa2b448d96702da5b31f061d0b83b430b74b3` |
| `hmac_sha256_test.json` | 69111 | `2d201cfa61d1bf95e6f5d07d96634b4a348b31e8eaa277ad7c8d09677b7a743f` |
| `hmac_sha384_test.json` | 78567 | `28b9776e979dd755d852ca471043ea6cedce8b15f7a28abdf6ea9efd982b43c0` |
| `hmac_sha512_test.json` | 88023 | `b6c90477bdb4a6fc8ee3d1f7b2c0b69a8dfffab34718abaa6cabd71cc2ba1207` |
| `json_web_encryption_test.json` | 120449 | `2fee073795830ee029ddb84d2d7bcbad05fde6e55ee2d00b153a0aa40a72d7d2` |
| `json_web_signature_test.json` | 252527 | `8e687a06fe8359f4ec51480f1a9f73c8faebd6f4c01b818b843b44eee54fd5d9` |
| `pbkdf2_hmacsha256_test.json` | 27868 | `1bf37af2cefe40c829ee9ecebb3505bb6424be8824bc97aa3e1c2076e860d192` |
| `pbkdf2_hmacsha384_test.json` | 26845 | `892613e78d38f1b81df77f1321a59a9fbf6d5c5d1c702126b9f709d7fd242483` |
| `pbkdf2_hmacsha512_test.json` | 26845 | `6a764a448b7a283478340d58f5dc20455524e8589a935fb0d66fb851e997b1c8` |
| `rsa_oaep_2048_sha256_mgf1sha256_test.json` | 41082 | `83dce701e3d8640ac56e6d7bf37a5a8f9bd6a336e1e932a1e9bfe4ba9c5ea3a9` |
| `rsa_oaep_3072_sha256_mgf1sha256_test.json` | 55686 | `c8122302f522bfd539650c71c4aa966bd1f89acb50c6f4c190030fdb9b2684a4` |
| `rsa_oaep_4096_sha256_mgf1sha256_test.json` | 70341 | `e0eb85bcd6d66a85941ee3d98e44f7d1ffb0cf870ba6550e1ed3bec4174c60a9` |
| `rsa_oaep_misc_test.json` | 1819052 | `a989f2f0fb3151fe45ba93c629beb620fc949a0ba0ff1f694e451a6885449c79` |
| `rsa_pkcs1_2048_sig_gen_test.json` | 105318 | `587b3d27d3429f2118cb02818da4d08eb3f36f50c747939eb550fae4337ccbf0` |
| `rsa_pkcs1_3072_sig_gen_test.json` | 95388 | `45153219d486fd135d35aa968a957a0c015c7829e8dc59bea5f87e6c30912677` |
| `rsa_pkcs1_4096_sig_gen_test.json` | 84212 | `f13eadbec6c45291cb33e6b2fa0a0c2b862d0bd2eaec29f930d3b78067cd48c7` |
| `rsa_pss_2048_sha256_mgf1_32_test.json` | 85280 | `7f6efafc160f4816b96cbf1c12188a31051d7e3f001e27505d9edb5f2a0e325c` |
| `rsa_pss_2048_sha384_mgf1_48_test.json` | 110184 | `66d464778b0b2f683a1d1a20e94f77e9472b8cc393b45f423fa08a48e677063c` |
| `rsa_pss_3072_sha256_mgf1_32_test.json` | 113786 | `cca48433e6d1accb57f65b3396c4f4dd93c776467101c3f0948e74c283fd4749` |
| `rsa_pss_4096_sha256_mgf1_32_test.json` | 142295 | `e627cbf5139a01e0a446c4fe15911f6268224fdd3ef4a1eb714b3942b5686410` |
| `rsa_pss_4096_sha384_mgf1_48_test.json` | 184095 | `d632649a7630f7c267eda576714ca11cf0ff068d6622f576b8701f923c112577` |
| `rsa_pss_4096_sha512_mgf1_64_test.json` | 232338 | `c93ceaa56a190c9fd4707441c5c6a75839f108202d88aec891697f9623042547` |
| `rsa_signature_2048_sha256_test.json` | 211075 | `94a917b01ff50fb874cfc05bf29b4af44868d944a6558201cf18380da93fb393` |
| `rsa_signature_2048_sha384_test.json` | 203297 | `c571c105d261c0ff588a2888a529f152563fb3b77894b7620d4e4f8f934f2c1d` |
| `rsa_signature_2048_sha512_test.json` | 207663 | `16ea24b039905d054bdb6004f5fd179374e150b7b6d73a7ba654b6d00eab12ef` |
| `rsa_signature_3072_sha256_test.json` | 275722 | `0f5f18cabfaad3e2792e82f7e9882f8999049b456714de924b8a5e202f61ca43` |
| `rsa_signature_3072_sha384_test.json` | 270950 | `73499ee649d8fb703b3f0f455fa36f7682fde677c590a736958ebce05ab27dae` |
| `rsa_signature_3072_sha512_test.json` | 276682 | `09aa3336fdb7be216180ce944ca7b2a052e1de38c210435c19506327d4a36ebd` |
| `rsa_signature_4096_sha256_test.json` | 336643 | `957aca128e30bd02c8982f8ca482d6521d16683f4bbc3f193cdfd4c8f04bc667` |
| `rsa_signature_4096_sha384_test.json` | 337859 | `bc26f16b9fc9a90628864d3d1111ef48a4bd00b9d4870bfab88ff326e309e073` |
| `rsa_signature_4096_sha512_test.json` | 337859 | `9d6e67b1eb0d7040db411835238efd20e9302399a258bdff82de3f38e0f2855a` |
| `rsa_signature_8192_sha256_test.json` | 603244 | `86df4075b4ce5954726abfa00cc19ebe8b608d6d99094d5e123d6a3a86568bd9` |
| `x25519_jwk_test.json` | 390886 | `3f793624218bceeb0595d23770f602bac8b947641e8aba688f2830e6a2e48eb3` |
| `x25519_test.json` | 253890 | `35c3f5231cf25cc640b524d403461deee9e49441d5d915a3a25b2c8ff5adbe7d` |

To update: download the same file names at a new commit into an empty
directory, check each is valid JSON with the expected `algorithm` and
`schema`, replace the files here, update the commit, date and table above,
and re-run the family tests (their deviation lists name `tcId`s, which can
change between commits).
