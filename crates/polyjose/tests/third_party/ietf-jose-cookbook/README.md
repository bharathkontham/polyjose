# ietf-jose/cookbook (vendored, JWE part)

- Upstream: https://github.com/ietf-jose/cookbook
- Commit: `13692b68bfc18b99557a5b1ed311fd5077bfff04` (2016-11-12, "include aesthetics for automated testing"),
  the head of `master`.
- Vendored: the 13 files of `jwe/` (RFC 7520 §5.1–§5.13) plus the repository `LICENSE`, byte for byte,
  on 2026-11-06, from `https://raw.githubusercontent.com/ietf-jose/cookbook/<commit>/<path>`.
- License: the Unlicense (public-domain dedication). See `LICENSE` in this directory. The files are
  unmodified.

Each file is one RFC 7520 §5 example as JSON: `title`, `input` (plaintext, keys, `alg`, `enc`),
`generated` (the random values the RFC prints: CEK, IV, ephemeral keys, `p2s`), `encrypting_key`,
`encrypting_content` and `output` (compact, general and flattened JSON), plus `reproducible` where
the output can be regenerated from the printed values.

These files are **source material, not conformance vectors**: they are kept out of
`conformance/vectors/`, whose runner would load them as vectors in its own schema and fail.
The JWE conformance vectors are generated from them (with `source` set to "RFC 7520 §5.x") rather
than transcribed by hand from the RFC text, to avoid transcription errors. Known RFC 7520 issues
that the vectors must account for:

- erratum [4802](https://www.rfc-editor.org/errata/eid4802) (§5.7.5, the flattened example's
  protected header and tag);
- erratum [7680](https://www.rfc-editor.org/errata/eid7680) (§5.9, DEFLATE output is not unique);
- §5.5.5 cites the figure numbers of §5.4, and the Fig. 211 caption says "Recipient #2" but belongs
  to recipient #3 (typos, not filed as errata).

| File | Bytes | SHA-256 |
|---|---|---|
| `LICENSE` | 1211 | `60d2c28d19d2bdf7bbaa59829e7a595234265e8111a01ccb74d25d6c4d2d013a` |
| `jwe/5_1.key_encryption_using_rsa_v15_and_aes-hmac-sha2.json` | 6429 | `40a7c98fa1ad4c78ae4224a2c1188302fce1ee903c4f593c9833aaca53d1456a` |
| `jwe/5_2.key_encryption_using_rsa-oaep_with_aes-gcm.json` | 9200 | `195356b864b4f55aa5b413735b7e1e64e603bd2a200164839f16ae2640f4f193` |
| `jwe/5_3.key_wrap_using_pbes2-aes-keywrap_with-aes-cbc-hmac-sha2.json` | 4565 | `7dea11ab9c85a726c0623b29b965c73281a94889a075746e11d37f38c41ad8d0` |
| `jwe/5_4.key_agreement_with_key_wrapping_using_ecdh-es_and_aes-keywrap_with_aes-gcm.json` | 5156 | `7d41160d7168c4696255db7dfba2f6652ada15d4466519a30422e8773c0f212f` |
| `jwe/5_5.key_agreement_using_ecdh-es_with_aes-cbc-hmac-sha2.json` | 4620 | `18702a20ddc4510a1cee0ed3a8e97c8f85e9357e696f4acbf16c8f4334904785` |
| `jwe/5_6.direct_encryption_using_aes-gcm.json` | 3100 | `6a2a527e4b2c0f84d53cf0f3782aa4b33a43e2faa371b8e691a1f3a9e6a63e34` |
| `jwe/5_7.key_wrap_using_aes-gcm_keywrap_with_aes-cbc-hmac-sha2.json` | 4153 | `c205d200ab3385b822315f87166680d65dfb34e918d591cb606654b85c2669ec` |
| `jwe/5_8.key_wrap_using_aes-keywrap_with_aes-gcm.json` | 3450 | `e0da5b710dc697984cb7aa93c8bad6fe97db74b6507af087a4ceae8bf70d13e4` |
| `jwe/5_9.compressed_content.json` | 3233 | `83b5972de5e59534288348d83b4d8597424d5529f58ab93c9b3f2f29ae28b856` |
| `jwe/5_10.including_additional_authentication_data.json` | 3912 | `4a294adec448e697c16640eef781f66f1dfc1e0eb495aaf88566fcfc14094ff9` |
| `jwe/5_11.protecting_specific_header_fields.json` | 2893 | `2fd1f245c429ee9e891d44eeef7a8c4f921d5762faf7e87446966ed0682d7d2e` |
| `jwe/5_12.protecting_content_only.json` | 2769 | `1ec7c0db6e374767b85f7606f3bff90362aef1b64c4f4f9f4ae6b816fa181cd8` |
| `jwe/5_13.encrypting_to_multiple_recipients.json` | 7189 | `5a73f2fb0af8fce23c0d50e2feb8bd03cbf403edc00216b8069546a937c2c6f0` |

To update: download the same paths at a new commit into an empty directory, check each is valid
JSON with the members above, replace the files here, update the commit, date and table above, and
regenerate the conformance vectors that cite them.
