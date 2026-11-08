# Release signing key

`polyjose-release.asc` is the public OpenPGP key that signs polyjose releases:

- the `SHA256SUMS.asc` file attached to each GitHub Release
- the Maven Central artifacts (`dev.polyjose`)

Fingerprint: `D413 52A0 F5B7 FA33 9E03  6C6B 0972 72B7 A3B1 FFE6` (RSA 4096, expires 2029-11-04).

The same key is published on two keyservers:

- [keys.openpgp.org](https://keys.openpgp.org/vks/v1/by-fingerprint/D41352A0F5B7FA339E036C6B097272B7A3B1FFE6)
- [keyserver.ubuntu.com](https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xD41352A0F5B7FA339E036C6B097272B7A3B1FFE6)

Check the fingerprint before you trust the key:

```sh
gpg --show-keys --with-fingerprint .github/keys/polyjose-release.asc
gpg --import .github/keys/polyjose-release.asc
```
