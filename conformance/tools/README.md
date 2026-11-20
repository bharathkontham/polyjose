# conformance/tools

How the vectors in `../vectors/` were produced: generators built on independent implementations (Node's `crypto`, which is OpenSSL, and Python's standard library), never on polyjose. They are run by hand when vectors are added or regenerated; no test suite runs them, except `rsa-oaep-oracle.mjs`, which `scripts/test-all.sh node` runs as a check.

- `jws-oracle/`, `jwt-oracle/`, `jwk-oracle/`: one generator each, with a README.
- `rsa-oaep-oracle.mjs`: checks every exact RSA-OAEP-256 vector against its test-only private key.
- `jwe/`: the JWE generators and `reproduce.sh`, which re-runs them and compares their output with the committed vectors byte for byte.

**About the `jwe/tNN-*` and `fNN-*` names:** they record the work item that produced each file (for example `t13-ecdh-es.js`), not what it does. They are kept on purpose. A vector names one of them: `vectors/jwe/negative-crypto/ecdh-es-a256kw-p521-decrypts.json` cites `t13-p521-key.json`, so a rename would change that vector's bytes and with them the vector-set digest every platform checks. The index in `vectors/jwe/README.md` and [conformance/README.md, "Tools"](../README.md#tools) also name each generator, and the latter lists what each one writes.
