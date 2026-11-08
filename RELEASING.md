# Releasing polyjose

The procedure for the owner and the release agent, from a version bump to packages on crates.io, npm, Maven Central and SPM. The workflows are the source of truth: [`release.yml`](.github/workflows/release.yml) builds, signs and attests a **draft** GitHub Release, and [`publish.yml`](.github/workflows/publish.yml) publishes exactly the draft's bytes. Both are `workflow_dispatch` only.

**Who does what (ADR 0038 §1).** Agents prepare, tag, verify, and dispatch `release.yml` (both modes) and `publish.yml` with `dry_run: true`, and only after the owner's go-ahead. Only the owner dispatches `publish.yml` with `dry_run: false`, approves an environment `publish` deployment (this approval is **Gate 3**), and presses Publish in the Maven Central Portal. An agent never approves a deployment and never publishes.

## 1. One-time setup: done

The owner did and verified all of it on 2026-11-08: the npm org `polyjose`, the Central namespace `dev.polyjose` and its user token, the bootstrap tokens, the trusted publishers, the environments, the secrets and variables, the `v*` tag ruleset, immutable releases, and the release key on the keyservers. The full steps are in the private brain repo, **polyjose-brain `releases/v0.1.0/owner-publishing-setup.md`**.

What the workflows read (names only):

| Name | Kind | Scope | Read by |
|---|---|---|---|
| `publish` | environment | owner is the required reviewer; tags `v*` and `dryrun-*` | `publish.yml`: `crates`, `npm`, `maven`, `github` jobs |
| `release-signing` | environment | tags `v*` only | `release.yml`: `sums` job, tag mode |
| `GPG_SIGNING_KEY`, `GPG_SIGNING_KEY_PASSWORD` | secret | env `release-signing` | `release.yml` `sums` |
| `GPG_FINGERPRINT` | variable | repository | `release.yml` `sums`; `publish.yml` `assets`, `github` |
| `MAVEN_CENTRAL_USERNAME`, `MAVEN_CENTRAL_PASSWORD` | secret | env `publish` | `publish.yml` `maven` |
| `CARGO_REGISTRY_BOOTSTRAP_TOKEN` | secret | env `publish` | `publish.yml` `crates`, only with `bootstrap: true` |
| `NPM_BOOTSTRAP_TOKEN` | secret | env `publish` | `publish.yml` `npm`, only with `bootstrap: true` |

The guide also sets a variable `GPG_SIGNING_KEY_ID`, which no workflow reads. Because the environments admit tags only, **tag-mode `release.yml` and every `publish.yml` run are dispatched from the tag ref** (`--ref vX.Y.Z`, the same value as the `tag` input). Both workflows refuse any other ref.

### Owner to-dos after the first publish (0.1.0)

- [ ] Revoke both bootstrap tokens on crates.io and npm, then `gh secret delete CARGO_REGISTRY_BOOTSTRAP_TOKEN --env publish` and `gh secret delete NPM_BOOTSTRAP_TOKEN --env publish`.
- [ ] Check that the crate `polyjose` and all 10 npm packages (`@polyjose/node`, `@polyjose/wasm`, the 8 `@polyjose/node-*`) show the trusted publisher `bharathkontham/polyjose`, `publish.yml`, environment `publish`. Then turn on npm's "Require two-factor authentication and disallow tokens" for each package.
- [ ] From 0.1.1 on, dispatch `publish.yml` with `bootstrap: false`, which is the default. crates.io and npm then authenticate by OIDC, with provenance.

## 2. Release public key

[`.github/keys/polyjose-release.asc`](.github/keys/polyjose-release.asc) has fingerprint `D41352A0F5B7FA339E036C6B097272B7A3B1FFE6` (RSA 4096, expires 2029-11-04) and is also on keys.openpgp.org and keyserver.ubuntu.com ([keys README](.github/keys/README.md)). It signs `SHA256SUMS.asc` and the Maven artifacts. To verify a release:

```sh
gpg --show-keys --with-fingerprint .github/keys/polyjose-release.asc   # must show D413 52A0 ... A3B1 FFE6
gpg --import .github/keys/polyjose-release.asc   # or: gpg --keyserver hkps://keys.openpgp.org --recv-keys D41352A0F5B7FA339E036C6B097272B7A3B1FFE6
gh release download vX.Y.Z --repo bharathkontham/polyjose --dir rel && cd rel
gpg --verify SHA256SUMS.asc SHA256SUMS            # "Good signature", primary key D41352A0...
sha256sum -c SHA256SUMS                           # macOS: shasum -a 256 -c SHA256SUMS
gh attestation verify <asset> --repo bharathkontham/polyjose
```

**Rotation:** the key's expiry or any suspicion of compromise means a new key and a new ADR. Commit the new public key here, update `GPG_FINGERPRINT` and the `release-signing` secrets, and publish the key to both keyservers. On compromise, also publish the old key's revocation and an advisory ([SECURITY.md](SECURITY.md)).

## 3. Pre-release checklist

Before the tag (items 1–6) and before Gate 3 (item 7):

1. [ ] The candidate run (step 2 below) is green, at the release PR head, and less than about 90 days old.
2. [ ] `scripts/fuzz.sh --seconds 600` reports no crash. `jws` and `jwe` get far fewer execs per second, so also give those two a longer budget, for example `scripts/fuzz.sh --seconds 3600 jws jwe`.
3. [ ] MSRV: `cargo +1.89.0 check -p polyjose`.
4. [ ] The rsa 0.10 advisory re-check (ADR 0055): is there a stable `rsa` 0.10.x that RUSTSEC-2023-0071 marks as patched, with no other advisory? If so, note it for an adoption feature. It is never part of the current release.
5. [ ] An orchestrator short check of `publish.yml` (secrets, pins, gating, inputs, permissions). **0.1.0: done** on 2026-11-08 against 4e2808d. It found two fixes, `--no-verify` on the cargo steps and `--ignore-scripts` on `npm publish`; both landed and were rechecked. For later releases, re-check whenever `publish.yml` or `scripts/release/` changed since the last release.
6. [ ] Version and changelog: `scripts/release/check-version.sh X.Y.Z --notes "$(mktemp)"` passes.
7. [ ] The draft is verified (step 5 below).

## 4. Release steps

1. **Version and CHANGELOG PR** (release agent, branch `chore/release-X.Y.Z`). Bump every manifest that [`check-version.sh`](scripts/release/check-version.sh) checks. Set the `Package.swift` url to `.../releases/download/vX.Y.Z/PolyjoseFFI.xcframework.zip`, and add a `## [X.Y.Z]` section to `CHANGELOG.md`, which becomes the release notes.
2. **Candidate** (owner's go-ahead): `gh workflow run release.yml --repo bharathkontham/polyjose --ref chore/release-X.Y.Z -f mode=candidate`. It builds everything unsigned and creates no release. When it is green:
   - `gh run download <run-id> --name apple-xcframework`
   - write the zip's SHA-256 into `Package.swift`'s `checksum:`
   - write `platforms/swift/release-candidate.json` with exactly `{"run_id": <run-id>, "commit": "<the run's 40-hex head sha>", "sha256": "<zip sha256>"}`
   - commit only those two files, then run the checklist (items 1–6).
3. **Merge** the release PR (owner review, then git-ops). Nothing else may land on `main` between the candidate commit and the tag (section 5).
4. **Tag** (release agent): `git tag -a vX.Y.Z -m "polyjose X.Y.Z"` on the merged commit, then `git push origin vX.Y.Z`. Then, with the owner's go-ahead, run the tag-mode dispatch **from the tag ref**: `gh workflow run release.yml --repo bharathkontham/polyjose --ref vX.Y.Z -f mode=tag -f tag=vX.Y.Z`. It reuses the candidate's Apple zip ([`apple-candidate.sh`](scripts/release/apple-candidate.sh)), rebuilds everything else from the tag, signs in `release-signing`, attests, and creates the draft.
5. **Verify the draft**, in a fresh directory (listing a draft needs push access):
   ```sh
   d=$(mktemp -d)
   gh release download vX.Y.Z --repo bharathkontham/polyjose --dir "$d"
   scripts/release/verify-draft.sh "$d" vX.Y.Z .github/keys/polyjose-release.asc D41352A0F5B7FA339E036C6B097272B7A3B1FFE6
   for f in "$d"/*; do gh attestation verify "$f" --repo bharathkontham/polyjose; done
   ```
   [`verify-draft.sh`](scripts/release/verify-draft.sh) checks `SHA256SUMS.asc` against the committed key and every asset against `SHA256SUMS`.
6. **Dry run** (owner's go-ahead) on the real draft, from the tag ref: `gh workflow run publish.yml --repo bharathkontham/polyjose --ref vX.Y.Z -f tag=vX.Y.Z -f dry_run=true -f bootstrap=true`. Use `bootstrap=true` for 0.1.0 only. Even a dry run waits in `publish`, so the owner approves each job. Every job must be green. If the dry run exposes a workflow bug, the fix ships under the next patch tag (section 5).
7. **Gate 3** (owner only): the same dispatch with `-f dry_run=false`, approving each `publish` job in turn: `crates` → `npm` (8 platform packages, `@polyjose/node`, `@polyjose/wasm`) → `maven` (upload, polled until `VALIDATED`; its log prints the deployment id) → `github` (un-drafts the release, which makes SPM live). The `spm` job then resolves and builds the package at the tag.
8. **Maven Central Portal** (owner): Deployments → the printed deployment id → check it → **Publish**.
9. **Docs**: the release agent opens a `polyjose-docs` PR (version, changelog, install snippets) for git-ops, and writes the session summary in the brain.

Optional: `publish.yml` also accepts a disposable `dryrun-vX.Y.Z[-N]` draft, with `dry_run: true` only, and unsigned assets are allowed there. It is not used for 0.1.0.

## 5. Rules the workflows enforce

- **A `v*` tag is never moved, deleted or re-pushed,** and `release.yml` refuses to re-release a tag. If a tag run, the dry run or a publish job fails because of a bug, the fix ships as the next patch version.
- `platforms/swift/release-candidate.json` has exactly the keys `run_id`, `commit` and `sha256`. Between the candidate commit and the tag, only `Package.swift`'s `url:`/`checksum:` lines and that file may change. Otherwise, re-run the candidate and re-record both files.
- Candidate artifacts expire after about 90 days (GitHub's default retention; the workflows set none). If the candidate is older, re-run it before tagging.
- `publish.yml` re-runs are idempotent on crates.io and npm: a version already published with the same bytes is skipped, and one with other bytes fails. A Maven re-upload creates a second deployment, which the owner drops in the Portal.
