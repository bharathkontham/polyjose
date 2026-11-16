# AppleKey on a real iPhone

The automated runs test `AppleKey` on the macOS host and on the iOS Simulator. A simulator pass of
the Secure Enclave tests is not hardware evidence (ADR 0072 §6.2), and keys that show a system
prompt need a person. This runbook covers both, on a real iPhone, before Gate 2 of a release that
changes platform-key code (RELEASING.md). It records what happened; it doesn't assume the answers.

## What you need

- An iPhone on iOS 16 or later with a passcode set and Face ID or Touch ID enrolled, connected to
  the Mac, unlocked, with Developer Mode on.
- Xcode 27.2, and an Apple development team you can sign with. Find its team ID under
  **Xcode › Settings › Accounts**.
- The checkout at the tree you are testing, with the XCFramework built from it:

```sh
source .toolchain-env.sh   # in the polyjose workspace; otherwise set up Xcode yourself
cd polyjose
platforms/swift/scripts/build-xcframework.sh
git rev-parse HEAD^{tree}   # the tree, for the STATE.md row
```

Set these once in the shell:

```sh
DEVICE=<the iPhone's identifier, from: xcrun devicectl list devices>
TEAM=<your team ID>
PROJECT=platforms/swift/HostedTests/PolyjoseHosted.xcodeproj
T=PolyjoseHostedTests/AppleKeyHostedTests
hosted() {
  POLYJOSE_LOCAL_XCFRAMEWORK=1 xcodebuild test -project "$PROJECT" -scheme PolyjoseHosted \
    -destination "platform=iOS,id=$DEVICE" DEVELOPMENT_TEAM="$TEAM" -allowProvisioningUpdates "$@" 2>&1 |
    tee -a device-tests.log | grep -E "Test Case .*(passed|failed|skipped)|POLYJOSE-|error:"
}
```

The project signs the host app `dev.polyjose.hosted.app` and the test bundle
`dev.polyjose.hosted.tests` with automatic signing. If Xcode reports that an identifier is not
available to your team, change both in `platforms/swift/HostedTests/project.yml` and in the
project (or regenerate it with `xcodegen generate`), and don't commit that change.

The host app sets `NSFaceIDUsageDescription` (the build setting
`INFOPLIST_KEY_NSFaceIDUsageDescription` in `project.yml` and the project), which Apple requires of
an app that uses Face ID. Without it, step 3 crashes the host app with "attempted to access
privacy-sensitive data without a usage description. The app's Info.plist must contain an
NSFaceIDUsageDescription key".

## 1. Keys that persist (no prompt)

The same two runs as `platforms/swift/scripts/test-simulators.sh`, on the device. Run 1 generates a
Secure Enclave ES256 key, a Keychain ES384 key and a Keychain RS256 key and leaves them; run 2, a new
process, finds each by its tag, signs, deletes it, and checks that it is gone. On a device the
public JWKs of run 1 are kept in the app's own container.

```sh
TEST_RUNNER_POLYJOSE_HOSTED_PHASE=1 hosted \
  -skip-testing:$T/testRun2SecureEnclave -skip-testing:$T/testRun2Keychain \
  -skip-testing:$T/testDeviceUserPresence -skip-testing:$T/testDeviceBiometryCurrentSet \
  -skip-testing:$T/testDeviceReusedContext
TEST_RUNNER_POLYJOSE_HOSTED_PHASE=2 hosted -only-testing:$T/testRun2SecureEnclave -only-testing:$T/testRun2Keychain
```

Expected: `testRun1SecureEnclave`, `testRun1Keychain`, `testRun2SecureEnclave` and
`testRun2Keychain` passed, and `POLYJOSE-SECURE-ENCLAVE available`. Record:
- each test's result;
- the three `POLYJOSE-ATTRIBUTES` lines of run 1. The ES384 and RS256 lines are asserted
  (`kSecAttrAccessible=aku`). The Secure Enclave line is only printed: on the iOS 27.2 simulator it
  reads `kSecAttrAccessible=dk kSecAttrAccessControl=<SecAccessControlRef: cku;dacl(true)>`; note
  what the device prints.

## 2. A `.userPresence` key: approve, then cancel

```sh
hosted -only-testing:$T/testDeviceUserPresence
```

The test makes a Secure Enclave key with `.userPresence` and signs with it three times, each time
off the main thread. Watch the phone:
1. A prompt appears: **approve it** (Face ID, Touch ID or passcode).
2. A second prompt appears: **cancel it**.
3. A third prompt appears (a direct `SecKeyCreateSignature` call, for the raw error): **cancel it**.

The test passes whatever you do; the answers are in its `POLYJOSE-DEVICE` lines. Record:
- **Does the prompt appear during the call?** It does if prompt 1 appeared while the test waited.
- **Does the call block its thread?** `userPresence, approve the prompt: returned after N s`: N
  about as long as you took to approve means the call waited for the prompt. `main thread: false`
  confirms where it ran.
- **Which error does cancel give?** `userPresence cancel:` should read
  `UserAuthenticationRequired`. Any other code means the mapping in `AppleKey.swift` misses the
  platform's cancel error: report it with the next line.
- **The raw cancel error:** `userPresence raw cancel: signed=false domain=<domain> code=<code>`.
  Record the domain and code exactly. `AppleKey` maps `NSOSStatusErrorDomain` `errSecUserCanceled`
  (-128) and `LAErrorDomain` cancels to `UserAuthenticationRequired`. If the domain is
  `CryptoTokenKit` (for example code -4, canceled by user), the mapping doesn't cover it yet
  (audit L1 in the feature backlog): report it.
- `userPresence approve:` should read `signed`.

## 3. A `.biometryCurrentSet` key

```sh
hosted -only-testing:$T/testDeviceBiometryCurrentSet
```

On the first Face ID use, iOS asks once whether the app may use Face ID: **allow it**. Then a
prompt appears: **authenticate with Face ID or Touch ID** (not the passcode). Expected:
`POLYJOSE-DEVICE biometryCurrentSet: signed`. Record the line and whether the prompt offered the
passcode (on an iPhone 16 with iOS 27.0.1 it offered Face ID only). If the host app crashes with
"attempted to access privacy-sensitive data without a usage description", the built app lacks
`NSFaceIDUsageDescription`: see "What you need".

## 4. One `LAContext` for two signatures

```sh
hosted -only-testing:$T/testDeviceReusedContext
```

The test stores a Secure Enclave key with `.userPresence`, opens it with one `LAContext`
(`touchIDAuthenticationAllowableReuseDuration` 30 s), and signs twice within a few seconds.
**Approve every prompt** and count them. Record the two `POLYJOSE-DEVICE context` lines (both
should read `signed`) and **how many prompts appeared: 1 or 2**.

## 5. A device that can't authenticate (optional)

Only on a spare device whose settings you can change. Remove every Face ID appearance or Touch ID
fingerprint (**Settings › Face ID & Passcode**), keep the passcode, and run step 3 again:

```sh
hosted -only-testing:$T/testDeviceBiometryCurrentSet
```

Record whether a prompt appeared, and the `POLYJOSE-DEVICE biometryCurrentSet:` line or the error
the test fails with if the key can't be created. `AppleKey` maps `LAError.biometryNotEnrolled`,
`.biometryNotAvailable` and `.passcodeNotSet` to `UserAuthenticationRequired` (ADR 0071 §6, "can't
authenticate"); any other code means the platform reports this state differently: report it.
Turning the passcode off removes the device's Apple Pay cards and the keychain items that need a
passcode (`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`), so do that only on a device set up
for testing; then run the same test and record the same line with no passcode set.

## 6. Record the result

Add one row for the device to `STATE.md` in the private brain repo, polyjose-brain (the
maintainers' record of test runs), on the tree from "What you need", and keep `device-tests.log`:

```text
| <date> | AppleKey device run | <iPhone model> | iOS <version> | tree <tree hash> | secure-enclave: <pass/fail> | keychain ES384, RS256: <pass/fail> | SE item attributes: <kSecAttrAccessible>, <access control> | userPresence: prompt during call <yes/no>, blocked <yes/no, N s>, cancel <code>, raw <domain> <code> | biometryCurrentSet: <signed/code> | LAContext reuse: <1/2> prompts | can't authenticate: no biometry <code/not run>, no passcode <code/not run> |
```
