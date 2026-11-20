# Android device tests: `AndroidKeystoreKey` on a real device

The automated run (`scripts/run-instrumented.sh`) uses the emulator, whose Keystore is software and
which has no StrongBox: it proves that the code works, not that keys live in hardware (ADR 0072 §6).
This runbook is the hardware evidence. It needs a person and a real device, and it is run by the
owner before Gate 2 of feature 0025, on the feature-tip tree. Nothing here is run by the tester.

## What you need

- A real Android device, API 31 or later (ECDH-ES needs 31; RSA-OAEP-256 needs 34), with USB
  debugging on. A device with StrongBox (`adb shell pm list features | grep strongbox`) is best;
  without one, step 1's StrongBox half and step 2's StrongBox half are `SKIPPED (no StrongBox)`.
- A secure lock screen (PIN, pattern or password) and an enrolled fingerprint or face (class 3,
  "strong") for steps 3 and 4.
- This workspace's toolchain: `source /Users/bharath/bharathwork/joserust/.toolchain-env.sh`.
- No emulator running, so the device is the only `adb` target (or set `ANDROID_SERIAL`).

Record before you start: device model, Android version and API level
(`adb shell getprop ro.product.model`, `ro.build.version.release`, `ro.build.version.sdk`), and the
tree (`git -C polyjose rev-parse HEAD^{tree}`).

## The automated suite on the device

From `bindings/kotlin`, with the device connected:

```sh
./gradlew --no-daemon :polyjose:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.notClass=dev.polyjose.AndroidKeystoreKeyDeviceTest
adb logcat -d -s polyjose-t04:I
```

Expected: every test passes (`android/build/reports/androidTests/connected/debug/index.html`);
`AndroidKeystoreKeyAuthTest` passes because the device has a secure lock screen. The `polyjose-t04`
log lines are the values steps 1, 2 and 5 record.

## Manual steps

1. **Security level and StrongBox.**
   - Log line `securityLevel of a default ES256 key: …`. Expected: `TrustedEnvironment` (never
     `StrongBox`: `Off` never asks for it).
   - On a StrongBox device, `strongBoxIsNeverASilentDowngrade` takes its StrongBox branch. Expected
     log lines: `StrongBox ES256: StrongBox, signs`, `StrongBox RS256: StrongBox, signs`,
     `StrongBox ECDH-ES P-256: StrongBox, decrypts`; and ES384 with `Required` is refused
     (`UnsupportedAlgorithm`, asserted by the test).
   - Without StrongBox: `Required` fails with `PlatformKeyFailed` and leaves no key, `Preferred`
     reports a level other than `StrongBox` (asserted); record the `Preferred` log line.
2. **RSA-OAEP-256.** Log lines `RSA-OAEP-256 on API <n>: PASS` (TEE; the test also checks that a
   tampered encrypted key is `DecryptionFailed`). On a StrongBox device, `StrongBox RSA-OAEP-256:
   PASS (StrongBox)` or `FAIL (<code>)`: record which; it is not asserted, because StrongBox
   RSA-OAEP-256 is unverified (ADR 0072 §5).
3. **A time-bound key before and after a `BiometricPrompt`.** Unlock the device, then run:

   ```sh
   adb shell am instrument -w -e class 'dev.polyjose.AndroidKeystoreKeyDeviceTest#timeBoundKeyBeforeAndAfterAPrompt' \
     -e polyjoseExpect success dev.polyjose.test/androidx.test.runner.AndroidJUnitRunner
   ```

   (The test APK is installed by the suite above; if Gradle uninstalled it, run
   `./gradlew :polyjose:installDebugAndroidTest` first.) A prompt titled "polyjose DEVICE-TESTS
   step 3" appears: authenticate with the biometric. Expected: `OK (1 test)`. The test asserts that
   signing failed with `UserAuthenticationRequired` before the prompt and signed, verified, within
   30 s after it.
4. **A per-use signing key with `BiometricPromptAuthorizer`.**

   ```sh
   adb shell am instrument -w -e class 'dev.polyjose.AndroidKeystoreKeyDeviceTest#perUseKeyWithBiometricPromptAuthorizer' \
     -e polyjoseExpect success dev.polyjose.test/androidx.test.runner.AndroidJUnitRunner
   ```

   A prompt titled "polyjose DEVICE-TESTS step 4" appears during the sign call: authenticate with
   the biometric. Expected: `OK (1 test)` (the token verifies). Run it again with
   `-e polyjoseExpect cancel` and press **Cancel**. Expected: `OK (1 test)`, the sign failed with
   `UserAuthenticationRequired`. Record what each prompt showed.
5. **PS256 signed on the device verifies** in pure Rust (the Nimbus PSS report, research §3 note 4):
   `aKeystorePssSignatureVerifiesInPureRust` and the PS rows of `everySigningRowSignsAndVerifies`
   pass. Expected: both pass in the suite above.

When the run is done, delete nothing by hand: every test deletes its keys.

## The STATE.md row

Add one row per device to `polyjose-brain/STATE.md` (last green test runs), on the feature-tip tree:

| Device (model) | Android, API | Tree | Default key level | TEE: sign / ECDH / RSA-OAEP-256 | StrongBox: ES256 / RS256 / ECDH P-256 / RSA-OAEP-256 | Step 3 | Step 4 (success, cancel) | PS256 |
|---|---|---|---|---|---|---|---|---|
| | | | | | | | | |

Write PASS, FAIL (with the code) or SKIPPED (with the reason) in each cell. Until a row exists, the
docs describe StrongBox and the TEE on real devices as not verified.
