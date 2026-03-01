# Android Port of OpenFHE

This directory contains the Android port of the OpenFHE library, exposing a C bridge for threshold CKKS (multiparty) cryptography via JNI for use in Kotlin/Java Android apps.

## Overview

- **C++ Core:** OpenFHE v1.4.2, cross-compiled as static libraries via Android NDK
- **C Bridge:** `openfhe_android.h`/`.cpp` — all threshold CKKS operations via opaque `void*` handles
- **JNI Bridge:** `jni_bridge.cpp` — maps every C bridge function to JNI native methods
- **Kotlin Wrapper:** `kotlin-wrapper/OpenFHE.kt` — idiomatic Kotlin class wrapping the JNI layer
- **Build Script:** `build_android.sh` — cross-compiles for `arm64-v8a` and `x86_64`
- **App CMake:** `app-cmake/CMakeLists.txt` — template for Android Studio projects

## Architecture

```
┌──────────────────────────────────┐
│   Kotlin App (OpenFHE.kt)        │
│   ↓ JNI calls                    │
├──────────────────────────────────┤
│   jni_bridge.cpp (shared .so)    │
│   ↓ C function calls             │
├──────────────────────────────────┤
│   openfhe_android.cpp (static)   │
│   ↓ OpenFHE C++ API              │
├──────────────────────────────────┤
│   libOPENFHEpke_static.a         │
│   libOPENFHEcore_static.a        │
│   libOPENFHEbinfhe_static.a      │
└──────────────────────────────────┘
```

## Prerequisites

- **Android NDK** r25+ (tested with r29)
- **CMake** 3.22+
- macOS or Linux host

Set the `NDK` environment variable to your NDK path, e.g.:
```bash
export NDK=/path/to/android-ndk-r29
```

## Step 1: Build Static Libraries

```bash
cd openfhe_android
chmod +x build_android.sh
./build_android.sh
```

This produces:
```
install-arm64-v8a/
  lib/
    libOPENFHEcore_static.a
    libOPENFHEpke_static.a
    libOPENFHEbinfhe_static.a
    libopenfhe_android.a
  include/
    openfhe_android.h
    openfhe/...

install-x86_64/
  (same layout)
```

## Step 2: Create Android Studio Project

1. Create a new **Native C++** Android Studio project (or add native support to an existing one).
2. Set minimum SDK to **API 29** (Android 10).

## Step 3: Copy Files Into Your Project

```
YourApp/
  app/src/main/
    cpp/
      CMakeLists.txt        ← from app-cmake/CMakeLists.txt
      jni_bridge.cpp        ← from this directory
      openfhe_android.h     ← from this directory
    java/com/example/openfhe/
      OpenFHE.kt            ← from kotlin-wrapper/OpenFHE.kt
```

Also copy (or symlink) the prebuilt install directories so the app CMake can find them.

## Step 4: Configure Gradle

In `app/build.gradle.kts`:

```kotlin
android {
    defaultConfig {
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
        }
    }
}
```

Edit the `OPENFHE_PREBUILT_DIR` path in `app/src/main/cpp/CMakeLists.txt` to point at your `install-${ANDROID_ABI}` directories.

## Step 5: Build & Run

Build the project in Android Studio. The Gradle build will:
1. Invoke CMake with the NDK toolchain
2. Compile `jni_bridge.cpp` into `libopenfhe_jni.so`
3. Link the prebuilt OpenFHE static libs into it
4. Package the `.so` into the APK

## Usage from Kotlin

```kotlin
import com.example.openfhe.OpenFHE

val fhe = OpenFHE()

// Create context
val ctx = fhe.genCryptoContext(multDepth = 7, scaleModSize = 50,
                               firstModSize = 60, batchSize = 32)

// Lead party key generation
val kp1 = fhe.keygen(ctx)
val pk1 = fhe.keypairGetPublicKey(kp1)
val sk1 = fhe.keypairGetSecretKey(kp1)

// Encode & encrypt
val pt = fhe.makeCKKSPackedPlaintext(ctx, doubleArrayOf(1.0, 2.0, 3.0))
val ct = fhe.encrypt(ctx, pk1, pt)

// Homomorphic add
val ct2 = fhe.evalAddCtDouble(ctx, ct, 10.0)

// Cleanup
fhe.destroyCiphertext(ct2)
fhe.destroyCiphertext(ct)
fhe.destroyPlaintext(pt)
fhe.destroyPrivateKey(sk1)
fhe.destroyPublicKey(pk1)
fhe.destroyKeypair(kp1)
fhe.destroyContext(ctx)
```

## Multiparty (Threshold) Example

```kotlin
val fhe = OpenFHE()
val ctx = fhe.genCryptoContext()

// --- Party 1 (lead) ---
val kp1 = fhe.keygen(ctx)
val pk1 = fhe.keypairGetPublicKey(kp1)
val sk1 = fhe.keypairGetSecretKey(kp1)
val pk1Bytes = fhe.serializePublicKey(pk1)

// --- Party 2 (join) ---
val kp2 = fhe.multipartyKeygen(ctx, pk1Bytes)
val pk2 = fhe.keypairGetPublicKey(kp2)
val sk2 = fhe.keypairGetSecretKey(kp2)
val jointTag = fhe.getPublicKeyTag(pk2)!!

// --- Eval mult key protocol (2 rounds) ---
val ek1 = fhe.keySwitchGen(ctx, sk1)
val ek1Bytes = fhe.serializeEvalKey(ek1)
val ek2 = fhe.multiKeySwitchGen(ctx, sk2, ek1Bytes)
val combined = fhe.multiAddEvalKeys(ctx, ek1, ek2, jointTag)
val combinedBytes = fhe.serializeEvalKey(combined)

val round2_1 = fhe.multiMultEvalKey(ctx, sk1, combinedBytes, jointTag)
val round2_2 = fhe.multiMultEvalKey(ctx, sk2, combinedBytes, jointTag)
val finalEk = fhe.multiAddEvalMultKeys(ctx, round2_1, round2_2, jointTag)
val finalEkBytes = fhe.serializeEvalKey(finalEk)
fhe.insertEvalMultKey(ctx, finalEkBytes)

// --- Encrypt under joint key & compute ---
val pt = fhe.makeCKKSPackedPlaintext(ctx, doubleArrayOf(1.0, 2.0, 3.0))
val ct = fhe.encrypt(ctx, pk2, pt)  // encrypt under joint public key
val ct2 = fhe.evalMultCtDouble(ctx, ct, 5.0)

// --- Decrypt (both parties contribute) ---
val partial1 = fhe.multipartyDecryptLead(ctx, ct2, sk1)
val partial2 = fhe.multipartyDecryptMain(ctx, ct2, sk2)
val result = fhe.multipartyDecryptFusion(ctx, longArrayOf(partial1, partial2))
val values = fhe.plaintextGetRealPackedValue(result, 3)
// values ≈ [5.0, 10.0, 15.0]

// --- Cleanup (all handles) ---
// ... destroy all handles ...
```

## API Reference

See `openfhe_android.h` for the full C bridge API documentation. The Kotlin wrapper in `OpenFHE.kt` provides a 1:1 mapping with idiomatic Kotlin naming.

## Directory Structure

```
openfhe_android/
  openfhe_android.h        # C bridge header
  openfhe_android.cpp      # C bridge implementation
  jni_bridge.cpp           # JNI ↔ C bridge
  build_android.sh         # NDK cross-compile script
  CMakeLists.txt           # For parent cmake (library build)
  app-cmake/
    CMakeLists.txt         # For Android Studio projects
  kotlin-wrapper/
    OpenFHE.kt             # Kotlin wrapper class
  build-arm64-v8a/         # Build artifacts (arm64)
  build-x86_64/            # Build artifacts (x86_64)
  install-arm64-v8a/       # Installed libs + headers (arm64)
  install-x86_64/          # Installed libs + headers (x86_64)
```

## Differences from iOS Port

| Aspect | iOS | Android |
|--------|-----|---------|
| Bridge layer | C → Swift (direct) | C → JNI → Kotlin |
| Output | `.xcframework` (fat static) | Prebuilt `.a` → `.so` via app CMake |
| Host language | Swift via bridging header | Kotlin via JNI |
| Build tool | Xcode / xcodebuild | Android Studio / Gradle + CMake |
| Architectures | arm64 (device), arm64/x86_64 (sim) | arm64-v8a, x86_64 |
