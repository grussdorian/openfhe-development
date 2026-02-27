# Basic ios port of openFHE

This directory contains the iOS port of the OpenFHE library, exposing a C bridge for threshold CKKS (multiparty) cryptography, along with robust test suites and build scripts for integration into Swift/iOS projects.

## Overview

- **C++ Core:** OpenFHE v1.4.2, built as static libraries (`libOPENFHEcore_static.a`, `libOPENFHEpke_static.a`)
- **C Bridge:** `openfhe_ios.h`/`.cpp` — exposes all threshold CKKS operations via opaque `void*` handles for Swift interop
- **Build Script:** `build_ios.sh` — cross-compiles for iOS device/simulator, produces `.xcframework`
- **Test Suites:**
  - `OpenFHETests.swift`: API surface and correctness
  - `RobustFHETests.swift`: edge cases, chained ops, precision, memory
  - `MultipartyGPSTests.swift`: multiparty protocol, GPS proximity, floating-point stress
- **SwiftUI Demo:** Example `ContentView.swift` with test suite picker and live results

Note: initial startup time is long, disable debugging for faster initial startup. Tested on iphone SE 3 ios 26.3 and Xcode 26.2

## Exposed C Bridge Functions (openfhe_ios.h)

All functions use opaque `void*` handles for FHE objects. Memory must be managed via explicit destroy functions.

### CryptoContext
- `ofhe_gen_crypto_context(mult_depth, scale_mod_size, first_mod_size, batch_size)` — Create threshold CKKS context
- `ofhe_serialize_context(ctx, &out_buf, &out_len)` / `ofhe_deserialize_context(buf, len)` — Serialize/restore context
- `ofhe_destroy_context(ctx)` — Free context

### Key Generation (Threshold Multiparty)
- `ofhe_keygen(ctx)` — Lead party keygen
- `ofhe_multiparty_keygen(ctx, prev_pk_buf, prev_pk_len)` — Join party keygen
- `ofhe_keypair_get_public_key(kp)` / `ofhe_keypair_get_secret_key(kp)` — Extract PK/SK
- `ofhe_get_public_key_tag(pk)` — Get key tag string
- `ofhe_destroy_keypair(kp)` / `ofhe_destroy_public_key(pk)` / `ofhe_destroy_private_key(sk)` — Free keys

### Eval Mult Key Protocol (Threshold)
- `ofhe_key_switch_gen(ctx, sk)` — Lead: KeySwitchGen
- `ofhe_multi_key_switch_gen(ctx, sk, prev_eval_buf, prev_eval_len)` — Join: MultiKeySwitchGen
- `ofhe_multi_add_eval_keys(ctx, ek1, ek2, key_tag)` — Combine eval keys (round 1)
- `ofhe_multi_mult_eval_key(ctx, sk, combined_eval_buf, combined_eval_len, key_tag)` — Round 2 share
- `ofhe_multi_add_eval_mult_keys(ctx, ek1, ek2, key_tag)` — Combine eval mult keys (round 2)
- `ofhe_insert_eval_mult_key(ctx, eval_key_buf, eval_key_len)` — Install eval mult key
- `ofhe_serialize_eval_key(ek, &out_buf, &out_len)` / `ofhe_deserialize_eval_key(ctx, buf, len)` — Serialize/restore eval key
- `ofhe_destroy_eval_key(ek)` — Free eval key

### Encoding
- `ofhe_make_ckks_packed_plaintext(ctx, values, count)` — Encode vector as CKKS plaintext
- `ofhe_plaintext_get_real_packed_value(pt, out_values, max_count)` — Extract decoded values
- `ofhe_plaintext_set_length(pt, length)` — Set plaintext length
- `ofhe_destroy_plaintext(pt)` — Free plaintext

### Encryption / Decryption
- `ofhe_encrypt(ctx, pk, pt)` — Encrypt plaintext
- `ofhe_multiparty_decrypt_lead(ctx, ct, sk)` — Lead partial decrypt
- `ofhe_multiparty_decrypt_main(ctx, ct, sk)` — Join partial decrypt
- `ofhe_multiparty_decrypt_fusion(ctx, partials, partials_count)` — Fuse partial decryptions
- `ofhe_destroy_ciphertext(ct)` — Free ciphertext

### Homomorphic Operations
- `ofhe_eval_add_ct_ct(ctx, ct1, ct2)` — Add ciphertexts
- `ofhe_eval_add_ct_pt(ctx, ct, pt)` — Add ciphertext + plaintext
- `ofhe_eval_add_ct_double(ctx, ct, scalar)` — Add ciphertext + scalar
- `ofhe_eval_sub_ct_ct(ctx, ct1, ct2)` — Subtract ciphertexts
- `ofhe_eval_sub_ct_pt(ctx, ct, pt)` — Subtract plaintext from ciphertext
- `ofhe_eval_mult_ct_ct(ctx, ct1, ct2)` — Multiply ciphertexts (needs eval mult key)
- `ofhe_eval_mult_ct_pt(ctx, ct, pt)` — Multiply ciphertext + plaintext
- `ofhe_eval_mult_ct_double(ctx, ct, scalar)` — Multiply ciphertext + scalar

### Serialization
- `ofhe_serialize_ciphertext(ct, &out_buf, &out_len)` / `ofhe_deserialize_ciphertext(ctx, buf, len)` — Ciphertext
- `ofhe_serialize_public_key(pk, &out_buf, &out_len)` / `ofhe_deserialize_public_key(ctx, buf, len)` — Public key
- `ofhe_serialize_private_key(sk, &out_buf, &out_len)` / `ofhe_deserialize_private_key(ctx, buf, len)` — Private key
- `ofhe_free_buffer(buf)` — Free any buffer returned by serialize functions

### Error Handling
- `ofhe_last_error()` — Get last error message (thread-local)
- `ofhe_clear_error()` — Clear last error


## Directory Structure

- `openfhe_ios.h` / `openfhe_ios.cpp` — C bridge header/impl
- `build_ios.sh` — iOS static lib/xcframework build script
- `OpenFHETests.swift` — API and correctness tests
- `RobustFHETests.swift` — advanced/edge-case tests
- `MultipartyGPSTests.swift` — multiparty protocol + GPS precision tests
- `ContentView.swift` — SwiftUI test runner UI
- `INTEGRATION_CHECKLIST.md` — step-by-step integration guide

## Building the iOS Static Libraries & XCFramework

1. **Install Prerequisites for ios:**
   - Xcode command line tools

   ```bash
   chmod +x build_ios.sh
   ./build_ios.sh xcframework
   ```

Then copy `OpenFHE.xcframework` into your ios project. 