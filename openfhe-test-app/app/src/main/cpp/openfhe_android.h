/*
 * openfhe_android.h — C bridge for OpenFHE threshold-CKKS on Android
 *
 * Opaque-handle design: C sees only void* handles.
 * All memory is managed via explicit _destroy() calls.
 *
 * This covers exactly the API surface used by client.py:
 *   - CryptoContext setup & serialization
 *   - Threshold key generation (lead + join)
 *   - CKKS plaintext encoding
 *   - Encrypt / Decrypt (multiparty partial + fusion)
 *   - EvalAdd, EvalSub, EvalMult (ct-ct and ct-pt and ct-scalar)
 *   - Ciphertext / PublicKey / EvalKey serialization to/from buffer
 */

#ifndef OPENFHE_ANDROID_H
#define OPENFHE_ANDROID_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * Opaque handle types
 * ================================================================ */
typedef void* OFHEContext;
typedef void* OFHEKeyPair;
typedef void* OFHEPublicKey;
typedef void* OFHEPrivateKey;
typedef void* OFHECiphertext;
typedef void* OFHEPlaintext;
typedef void* OFHEEvalKey;

/* ================================================================
 * Error handling
 * ================================================================ */

/** Returns the last error message (thread-local). NULL if no error. */
const char* ofhe_last_error(void);

/** Clears the last error. */
void ofhe_clear_error(void);

/* ================================================================
 * CryptoContext — creation & serialization
 * ================================================================ */

/**
 * Generate a new CKKS crypto context with MULTIPARTY enabled.
 * @param mult_depth  Multiplicative depth (e.g., 7)
 * @param scale_mod_size  Scaling mod size in bits (e.g., 50)
 * @param first_mod_size  First mod size in bits (e.g., 60)
 * @param batch_size  Batch size / number of slots (e.g., 32)
 * @return OFHEContext handle, or NULL on failure.
 */
OFHEContext ofhe_gen_crypto_context(uint32_t mult_depth,
                                    uint32_t scale_mod_size,
                                    uint32_t first_mod_size,
                                    uint32_t batch_size);

/**
 * Serialize a CryptoContext to a binary buffer.
 * Caller must free *out_buf with free().
 * @return true on success.
 */
bool ofhe_serialize_context(OFHEContext ctx,
                            uint8_t** out_buf,
                            size_t* out_len);

/**
 * Deserialize a CryptoContext from a binary buffer.
 * @return OFHEContext handle, or NULL on failure.
 */
OFHEContext ofhe_deserialize_context(const uint8_t* buf, size_t len);

/** Destroy a CryptoContext handle. */
void ofhe_destroy_context(OFHEContext ctx);

/* ================================================================
 * Key Generation — Threshold (Multiparty)
 * ================================================================ */

/**
 * Lead party: generate initial key pair.
 * @return OFHEKeyPair handle, or NULL on failure.
 */
OFHEKeyPair ofhe_keygen(OFHEContext ctx);

/**
 * Non-lead party: generate key pair from the previous party's public key.
 * @param prev_pk  Serialized previous public key buffer.
 * @return OFHEKeyPair handle, or NULL on failure.
 */
OFHEKeyPair ofhe_multiparty_keygen(OFHEContext ctx,
                                    const uint8_t* prev_pk_buf,
                                    size_t prev_pk_len);

/** Extract public key from a KeyPair. Caller must destroy it. */
OFHEPublicKey ofhe_keypair_get_public_key(OFHEKeyPair kp);

/** Extract secret key from a KeyPair. Caller must destroy it. */
OFHEPrivateKey ofhe_keypair_get_secret_key(OFHEKeyPair kp);

/**
 * Get the key tag string from a public key.
 * The returned pointer is valid until the public key is destroyed.
 * @return Key tag C string, or NULL on failure.
 */
const char* ofhe_get_public_key_tag(OFHEPublicKey pk);

void ofhe_destroy_keypair(OFHEKeyPair kp);
void ofhe_destroy_public_key(OFHEPublicKey pk);
void ofhe_destroy_private_key(OFHEPrivateKey sk);

/* ================================================================
 * Eval Mult Key Generation — Threshold (2 rounds)
 * ================================================================ */

/**
 * Lead: KeySwitchGen(sk, sk) → round-1 eval share.
 * @return OFHEEvalKey handle, or NULL on failure.
 */
OFHEEvalKey ofhe_key_switch_gen(OFHEContext ctx, OFHEPrivateKey sk);

/**
 * Non-lead: MultiKeySwitchGen(sk, sk, prev_eval_key).
 * @param prev_eval_buf  Serialized previous eval key.
 * @return OFHEEvalKey handle.
 */
OFHEEvalKey ofhe_multi_key_switch_gen(OFHEContext ctx,
                                       OFHEPrivateKey sk,
                                       const uint8_t* prev_eval_buf,
                                       size_t prev_eval_len);

/**
 * Round 2: MultiMultEvalKey(sk, combined_eval_key, joint_pk_tag).
 * @param combined_eval_buf  Serialized combined eval key from round 1.
 * @param joint_pk_tag       Key tag string for the joint public key.
 * @return OFHEEvalKey handle.
 */
OFHEEvalKey ofhe_multi_mult_eval_key(OFHEContext ctx,
                                      OFHEPrivateKey sk,
                                      const uint8_t* combined_eval_buf,
                                      size_t combined_eval_len,
                                      const char* joint_pk_tag);

/**
 * Install an eval mult key into the context (cc.InsertEvalMultKey).
 * @param eval_key_buf  Serialized eval key.
 * @return true on success.
 */
bool ofhe_insert_eval_mult_key(OFHEContext ctx,
                               const uint8_t* eval_key_buf,
                               size_t eval_key_len);

/** Combine two eval keys: MultiAddEvalKeys(ek1, ek2, keyTag).
 *  @param key_tag  Joint public key tag (from ofhe_get_public_key_tag).
 */
OFHEEvalKey ofhe_multi_add_eval_keys(OFHEContext ctx,
                                      OFHEEvalKey ek1,
                                      OFHEEvalKey ek2,
                                      const char* key_tag);

/** Combine two eval mult keys: MultiAddEvalMultKeys(ek1, ek2, keyTag).
 *  @param key_tag  Key tag for the combined eval key.
 */
OFHEEvalKey ofhe_multi_add_eval_mult_keys(OFHEContext ctx,
                                           OFHEEvalKey ek1,
                                           OFHEEvalKey ek2,
                                           const char* key_tag);

void ofhe_destroy_eval_key(OFHEEvalKey ek);

/* ================================================================
 * Encoding — CKKS packed plaintext
 * ================================================================ */

/**
 * Encode a vector of doubles into a CKKS packed plaintext.
 * @param values  Array of doubles.
 * @param count   Number of elements.
 * @return OFHEPlaintext handle.
 */
OFHEPlaintext ofhe_make_ckks_packed_plaintext(OFHEContext ctx,
                                               const double* values,
                                               size_t count);

/**
 * Extract real values from a decrypted plaintext.
 * @param pt         Plaintext handle.
 * @param out_values Caller-allocated array (at least max_count doubles).
 * @param max_count  Max number of values to extract.
 * @return Actual number of values written.
 */
size_t ofhe_plaintext_get_real_packed_value(OFHEPlaintext pt,
                                            double* out_values,
                                            size_t max_count);

/** Set the length of a plaintext (for fusion). */
void ofhe_plaintext_set_length(OFHEPlaintext pt, size_t length);

void ofhe_destroy_plaintext(OFHEPlaintext pt);

/* ================================================================
 * Encrypt / Decrypt
 * ================================================================ */

/**
 * Encrypt a plaintext under a public key.
 * @return OFHECiphertext handle, or NULL on failure.
 */
OFHECiphertext ofhe_encrypt(OFHEContext ctx,
                             OFHEPublicKey pk,
                             OFHEPlaintext pt);

/**
 * Multiparty partial decrypt — LEAD party.
 * @param ct  ciphertext to partially decrypt.
 * @param sk  lead party's secret key share.
 * @return OFHECiphertext handle (partial decryption result).
 */
OFHECiphertext ofhe_multiparty_decrypt_lead(OFHEContext ctx,
                                             OFHECiphertext ct,
                                             OFHEPrivateKey sk);

/**
 * Multiparty partial decrypt — NON-LEAD party.
 */
OFHECiphertext ofhe_multiparty_decrypt_main(OFHEContext ctx,
                                             OFHECiphertext ct,
                                             OFHEPrivateKey sk);

/**
 * Fuse all partial decryptions into a plaintext.
 * @param partials      Array of OFHECiphertext handles.
 * @param partials_count  Number of partial decryptions.
 * @return OFHEPlaintext handle with the result.
 */
OFHEPlaintext ofhe_multiparty_decrypt_fusion(OFHEContext ctx,
                                              OFHECiphertext* partials,
                                              size_t partials_count);

/* ================================================================
 * Homomorphic Operations
 * ================================================================ */

/** ct + ct */
OFHECiphertext ofhe_eval_add_ct_ct(OFHEContext ctx,
                                    OFHECiphertext ct1,
                                    OFHECiphertext ct2);

/** ct + plaintext */
OFHECiphertext ofhe_eval_add_ct_pt(OFHEContext ctx,
                                    OFHECiphertext ct,
                                    OFHEPlaintext pt);

/** ct + scalar (double) */
OFHECiphertext ofhe_eval_add_ct_double(OFHEContext ctx,
                                        OFHECiphertext ct,
                                        double scalar);

/** ct - ct */
OFHECiphertext ofhe_eval_sub_ct_ct(OFHEContext ctx,
                                    OFHECiphertext ct1,
                                    OFHECiphertext ct2);

/** ct - plaintext */
OFHECiphertext ofhe_eval_sub_ct_pt(OFHEContext ctx,
                                    OFHECiphertext ct,
                                    OFHEPlaintext pt);

/** ct * ct (requires eval mult key) */
OFHECiphertext ofhe_eval_mult_ct_ct(OFHEContext ctx,
                                     OFHECiphertext ct1,
                                     OFHECiphertext ct2);

/** ct * plaintext */
OFHECiphertext ofhe_eval_mult_ct_pt(OFHEContext ctx,
                                     OFHECiphertext ct,
                                     OFHEPlaintext pt);

/** ct * scalar (double) */
OFHECiphertext ofhe_eval_mult_ct_double(OFHEContext ctx,
                                         OFHECiphertext ct,
                                         double scalar);

void ofhe_destroy_ciphertext(OFHECiphertext ct);

/* ================================================================
 * Serialization — Ciphertext, PublicKey, EvalKey
 *
 * All serialize to caller-owned buffers (free with free()).
 * All deserialize from const buffers.
 * ================================================================ */

bool ofhe_serialize_ciphertext(OFHECiphertext ct, uint8_t** out_buf, size_t* out_len);
OFHECiphertext ofhe_deserialize_ciphertext(OFHEContext ctx, const uint8_t* buf, size_t len);

bool ofhe_serialize_public_key(OFHEPublicKey pk, uint8_t** out_buf, size_t* out_len);
OFHEPublicKey ofhe_deserialize_public_key(OFHEContext ctx, const uint8_t* buf, size_t len);

bool ofhe_serialize_eval_key(OFHEEvalKey ek, uint8_t** out_buf, size_t* out_len);
OFHEEvalKey ofhe_deserialize_eval_key(OFHEContext ctx, const uint8_t* buf, size_t len);

bool ofhe_serialize_private_key(OFHEPrivateKey sk, uint8_t** out_buf, size_t* out_len);
OFHEPrivateKey ofhe_deserialize_private_key(OFHEContext ctx, const uint8_t* buf, size_t len);

/* ================================================================
 * Utility
 * ================================================================ */

/** Free a buffer returned by any ofhe_serialize_* function. */
void ofhe_free_buffer(uint8_t* buf);

#ifdef __cplusplus
}
#endif

#endif /* OPENFHE_ANDROID_H */
