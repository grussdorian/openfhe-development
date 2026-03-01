/*
 * openfhe_android.cpp — C bridge implementation for OpenFHE threshold-CKKS on android
 *
 * Translates opaque C handles ↔ OpenFHE C++ shared_ptr types.
 * Uses binary serialization (cereal PortableBinary) for all wire formats.
 */

#include "openfhe_android.h"

// OpenFHE headers
#include "openfhe.h"
#include "cryptocontext-ser.h"
#include "ciphertext-ser.h"
#include "key/keypair.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/gen-cryptocontext-ckksrns.h"

#include <cstring>
#include <sstream>
#include <string>
#include <vector>

using namespace lbcrypto;

// ================================================================
// Thread-local error handling
// ================================================================
static thread_local std::string g_last_error;

static void set_error(const std::string& msg) {
    g_last_error = msg;
}

extern "C" const char* ofhe_last_error(void) {
    return g_last_error.empty() ? nullptr : g_last_error.c_str();
}

extern "C" void ofhe_clear_error(void) {
    g_last_error.clear();
}

// ================================================================
// Internal casting helpers
// ================================================================

// Each handle is a raw pointer to a heap-allocated shared_ptr (or value).
// This avoids exposing C++ types across the ABI boundary.

struct HandleCC {
    CryptoContext<DCRTPoly> cc;
};

struct HandleKP {
    KeyPair<DCRTPoly> kp;
    HandleKP(const KeyPair<DCRTPoly>& kp_) : kp(kp_) {}
};

struct HandlePK {
    PublicKey<DCRTPoly> pk;
};

struct HandleSK {
    PrivateKey<DCRTPoly> sk;
};

struct HandleCT {
    Ciphertext<DCRTPoly> ct;
};

struct HandlePT {
    Plaintext pt;
};

struct HandleEK {
    EvalKey<DCRTPoly> ek;
};

#define WRAP_CC(x) reinterpret_cast<OFHEContext>(new HandleCC{x})
#define UNWRAP_CC(h) (reinterpret_cast<HandleCC*>(h)->cc)
#define WRAP_KP(x) reinterpret_cast<OFHEKeyPair>(new HandleKP(x))
#define UNWRAP_KP(h) (reinterpret_cast<HandleKP*>(h)->kp)
#define WRAP_PK(x) reinterpret_cast<OFHEPublicKey>(new HandlePK{x})
#define UNWRAP_PK(h) (reinterpret_cast<HandlePK*>(h)->pk)
#define WRAP_SK(x) reinterpret_cast<OFHEPrivateKey>(new HandleSK{x})
#define UNWRAP_SK(h) (reinterpret_cast<HandleSK*>(h)->sk)
#define WRAP_CT(x) reinterpret_cast<OFHECiphertext>(new HandleCT{x})
#define UNWRAP_CT(h) (reinterpret_cast<HandleCT*>(h)->ct)
#define WRAP_PT(x) reinterpret_cast<OFHEPlaintext>(new HandlePT{x})
#define UNWRAP_PT(h) (reinterpret_cast<HandlePT*>(h)->pt)
#define WRAP_EK(x) reinterpret_cast<OFHEEvalKey>(new HandleEK{x})
#define UNWRAP_EK(h) (reinterpret_cast<HandleEK*>(h)->ek)

// ================================================================
// Serialization to/from memory buffer helpers
// ================================================================

template <typename T>
static bool serialize_to_buf(const T& obj, uint8_t** out_buf, size_t* out_len) {
    try {
        std::ostringstream oss(std::ios::binary);
        Serial::Serialize(obj, oss, SerType::BINARY);
        std::string data = oss.str();
        *out_len = data.size();
        *out_buf = (uint8_t*)malloc(*out_len);
        if (!*out_buf) {
            set_error("malloc failed");
            return false;
        }
        memcpy(*out_buf, data.data(), *out_len);
        return true;
    } catch (const std::exception& e) {
        set_error(std::string("Serialize error: ") + e.what());
        return false;
    }
}

template <typename T>
static bool deserialize_from_buf(const uint8_t* buf, size_t len, T& obj) {
    try {
        std::string data(reinterpret_cast<const char*>(buf), len);
        std::istringstream iss(data, std::ios::binary);
        Serial::Deserialize(obj, iss, SerType::BINARY);
        return true;
    } catch (const std::exception& e) {
        set_error(std::string("Deserialize error: ") + e.what());
        return false;
    }
}

// ================================================================
// CryptoContext
// ================================================================

extern "C" OFHEContext ofhe_gen_crypto_context(uint32_t mult_depth,
                                                uint32_t scale_mod_size,
                                                uint32_t first_mod_size,
                                                uint32_t batch_size) {
    try {
        CCParams<CryptoContextCKKSRNS> params;
        params.SetMultiplicativeDepth(mult_depth);
        params.SetScalingModSize(scale_mod_size);
        params.SetFirstModSize(first_mod_size);
        params.SetBatchSize(batch_size);
        params.SetSecurityLevel(HEStd_128_classic);

        auto cc = GenCryptoContext(params);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
        cc->Enable(MULTIPARTY);

        return WRAP_CC(cc);
    } catch (const std::exception& e) {
        set_error(std::string("GenCryptoContext: ") + e.what());
        return nullptr;
    }
}

extern "C" bool ofhe_serialize_context(OFHEContext ctx,
                                        uint8_t** out_buf,
                                        size_t* out_len) {
    if (!ctx) { set_error("null context"); return false; }
    return serialize_to_buf(UNWRAP_CC(ctx), out_buf, out_len);
}

extern "C" OFHEContext ofhe_deserialize_context(const uint8_t* buf, size_t len) {
    CryptoContext<DCRTPoly> cc;
    if (!deserialize_from_buf(buf, len, cc)) return nullptr;
    return WRAP_CC(cc);
}

extern "C" void ofhe_destroy_context(OFHEContext ctx) {
    delete reinterpret_cast<HandleCC*>(ctx);
}

// ================================================================
// Key Generation
// ================================================================

extern "C" OFHEKeyPair ofhe_keygen(OFHEContext ctx) {
    try {
        auto& cc = UNWRAP_CC(ctx);
        auto kp = cc->KeyGen();
        if (!kp.good()) { set_error("KeyGen failed"); return nullptr; }
        return WRAP_KP(kp);
    } catch (const std::exception& e) {
        set_error(std::string("KeyGen: ") + e.what());
        return nullptr;
    }
}

extern "C" OFHEKeyPair ofhe_multiparty_keygen(OFHEContext ctx,
                                               const uint8_t* prev_pk_buf,
                                               size_t prev_pk_len) {
    try {
        auto& cc = UNWRAP_CC(ctx);
        PublicKey<DCRTPoly> prev_pk;
        if (!deserialize_from_buf(prev_pk_buf, prev_pk_len, prev_pk))
            return nullptr;
        auto kp = cc->MultipartyKeyGen(prev_pk);
        if (!kp.good()) { set_error("MultipartyKeyGen failed"); return nullptr; }
        return WRAP_KP(kp);
    } catch (const std::exception& e) {
        set_error(std::string("MultipartyKeyGen: ") + e.what());
        return nullptr;
    }
}

extern "C" OFHEPublicKey ofhe_keypair_get_public_key(OFHEKeyPair kp) {
    if (!kp) { set_error("null keypair"); return nullptr; }
    return WRAP_PK(UNWRAP_KP(kp).publicKey);
}

extern "C" OFHEPrivateKey ofhe_keypair_get_secret_key(OFHEKeyPair kp) {
    if (!kp) { set_error("null keypair"); return nullptr; }
    return WRAP_SK(UNWRAP_KP(kp).secretKey);
}

extern "C" void ofhe_destroy_keypair(OFHEKeyPair kp) { delete reinterpret_cast<HandleKP*>(kp); }
extern "C" void ofhe_destroy_public_key(OFHEPublicKey pk) { delete reinterpret_cast<HandlePK*>(pk); }
extern "C" void ofhe_destroy_private_key(OFHEPrivateKey sk) { delete reinterpret_cast<HandleSK*>(sk); }

// Store the tag string so the pointer remains valid until the PK is destroyed
static thread_local std::string g_pk_tag_buf;

extern "C" const char* ofhe_get_public_key_tag(OFHEPublicKey pk) {
    if (!pk) { set_error("null public key"); return nullptr; }
    try {
        g_pk_tag_buf = UNWRAP_PK(pk)->GetKeyTag();
        return g_pk_tag_buf.c_str();
    } catch (const std::exception& e) {
        set_error(std::string("GetKeyTag: ") + e.what());
        return nullptr;
    }
}

// ================================================================
// Eval Mult Key — Threshold Rounds
// ================================================================

extern "C" OFHEEvalKey ofhe_key_switch_gen(OFHEContext ctx, OFHEPrivateKey sk) {
    try {
        auto& cc = UNWRAP_CC(ctx);
        auto& secret = UNWRAP_SK(sk);
        auto ek = cc->KeySwitchGen(secret, secret);
        return WRAP_EK(ek);
    } catch (const std::exception& e) {
        set_error(std::string("KeySwitchGen: ") + e.what());
        return nullptr;
    }
}

extern "C" OFHEEvalKey ofhe_multi_key_switch_gen(OFHEContext ctx,
                                                  OFHEPrivateKey sk,
                                                  const uint8_t* prev_eval_buf,
                                                  size_t prev_eval_len) {
    try {
        auto& cc = UNWRAP_CC(ctx);
        auto& secret = UNWRAP_SK(sk);
        EvalKey<DCRTPoly> prev_ek;
        if (!deserialize_from_buf(prev_eval_buf, prev_eval_len, prev_ek))
            return nullptr;
        auto ek = cc->MultiKeySwitchGen(secret, secret, prev_ek);
        return WRAP_EK(ek);
    } catch (const std::exception& e) {
        set_error(std::string("MultiKeySwitchGen: ") + e.what());
        return nullptr;
    }
}

extern "C" OFHEEvalKey ofhe_multi_mult_eval_key(OFHEContext ctx,
                                                 OFHEPrivateKey sk,
                                                 const uint8_t* combined_eval_buf,
                                                 size_t combined_eval_len,
                                                 const char* joint_pk_tag) {
    try {
        auto& cc = UNWRAP_CC(ctx);
        auto& secret = UNWRAP_SK(sk);
        EvalKey<DCRTPoly> combined;
        if (!deserialize_from_buf(combined_eval_buf, combined_eval_len, combined))
            return nullptr;
        std::string tag = joint_pk_tag ? joint_pk_tag : "";
        auto ek = cc->MultiMultEvalKey(secret, combined, tag);
        return WRAP_EK(ek);
    } catch (const std::exception& e) {
        set_error(std::string("MultiMultEvalKey: ") + e.what());
        return nullptr;
    }
}

extern "C" bool ofhe_insert_eval_mult_key(OFHEContext ctx,
                                           const uint8_t* eval_key_buf,
                                           size_t eval_key_len) {
    try {
        auto& cc = UNWRAP_CC(ctx);
        EvalKey<DCRTPoly> ek;
        if (!deserialize_from_buf(eval_key_buf, eval_key_len, ek))
            return false;
        cc->InsertEvalMultKey({ek});
        return true;
    } catch (const std::exception& e) {
        set_error(std::string("InsertEvalMultKey: ") + e.what());
        return false;
    }
}

extern "C" OFHEEvalKey ofhe_multi_add_eval_keys(OFHEContext ctx,
                                                 OFHEEvalKey ek1,
                                                 OFHEEvalKey ek2,
                                                 const char* key_tag) {
    try {
        auto& cc = UNWRAP_CC(ctx);
        std::string tag = key_tag ? key_tag : "";
        auto result = cc->MultiAddEvalKeys(UNWRAP_EK(ek1), UNWRAP_EK(ek2), tag);
        return WRAP_EK(result);
    } catch (const std::exception& e) {
        set_error(std::string("MultiAddEvalKeys: ") + e.what());
        return nullptr;
    }
}

extern "C" OFHEEvalKey ofhe_multi_add_eval_mult_keys(OFHEContext ctx,
                                                      OFHEEvalKey ek1,
                                                      OFHEEvalKey ek2,
                                                      const char* key_tag) {
    try {
        auto& cc = UNWRAP_CC(ctx);
        std::string tag = key_tag ? key_tag : "";
        auto result = cc->MultiAddEvalMultKeys(UNWRAP_EK(ek1), UNWRAP_EK(ek2), tag);
        return WRAP_EK(result);
    } catch (const std::exception& e) {
        set_error(std::string("MultiAddEvalMultKeys: ") + e.what());
        return nullptr;
    }
}

extern "C" void ofhe_destroy_eval_key(OFHEEvalKey ek) {
    delete reinterpret_cast<HandleEK*>(ek);
}

// ================================================================
// Encoding — CKKS
// ================================================================

extern "C" OFHEPlaintext ofhe_make_ckks_packed_plaintext(OFHEContext ctx,
                                                          const double* values,
                                                          size_t count) {
    try {
        auto& cc = UNWRAP_CC(ctx);
        std::vector<double> vec(values, values + count);
        auto pt = cc->MakeCKKSPackedPlaintext(vec);
        return WRAP_PT(pt);
    } catch (const std::exception& e) {
        set_error(std::string("MakeCKKSPackedPlaintext: ") + e.what());
        return nullptr;
    }
}

extern "C" size_t ofhe_plaintext_get_real_packed_value(OFHEPlaintext pt,
                                                       double* out_values,
                                                       size_t max_count) {
    if (!pt) { set_error("null plaintext"); return 0; }
    try {
        auto& plain = UNWRAP_PT(pt);
        auto vals = plain->GetRealPackedValue();
        size_t n = std::min(vals.size(), max_count);
        for (size_t i = 0; i < n; ++i)
            out_values[i] = vals[i];
        return n;
    } catch (const std::exception& e) {
        set_error(std::string("GetRealPackedValue: ") + e.what());
        return 0;
    }
}

extern "C" void ofhe_plaintext_set_length(OFHEPlaintext pt, size_t length) {
    if (!pt) return;
    UNWRAP_PT(pt)->SetLength(length);
}

extern "C" void ofhe_destroy_plaintext(OFHEPlaintext pt) {
    delete reinterpret_cast<HandlePT*>(pt);
}

// ================================================================
// Encrypt / Decrypt
// ================================================================

extern "C" OFHECiphertext ofhe_encrypt(OFHEContext ctx,
                                        OFHEPublicKey pk,
                                        OFHEPlaintext pt) {
    if (!ctx) { set_error("Encrypt: ctx is null"); return nullptr; }
    if (!pk)  { set_error("Encrypt: public key is null"); return nullptr; }
    if (!pt)  { set_error("Encrypt: plaintext is null"); return nullptr; }
    try {
        auto& cc = UNWRAP_CC(ctx);
        auto ct = cc->Encrypt(UNWRAP_PK(pk), UNWRAP_PT(pt));
        if (!ct) { set_error("Encrypt returned null"); return nullptr; }
        return WRAP_CT(ct);
    } catch (const std::exception& e) {
        set_error(std::string("Encrypt: ") + e.what());
        return nullptr;
    }
}

extern "C" OFHECiphertext ofhe_multiparty_decrypt_lead(OFHEContext ctx,
                                                        OFHECiphertext ct,
                                                        OFHEPrivateKey sk) {
    try {
        auto& cc = UNWRAP_CC(ctx);
        auto partials = cc->MultipartyDecryptLead({UNWRAP_CT(ct)}, UNWRAP_SK(sk));
        if (partials.empty()) { set_error("MultipartyDecryptLead empty"); return nullptr; }
        return WRAP_CT(partials[0]);
    } catch (const std::exception& e) {
        set_error(std::string("MultipartyDecryptLead: ") + e.what());
        return nullptr;
    }
}

extern "C" OFHECiphertext ofhe_multiparty_decrypt_main(OFHEContext ctx,
                                                        OFHECiphertext ct,
                                                        OFHEPrivateKey sk) {
    try {
        auto& cc = UNWRAP_CC(ctx);
        auto partials = cc->MultipartyDecryptMain({UNWRAP_CT(ct)}, UNWRAP_SK(sk));
        if (partials.empty()) { set_error("MultipartyDecryptMain empty"); return nullptr; }
        return WRAP_CT(partials[0]);
    } catch (const std::exception& e) {
        set_error(std::string("MultipartyDecryptMain: ") + e.what());
        return nullptr;
    }
}

extern "C" OFHEPlaintext ofhe_multiparty_decrypt_fusion(OFHEContext ctx,
                                                         OFHECiphertext* partials,
                                                         size_t partials_count) {
    try {
        auto& cc = UNWRAP_CC(ctx);
        std::vector<Ciphertext<DCRTPoly>> partial_vec;
        partial_vec.reserve(partials_count);
        for (size_t i = 0; i < partials_count; ++i) {
            partial_vec.push_back(UNWRAP_CT(partials[i]));
        }
        Plaintext result;
        cc->MultipartyDecryptFusion(partial_vec, &result);
        return WRAP_PT(result);
    } catch (const std::exception& e) {
        set_error(std::string("MultipartyDecryptFusion: ") + e.what());
        return nullptr;
    }
}

// ================================================================
// Homomorphic Operations
// ================================================================

extern "C" OFHECiphertext ofhe_eval_add_ct_ct(OFHEContext ctx,
                                               OFHECiphertext ct1,
                                               OFHECiphertext ct2) {
    try {
        auto& cc = UNWRAP_CC(ctx);
        auto result = cc->EvalAdd(UNWRAP_CT(ct1), UNWRAP_CT(ct2));
        return WRAP_CT(result);
    } catch (const std::exception& e) {
        set_error(std::string("EvalAdd ct+ct: ") + e.what());
        return nullptr;
    }
}

extern "C" OFHECiphertext ofhe_eval_add_ct_pt(OFHEContext ctx,
                                               OFHECiphertext ct,
                                               OFHEPlaintext pt) {
    try {
        auto& cc = UNWRAP_CC(ctx);
        auto& plain = UNWRAP_PT(pt);
        auto result = cc->EvalAdd(UNWRAP_CT(ct), plain);
        return WRAP_CT(result);
    } catch (const std::exception& e) {
        set_error(std::string("EvalAdd ct+pt: ") + e.what());
        return nullptr;
    }
}

extern "C" OFHECiphertext ofhe_eval_add_ct_double(OFHEContext ctx,
                                                    OFHECiphertext ct,
                                                    double scalar) {
    try {
        auto& cc = UNWRAP_CC(ctx);
        auto result = cc->EvalAdd(UNWRAP_CT(ct), scalar);
        return WRAP_CT(result);
    } catch (const std::exception& e) {
        set_error(std::string("EvalAdd ct+double: ") + e.what());
        return nullptr;
    }
}

extern "C" OFHECiphertext ofhe_eval_sub_ct_ct(OFHEContext ctx,
                                               OFHECiphertext ct1,
                                               OFHECiphertext ct2) {
    try {
        auto& cc = UNWRAP_CC(ctx);
        auto result = cc->EvalSub(UNWRAP_CT(ct1), UNWRAP_CT(ct2));
        return WRAP_CT(result);
    } catch (const std::exception& e) {
        set_error(std::string("EvalSub ct-ct: ") + e.what());
        return nullptr;
    }
}

extern "C" OFHECiphertext ofhe_eval_sub_ct_pt(OFHEContext ctx,
                                               OFHECiphertext ct,
                                               OFHEPlaintext pt) {
    try {
        auto& cc = UNWRAP_CC(ctx);
        auto& plain = UNWRAP_PT(pt);
        auto result = cc->EvalSub(UNWRAP_CT(ct), plain);
        return WRAP_CT(result);
    } catch (const std::exception& e) {
        set_error(std::string("EvalSub ct-pt: ") + e.what());
        return nullptr;
    }
}

extern "C" OFHECiphertext ofhe_eval_mult_ct_ct(OFHEContext ctx,
                                                OFHECiphertext ct1,
                                                OFHECiphertext ct2) {
    try {
        auto& cc = UNWRAP_CC(ctx);
        auto result = cc->EvalMult(UNWRAP_CT(ct1), UNWRAP_CT(ct2));
        return WRAP_CT(result);
    } catch (const std::exception& e) {
        set_error(std::string("EvalMult ct*ct: ") + e.what());
        return nullptr;
    }
}

extern "C" OFHECiphertext ofhe_eval_mult_ct_pt(OFHEContext ctx,
                                                OFHECiphertext ct,
                                                OFHEPlaintext pt) {
    try {
        auto& cc = UNWRAP_CC(ctx);
        auto result = cc->EvalMult(UNWRAP_CT(ct), UNWRAP_PT(pt));
        return WRAP_CT(result);
    } catch (const std::exception& e) {
        set_error(std::string("EvalMult ct*pt: ") + e.what());
        return nullptr;
    }
}

extern "C" OFHECiphertext ofhe_eval_mult_ct_double(OFHEContext ctx,
                                                     OFHECiphertext ct,
                                                     double scalar) {
    try {
        auto& cc = UNWRAP_CC(ctx);
        auto result = cc->EvalMult(UNWRAP_CT(ct), scalar);
        return WRAP_CT(result);
    } catch (const std::exception& e) {
        set_error(std::string("EvalMult ct*double: ") + e.what());
        return nullptr;
    }
}

extern "C" void ofhe_destroy_ciphertext(OFHECiphertext ct) {
    delete reinterpret_cast<HandleCT*>(ct);
}

// ================================================================
// Serialization — Ciphertext, PublicKey, EvalKey, PrivateKey
// ================================================================

extern "C" bool ofhe_serialize_ciphertext(OFHECiphertext ct, uint8_t** out_buf, size_t* out_len) {
    if (!ct) { set_error("null ciphertext"); return false; }
    return serialize_to_buf(UNWRAP_CT(ct), out_buf, out_len);
}

extern "C" OFHECiphertext ofhe_deserialize_ciphertext(OFHEContext ctx, const uint8_t* buf, size_t len) {
    (void)ctx; // context is set automatically during deserialization
    Ciphertext<DCRTPoly> ct;
    if (!deserialize_from_buf(buf, len, ct)) return nullptr;
    return WRAP_CT(ct);
}

extern "C" bool ofhe_serialize_public_key(OFHEPublicKey pk, uint8_t** out_buf, size_t* out_len) {
    if (!pk) { set_error("null public key"); return false; }
    return serialize_to_buf(UNWRAP_PK(pk), out_buf, out_len);
}

extern "C" OFHEPublicKey ofhe_deserialize_public_key(OFHEContext ctx, const uint8_t* buf, size_t len) {
    (void)ctx;
    PublicKey<DCRTPoly> pk;
    if (!deserialize_from_buf(buf, len, pk)) return nullptr;
    return WRAP_PK(pk);
}

extern "C" bool ofhe_serialize_eval_key(OFHEEvalKey ek, uint8_t** out_buf, size_t* out_len) {
    if (!ek) { set_error("null eval key"); return false; }
    return serialize_to_buf(UNWRAP_EK(ek), out_buf, out_len);
}

extern "C" OFHEEvalKey ofhe_deserialize_eval_key(OFHEContext ctx, const uint8_t* buf, size_t len) {
    (void)ctx;
    EvalKey<DCRTPoly> ek;
    if (!deserialize_from_buf(buf, len, ek)) return nullptr;
    return WRAP_EK(ek);
}

extern "C" bool ofhe_serialize_private_key(OFHEPrivateKey sk, uint8_t** out_buf, size_t* out_len) {
    if (!sk) { set_error("null private key"); return false; }
    return serialize_to_buf(UNWRAP_SK(sk), out_buf, out_len);
}

extern "C" OFHEPrivateKey ofhe_deserialize_private_key(OFHEContext ctx, const uint8_t* buf, size_t len) {
    (void)ctx;
    PrivateKey<DCRTPoly> sk;
    if (!deserialize_from_buf(buf, len, sk)) return nullptr;
    return WRAP_SK(sk);
}

// ================================================================
// Utility
// ================================================================

extern "C" void ofhe_free_buffer(uint8_t* buf) {
    free(buf);
}
