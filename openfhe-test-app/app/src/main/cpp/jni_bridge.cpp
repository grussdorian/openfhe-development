/*
 * jni_bridge.cpp — Full JNI bridge for OpenFHE Android
 *
 * Maps every C bridge function in openfhe_android.h to a JNI native method.
 * Java/Kotlin class: com.example.openfhe.OpenFHE
 *
 * Opaque handles are passed as jlong (pointer-sized integers).
 * Byte buffers are passed as jbyteArray.
 * Double arrays are passed as jdoubleArray.
 */

#include <jni.h>
#include "openfhe_android.h"
#include <string>
#include <cstring>
#include <vector>



// ================================================================
// Helper: throw a Java exception from the last native error
// ================================================================
static void throwIfError(JNIEnv* env) {
    const char* err = ofhe_last_error();
    if (err) {
        jclass cls = env->FindClass("java/lang/RuntimeException");
        env->ThrowNew(cls, err);
        ofhe_clear_error();
    }
}

// ================================================================
// Error handling
// ================================================================

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_openfhe_OpenFHE_nativeLastError(JNIEnv* env, jobject) {
    const char* err = ofhe_last_error();
    if (!err) return nullptr;
    return env->NewStringUTF(err);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_openfhe_OpenFHE_nativeClearError(JNIEnv* env, jobject) {
    ofhe_clear_error();
}

// ================================================================
// CryptoContext
// ================================================================

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_openfhe_OpenFHE_nativeGenCryptoContext(
        JNIEnv* env, jobject,
        jint multDepth, jint scaleModSize, jint firstModSize, jint batchSize) {
    OFHEContext ctx = ofhe_gen_crypto_context(
        (uint32_t)multDepth, (uint32_t)scaleModSize,
        (uint32_t)firstModSize, (uint32_t)batchSize);
    if (!ctx) throwIfError(env);
    return reinterpret_cast<jlong>(ctx);
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_openfhe_OpenFHE_nativeSerializeContext(
        JNIEnv* env, jobject, jlong ctxPtr) {
    uint8_t* buf = nullptr;
    size_t len = 0;
    if (!ofhe_serialize_context(reinterpret_cast<OFHEContext>(ctxPtr), &buf, &len)) {
        throwIfError(env);
        return nullptr;
    }
    jbyteArray result = env->NewByteArray((jsize)len);
    env->SetByteArrayRegion(result, 0, (jsize)len, reinterpret_cast<jbyte*>(buf));
    ofhe_free_buffer(buf);
    return result;
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_openfhe_OpenFHE_nativeDeserializeContext(
        JNIEnv* env, jobject, jbyteArray data) {
    jsize len = env->GetArrayLength(data);
    jbyte* buf = env->GetByteArrayElements(data, nullptr);
    OFHEContext ctx = ofhe_deserialize_context(reinterpret_cast<const uint8_t*>(buf), (size_t)len);
    env->ReleaseByteArrayElements(data, buf, JNI_ABORT);
    if (!ctx) throwIfError(env);
    return reinterpret_cast<jlong>(ctx);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_openfhe_OpenFHE_nativeDestroyContext(
        JNIEnv*, jobject, jlong ctxPtr) {
    ofhe_destroy_context(reinterpret_cast<OFHEContext>(ctxPtr));
}

// ================================================================
// Key Generation
// ================================================================

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_openfhe_OpenFHE_nativeKeygen(
        JNIEnv* env, jobject, jlong ctxPtr) {
    OFHEKeyPair kp = ofhe_keygen(reinterpret_cast<OFHEContext>(ctxPtr));
    if (!kp) throwIfError(env);
    return reinterpret_cast<jlong>(kp);
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_openfhe_OpenFHE_nativeMultipartyKeygen(
        JNIEnv* env, jobject, jlong ctxPtr, jbyteArray prevPkBuf) {
    jsize len = env->GetArrayLength(prevPkBuf);
    jbyte* buf = env->GetByteArrayElements(prevPkBuf, nullptr);
    OFHEKeyPair kp = ofhe_multiparty_keygen(
        reinterpret_cast<OFHEContext>(ctxPtr),
        reinterpret_cast<const uint8_t*>(buf), (size_t)len);
    env->ReleaseByteArrayElements(prevPkBuf, buf, JNI_ABORT);
    if (!kp) throwIfError(env);
    return reinterpret_cast<jlong>(kp);
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_openfhe_OpenFHE_nativeKeypairGetPublicKey(
        JNIEnv* env, jobject, jlong kpPtr) {
    OFHEPublicKey pk = ofhe_keypair_get_public_key(reinterpret_cast<OFHEKeyPair>(kpPtr));
    if (!pk) throwIfError(env);
    return reinterpret_cast<jlong>(pk);
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_openfhe_OpenFHE_nativeKeypairGetSecretKey(
        JNIEnv* env, jobject, jlong kpPtr) {
    OFHEPrivateKey sk = ofhe_keypair_get_secret_key(reinterpret_cast<OFHEKeyPair>(kpPtr));
    if (!sk) throwIfError(env);
    return reinterpret_cast<jlong>(sk);
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_openfhe_OpenFHE_nativeGetPublicKeyTag(
        JNIEnv* env, jobject, jlong pkPtr) {
    const char* tag = ofhe_get_public_key_tag(reinterpret_cast<OFHEPublicKey>(pkPtr));
    if (!tag) {
        throwIfError(env);
        return nullptr;
    }
    return env->NewStringUTF(tag);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_openfhe_OpenFHE_nativeDestroyKeypair(JNIEnv*, jobject, jlong ptr) {
    ofhe_destroy_keypair(reinterpret_cast<OFHEKeyPair>(ptr));
}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_openfhe_OpenFHE_nativeDestroyPublicKey(JNIEnv*, jobject, jlong ptr) {
    ofhe_destroy_public_key(reinterpret_cast<OFHEPublicKey>(ptr));
}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_openfhe_OpenFHE_nativeDestroyPrivateKey(JNIEnv*, jobject, jlong ptr) {
    ofhe_destroy_private_key(reinterpret_cast<OFHEPrivateKey>(ptr));
}

// ================================================================
// Eval Mult Key — Threshold Rounds
// ================================================================

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_openfhe_OpenFHE_nativeKeySwitchGen(
        JNIEnv* env, jobject, jlong ctxPtr, jlong skPtr) {
    OFHEEvalKey ek = ofhe_key_switch_gen(
        reinterpret_cast<OFHEContext>(ctxPtr),
        reinterpret_cast<OFHEPrivateKey>(skPtr));
    if (!ek) throwIfError(env);
    return reinterpret_cast<jlong>(ek);
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_openfhe_OpenFHE_nativeMultiKeySwitchGen(
        JNIEnv* env, jobject, jlong ctxPtr, jlong skPtr, jbyteArray prevEvalBuf) {
    jsize len = env->GetArrayLength(prevEvalBuf);
    jbyte* buf = env->GetByteArrayElements(prevEvalBuf, nullptr);
    OFHEEvalKey ek = ofhe_multi_key_switch_gen(
        reinterpret_cast<OFHEContext>(ctxPtr),
        reinterpret_cast<OFHEPrivateKey>(skPtr),
        reinterpret_cast<const uint8_t*>(buf), (size_t)len);
    env->ReleaseByteArrayElements(prevEvalBuf, buf, JNI_ABORT);
    if (!ek) throwIfError(env);
    return reinterpret_cast<jlong>(ek);
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_openfhe_OpenFHE_nativeMultiMultEvalKey(
        JNIEnv* env, jobject, jlong ctxPtr, jlong skPtr,
        jbyteArray combinedEvalBuf, jstring jointPkTag) {
    jsize len = env->GetArrayLength(combinedEvalBuf);
    jbyte* buf = env->GetByteArrayElements(combinedEvalBuf, nullptr);
    const char* tag = env->GetStringUTFChars(jointPkTag, nullptr);
    OFHEEvalKey ek = ofhe_multi_mult_eval_key(
        reinterpret_cast<OFHEContext>(ctxPtr),
        reinterpret_cast<OFHEPrivateKey>(skPtr),
        reinterpret_cast<const uint8_t*>(buf), (size_t)len, tag);
    env->ReleaseStringUTFChars(jointPkTag, tag);
    env->ReleaseByteArrayElements(combinedEvalBuf, buf, JNI_ABORT);
    if (!ek) throwIfError(env);
    return reinterpret_cast<jlong>(ek);
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_example_openfhe_OpenFHE_nativeInsertEvalMultKey(
        JNIEnv* env, jobject, jlong ctxPtr, jbyteArray evalKeyBuf) {
    jsize len = env->GetArrayLength(evalKeyBuf);
    jbyte* buf = env->GetByteArrayElements(evalKeyBuf, nullptr);
    bool ok = ofhe_insert_eval_mult_key(
        reinterpret_cast<OFHEContext>(ctxPtr),
        reinterpret_cast<const uint8_t*>(buf), (size_t)len);
    env->ReleaseByteArrayElements(evalKeyBuf, buf, JNI_ABORT);
    if (!ok) throwIfError(env);
    return ok ? JNI_TRUE : JNI_FALSE;
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_openfhe_OpenFHE_nativeMultiAddEvalKeys(
        JNIEnv* env, jobject, jlong ctxPtr,
        jlong ek1Ptr, jlong ek2Ptr, jstring keyTag) {
    const char* tag = env->GetStringUTFChars(keyTag, nullptr);
    OFHEEvalKey ek = ofhe_multi_add_eval_keys(
        reinterpret_cast<OFHEContext>(ctxPtr),
        reinterpret_cast<OFHEEvalKey>(ek1Ptr),
        reinterpret_cast<OFHEEvalKey>(ek2Ptr), tag);
    env->ReleaseStringUTFChars(keyTag, tag);
    if (!ek) throwIfError(env);
    return reinterpret_cast<jlong>(ek);
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_openfhe_OpenFHE_nativeMultiAddEvalMultKeys(
        JNIEnv* env, jobject, jlong ctxPtr,
        jlong ek1Ptr, jlong ek2Ptr, jstring keyTag) {
    const char* tag = env->GetStringUTFChars(keyTag, nullptr);
    OFHEEvalKey ek = ofhe_multi_add_eval_mult_keys(
        reinterpret_cast<OFHEContext>(ctxPtr),
        reinterpret_cast<OFHEEvalKey>(ek1Ptr),
        reinterpret_cast<OFHEEvalKey>(ek2Ptr), tag);
    env->ReleaseStringUTFChars(keyTag, tag);
    if (!ek) throwIfError(env);
    return reinterpret_cast<jlong>(ek);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_openfhe_OpenFHE_nativeDestroyEvalKey(JNIEnv*, jobject, jlong ptr) {
    ofhe_destroy_eval_key(reinterpret_cast<OFHEEvalKey>(ptr));
}

// ================================================================
// Encoding
// ================================================================

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_openfhe_OpenFHE_nativeMakeCKKSPackedPlaintext(
        JNIEnv* env, jobject, jlong ctxPtr, jdoubleArray values) {
    jsize count = env->GetArrayLength(values);
    jdouble* vals = env->GetDoubleArrayElements(values, nullptr);
    OFHEPlaintext pt = ofhe_make_ckks_packed_plaintext(
        reinterpret_cast<OFHEContext>(ctxPtr), vals, (size_t)count);
    env->ReleaseDoubleArrayElements(values, vals, JNI_ABORT);
    if (!pt) throwIfError(env);
    return reinterpret_cast<jlong>(pt);
}

extern "C"
JNIEXPORT jdoubleArray JNICALL
Java_com_example_openfhe_OpenFHE_nativePlaintextGetRealPackedValue(
        JNIEnv* env, jobject, jlong ptPtr, jint maxCount) {
    auto* out = new double[(size_t)maxCount];
    size_t n = ofhe_plaintext_get_real_packed_value(
        reinterpret_cast<OFHEPlaintext>(ptPtr), out, (size_t)maxCount);
    jdoubleArray result = env->NewDoubleArray((jsize)n);
    env->SetDoubleArrayRegion(result, 0, (jsize)n, out);
    delete[] out;
    return result;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_openfhe_OpenFHE_nativePlaintextSetLength(
        JNIEnv*, jobject, jlong ptPtr, jint length) {
    ofhe_plaintext_set_length(reinterpret_cast<OFHEPlaintext>(ptPtr), (size_t)length);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_openfhe_OpenFHE_nativeDestroyPlaintext(JNIEnv*, jobject, jlong ptr) {
    ofhe_destroy_plaintext(reinterpret_cast<OFHEPlaintext>(ptr));
}

// ================================================================
// Encrypt / Decrypt
// ================================================================

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_openfhe_OpenFHE_nativeEncrypt(
        JNIEnv* env, jobject, jlong ctxPtr, jlong pkPtr, jlong ptPtr) {
    OFHECiphertext ct = ofhe_encrypt(
        reinterpret_cast<OFHEContext>(ctxPtr),
        reinterpret_cast<OFHEPublicKey>(pkPtr),
        reinterpret_cast<OFHEPlaintext>(ptPtr));
    if (!ct) throwIfError(env);
    return reinterpret_cast<jlong>(ct);
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_openfhe_OpenFHE_nativeMultipartyDecryptLead(
        JNIEnv* env, jobject, jlong ctxPtr, jlong ctPtr, jlong skPtr) {
    OFHECiphertext partial = ofhe_multiparty_decrypt_lead(
        reinterpret_cast<OFHEContext>(ctxPtr),
        reinterpret_cast<OFHECiphertext>(ctPtr),
        reinterpret_cast<OFHEPrivateKey>(skPtr));
    if (!partial) throwIfError(env);
    return reinterpret_cast<jlong>(partial);
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_openfhe_OpenFHE_nativeMultipartyDecryptMain(
        JNIEnv* env, jobject, jlong ctxPtr, jlong ctPtr, jlong skPtr) {
    OFHECiphertext partial = ofhe_multiparty_decrypt_main(
        reinterpret_cast<OFHEContext>(ctxPtr),
        reinterpret_cast<OFHECiphertext>(ctPtr),
        reinterpret_cast<OFHEPrivateKey>(skPtr));
    if (!partial) throwIfError(env);
    return reinterpret_cast<jlong>(partial);
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_openfhe_OpenFHE_nativeMultipartyDecryptFusion(
        JNIEnv* env, jobject, jlong ctxPtr, jlongArray partialPtrs) {
    jsize count = env->GetArrayLength(partialPtrs);
    jlong* ptrs = env->GetLongArrayElements(partialPtrs, nullptr);
    auto* partials = new OFHECiphertext[(size_t)count];
    for (jsize i = 0; i < count; ++i) {
        partials[i] = reinterpret_cast<OFHECiphertext>(ptrs[i]);
    }
    OFHEPlaintext result = ofhe_multiparty_decrypt_fusion(
        reinterpret_cast<OFHEContext>(ctxPtr), partials, (size_t)count);
    delete[] partials;
    env->ReleaseLongArrayElements(partialPtrs, ptrs, JNI_ABORT);
    if (!result) throwIfError(env);
    return reinterpret_cast<jlong>(result);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_openfhe_OpenFHE_nativeDestroyCiphertext(JNIEnv*, jobject, jlong ptr) {
    ofhe_destroy_ciphertext(reinterpret_cast<OFHECiphertext>(ptr));
}

// ================================================================
// Homomorphic Operations
// ================================================================

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_openfhe_OpenFHE_nativeEvalAddCtCt(
        JNIEnv* env, jobject, jlong ctxPtr, jlong ct1Ptr, jlong ct2Ptr) {
    OFHECiphertext r = ofhe_eval_add_ct_ct(
        reinterpret_cast<OFHEContext>(ctxPtr),
        reinterpret_cast<OFHECiphertext>(ct1Ptr),
        reinterpret_cast<OFHECiphertext>(ct2Ptr));
    if (!r) throwIfError(env);
    return reinterpret_cast<jlong>(r);
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_openfhe_OpenFHE_nativeEvalAddCtPt(
        JNIEnv* env, jobject, jlong ctxPtr, jlong ctPtr, jlong ptPtr) {
    OFHECiphertext r = ofhe_eval_add_ct_pt(
        reinterpret_cast<OFHEContext>(ctxPtr),
        reinterpret_cast<OFHECiphertext>(ctPtr),
        reinterpret_cast<OFHEPlaintext>(ptPtr));
    if (!r) throwIfError(env);
    return reinterpret_cast<jlong>(r);
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_openfhe_OpenFHE_nativeEvalAddCtDouble(
        JNIEnv* env, jobject, jlong ctxPtr, jlong ctPtr, jdouble scalar) {
    OFHECiphertext r = ofhe_eval_add_ct_double(
        reinterpret_cast<OFHEContext>(ctxPtr),
        reinterpret_cast<OFHECiphertext>(ctPtr), scalar);
    if (!r) throwIfError(env);
    return reinterpret_cast<jlong>(r);
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_openfhe_OpenFHE_nativeEvalSubCtCt(
        JNIEnv* env, jobject, jlong ctxPtr, jlong ct1Ptr, jlong ct2Ptr) {
    OFHECiphertext r = ofhe_eval_sub_ct_ct(
        reinterpret_cast<OFHEContext>(ctxPtr),
        reinterpret_cast<OFHECiphertext>(ct1Ptr),
        reinterpret_cast<OFHECiphertext>(ct2Ptr));
    if (!r) throwIfError(env);
    return reinterpret_cast<jlong>(r);
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_openfhe_OpenFHE_nativeEvalSubCtPt(
        JNIEnv* env, jobject, jlong ctxPtr, jlong ctPtr, jlong ptPtr) {
    OFHECiphertext r = ofhe_eval_sub_ct_pt(
        reinterpret_cast<OFHEContext>(ctxPtr),
        reinterpret_cast<OFHECiphertext>(ctPtr),
        reinterpret_cast<OFHEPlaintext>(ptPtr));
    if (!r) throwIfError(env);
    return reinterpret_cast<jlong>(r);
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_openfhe_OpenFHE_nativeEvalMultCtCt(
        JNIEnv* env, jobject, jlong ctxPtr, jlong ct1Ptr, jlong ct2Ptr) {
    OFHECiphertext r = ofhe_eval_mult_ct_ct(
        reinterpret_cast<OFHEContext>(ctxPtr),
        reinterpret_cast<OFHECiphertext>(ct1Ptr),
        reinterpret_cast<OFHECiphertext>(ct2Ptr));
    if (!r) throwIfError(env);
    return reinterpret_cast<jlong>(r);
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_openfhe_OpenFHE_nativeEvalMultCtPt(
        JNIEnv* env, jobject, jlong ctxPtr, jlong ctPtr, jlong ptPtr) {
    OFHECiphertext r = ofhe_eval_mult_ct_pt(
        reinterpret_cast<OFHEContext>(ctxPtr),
        reinterpret_cast<OFHECiphertext>(ctPtr),
        reinterpret_cast<OFHEPlaintext>(ptPtr));
    if (!r) throwIfError(env);
    return reinterpret_cast<jlong>(r);
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_openfhe_OpenFHE_nativeEvalMultCtDouble(
        JNIEnv* env, jobject, jlong ctxPtr, jlong ctPtr, jdouble scalar) {
    OFHECiphertext r = ofhe_eval_mult_ct_double(
        reinterpret_cast<OFHEContext>(ctxPtr),
        reinterpret_cast<OFHECiphertext>(ctPtr), scalar);
    if (!r) throwIfError(env);
    return reinterpret_cast<jlong>(r);
}

// ================================================================
// Serialization
// ================================================================

// --- Ciphertext ---
extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_openfhe_OpenFHE_nativeSerializeCiphertext(
        JNIEnv* env, jobject, jlong ctPtr) {
    uint8_t* buf = nullptr; size_t len = 0;
    if (!ofhe_serialize_ciphertext(reinterpret_cast<OFHECiphertext>(ctPtr), &buf, &len)) {
        throwIfError(env); return nullptr;
    }
    jbyteArray result = env->NewByteArray((jsize)len);
    env->SetByteArrayRegion(result, 0, (jsize)len, reinterpret_cast<jbyte*>(buf));
    ofhe_free_buffer(buf);
    return result;
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_openfhe_OpenFHE_nativeDeserializeCiphertext(
        JNIEnv* env, jobject, jlong ctxPtr, jbyteArray data) {
    jsize len = env->GetArrayLength(data);
    jbyte* buf = env->GetByteArrayElements(data, nullptr);
    OFHECiphertext ct = ofhe_deserialize_ciphertext(
        reinterpret_cast<OFHEContext>(ctxPtr),
        reinterpret_cast<const uint8_t*>(buf), (size_t)len);
    env->ReleaseByteArrayElements(data, buf, JNI_ABORT);
    if (!ct) throwIfError(env);
    return reinterpret_cast<jlong>(ct);
}

// --- PublicKey ---
extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_openfhe_OpenFHE_nativeSerializePublicKey(
        JNIEnv* env, jobject, jlong pkPtr) {
    uint8_t* buf = nullptr; size_t len = 0;
    if (!ofhe_serialize_public_key(reinterpret_cast<OFHEPublicKey>(pkPtr), &buf, &len)) {
        throwIfError(env); return nullptr;
    }
    jbyteArray result = env->NewByteArray((jsize)len);
    env->SetByteArrayRegion(result, 0, (jsize)len, reinterpret_cast<jbyte*>(buf));
    ofhe_free_buffer(buf);
    return result;
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_openfhe_OpenFHE_nativeDeserializePublicKey(
        JNIEnv* env, jobject, jlong ctxPtr, jbyteArray data) {
    jsize len = env->GetArrayLength(data);
    jbyte* buf = env->GetByteArrayElements(data, nullptr);
    OFHEPublicKey pk = ofhe_deserialize_public_key(
        reinterpret_cast<OFHEContext>(ctxPtr),
        reinterpret_cast<const uint8_t*>(buf), (size_t)len);
    env->ReleaseByteArrayElements(data, buf, JNI_ABORT);
    if (!pk) throwIfError(env);
    return reinterpret_cast<jlong>(pk);
}

// --- EvalKey ---
extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_openfhe_OpenFHE_nativeSerializeEvalKey(
        JNIEnv* env, jobject, jlong ekPtr) {
    uint8_t* buf = nullptr; size_t len = 0;
    if (!ofhe_serialize_eval_key(reinterpret_cast<OFHEEvalKey>(ekPtr), &buf, &len)) {
        throwIfError(env); return nullptr;
    }
    jbyteArray result = env->NewByteArray((jsize)len);
    env->SetByteArrayRegion(result, 0, (jsize)len, reinterpret_cast<jbyte*>(buf));
    ofhe_free_buffer(buf);
    return result;
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_openfhe_OpenFHE_nativeDeserializeEvalKey(
        JNIEnv* env, jobject, jlong ctxPtr, jbyteArray data) {
    jsize len = env->GetArrayLength(data);
    jbyte* buf = env->GetByteArrayElements(data, nullptr);
    OFHEEvalKey ek = ofhe_deserialize_eval_key(
        reinterpret_cast<OFHEContext>(ctxPtr),
        reinterpret_cast<const uint8_t*>(buf), (size_t)len);
    env->ReleaseByteArrayElements(data, buf, JNI_ABORT);
    if (!ek) throwIfError(env);
    return reinterpret_cast<jlong>(ek);
}

// --- PrivateKey ---
extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_openfhe_OpenFHE_nativeSerializePrivateKey(
        JNIEnv* env, jobject, jlong skPtr) {
    uint8_t* buf = nullptr; size_t len = 0;
    if (!ofhe_serialize_private_key(reinterpret_cast<OFHEPrivateKey>(skPtr), &buf, &len)) {
        throwIfError(env); return nullptr;
    }
    jbyteArray result = env->NewByteArray((jsize)len);
    env->SetByteArrayRegion(result, 0, (jsize)len, reinterpret_cast<jbyte*>(buf));
    ofhe_free_buffer(buf);
    return result;
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_openfhe_OpenFHE_nativeDeserializePrivateKey(
        JNIEnv* env, jobject, jlong ctxPtr, jbyteArray data) {
    jsize len = env->GetArrayLength(data);
    jbyte* buf = env->GetByteArrayElements(data, nullptr);
    OFHEPrivateKey sk = ofhe_deserialize_private_key(
        reinterpret_cast<OFHEContext>(ctxPtr),
        reinterpret_cast<const uint8_t*>(buf), (size_t)len);
    env->ReleaseByteArrayElements(data, buf, JNI_ABORT);
    if (!sk) throwIfError(env);
    return reinterpret_cast<jlong>(sk);
}