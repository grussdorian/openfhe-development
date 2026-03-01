package com.example.openfhe

/**
 * Kotlin wrapper for the OpenFHE threshold-CKKS C bridge (via JNI).
 *
 * All FHE objects are represented as opaque Long handles (native pointers).
 * Call the corresponding destroy*() method when done to free native memory.
 *
 * Usage:
 *   val fhe = OpenFHE()
 *   val ctx = fhe.genCryptoContext(7, 50, 60, 32)
 *   val kp  = fhe.keygen(ctx)
 *   val pk  = fhe.keypairGetPublicKey(kp)
 *   val sk  = fhe.keypairGetSecretKey(kp)
 *   // ... encrypt, compute, decrypt ...
 *   fhe.destroyPrivateKey(sk)
 *   fhe.destroyPublicKey(pk)
 *   fhe.destroyKeypair(kp)
 *   fhe.destroyContext(ctx)
 */
class OpenFHE {

    companion object {
        init {
            System.loadLibrary("openfhe_jni")
        }
    }

    // ================================================================
    // Error handling
    // ================================================================

    /** Returns the last native error message, or null. */
    fun lastError(): String? = nativeLastError()

    /** Clears the last native error. */
    fun clearError() = nativeClearError()

    // ================================================================
    // CryptoContext
    // ================================================================

    /** Create a threshold-CKKS CryptoContext. Returns handle (0 on failure). */
    fun genCryptoContext(
        multDepth: Int = 7,
        scaleModSize: Int = 50,
        firstModSize: Int = 60,
        batchSize: Int = 32
    ): Long = nativeGenCryptoContext(multDepth, scaleModSize, firstModSize, batchSize)

    /** Serialize a CryptoContext to bytes. */
    fun serializeContext(ctx: Long): ByteArray = nativeSerializeContext(ctx)

    /** Deserialize a CryptoContext from bytes. Returns handle. */
    fun deserializeContext(data: ByteArray): Long = nativeDeserializeContext(data)

    /** Free a CryptoContext. */
    fun destroyContext(ctx: Long) = nativeDestroyContext(ctx)

    // ================================================================
    // Key Generation — Threshold
    // ================================================================

    /** Lead party keygen. Returns KeyPair handle. */
    fun keygen(ctx: Long): Long = nativeKeygen(ctx)

    /** Non-lead party keygen from serialized previous public key. Returns KeyPair handle. */
    fun multipartyKeygen(ctx: Long, prevPkBytes: ByteArray): Long =
        nativeMultipartyKeygen(ctx, prevPkBytes)

    /** Extract public key from KeyPair. Returns PublicKey handle. */
    fun keypairGetPublicKey(kp: Long): Long = nativeKeypairGetPublicKey(kp)

    /** Extract secret key from KeyPair. Returns PrivateKey handle. */
    fun keypairGetSecretKey(kp: Long): Long = nativeKeypairGetSecretKey(kp)

    /** Get the key tag string from a public key. */
    fun getPublicKeyTag(pk: Long): String? = nativeGetPublicKeyTag(pk)

    fun destroyKeypair(kp: Long) = nativeDestroyKeypair(kp)
    fun destroyPublicKey(pk: Long) = nativeDestroyPublicKey(pk)
    fun destroyPrivateKey(sk: Long) = nativeDestroyPrivateKey(sk)

    // ================================================================
    // Eval Mult Key — Threshold Rounds
    // ================================================================

    /** Lead: KeySwitchGen(sk, sk) → round-1 eval share. */
    fun keySwitchGen(ctx: Long, sk: Long): Long = nativeKeySwitchGen(ctx, sk)

    /** Non-lead: MultiKeySwitchGen with serialized previous eval key. */
    fun multiKeySwitchGen(ctx: Long, sk: Long, prevEvalBytes: ByteArray): Long =
        nativeMultiKeySwitchGen(ctx, sk, prevEvalBytes)

    /** Round 2: MultiMultEvalKey. */
    fun multiMultEvalKey(ctx: Long, sk: Long, combinedEvalBytes: ByteArray, jointPkTag: String): Long =
        nativeMultiMultEvalKey(ctx, sk, combinedEvalBytes, jointPkTag)

    /** Install eval mult key into context. */
    fun insertEvalMultKey(ctx: Long, evalKeyBytes: ByteArray): Boolean =
        nativeInsertEvalMultKey(ctx, evalKeyBytes)

    /** Combine two eval keys (round 1). */
    fun multiAddEvalKeys(ctx: Long, ek1: Long, ek2: Long, keyTag: String): Long =
        nativeMultiAddEvalKeys(ctx, ek1, ek2, keyTag)

    /** Combine two eval mult keys (round 2). */
    fun multiAddEvalMultKeys(ctx: Long, ek1: Long, ek2: Long, keyTag: String): Long =
        nativeMultiAddEvalMultKeys(ctx, ek1, ek2, keyTag)

    fun destroyEvalKey(ek: Long) = nativeDestroyEvalKey(ek)

    // ================================================================
    // Encoding
    // ================================================================

    /** Encode a DoubleArray as a CKKS packed plaintext. Returns Plaintext handle. */
    fun makeCKKSPackedPlaintext(ctx: Long, values: DoubleArray): Long =
        nativeMakeCKKSPackedPlaintext(ctx, values)

    /** Decode plaintext to DoubleArray. */
    fun plaintextGetRealPackedValue(pt: Long, maxCount: Int = 32): DoubleArray =
        nativePlaintextGetRealPackedValue(pt, maxCount)

    /** Set plaintext length (for fusion). */
    fun plaintextSetLength(pt: Long, length: Int) = nativePlaintextSetLength(pt, length)

    fun destroyPlaintext(pt: Long) = nativeDestroyPlaintext(pt)

    // ================================================================
    // Encrypt / Decrypt
    // ================================================================

    /** Encrypt plaintext under a public key. Returns Ciphertext handle. */
    fun encrypt(ctx: Long, pk: Long, pt: Long): Long = nativeEncrypt(ctx, pk, pt)

    /** Multiparty partial decrypt — LEAD party. Returns partial Ciphertext handle. */
    fun multipartyDecryptLead(ctx: Long, ct: Long, sk: Long): Long =
        nativeMultipartyDecryptLead(ctx, ct, sk)

    /** Multiparty partial decrypt — NON-LEAD party. Returns partial Ciphertext handle. */
    fun multipartyDecryptMain(ctx: Long, ct: Long, sk: Long): Long =
        nativeMultipartyDecryptMain(ctx, ct, sk)

    /** Fuse partial decryptions. Returns Plaintext handle. */
    fun multipartyDecryptFusion(ctx: Long, partials: LongArray): Long =
        nativeMultipartyDecryptFusion(ctx, partials)

    fun destroyCiphertext(ct: Long) = nativeDestroyCiphertext(ct)

    // ================================================================
    // Homomorphic Operations
    // ================================================================

    fun evalAddCtCt(ctx: Long, ct1: Long, ct2: Long): Long = nativeEvalAddCtCt(ctx, ct1, ct2)
    fun evalAddCtPt(ctx: Long, ct: Long, pt: Long): Long = nativeEvalAddCtPt(ctx, ct, pt)
    fun evalAddCtDouble(ctx: Long, ct: Long, scalar: Double): Long = nativeEvalAddCtDouble(ctx, ct, scalar)
    fun evalSubCtCt(ctx: Long, ct1: Long, ct2: Long): Long = nativeEvalSubCtCt(ctx, ct1, ct2)
    fun evalSubCtPt(ctx: Long, ct: Long, pt: Long): Long = nativeEvalSubCtPt(ctx, ct, pt)
    fun evalMultCtCt(ctx: Long, ct1: Long, ct2: Long): Long = nativeEvalMultCtCt(ctx, ct1, ct2)
    fun evalMultCtPt(ctx: Long, ct: Long, pt: Long): Long = nativeEvalMultCtPt(ctx, ct, pt)
    fun evalMultCtDouble(ctx: Long, ct: Long, scalar: Double): Long = nativeEvalMultCtDouble(ctx, ct, scalar)

    // ================================================================
    // Serialization
    // ================================================================

    fun serializeCiphertext(ct: Long): ByteArray = nativeSerializeCiphertext(ct)
    fun deserializeCiphertext(ctx: Long, data: ByteArray): Long = nativeDeserializeCiphertext(ctx, data)

    fun serializePublicKey(pk: Long): ByteArray = nativeSerializePublicKey(pk)
    fun deserializePublicKey(ctx: Long, data: ByteArray): Long = nativeDeserializePublicKey(ctx, data)

    fun serializeEvalKey(ek: Long): ByteArray = nativeSerializeEvalKey(ek)
    fun deserializeEvalKey(ctx: Long, data: ByteArray): Long = nativeDeserializeEvalKey(ctx, data)

    fun serializePrivateKey(sk: Long): ByteArray = nativeSerializePrivateKey(sk)
    fun deserializePrivateKey(ctx: Long, data: ByteArray): Long = nativeDeserializePrivateKey(ctx, data)

    // ================================================================
    // Native method declarations
    // ================================================================

    // Error
    private external fun nativeLastError(): String?
    private external fun nativeClearError()

    // CryptoContext
    private external fun nativeGenCryptoContext(multDepth: Int, scaleModSize: Int, firstModSize: Int, batchSize: Int): Long
    private external fun nativeSerializeContext(ctx: Long): ByteArray
    private external fun nativeDeserializeContext(data: ByteArray): Long
    private external fun nativeDestroyContext(ctx: Long)

    // Key Generation
    private external fun nativeKeygen(ctx: Long): Long
    private external fun nativeMultipartyKeygen(ctx: Long, prevPkBuf: ByteArray): Long
    private external fun nativeKeypairGetPublicKey(kp: Long): Long
    private external fun nativeKeypairGetSecretKey(kp: Long): Long
    private external fun nativeGetPublicKeyTag(pk: Long): String?
    private external fun nativeDestroyKeypair(kp: Long)
    private external fun nativeDestroyPublicKey(pk: Long)
    private external fun nativeDestroyPrivateKey(sk: Long)

    // Eval Mult Key
    private external fun nativeKeySwitchGen(ctx: Long, sk: Long): Long
    private external fun nativeMultiKeySwitchGen(ctx: Long, sk: Long, prevEvalBuf: ByteArray): Long
    private external fun nativeMultiMultEvalKey(ctx: Long, sk: Long, combinedEvalBuf: ByteArray, jointPkTag: String): Long
    private external fun nativeInsertEvalMultKey(ctx: Long, evalKeyBuf: ByteArray): Boolean
    private external fun nativeMultiAddEvalKeys(ctx: Long, ek1: Long, ek2: Long, keyTag: String): Long
    private external fun nativeMultiAddEvalMultKeys(ctx: Long, ek1: Long, ek2: Long, keyTag: String): Long
    private external fun nativeDestroyEvalKey(ek: Long)

    // Encoding
    private external fun nativeMakeCKKSPackedPlaintext(ctx: Long, values: DoubleArray): Long
    private external fun nativePlaintextGetRealPackedValue(pt: Long, maxCount: Int): DoubleArray
    private external fun nativePlaintextSetLength(pt: Long, length: Int)
    private external fun nativeDestroyPlaintext(pt: Long)

    // Encrypt / Decrypt
    private external fun nativeEncrypt(ctx: Long, pk: Long, pt: Long): Long
    private external fun nativeMultipartyDecryptLead(ctx: Long, ct: Long, sk: Long): Long
    private external fun nativeMultipartyDecryptMain(ctx: Long, ct: Long, sk: Long): Long
    private external fun nativeMultipartyDecryptFusion(ctx: Long, partials: LongArray): Long
    private external fun nativeDestroyCiphertext(ct: Long)

    // Homomorphic Ops
    private external fun nativeEvalAddCtCt(ctx: Long, ct1: Long, ct2: Long): Long
    private external fun nativeEvalAddCtPt(ctx: Long, ct: Long, pt: Long): Long
    private external fun nativeEvalAddCtDouble(ctx: Long, ct: Long, scalar: Double): Long
    private external fun nativeEvalSubCtCt(ctx: Long, ct1: Long, ct2: Long): Long
    private external fun nativeEvalSubCtPt(ctx: Long, ct: Long, pt: Long): Long
    private external fun nativeEvalMultCtCt(ctx: Long, ct1: Long, ct2: Long): Long
    private external fun nativeEvalMultCtPt(ctx: Long, ct: Long, pt: Long): Long
    private external fun nativeEvalMultCtDouble(ctx: Long, ct: Long, scalar: Double): Long

    // Serialization
    private external fun nativeSerializeCiphertext(ct: Long): ByteArray
    private external fun nativeDeserializeCiphertext(ctx: Long, data: ByteArray): Long
    private external fun nativeSerializePublicKey(pk: Long): ByteArray
    private external fun nativeDeserializePublicKey(ctx: Long, data: ByteArray): Long
    private external fun nativeSerializeEvalKey(ek: Long): ByteArray
    private external fun nativeDeserializeEvalKey(ctx: Long, data: ByteArray): Long
    private external fun nativeSerializePrivateKey(sk: Long): ByteArray
    private external fun nativeDeserializePrivateKey(ctx: Long, data: ByteArray): Long
}
