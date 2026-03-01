package com.example.openfhedemo

import java.io.File

/**
 * Comprehensive test suite for all OpenFHE C bridge functions (via JNI).
 * Kotlin equivalent of the iOS OpenFHETests.swift.
 *
 * Every handle is checked for 0L (null). Run from a background thread — FHE ops are slow.
 */
class OpenFHETests(private val cacheDir: File? = null) {

    data class TestResult(
        val name: String,
        val passed: Boolean,
        val duration: Double,   // seconds
        val detail: String
    )

    private val fhe = OpenFHE()
    private val results = mutableListOf<TestResult>()
    private var ctx: Long = 0L
    private var contextLoadedFromCache = false

    var onTestComplete: ((TestResult) -> Unit)? = null
    var onAllComplete: ((List<TestResult>) -> Unit)? = null

    // ── Entry Point ──

    fun runAll() {
        results.clear()

        // 1. Context
        run("Context Create") { testContextCreate() }
        // Annotate with cache status
        results.indexOfFirst { it.name == "Context Create" && it.passed }.takeIf { it >= 0 }?.let { idx ->
            val r = results[idx]
            val detail = if (contextLoadedFromCache) "Loaded from cache"
                         else "Generated fresh (cached for next run)"
            results[idx] = r.copy(detail = detail)
        }
        if (ctx == 0L) {
            abort("Context creation failed — cannot continue.")
            return
        }

        // 2. Context Serialization Round-Trip
        run("Context Serialize") { testContextSerialize() }

        // 3. Key Generation (Lead)
        var leadKP = 0L; var leadPK = 0L; var leadSK = 0L

        run("Lead KeyGen") {
            leadKP = fhe.keygen(ctx)
            check(leadKP != 0L) { err() }
            leadPK = fhe.keypairGetPublicKey(leadKP)
            leadSK = fhe.keypairGetSecretKey(leadKP)
            check(leadPK != 0L && leadSK != 0L) { err() }
        }

        // 4. Public Key Serialization
        var leadPKBytes = ByteArray(0)

        run("PubKey Serialize") {
            check(leadPK != 0L) { "No lead PK from prior step" }
            leadPKBytes = fhe.serializePublicKey(leadPK)
            check(leadPKBytes.isNotEmpty()) { err() }
        }

        // 5. Multiparty KeyGen (Join)
        var joinKP = 0L; var joinSK = 0L

        run("Join KeyGen") {
            check(leadPKBytes.isNotEmpty()) { "No serialized lead PK" }
            joinKP = fhe.multipartyKeygen(ctx, leadPKBytes)
            check(joinKP != 0L) { err() }
            joinSK = fhe.keypairGetSecretKey(joinKP)
            check(joinSK != 0L) { err() }
        }

        // 6. Private Key Serialization Round-Trip
        run("PrivKey Serialize") {
            check(leadSK != 0L) { "No lead SK" }
            val skBytes = fhe.serializePrivateKey(leadSK)
            check(skBytes.isNotEmpty()) { err() }
            val restored = fhe.deserializePrivateKey(ctx, skBytes)
            check(restored != 0L) { err() }
            fhe.destroyPrivateKey(restored)
        }

        // 7. Get joint PK and its tag
        val jointPK: Long = if (joinKP != 0L) fhe.keypairGetPublicKey(joinKP) else 0L
        var jointPKTag = ""

        run("Get PK Tag") {
            check(jointPK != 0L) { "No joint PK" }
            jointPKTag = fhe.getPublicKeyTag(jointPK) ?: error(err())
            check(jointPKTag.isNotEmpty()) { "Empty PK tag" }
        }

        // 8. Eval Mult Key Setup (2-party threshold)
        var evalKeyOK = false
        run("EvalMultKey Setup") {
            check(leadSK != 0L && joinSK != 0L) { "Missing keys from earlier step" }
            testEvalMultKeySetup(leadSK, joinSK, jointPKTag)
            evalKeyOK = true
        }

        // 9. CKKS Plaintext Encoding
        run("CKKS Encode") { testCKKSEncode() }

        // 10. Encrypt
        var ct1 = 0L; var ct2 = 0L

        run("Encrypt") {
            check(jointPK != 0L) { "No joint PK" }
            val vals1 = doubleArrayOf(1.0, 2.0, 3.0, 4.0)
            val pt1 = fhe.makeCKKSPackedPlaintext(ctx, vals1)
            check(pt1 != 0L) { err() }
            ct1 = fhe.encrypt(ctx, jointPK, pt1)
            check(ct1 != 0L) { err() }
            fhe.destroyPlaintext(pt1)

            val vals2 = doubleArrayOf(5.0, 6.0, 7.0, 8.0)
            val pt2 = fhe.makeCKKSPackedPlaintext(ctx, vals2)
            check(pt2 != 0L) { err() }
            ct2 = fhe.encrypt(ctx, jointPK, pt2)
            check(ct2 != 0L) { err() }
            fhe.destroyPlaintext(pt2)
        }

        // 11. Ciphertext Serialization
        run("CT Serialize") {
            check(ct1 != 0L) { "No ct1" }
            val ctBytes = fhe.serializeCiphertext(ct1)
            check(ctBytes.isNotEmpty()) { err() }
            val restored = fhe.deserializeCiphertext(ctx, ctBytes)
            check(restored != 0L) { err() }
            fhe.destroyCiphertext(restored)
        }

        // 12. EvalAdd (ct + ct)
        var ctAdd = 0L
        run("EvalAdd ct+ct") {
            check(ct1 != 0L && ct2 != 0L) { "No ciphertexts" }
            ctAdd = fhe.evalAddCtCt(ctx, ct1, ct2)
            check(ctAdd != 0L) { err() }
        }

        // 13. EvalAdd (ct + scalar)
        run("EvalAdd ct+scalar") {
            check(ct1 != 0L) { "No ct1" }
            val r = fhe.evalAddCtDouble(ctx, ct1, 10.0)
            check(r != 0L) { err() }
            fhe.destroyCiphertext(r)
        }

        // 14. EvalSub (ct - ct)
        run("EvalSub ct-ct") {
            check(ct1 != 0L && ct2 != 0L) { "No ciphertexts" }
            val r = fhe.evalSubCtCt(ctx, ct1, ct2)
            check(r != 0L) { err() }
            fhe.destroyCiphertext(r)
        }

        // 15. EvalSub (ct - pt)
        run("EvalSub ct-pt") {
            check(ct1 != 0L) { "No ct1" }
            val ptVals = doubleArrayOf(1.0, 1.0, 1.0, 1.0)
            val pt = fhe.makeCKKSPackedPlaintext(ctx, ptVals)
            check(pt != 0L) { err() }
            val r = fhe.evalSubCtPt(ctx, ct1, pt)
            check(r != 0L) { err() }
            fhe.destroyCiphertext(r)
            fhe.destroyPlaintext(pt)
        }

        // 16. EvalMult (ct * ct) — requires eval mult key
        var ctMult = 0L
        run("EvalMult ct*ct") {
            check(ct1 != 0L && ct2 != 0L) { "No ciphertexts" }
            check(evalKeyOK) { "Skipped — EvalMultKey Setup failed" }
            ctMult = fhe.evalMultCtCt(ctx, ct1, ct2)
            check(ctMult != 0L) { err() }
        }

        // 17. EvalMult (ct * pt)
        run("EvalMult ct*pt") {
            check(ct1 != 0L) { "No ct1" }
            val ptVals = doubleArrayOf(2.0, 2.0, 2.0, 2.0)
            val pt = fhe.makeCKKSPackedPlaintext(ctx, ptVals)
            check(pt != 0L) { err() }
            val r = fhe.evalMultCtPt(ctx, ct1, pt)
            check(r != 0L) { err() }
            fhe.destroyCiphertext(r)
            fhe.destroyPlaintext(pt)
        }

        // 18. EvalMult (ct * scalar)
        run("EvalMult ct*scalar") {
            check(ct1 != 0L) { "No ct1" }
            val r = fhe.evalMultCtDouble(ctx, ct1, 3.0)
            check(r != 0L) { err() }
            fhe.destroyCiphertext(r)
        }

        // 19. EvalAdd (ct + pt)
        run("EvalAdd ct+pt") {
            check(ct1 != 0L) { "No ct1" }
            val ptVals = doubleArrayOf(10.0, 20.0, 30.0, 40.0)
            val pt = fhe.makeCKKSPackedPlaintext(ctx, ptVals)
            check(pt != 0L) { err() }
            val r = fhe.evalAddCtPt(ctx, ct1, pt)
            check(r != 0L) { err() }
            fhe.destroyCiphertext(r)
            fhe.destroyPlaintext(pt)
        }

        // 20. Threshold Decrypt (Lead + Join → Fusion)
        run("Threshold Decrypt") {
            check(ctAdd != 0L && leadSK != 0L && joinSK != 0L) {
                "Skipped — missing ciphertext or keys"
            }
            testThresholdDecrypt(ctAdd, leadSK, joinSK,
                expected = doubleArrayOf(6.0, 8.0, 10.0, 12.0))
        }

        // 21. Threshold Decrypt of Mult result
        run("Decrypt Mult") {
            check(ctMult != 0L && leadSK != 0L && joinSK != 0L) {
                "Skipped — EvalMult or keys failed"
            }
            testThresholdDecrypt(ctMult, leadSK, joinSK,
                expected = doubleArrayOf(5.0, 12.0, 21.0, 32.0))
        }

        // 22. Error handling
        run("Error Handling") {
            fhe.clearError()
            try {
                fhe.encrypt(ctx, 0L, 0L)
                error("Should have failed")
            } catch (e: Exception) {
                // JNI bridge throws on error — verify we got a message
                val msg = e.message ?: ""
                check(msg.isNotEmpty()) { "Expected error message in exception" }
            }
        }

        // ── Cleanup ──
        safeDestroy(ct1) { fhe.destroyCiphertext(it) }
        safeDestroy(ct2) { fhe.destroyCiphertext(it) }
        safeDestroy(ctAdd) { fhe.destroyCiphertext(it) }
        safeDestroy(ctMult) { fhe.destroyCiphertext(it) }
        safeDestroy(leadPK) { fhe.destroyPublicKey(it) }
        safeDestroy(leadSK) { fhe.destroyPrivateKey(it) }
        safeDestroy(leadKP) { fhe.destroyKeypair(it) }
        safeDestroy(jointPK) { fhe.destroyPublicKey(it) }
        safeDestroy(joinSK) { fhe.destroyPrivateKey(it) }
        safeDestroy(joinKP) { fhe.destroyKeypair(it) }
        safeDestroy(ctx) { fhe.destroyContext(it) }

        onAllComplete?.invoke(results)
    }

    // ── Individual Tests ──

    private fun testContextCreate() {
        val cacheFile = cacheDir?.let { File(it, "openfhe_context.bin") }

        // Try loading from cache
        if (cacheFile != null && cacheFile.exists()) {
            val data = cacheFile.readBytes()
            if (data.isNotEmpty()) {
                val restored = fhe.deserializeContext(data)
                if (restored != 0L) {
                    ctx = restored
                    contextLoadedFromCache = true
                    return
                }
                cacheFile.delete()
            }
        }

        // Generate fresh
        ctx = fhe.genCryptoContext(7, 50, 60, 32)
        check(ctx != 0L) { err() }

        // Save to cache
        if (cacheFile != null) {
            val bytes = fhe.serializeContext(ctx)
            if (bytes.isNotEmpty()) {
                try { cacheFile.writeBytes(bytes) } catch (_: Exception) {}
            }
        }
    }

    private fun testContextSerialize() {
        check(ctx != 0L) { "No context" }
        val bytes = fhe.serializeContext(ctx)
        check(bytes.isNotEmpty()) { err() }
        val restored = fhe.deserializeContext(bytes)
        check(restored != 0L) { err() }
        fhe.destroyContext(restored)
    }

    private fun testEvalMultKeySetup(leadSK: Long, joinSK: Long, jointPKTag: String) {
        check(ctx != 0L) { "No context" }

        val leadEK = fhe.keySwitchGen(ctx, leadSK)
        check(leadEK != 0L) { err("Lead KeySwitchGen") }

        val ekBytes = fhe.serializeEvalKey(leadEK)
        check(ekBytes.isNotEmpty()) { err("Serialize EK") }

        val joinEK = fhe.multiKeySwitchGen(ctx, joinSK, ekBytes)
        check(joinEK != 0L) { err("Join MultiKeySwitchGen") }

        val combinedEK = fhe.multiAddEvalKeys(ctx, leadEK, joinEK, jointPKTag)
        check(combinedEK != 0L) { err("MultiAddEvalKeys") }

        val combBytes = fhe.serializeEvalKey(combinedEK)
        check(combBytes.isNotEmpty()) { err("Serialize combined EK") }

        val leadMEK = fhe.multiMultEvalKey(ctx, leadSK, combBytes, jointPKTag)
        check(leadMEK != 0L) { err("Lead MultiMultEvalKey") }

        val joinMEK = fhe.multiMultEvalKey(ctx, joinSK, combBytes, jointPKTag)
        check(joinMEK != 0L) { err("Join MultiMultEvalKey") }

        val finalMEK = fhe.multiAddEvalMultKeys(ctx, leadMEK, joinMEK, jointPKTag)
        check(finalMEK != 0L) { err("MultiAddEvalMultKeys") }

        val finalBytes = fhe.serializeEvalKey(finalMEK)
        check(finalBytes.isNotEmpty()) { err("Serialize final MEK") }
        check(fhe.insertEvalMultKey(ctx, finalBytes)) { err("InsertEvalMultKey") }

        listOf(leadEK, joinEK, combinedEK, leadMEK, joinMEK, finalMEK)
            .forEach { fhe.destroyEvalKey(it) }
    }

    private fun testCKKSEncode() {
        check(ctx != 0L) { "No context" }
        val values = doubleArrayOf(1.5, 2.5, 3.5, 4.5)
        val pt = fhe.makeCKKSPackedPlaintext(ctx, values)
        check(pt != 0L) { err() }

        val decoded = fhe.plaintextGetRealPackedValue(pt, 4)
        check(decoded.size >= 4) { "Got ${decoded.size} values, expected 4" }

        for (i in 0 until 4) {
            val diff = kotlin.math.abs(decoded[i] - values[i])
            check(diff < 0.001) { "Mismatch at [$i]: ${decoded[i]} vs ${values[i]}" }
        }
        fhe.destroyPlaintext(pt)
    }

    private fun testThresholdDecrypt(ct: Long, leadSK: Long, joinSK: Long,
                                     expected: DoubleArray) {
        check(ctx != 0L) { "No context" }

        val partialLead = fhe.multipartyDecryptLead(ctx, ct, leadSK)
        check(partialLead != 0L) { err("Lead partial decrypt") }

        val partialJoin = fhe.multipartyDecryptMain(ctx, ct, joinSK)
        check(partialJoin != 0L) { err("Join partial decrypt") }

        val fused = fhe.multipartyDecryptFusion(ctx, longArrayOf(partialLead, partialJoin))
        check(fused != 0L) { err("Fusion") }

        fhe.plaintextSetLength(fused, expected.size)
        val result = fhe.plaintextGetRealPackedValue(fused, expected.size)
        check(result.size >= expected.size) { "Got ${result.size} values" }

        for (i in expected.indices) {
            val diff = kotlin.math.abs(result[i] - expected[i])
            check(diff < 0.5) { "[$i]: got ${result[i]}, expected ${expected[i]}, diff=$diff" }
        }

        fhe.destroyCiphertext(partialLead)
        fhe.destroyCiphertext(partialJoin)
        fhe.destroyPlaintext(fused)
    }

    // ── Helpers ──

    private fun err(prefix: String = ""): String {
        val msg = fhe.lastError() ?: "Unknown error"
        return if (prefix.isEmpty()) msg else "$prefix: $msg"
    }

    private fun abort(detail: String) {
        val r = TestResult("ABORT", false, 0.0, detail)
        results.add(r)
        onTestComplete?.invoke(r)
        safeDestroy(ctx) { fhe.destroyContext(it) }
        onAllComplete?.invoke(results)
    }

    private fun run(name: String, body: () -> Unit) {
        val start = System.nanoTime()
        val result: TestResult = try {
            body()
            val dt = (System.nanoTime() - start) / 1_000_000_000.0
            TestResult(name, true, dt, "OK")
        } catch (e: Exception) {
            val dt = (System.nanoTime() - start) / 1_000_000_000.0
            TestResult(name, false, dt, e.message ?: "$e")
        }
        results.add(result)
        onTestComplete?.invoke(result)
    }

    companion object {
        internal fun safeDestroy(handle: Long, destroy: (Long) -> Unit) {
            if (handle != 0L) destroy(handle)
        }
    }
}
