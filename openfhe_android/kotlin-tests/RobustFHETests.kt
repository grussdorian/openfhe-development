package com.example.openfhedemo

import java.io.File
import kotlin.math.abs

/**
 * Robust FHE test suite — verifies correctness, precision, edge cases,
 * chained operations, serialization round-trips under computation,
 * and memory safety. Reuses the cached crypto context from OpenFHETests.
 *
 * Kotlin equivalent of the iOS RobustFHETests.swift.
 * All handles are checked for 0L. Run from a background thread.
 */
class RobustFHETests(private val cacheDir: File? = null) {

    private val fhe = OpenFHE()
    private val results = mutableListOf<OpenFHETests.TestResult>()
    private var ctx = 0L
    private var leadSK = 0L
    private var joinSK = 0L
    private var jointPK = 0L
    private var evalKeyReady = false

    var onTestComplete: ((OpenFHETests.TestResult) -> Unit)? = null
    var onAllComplete: ((List<OpenFHETests.TestResult>) -> Unit)? = null

    // ── Entry Point ──

    fun runAll() {
        results.clear()

        // Setup (shared across all tests)
        run("Setup Context") { setupContext() }
        if (ctx == 0L) { abort("Context setup failed"); return }

        run("Setup Keys") { setupKeys() }
        if (leadSK == 0L || joinSK == 0L || jointPK == 0L) { abort("Key setup failed"); return }

        run("Setup EvalMultKey") { setupEvalMultKey() }

        // ── 1. Precision Tests ──
        run("Precision: Small values") {
            testEncryptDecrypt(doubleArrayOf(0.001, 0.002, 0.003, 0.004), 0.001, "Small")
        }
        run("Precision: Large values") {
            testEncryptDecrypt(doubleArrayOf(1e6, 2e6, 3e6, 4e6), 1.0, "Large")
        }
        run("Precision: Negative values") {
            testEncryptDecrypt(doubleArrayOf(-3.14, -2.71, -1.41, -0.57), 0.01, "Negative")
        }
        run("Precision: Mixed sign") {
            testEncryptDecrypt(doubleArrayOf(-100.0, 0.0, 50.5, 200.0), 0.5, "Mixed")
        }

        // ── 2. Zero Vector ──
        run("Zero vector add") {
            val a = doubleArrayOf(1.0, 2.0, 3.0, 4.0)
            val z = doubleArrayOf(0.0, 0.0, 0.0, 0.0)
            testBinaryOp(a, z, a, BinOp.ADD, 0.5)
        }
        run("Zero vector mult") {
            val a = doubleArrayOf(1.0, 2.0, 3.0, 4.0)
            val z = doubleArrayOf(0.0, 0.0, 0.0, 0.0)
            testBinaryOp(a, z, z, BinOp.MULT, 0.5)
        }

        // ── 3. Identity Operations ──
        run("Add then sub = identity") {
            val a = doubleArrayOf(10.0, 20.0, 30.0, 40.0)
            val b = doubleArrayOf(5.0, 5.0, 5.0, 5.0)
            testChainedAddSub(a, b, a, 0.5)
        }
        run("Mult by 1 = identity") {
            val a = doubleArrayOf(7.0, 8.0, 9.0, 10.0)
            testScalarMult(a, 1.0, a, 0.5)
        }
        run("Mult by -1 = negation") {
            val a = doubleArrayOf(3.0, 6.0, 9.0, 12.0)
            testScalarMult(a, -1.0, doubleArrayOf(-3.0, -6.0, -9.0, -12.0), 0.5)
        }

        // ── 4. Chained Operations ──
        run("(a+b) * c") {
            testChainedAddThenMult(
                a = doubleArrayOf(1.0, 2.0, 3.0, 4.0),
                b = doubleArrayOf(1.0, 1.0, 1.0, 1.0),
                c = doubleArrayOf(2.0, 2.0, 2.0, 2.0),
                expected = doubleArrayOf(4.0, 6.0, 8.0, 10.0),
                tolerance = 0.5
            )
        }
        run("a*b + c*d") {
            testDotProduct(
                a = doubleArrayOf(1.0, 2.0, 3.0, 4.0),
                b = doubleArrayOf(2.0, 2.0, 2.0, 2.0),
                c = doubleArrayOf(1.0, 1.0, 1.0, 1.0),
                d = doubleArrayOf(3.0, 3.0, 3.0, 3.0),
                expected = doubleArrayOf(5.0, 7.0, 9.0, 11.0),
                tolerance = 0.5
            )
        }
        run("Scalar add + scalar mult") {
            testScalarChain(
                a = doubleArrayOf(1.0, 2.0, 3.0, 4.0),
                addScalar = 10.0, multScalar = 3.0,
                expected = doubleArrayOf(33.0, 36.0, 39.0, 42.0),
                tolerance = 0.5
            )
        }

        // ── 5. Serialization Under Computation ──
        run("Serialize mid-computation") { testSerializeMidComputation() }

        // ── 6. Multiple Encryptions Same Plaintext ──
        run("Double encrypt differ") { testDoubleEncrypt() }

        // ── 7. Euclidean Distance² ──
        run("Distance² computation") {
            testDistanceSquared(
                a = doubleArrayOf(1.0, 2.0, 3.0, 4.0),
                b = doubleArrayOf(5.0, 6.0, 7.0, 8.0),
                expectedSquares = doubleArrayOf(16.0, 16.0, 16.0, 16.0),
                tolerance = 1.0
            )
        }

        // ── 8. Memory Stress ──
        run("Alloc/free 20 CTs") { testMemoryStress(20) }

        // ── 9. Large Batch ──
        run("Batch 32 slots") {
            val vals = DoubleArray(32) { it.toDouble() }
            testEncryptDecrypt(vals, 0.5, "Batch32")
        }

        // ── 10. Commutativity ──
        run("Add commutative") {
            val a = doubleArrayOf(1.0, 2.0, 3.0, 4.0)
            val b = doubleArrayOf(5.0, 6.0, 7.0, 8.0)
            testCommutativity(a, b, BinOp.ADD, 0.5)
        }
        run("Mult commutative") {
            val a = doubleArrayOf(1.0, 2.0, 3.0, 4.0)
            val b = doubleArrayOf(5.0, 6.0, 7.0, 8.0)
            check(evalKeyReady) { "EvalMultKey not ready" }
            testCommutativity(a, b, BinOp.MULT, 0.5)
        }

        // Cleanup
        cleanup()
        onAllComplete?.invoke(results)
    }

    // ── Setup ──

    private fun setupContext() {
        val cacheFile = cacheDir?.let { File(it, "openfhe_context.bin") }

        if (cacheFile != null && cacheFile.exists()) {
            val data = cacheFile.readBytes()
            if (data.isNotEmpty()) {
                val restored = fhe.deserializeContext(data)
                if (restored != 0L) { ctx = restored; return }
            }
        }

        ctx = fhe.genCryptoContext(7, 50, 60, 32)
        check(ctx != 0L) { err() }

        if (cacheFile != null) {
            val bytes = fhe.serializeContext(ctx)
            if (bytes.isNotEmpty()) {
                try { cacheFile.writeBytes(bytes) } catch (_: Exception) {}
            }
        }
    }

    private fun setupKeys() {
        check(ctx != 0L) { "No context" }

        val leadKP = fhe.keygen(ctx)
        check(leadKP != 0L) { err() }
        val lPK = fhe.keypairGetPublicKey(leadKP)
        leadSK = fhe.keypairGetSecretKey(leadKP)
        check(lPK != 0L && leadSK != 0L) { err() }

        val pkBytes = fhe.serializePublicKey(lPK)
        check(pkBytes.isNotEmpty()) { err() }

        val joinKP = fhe.multipartyKeygen(ctx, pkBytes)
        check(joinKP != 0L) { err() }
        joinSK = fhe.keypairGetSecretKey(joinKP)
        jointPK = fhe.keypairGetPublicKey(joinKP)
        check(joinSK != 0L && jointPK != 0L) { err() }

        fhe.destroyPublicKey(lPK)
        fhe.destroyKeypair(leadKP)
        fhe.destroyKeypair(joinKP)
    }

    private fun setupEvalMultKey() {
        check(ctx != 0L && leadSK != 0L && joinSK != 0L && jointPK != 0L) {
            "Missing context or keys"
        }

        val tag = fhe.getPublicKeyTag(jointPK) ?: error(err())

        val leadEK = fhe.keySwitchGen(ctx, leadSK)
        check(leadEK != 0L) { err() }

        val ekBytes = fhe.serializeEvalKey(leadEK)
        check(ekBytes.isNotEmpty()) { err() }

        val joinEK = fhe.multiKeySwitchGen(ctx, joinSK, ekBytes)
        check(joinEK != 0L) { err() }

        val combined = fhe.multiAddEvalKeys(ctx, leadEK, joinEK, tag)
        check(combined != 0L) { err() }

        val combBytes = fhe.serializeEvalKey(combined)
        check(combBytes.isNotEmpty()) { err() }

        val lMEK = fhe.multiMultEvalKey(ctx, leadSK, combBytes, tag)
        check(lMEK != 0L) { err() }
        val jMEK = fhe.multiMultEvalKey(ctx, joinSK, combBytes, tag)
        check(jMEK != 0L) { err() }

        val final_ = fhe.multiAddEvalMultKeys(ctx, lMEK, jMEK, tag)
        check(final_ != 0L) { err() }

        val fBytes = fhe.serializeEvalKey(final_)
        check(fBytes.isNotEmpty()) { err() }
        check(fhe.insertEvalMultKey(ctx, fBytes)) { err() }

        listOf(leadEK, joinEK, combined, lMEK, jMEK, final_).forEach { fhe.destroyEvalKey(it) }
        evalKeyReady = true
    }

    // ── Encrypt / Decrypt Helpers ──

    private fun encrypt(values: DoubleArray): Long {
        check(ctx != 0L && jointPK != 0L) { "No context/PK" }
        val pt = fhe.makeCKKSPackedPlaintext(ctx, values)
        check(pt != 0L) { err() }
        val ct = fhe.encrypt(ctx, jointPK, pt)
        check(ct != 0L) { err() }
        fhe.destroyPlaintext(pt)
        return ct
    }

    private fun decrypt(ct: Long, count: Int): DoubleArray {
        check(ctx != 0L && leadSK != 0L && joinSK != 0L) { "No context/keys" }
        val pL = fhe.multipartyDecryptLead(ctx, ct, leadSK)
        check(pL != 0L) { err("Lead partial") }
        val pJ = fhe.multipartyDecryptMain(ctx, ct, joinSK)
        check(pJ != 0L) { err("Join partial") }

        val fused = fhe.multipartyDecryptFusion(ctx, longArrayOf(pL, pJ))
        check(fused != 0L) { err("Fusion") }

        fhe.plaintextSetLength(fused, count)
        val out = fhe.plaintextGetRealPackedValue(fused, count)
        check(out.size >= count) { "Got ${out.size} values, expected $count" }

        fhe.destroyCiphertext(pL)
        fhe.destroyCiphertext(pJ)
        fhe.destroyPlaintext(fused)
        return out
    }

    private fun assertClose(actual: DoubleArray, expected: DoubleArray,
                            tolerance: Double, label: String) {
        check(actual.size >= expected.size) {
            "$label: got ${actual.size} values, expected ${expected.size}"
        }
        for (i in expected.indices) {
            val diff = abs(actual[i] - expected[i])
            check(diff < tolerance) {
                "$label[$i]: got ${"%.4f".format(actual[i])}, " +
                "expected ${"%.4f".format(expected[i])}, diff=${"%.4f".format(diff)}"
            }
        }
    }

    // ── Test Implementations ──

    private fun testEncryptDecrypt(values: DoubleArray, tolerance: Double, label: String) {
        val ct = encrypt(values)
        val result = decrypt(ct, values.size)
        fhe.destroyCiphertext(ct)
        assertClose(result, values, tolerance, label)
    }

    enum class BinOp { ADD, SUB, MULT }

    private fun testBinaryOp(a: DoubleArray, b: DoubleArray, expected: DoubleArray,
                             op: BinOp, tolerance: Double) {
        check(ctx != 0L) { "No context" }
        val ctA = encrypt(a)
        val ctB = encrypt(b)

        val ctR = when (op) {
            BinOp.ADD  -> fhe.evalAddCtCt(ctx, ctA, ctB)
            BinOp.SUB  -> fhe.evalSubCtCt(ctx, ctA, ctB)
            BinOp.MULT -> fhe.evalMultCtCt(ctx, ctA, ctB)
        }
        check(ctR != 0L) { err() }

        val result = decrypt(ctR, expected.size)
        fhe.destroyCiphertext(ctA)
        fhe.destroyCiphertext(ctB)
        fhe.destroyCiphertext(ctR)
        assertClose(result, expected, tolerance, "$op")
    }

    private fun testChainedAddSub(a: DoubleArray, b: DoubleArray,
                                  expected: DoubleArray, tolerance: Double) {
        check(ctx != 0L) { "No context" }
        val ctA = encrypt(a)
        val ctB = encrypt(b)
        val ctSum = fhe.evalAddCtCt(ctx, ctA, ctB)
        check(ctSum != 0L) { err() }
        val ctResult = fhe.evalSubCtCt(ctx, ctSum, ctB)
        check(ctResult != 0L) { err() }

        val result = decrypt(ctResult, expected.size)
        listOf(ctA, ctB, ctSum, ctResult).forEach { fhe.destroyCiphertext(it) }
        assertClose(result, expected, tolerance, "AddSub")
    }

    private fun testScalarMult(a: DoubleArray, scalar: Double,
                               expected: DoubleArray, tolerance: Double) {
        check(ctx != 0L) { "No context" }
        val ctA = encrypt(a)
        val ctR = fhe.evalMultCtDouble(ctx, ctA, scalar)
        check(ctR != 0L) { err() }

        val result = decrypt(ctR, expected.size)
        fhe.destroyCiphertext(ctA)
        fhe.destroyCiphertext(ctR)
        assertClose(result, expected, tolerance, "ScalarMult")
    }

    private fun testChainedAddThenMult(a: DoubleArray, b: DoubleArray, c: DoubleArray,
                                       expected: DoubleArray, tolerance: Double) {
        check(ctx != 0L) { "No context" }
        val ctA = encrypt(a)
        val ctB = encrypt(b)
        val ctC = encrypt(c)

        val ctSum = fhe.evalAddCtCt(ctx, ctA, ctB)
        check(ctSum != 0L) { err() }
        check(evalKeyReady) { "No eval mult key" }
        val ctR = fhe.evalMultCtCt(ctx, ctSum, ctC)
        check(ctR != 0L) { err() }

        val result = decrypt(ctR, expected.size)
        listOf(ctA, ctB, ctC, ctSum, ctR).forEach { fhe.destroyCiphertext(it) }
        assertClose(result, expected, tolerance, "(a+b)*c")
    }

    private fun testDotProduct(a: DoubleArray, b: DoubleArray, c: DoubleArray, d: DoubleArray,
                               expected: DoubleArray, tolerance: Double) {
        check(ctx != 0L) { "No context" }
        check(evalKeyReady) { "No eval mult key" }

        val ctA = encrypt(a); val ctB = encrypt(b)
        val ctC = encrypt(c); val ctD = encrypt(d)

        val ctAB = fhe.evalMultCtCt(ctx, ctA, ctB)
        check(ctAB != 0L) { err() }
        val ctCD = fhe.evalMultCtCt(ctx, ctC, ctD)
        check(ctCD != 0L) { err() }
        val ctR = fhe.evalAddCtCt(ctx, ctAB, ctCD)
        check(ctR != 0L) { err() }

        val result = decrypt(ctR, expected.size)
        listOf(ctA, ctB, ctC, ctD, ctAB, ctCD, ctR).forEach { fhe.destroyCiphertext(it) }
        assertClose(result, expected, tolerance, "a*b+c*d")
    }

    private fun testScalarChain(a: DoubleArray, addScalar: Double, multScalar: Double,
                                expected: DoubleArray, tolerance: Double) {
        check(ctx != 0L) { "No context" }
        val ctA = encrypt(a)

        val ctAdded = fhe.evalAddCtDouble(ctx, ctA, addScalar)
        check(ctAdded != 0L) { err() }
        val ctR = fhe.evalMultCtDouble(ctx, ctAdded, multScalar)
        check(ctR != 0L) { err() }

        val result = decrypt(ctR, expected.size)
        listOf(ctA, ctAdded, ctR).forEach { fhe.destroyCiphertext(it) }
        assertClose(result, expected, tolerance, "ScalarChain")
    }

    private fun testSerializeMidComputation() {
        check(ctx != 0L) { "No context" }
        val a = doubleArrayOf(10.0, 20.0, 30.0, 40.0)
        val b = doubleArrayOf(1.0, 2.0, 3.0, 4.0)
        val ctA = encrypt(a)
        val ctB = encrypt(b)
        val ctSum = fhe.evalAddCtCt(ctx, ctA, ctB)
        check(ctSum != 0L) { err() }

        // Serialize the intermediate result
        val bytes = fhe.serializeCiphertext(ctSum)
        check(bytes.isNotEmpty()) { err() }

        // Deserialize and decrypt
        val restored = fhe.deserializeCiphertext(ctx, bytes)
        check(restored != 0L) { err() }

        val result = decrypt(restored, 4)
        listOf(ctA, ctB, ctSum, restored).forEach { fhe.destroyCiphertext(it) }
        assertClose(result, doubleArrayOf(11.0, 22.0, 33.0, 44.0), 0.5, "SerMidComp")
    }

    private fun testDoubleEncrypt() {
        val vals = doubleArrayOf(42.0, 43.0, 44.0, 45.0)
        val ct1 = encrypt(vals)
        val ct2 = encrypt(vals)

        // Serialize both — they should differ (randomized encryption)
        val bytes1 = fhe.serializeCiphertext(ct1)
        val bytes2 = fhe.serializeCiphertext(ct2)
        check(bytes1.isNotEmpty() && bytes2.isNotEmpty()) { err() }
        check(!bytes1.contentEquals(bytes2)) {
            "Two encryptions produced identical ciphertexts — randomization broken"
        }

        // Both should decrypt to same values
        val r1 = decrypt(ct1, 4)
        val r2 = decrypt(ct2, 4)
        fhe.destroyCiphertext(ct1)
        fhe.destroyCiphertext(ct2)
        assertClose(r1, vals, 0.5, "Enc1")
        assertClose(r2, vals, 0.5, "Enc2")
    }

    private fun testDistanceSquared(a: DoubleArray, b: DoubleArray,
                                    expectedSquares: DoubleArray, tolerance: Double) {
        check(ctx != 0L) { "No context" }
        check(evalKeyReady) { "No eval mult key" }

        val ctA = encrypt(a)
        val ctB = encrypt(b)

        val ctDiff = fhe.evalSubCtCt(ctx, ctA, ctB)
        check(ctDiff != 0L) { err() }
        val ctSq = fhe.evalMultCtCt(ctx, ctDiff, ctDiff)
        check(ctSq != 0L) { err() }

        val result = decrypt(ctSq, expectedSquares.size)
        listOf(ctA, ctB, ctDiff, ctSq).forEach { fhe.destroyCiphertext(it) }
        assertClose(result, expectedSquares, tolerance, "Dist²")
    }

    private fun testMemoryStress(count: Int) {
        val vals = doubleArrayOf(1.0, 2.0, 3.0, 4.0)
        val ciphertexts = mutableListOf<Long>()

        for (i in 0 until count) {
            ciphertexts.add(encrypt(vals))
        }

        val result = decrypt(ciphertexts.last(), 4)
        assertClose(result, vals, 0.5, "Stress")

        ciphertexts.forEach { fhe.destroyCiphertext(it) }
    }

    private fun testCommutativity(a: DoubleArray, b: DoubleArray,
                                  op: BinOp, tolerance: Double) {
        check(ctx != 0L) { "No context" }
        val ctA = encrypt(a)
        val ctB = encrypt(b)

        val (ct1, ct2) = when (op) {
            BinOp.ADD  -> Pair(fhe.evalAddCtCt(ctx, ctA, ctB), fhe.evalAddCtCt(ctx, ctB, ctA))
            BinOp.MULT -> Pair(fhe.evalMultCtCt(ctx, ctA, ctB), fhe.evalMultCtCt(ctx, ctB, ctA))
            BinOp.SUB  -> error("Sub is not commutative")
        }
        check(ct1 != 0L && ct2 != 0L) { err() }

        val v1 = decrypt(ct1, a.size)
        val v2 = decrypt(ct2, a.size)
        listOf(ctA, ctB, ct1, ct2).forEach { fhe.destroyCiphertext(it) }
        assertClose(v1, v2, tolerance, "Commute-$op")
    }

    // ── Cleanup ──

    private fun cleanup() {
        OpenFHETests.safeDestroy(leadSK) { fhe.destroyPrivateKey(it) }
        OpenFHETests.safeDestroy(joinSK) { fhe.destroyPrivateKey(it) }
        OpenFHETests.safeDestroy(jointPK) { fhe.destroyPublicKey(it) }
        OpenFHETests.safeDestroy(ctx) { fhe.destroyContext(it) }
    }

    // ── Helpers ──

    private fun err(prefix: String = ""): String {
        val msg = fhe.lastError() ?: "Unknown error"
        return if (prefix.isEmpty()) msg else "$prefix: $msg"
    }

    private fun abort(detail: String) {
        val r = OpenFHETests.TestResult("ABORT", false, 0.0, detail)
        results.add(r)
        onTestComplete?.invoke(r)
        cleanup()
        onAllComplete?.invoke(results)
    }

    private fun run(name: String, body: () -> Unit) {
        val start = System.nanoTime()
        val result: OpenFHETests.TestResult = try {
            body()
            val dt = (System.nanoTime() - start) / 1_000_000_000.0
            OpenFHETests.TestResult(name, true, dt, "OK")
        } catch (e: Exception) {
            val dt = (System.nanoTime() - start) / 1_000_000_000.0
            OpenFHETests.TestResult(name, false, dt, e.message ?: "$e")
        }
        results.add(result)
        onTestComplete?.invoke(result)
    }
}
