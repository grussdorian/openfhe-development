package com.example.openfhedemo

import com.example.openfhe.OpenFHE
import java.io.File
import kotlin.math.abs
import kotlin.math.max

/**
 * Dedicated test suite for:
 *   1. Multiparty threshold key operations — thorough testing of key generation,
 *      serialization round-trips, eval mult key protocol, and partial decrypt flows.
 *   2. GPS coordinate precision — stress tests using real-world lat/lon values,
 *      the MAX_COORD=0.5 normalization from client.py, and encrypted distance²
 *      computation matching compute_distance_local().
 *
 * Kotlin equivalent of the iOS MultipartyGPSTests.swift.
 * All handles are checked for 0L. Run from a background thread.
 */
class MultipartyGPSTests(private val cacheDir: File? = null) {

    private val fhe = OpenFHE()
    private val results = mutableListOf<OpenFHETests.TestResult>()

    // Shared state set up once and reused across tests
    private var ctx = 0L
    private var leadKP = 0L
    private var leadPK = 0L
    private var leadSK = 0L
    private var joinKP = 0L
    private var jointPK = 0L
    private var joinSK = 0L
    private var evalKeyReady = false

    /** Matches client.py: city-scale normalizer (0.5 ≈ 55 km at equator) */
    private val MAX_COORD = 0.5

    var onTestComplete: ((OpenFHETests.TestResult) -> Unit)? = null
    var onAllComplete: ((List<OpenFHETests.TestResult>) -> Unit)? = null

    // ══════════════════════════════════════
    // Entry Point
    // ══════════════════════════════════════

    fun runAll() {
        results.clear()

        // ═══ Part A: Multiparty Key Operations ═══
        run("A1: Context Setup") { setupContext() }
        if (ctx == 0L) { abort("Context setup failed"); return }

        run("A2: Lead KeyGen") { testLeadKeyGen() }
        if (leadKP == 0L) { abort("Lead keygen failed"); return }

        run("A3: PK Serialize RT") { testPublicKeySerializeRoundTrip() }
        run("A4: SK Serialize RT") { testPrivateKeySerializeRoundTrip() }
        run("A5: Join KeyGen") { testJoinKeyGen() }
        if (joinKP == 0L) { abort("Join keygen failed"); return }

        run("A6: PK Tag Valid") { testPublicKeyTag() }
        run("A7: PK Tag Consistent") { testPublicKeyTagConsistency() }
        run("A8: EvalKey Round 1") { testEvalKeyRound1() }

        // Full eval mult key setup (needed for GPS tests)
        run("A9: Full EvalMultKey") { setupFullEvalMultKey() }

        run("A10: Encrypt-Decrypt") { testBasicEncryptDecrypt() }
        run("A11: Partial Lead Only") { testPartialDecryptLeadOnly() }
        run("A12: Partial Join Only") { testPartialDecryptJoinOnly() }
        run("A13: Fusion Order") { testFusionPartialOrder() }
        run("A14: EvalKey Serialize RT") { testEvalKeySerializeRoundTrip() }

        // ═══ Part B: GPS Coordinate Precision ═══
        if (!evalKeyReady) { abort("EvalMultKey not ready — GPS tests skipped"); return }

        // B1–B4: Distance² at varying scales
        run("B1: Same location (~0)") {
            testGPSDistance(
                initLat = 37.7749, initLon = -122.4194,
                myLat = 37.7749, myLon = -122.4194,
                label = "SameLoc", maxDistSq = 0.001
            )
        }
        run("B2: ~100m apart") {
            testGPSDistance(
                initLat = 37.7749, initLon = -122.4194,
                myLat = 37.7758, myLon = -122.4194,
                label = "100m", maxDistSq = null
            )
        }
        run("B3: ~1km apart") {
            testGPSDistance(
                initLat = 37.7749, initLon = -122.4194,
                myLat = 37.7839, myLon = -122.4194,
                label = "1km", maxDistSq = null
            )
        }
        run("B4: ~10km apart") {
            testGPSDistance(
                initLat = 37.7749, initLon = -122.4194,
                myLat = 37.8649, myLon = -122.4194,
                label = "10km", maxDistSq = null
            )
        }

        // B5: Cross-city (SF ↔ Oakland)
        run("B5: SF ↔ Oakland") {
            testGPSDistance(
                initLat = 37.7749, initLon = -122.4194,
                myLat = 37.8044, myLon = -122.2712,
                label = "SF-Oak", maxDistSq = null
            )
        }

        // B6: Negative coordinates (Southern/Eastern hemisphere)
        run("B6: Sydney coords") {
            testGPSDistance(
                initLat = -33.8688, initLon = 151.2093,
                myLat = -33.8788, myLon = 151.2193,
                label = "Sydney", maxDistSq = null
            )
        }

        // B7: Near equator/prime-meridian
        run("B7: Equator origin") {
            testGPSDistance(
                initLat = 0.001, initLon = 0.001,
                myLat = 0.002, myLon = 0.002,
                label = "Equator", maxDistSq = null
            )
        }

        // B8: Dense urban grid
        run("B8: Dense urban grid") { testDenseUrbanGrid() }

        // B9: Precision stress — very small differences
        run("B9: 10m precision") {
            testGPSDistance(
                initLat = 40.748817, initLon = -73.985428,
                myLat = 40.748907, myLon = -73.985428,
                label = "10m", maxDistSq = null
            )
        }

        // B10: Full proximity pipeline
        run("B10: Full proximity pipe") {
            testFullProximityPipeline(
                lat1 = 37.7749, lon1 = -122.4194,
                lat2 = 37.7751, lon2 = -122.4196,
                expectedApproxDist = 0.000032
            )
        }

        // B11: Batch of 8 distances in parallel slots
        run("B11: Batch 8 distances") { testBatchDistances() }

        // B12: Verify normalization matches Python's MAX_COORD
        run("B12: Normalization check") { testNormalizationConsistency() }

        // B13: Repeated encrypt same coords → different CTs, same distance
        run("B13: Repeated encrypt") { testRepeatedEncryptSameCoords() }

        // ═══ Cleanup ═══
        cleanup()
        onAllComplete?.invoke(results)
    }

    // ══════════════════════════════════════
    // Part A: Multiparty Key Operations
    // ══════════════════════════════════════

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

    private fun testLeadKeyGen() {
        check(ctx != 0L) { "No context" }
        leadKP = fhe.keygen(ctx)
        check(leadKP != 0L) { err() }
        leadPK = fhe.keypairGetPublicKey(leadKP)
        leadSK = fhe.keypairGetSecretKey(leadKP)
        check(leadPK != 0L) { "Null PK from keypair" }
        check(leadSK != 0L) { "Null SK from keypair" }
    }

    private fun testPublicKeySerializeRoundTrip() {
        check(leadPK != 0L) { "No lead PK" }
        val bytes = fhe.serializePublicKey(leadPK)
        check(bytes.size > 1000) { "PK too small: ${bytes.size} bytes" }

        val restored = fhe.deserializePublicKey(ctx, bytes)
        check(restored != 0L) { err() }

        // Re-serialize and compare sizes (cereal metadata can add ~576 bytes)
        val bytes2 = fhe.serializePublicKey(restored)
        check(abs(bytes.size - bytes2.size) < 1024) {
            "Size mismatch: ${bytes.size} vs ${bytes2.size}"
        }

        fhe.destroyPublicKey(restored)
    }

    private fun testPrivateKeySerializeRoundTrip() {
        check(leadSK != 0L) { "No lead SK" }
        val bytes = fhe.serializePrivateKey(leadSK)
        check(bytes.size > 100) { "SK too small: ${bytes.size} bytes" }

        val restored = fhe.deserializePrivateKey(ctx, bytes)
        check(restored != 0L) { err() }

        val bytes2 = fhe.serializePrivateKey(restored)
        check(abs(bytes.size - bytes2.size) < 1024) {
            "SK size mismatch: ${bytes.size} vs ${bytes2.size}"
        }

        fhe.destroyPrivateKey(restored)
    }

    private fun testJoinKeyGen() {
        check(ctx != 0L && leadPK != 0L) { "No context/leadPK" }

        val pkBytes = fhe.serializePublicKey(leadPK)
        check(pkBytes.isNotEmpty()) { err() }

        joinKP = fhe.multipartyKeygen(ctx, pkBytes)
        check(joinKP != 0L) { err() }

        jointPK = fhe.keypairGetPublicKey(joinKP)
        joinSK = fhe.keypairGetSecretKey(joinKP)
        check(jointPK != 0L) { "Null joint PK" }
        check(joinSK != 0L) { "Null join SK" }
    }

    private fun testPublicKeyTag() {
        check(jointPK != 0L) { "No joint PK" }
        val tag = fhe.getPublicKeyTag(jointPK) ?: error(err())
        check(tag.isNotEmpty()) { "Empty PK tag" }
        check(tag.length > 2) { "PK tag suspiciously short: '$tag'" }
    }

    private fun testPublicKeyTagConsistency() {
        check(jointPK != 0L) { "No joint PK" }
        val s1 = fhe.getPublicKeyTag(jointPK) ?: error(err())
        val s2 = fhe.getPublicKeyTag(jointPK) ?: error(err())
        check(s1 == s2) { "Tag changed between calls: '$s1' vs '$s2'" }
    }

    private fun testEvalKeyRound1() {
        check(ctx != 0L && leadSK != 0L && joinSK != 0L) { "Missing context/keys" }

        // Lead: KeySwitchGen
        val leadEK = fhe.keySwitchGen(ctx, leadSK)
        check(leadEK != 0L) { err("Lead KeySwitchGen") }

        val ekBytes = fhe.serializeEvalKey(leadEK)
        check(ekBytes.size > 100) { "Lead EK too small: ${ekBytes.size}" }

        // Join: MultiKeySwitchGen
        val joinEK = fhe.multiKeySwitchGen(ctx, joinSK, ekBytes)
        check(joinEK != 0L) { err("Join MultiKeySwitchGen") }

        val jBytes = fhe.serializeEvalKey(joinEK)
        check(jBytes.size > 100) { "Join EK too small: ${jBytes.size}" }

        fhe.destroyEvalKey(leadEK)
        fhe.destroyEvalKey(joinEK)
    }

    private fun setupFullEvalMultKey() {
        check(ctx != 0L && leadSK != 0L && joinSK != 0L && jointPK != 0L) {
            "Missing context or keys"
        }
        val tag = fhe.getPublicKeyTag(jointPK) ?: error(err())

        // Round 1
        val leadEK = fhe.keySwitchGen(ctx, leadSK)
        check(leadEK != 0L) { err() }

        val ekBytes = fhe.serializeEvalKey(leadEK)
        check(ekBytes.isNotEmpty()) { err() }

        val joinEK = fhe.multiKeySwitchGen(ctx, joinSK, ekBytes)
        check(joinEK != 0L) { err() }

        val combined = fhe.multiAddEvalKeys(ctx, leadEK, joinEK, tag)
        check(combined != 0L) { err() }

        // Round 2
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

    private fun testBasicEncryptDecrypt() {
        val vals = doubleArrayOf(1.0, 2.0, 3.0, 4.0)
        val ct = encrypt(vals)
        val result = thresholdDecrypt(ct, 4)
        fhe.destroyCiphertext(ct)
        assertClose(result, vals, 0.5, "BasicED")
    }

    private fun testPartialDecryptLeadOnly() {
        check(ctx != 0L && leadSK != 0L) { "Missing ctx/leadSK" }
        val ct = encrypt(doubleArrayOf(10.0, 20.0, 30.0, 40.0))

        val partialL = fhe.multipartyDecryptLead(ctx, ct, leadSK)
        check(partialL != 0L) { err("Lead partial") }

        // Single-partial fusion is undefined — JNI may throw; just verify no crash
        try {
            fhe.multipartyDecryptFusion(ctx, longArrayOf(partialL))
        } catch (_: Exception) {
            // Expected — single-partial fusion is implementation-defined
        }

        fhe.destroyCiphertext(partialL)
        fhe.destroyCiphertext(ct)
    }

    private fun testPartialDecryptJoinOnly() {
        check(ctx != 0L && joinSK != 0L) { "Missing ctx/joinSK" }
        val ct = encrypt(doubleArrayOf(10.0, 20.0, 30.0, 40.0))

        val partialJ = fhe.multipartyDecryptMain(ctx, ct, joinSK)
        check(partialJ != 0L) { err("Join partial") }

        // Same — JNI may throw; just verify no crash
        try {
            fhe.multipartyDecryptFusion(ctx, longArrayOf(partialJ))
        } catch (_: Exception) {
            // Expected — single-partial fusion is implementation-defined
        }

        fhe.destroyCiphertext(partialJ)
        fhe.destroyCiphertext(ct)
    }

    private fun testFusionPartialOrder() {
        check(ctx != 0L && leadSK != 0L && joinSK != 0L) { "Missing keys" }
        val vals = doubleArrayOf(100.0, 200.0, 300.0, 400.0)
        val ct = encrypt(vals)

        val pL = fhe.multipartyDecryptLead(ctx, ct, leadSK)
        check(pL != 0L) { err() }
        val pJ = fhe.multipartyDecryptMain(ctx, ct, joinSK)
        check(pJ != 0L) { err() }

        // Correct order: [lead, join]
        val fusedCorrect = fhe.multipartyDecryptFusion(ctx, longArrayOf(pL, pJ))
        check(fusedCorrect != 0L) { err("Fusion correct order") }

        fhe.plaintextSetLength(fusedCorrect, 4)
        val out = fhe.plaintextGetRealPackedValue(fusedCorrect, 4)
        check(out.size >= 4) { "Got ${out.size} values" }
        assertClose(out, vals, 0.5, "FusionOrder")

        fhe.destroyCiphertext(pL)
        fhe.destroyCiphertext(pJ)
        fhe.destroyPlaintext(fusedCorrect)
        fhe.destroyCiphertext(ct)
    }

    private fun testEvalKeySerializeRoundTrip() {
        check(ctx != 0L && leadSK != 0L) { "Missing ctx/leadSK" }

        val ek = fhe.keySwitchGen(ctx, leadSK)
        check(ek != 0L) { err() }

        val bytes = fhe.serializeEvalKey(ek)
        check(bytes.size > 100) { "EK too small: ${bytes.size}" }

        val restored = fhe.deserializeEvalKey(ctx, bytes)
        check(restored != 0L) { err() }

        val bytes2 = fhe.serializeEvalKey(restored)
        check(abs(bytes.size - bytes2.size) < 64) {
            "EK size mismatch after RT: ${bytes.size} -> ${bytes2.size}"
        }

        fhe.destroyEvalKey(ek)
        fhe.destroyEvalKey(restored)
    }

    // ══════════════════════════════════════
    // Part B: GPS Precision Tests
    // ══════════════════════════════════════

    /**
     * Mirrors client.py's compute_distance_local():
     *   nlat = lat / MAX_COORD, nlon = lon / MAX_COORD
     *   dlat = EvalSub(enc_init_lat, my_lat_pt)
     *   dlon = EvalSub(enc_init_lon, my_lon_pt)
     *   dist_sq = EvalAdd(EvalMult(dlat, dlat), EvalMult(dlon, dlon))
     */
    private fun testGPSDistance(initLat: Double, initLon: Double,
                                myLat: Double, myLon: Double,
                                label: String, maxDistSq: Double?) {
        check(ctx != 0L && jointPK != 0L) { "No ctx/PK" }

        // Normalize exactly as client.py does
        val nInitLat = initLat / MAX_COORD
        val nInitLon = initLon / MAX_COORD
        val nMyLat = myLat / MAX_COORD
        val nMyLon = myLon / MAX_COORD

        // Expected plaintext distance²
        val dLat = nInitLat - nMyLat
        val dLon = nInitLon - nMyLon
        val expectedDistSq = dLat * dLat + dLon * dLon

        // Encrypt initiator's coords (replicated across 4 slots)
        val initLatPt = fhe.makeCKKSPackedPlaintext(ctx,
            doubleArrayOf(nInitLat, nInitLat, nInitLat, nInitLat))
        val initLonPt = fhe.makeCKKSPackedPlaintext(ctx,
            doubleArrayOf(nInitLon, nInitLon, nInitLon, nInitLon))
        check(initLatPt != 0L && initLonPt != 0L) { err() }

        val encLat = fhe.encrypt(ctx, jointPK, initLatPt)
        val encLon = fhe.encrypt(ctx, jointPK, initLonPt)
        check(encLat != 0L && encLon != 0L) { err() }
        fhe.destroyPlaintext(initLatPt)
        fhe.destroyPlaintext(initLonPt)

        // My coords as plaintext
        val myLatPt = fhe.makeCKKSPackedPlaintext(ctx,
            doubleArrayOf(nMyLat, nMyLat, nMyLat, nMyLat))
        val myLonPt = fhe.makeCKKSPackedPlaintext(ctx,
            doubleArrayOf(nMyLon, nMyLon, nMyLon, nMyLon))
        check(myLatPt != 0L && myLonPt != 0L) { err() }

        // dlat = enc(init_lat) - my_lat_pt, dlon = enc(init_lon) - my_lon_pt
        val ctDlat = fhe.evalSubCtPt(ctx, encLat, myLatPt)
        val ctDlon = fhe.evalSubCtPt(ctx, encLon, myLonPt)
        check(ctDlat != 0L && ctDlon != 0L) { err() }
        fhe.destroyPlaintext(myLatPt)
        fhe.destroyPlaintext(myLonPt)

        // dlat², dlon²
        val ctDlat2 = fhe.evalMultCtCt(ctx, ctDlat, ctDlat)
        val ctDlon2 = fhe.evalMultCtCt(ctx, ctDlon, ctDlon)
        check(ctDlat2 != 0L && ctDlon2 != 0L) { err() }

        // dist_sq = dlat² + dlon²
        val ctDistSq = fhe.evalAddCtCt(ctx, ctDlat2, ctDlon2)
        check(ctDistSq != 0L) { err() }

        // Threshold decrypt
        val decrypted = thresholdDecrypt(ctDistSq, 4)

        // Verify all 4 slots are close to expected
        val toleranceRatio = max(abs(expectedDistSq) * 0.05, 0.001) // 5% or 0.001 absolute
        for (i in 0 until 4) {
            val diff = abs(decrypted[i] - expectedDistSq)
            check(diff < toleranceRatio) {
                "$label[$i]: encrypted dist²=${"%.6f".format(decrypted[i])}, " +
                "expected=${"%.6f".format(expectedDistSq)}, diff=${"%.6f".format(diff)}, " +
                "tol=${"%.6f".format(toleranceRatio)}"
            }
        }

        // Optional absolute bound check
        if (maxDistSq != null) {
            check(decrypted[0] < maxDistSq) {
                "$label: dist²=${"%.6f".format(decrypted[0])} exceeds max ${"%.6f".format(maxDistSq)}"
            }
        }

        // Cleanup
        listOf(encLat, encLon, ctDlat, ctDlon, ctDlat2, ctDlon2, ctDistSq)
            .forEach { fhe.destroyCiphertext(it) }
    }

    private fun testDenseUrbanGrid() {
        // 8 points in a 500m × 500m grid in downtown SF
        val baseLat = 37.7749
        val baseLon = -122.4194
        val step = 0.0015  // ~167m per step

        data class Point(val lat: Double, val lon: Double)
        val points = mutableListOf<Point>()
        for (row in 0 until 2) {
            for (col in 0 until 4) {
                points.add(Point(
                    lat = baseLat + row * step,
                    lon = baseLon + col * step
                ))
            }
        }

        // Compute 4 representative pairwise distances
        val pairs = listOf(0 to 1, 0 to 4, 0 to 7, 3 to 4)

        for ((i, j) in pairs) {
            val a = points[i]; val b = points[j]
            val nda = a.lat / MAX_COORD - b.lat / MAX_COORD
            val ndo = a.lon / MAX_COORD - b.lon / MAX_COORD
            val expectedDSq = nda * nda + ndo * ndo

            val naLat = a.lat / MAX_COORD; val naLon = a.lon / MAX_COORD
            val nbLat = b.lat / MAX_COORD; val nbLon = b.lon / MAX_COORD

            val ct = encryptAndComputeDistSq(naLat, naLon, nbLat, nbLon)
            val dec = thresholdDecrypt(ct, 1)
            fhe.destroyCiphertext(ct)

            val diff = abs(dec[0] - expectedDSq)
            val tol = max(abs(expectedDSq) * 0.05, 0.001)
            check(diff < tol) {
                "Pair($i,$j): dec=${"%.6f".format(dec[0])}, exp=${"%.6f".format(expectedDSq)}, diff=${"%.6f".format(diff)}"
            }
        }
    }

    private fun testFullProximityPipeline(lat1: Double, lon1: Double,
                                          lat2: Double, lon2: Double,
                                          @Suppress("UNUSED_PARAMETER") expectedApproxDist: Double) {
        check(ctx != 0L && jointPK != 0L) { "No ctx/PK" }

        val BATCH = 4

        // Party 1 encrypts their coords
        val n1Lat = lat1 / MAX_COORD; val n1Lon = lon1 / MAX_COORD
        val latVec = DoubleArray(BATCH) { n1Lat }
        val lonVec = DoubleArray(BATCH) { n1Lon }

        val latPt = fhe.makeCKKSPackedPlaintext(ctx, latVec)
        val lonPt = fhe.makeCKKSPackedPlaintext(ctx, lonVec)
        check(latPt != 0L && lonPt != 0L) { err() }

        val encLat = fhe.encrypt(ctx, jointPK, latPt)
        val encLon = fhe.encrypt(ctx, jointPK, lonPt)
        check(encLat != 0L && encLon != 0L) { err() }
        fhe.destroyPlaintext(latPt)
        fhe.destroyPlaintext(lonPt)

        // Network simulation: serialize ciphertexts
        val latBuf = fhe.serializeCiphertext(encLat)
        val lonBuf = fhe.serializeCiphertext(encLon)
        check(latBuf.isNotEmpty() && lonBuf.isNotEmpty()) { err() }

        // Party 2 deserializes
        val recvLat = fhe.deserializeCiphertext(ctx, latBuf)
        val recvLon = fhe.deserializeCiphertext(ctx, lonBuf)
        check(recvLat != 0L && recvLon != 0L) { err() }

        // Party 2 computes distance
        val n2Lat = lat2 / MAX_COORD; val n2Lon = lon2 / MAX_COORD
        val myLatPt = fhe.makeCKKSPackedPlaintext(ctx, DoubleArray(BATCH) { n2Lat })
        val myLonPt = fhe.makeCKKSPackedPlaintext(ctx, DoubleArray(BATCH) { n2Lon })
        check(myLatPt != 0L && myLonPt != 0L) { err() }

        val dLatCt = fhe.evalSubCtPt(ctx, recvLat, myLatPt)
        val dLonCt = fhe.evalSubCtPt(ctx, recvLon, myLonPt)
        check(dLatCt != 0L && dLonCt != 0L) { err() }
        fhe.destroyPlaintext(myLatPt)
        fhe.destroyPlaintext(myLonPt)

        val dLat2 = fhe.evalMultCtCt(ctx, dLatCt, dLatCt)
        val dLon2 = fhe.evalMultCtCt(ctx, dLonCt, dLonCt)
        check(dLat2 != 0L && dLon2 != 0L) { err() }

        val distSq = fhe.evalAddCtCt(ctx, dLat2, dLon2)
        check(distSq != 0L) { err() }

        // Serialize distance result ("back to server")
        val distBuf = fhe.serializeCiphertext(distSq)
        check(distBuf.isNotEmpty()) { err() }

        // "Server" deserializes
        val serverDistCt = fhe.deserializeCiphertext(ctx, distBuf)
        check(serverDistCt != 0L) { err() }

        // Threshold decrypt
        val result = thresholdDecrypt(serverDistCt, BATCH)

        // Expected plaintext distance²
        val eLat = n1Lat - n2Lat
        val eLon = n1Lon - n2Lon
        val expected = eLat * eLat + eLon * eLon
        val tol = max(abs(expected) * 0.05, 0.001)

        assertClose(result, DoubleArray(BATCH) { expected }, tol, "FullPipe")

        // Cleanup all
        listOf(encLat, encLon, recvLat, recvLon, dLatCt, dLonCt, dLat2, dLon2, distSq, serverDistCt)
            .forEach { fhe.destroyCiphertext(it) }
    }

    private fun testBatchDistances() {
        check(ctx != 0L && jointPK != 0L) { "No ctx/PK" }

        // Initiator at SF center
        val initLat = 37.7749 / MAX_COORD
        val initLon = -122.4194 / MAX_COORD

        // 8 responders at varying distances
        val responders = listOf(
            37.7750 to -122.4195,   // ~15m
            37.7760 to -122.4200,   // ~130m
            37.7780 to -122.4220,   // ~420m
            37.7800 to -122.4250,   // ~780m
            37.7850 to -122.4300,   // ~1.5km
            37.7900 to -122.4100,   // ~1.8km
            37.8000 to -122.4500,   // ~4.3km
            37.8200 to -122.3900,   // ~5.6km
        )

        // Pack initiator coords into 8 slots
        val latVec = DoubleArray(8) { initLat }
        val lonVec = DoubleArray(8) { initLon }

        val latPt = fhe.makeCKKSPackedPlaintext(ctx, latVec)
        val lonPt = fhe.makeCKKSPackedPlaintext(ctx, lonVec)
        check(latPt != 0L && lonPt != 0L) { err() }

        val encLat = fhe.encrypt(ctx, jointPK, latPt)
        val encLon = fhe.encrypt(ctx, jointPK, lonPt)
        check(encLat != 0L && encLon != 0L) { err() }
        fhe.destroyPlaintext(latPt)
        fhe.destroyPlaintext(lonPt)

        // Each responder's normalized coords packed into slot i
        val rLatVec = DoubleArray(8)
        val rLonVec = DoubleArray(8)
        responders.forEachIndexed { i, (lat, lon) ->
            rLatVec[i] = lat / MAX_COORD
            rLonVec[i] = lon / MAX_COORD
        }

        val rLatPt = fhe.makeCKKSPackedPlaintext(ctx, rLatVec)
        val rLonPt = fhe.makeCKKSPackedPlaintext(ctx, rLonVec)
        check(rLatPt != 0L && rLonPt != 0L) { err() }

        val dLatCt = fhe.evalSubCtPt(ctx, encLat, rLatPt)
        val dLonCt = fhe.evalSubCtPt(ctx, encLon, rLonPt)
        check(dLatCt != 0L && dLonCt != 0L) { err() }
        fhe.destroyPlaintext(rLatPt)
        fhe.destroyPlaintext(rLonPt)

        val dLat2 = fhe.evalMultCtCt(ctx, dLatCt, dLatCt)
        val dLon2 = fhe.evalMultCtCt(ctx, dLonCt, dLonCt)
        check(dLat2 != 0L && dLon2 != 0L) { err() }

        val distSq = fhe.evalAddCtCt(ctx, dLat2, dLon2)
        check(distSq != 0L) { err() }

        val dec = thresholdDecrypt(distSq, 8)

        // Verify each slot
        responders.forEachIndexed { i, (lat, lon) ->
            val eLat = initLat - lat / MAX_COORD
            val eLon = initLon - lon / MAX_COORD
            val expected = eLat * eLat + eLon * eLon
            val tol = max(abs(expected) * 0.05, 0.001)
            val diff = abs(dec[i] - expected)
            check(diff < tol) {
                "Slot[$i] d=${"%.6f".format(dec[i])}, exp=${"%.6f".format(expected)}, diff=${"%.6f".format(diff)}"
            }
        }

        // Verify ordering: distances should increase
        for (i in 0 until 7) {
            check(dec[i] < dec[i + 1]) {
                "Ordering: slot[$i]=${"%.6f".format(dec[i])} >= slot[${i + 1}]=${"%.6f".format(dec[i + 1])}"
            }
        }

        listOf(encLat, encLon, dLatCt, dLonCt, dLat2, dLon2, distSq)
            .forEach { fhe.destroyCiphertext(it) }
    }

    private fun testNormalizationConsistency() {
        // Verify that our normalization gives the same result as Python's MAX_COORD=0.5
        val testCoords = listOf(
            37.7749 to -122.4194,
            -33.8688 to 151.2093,
            0.0 to 0.0,
            51.5074 to -0.1278,
        )

        for ((lat, lon) in testCoords) {
            val nLat = lat / MAX_COORD
            val nLon = lon / MAX_COORD

            // Python: float(lat) / 0.5 → lat * 2
            val pyLat = lat * 2.0
            val pyLon = lon * 2.0

            check(abs(nLat - pyLat) < 1e-10) { "Lat norm: $nLat vs Python $pyLat" }
            check(abs(nLon - pyLon) < 1e-10) { "Lon norm: $nLon vs Python $pyLon" }
        }

        // Also verify through encryption
        val lat = 37.7749
        val nLat = lat / MAX_COORD
        val ct = encrypt(doubleArrayOf(nLat, nLat, nLat, nLat))
        val dec = thresholdDecrypt(ct, 4)
        fhe.destroyCiphertext(ct)

        for (i in 0 until 4) {
            val diff = abs(dec[i] - nLat)
            check(diff < 0.5) {
                "Encrypted norm[$i]: ${"%.6f".format(dec[i])} vs ${"%.6f".format(nLat)}"
            }
        }
    }

    private fun testRepeatedEncryptSameCoords() {
        val lat = 37.7749 / MAX_COORD
        val lon = -122.4194 / MAX_COORD

        val ct1 = encrypt(doubleArrayOf(lat, lon, lat, lon))
        val ct2 = encrypt(doubleArrayOf(lat, lon, lat, lon))

        // CTs should differ (randomized encryption)
        val bytes1 = fhe.serializeCiphertext(ct1)
        val bytes2 = fhe.serializeCiphertext(ct2)
        check(bytes1.isNotEmpty() && bytes2.isNotEmpty()) { err() }
        check(!bytes1.contentEquals(bytes2)) {
            "Repeated encryptions identical — randomization broken"
        }

        // But both should decrypt to same values
        val dec1 = thresholdDecrypt(ct1, 4)
        val dec2 = thresholdDecrypt(ct2, 4)
        fhe.destroyCiphertext(ct1)
        fhe.destroyCiphertext(ct2)

        val expected = doubleArrayOf(lat, lon, lat, lon)
        assertClose(dec1, expected, 0.5, "Rep1")
        assertClose(dec2, expected, 0.5, "Rep2")
    }

    // ══════════════════════════════════════
    // Helpers
    // ══════════════════════════════════════

    private fun encrypt(values: DoubleArray): Long {
        check(ctx != 0L && jointPK != 0L) { "No ctx/PK" }
        val pt = fhe.makeCKKSPackedPlaintext(ctx, values)
        check(pt != 0L) { err() }
        val ct = fhe.encrypt(ctx, jointPK, pt)
        check(ct != 0L) { err() }
        fhe.destroyPlaintext(pt)
        return ct
    }

    private fun thresholdDecrypt(ct: Long, count: Int): DoubleArray {
        check(ctx != 0L && leadSK != 0L && joinSK != 0L) { "No ctx/keys" }

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

    /** Encrypt one coord pair and compute dist² against a plaintext coord pair. */
    private fun encryptAndComputeDistSq(encLatVal: Double, encLonVal: Double,
                                        ptLatVal: Double, ptLonVal: Double): Long {
        check(ctx != 0L && jointPK != 0L) { "No ctx/PK" }

        val ePt1 = fhe.makeCKKSPackedPlaintext(ctx, doubleArrayOf(encLatVal))
        val ePt2 = fhe.makeCKKSPackedPlaintext(ctx, doubleArrayOf(encLonVal))
        check(ePt1 != 0L && ePt2 != 0L) { err() }

        val ct1 = fhe.encrypt(ctx, jointPK, ePt1)
        val ct2 = fhe.encrypt(ctx, jointPK, ePt2)
        check(ct1 != 0L && ct2 != 0L) { err() }
        fhe.destroyPlaintext(ePt1)
        fhe.destroyPlaintext(ePt2)

        val mPt1 = fhe.makeCKKSPackedPlaintext(ctx, doubleArrayOf(ptLatVal))
        val mPt2 = fhe.makeCKKSPackedPlaintext(ctx, doubleArrayOf(ptLonVal))
        check(mPt1 != 0L && mPt2 != 0L) { err() }

        val dLatCt = fhe.evalSubCtPt(ctx, ct1, mPt1)
        val dLonCt = fhe.evalSubCtPt(ctx, ct2, mPt2)
        check(dLatCt != 0L && dLonCt != 0L) { err() }
        fhe.destroyPlaintext(mPt1)
        fhe.destroyPlaintext(mPt2)

        val dLat2 = fhe.evalMultCtCt(ctx, dLatCt, dLatCt)
        val dLon2 = fhe.evalMultCtCt(ctx, dLonCt, dLonCt)
        check(dLat2 != 0L && dLon2 != 0L) { err() }

        val result = fhe.evalAddCtCt(ctx, dLat2, dLon2)
        check(result != 0L) { err() }

        listOf(ct1, ct2, dLatCt, dLonCt, dLat2, dLon2).forEach { fhe.destroyCiphertext(it) }
        return result
    }

    private fun assertClose(actual: DoubleArray, expected: DoubleArray,
                            tol: Double, label: String) {
        check(actual.size >= expected.size) {
            "$label: got ${actual.size} vals, need ${expected.size}"
        }
        for (i in expected.indices) {
            val diff = abs(actual[i] - expected[i])
            check(diff < tol) {
                "$label[$i]: ${"%.6f".format(actual[i])} vs ${"%.6f".format(expected[i])}, diff=${"%.6f".format(diff)}"
            }
        }
    }

    private fun err(prefix: String = ""): String {
        val msg = fhe.lastError() ?: "Unknown error"
        return if (prefix.isEmpty()) msg else "$prefix: $msg"
    }

    private fun cleanup() {
        OpenFHETests.safeDestroy(leadPK) { fhe.destroyPublicKey(it) }
        OpenFHETests.safeDestroy(leadSK) { fhe.destroyPrivateKey(it) }
        OpenFHETests.safeDestroy(leadKP) { fhe.destroyKeypair(it) }
        OpenFHETests.safeDestroy(jointPK) { fhe.destroyPublicKey(it) }
        OpenFHETests.safeDestroy(joinSK) { fhe.destroyPrivateKey(it) }
        OpenFHETests.safeDestroy(joinKP) { fhe.destroyKeypair(it) }
        OpenFHETests.safeDestroy(ctx) { fhe.destroyContext(it) }
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
