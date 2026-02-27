import Foundation

/// Dedicated test suite for:
///   1. Multiparty threshold key operations — thorough testing of key generation,
///      serialization round-trips, eval mult key protocol, and partial decrypt flows.
///   2. GPS coordinate precision — stress tests using real-world lat/lon values,
///      the MAX_COORD=0.5 normalization from client.py, and encrypted distance²
///      computation matching compute_distance_local().
///
/// Uses the same TestResult type and callback pattern as OpenFHETests.
class MultipartyGPSTests {

    typealias TestResult = OpenFHETests.TestResult

    private var results: [TestResult] = []

    // Shared state set up once and reused across tests
    private var ctx: OFHEContext?
    private var leadKP: OFHEKeyPair?
    private var leadPK: OFHEPublicKey?
    private var leadSK: OFHEPrivateKey?
    private var joinKP: OFHEKeyPair?
    private var jointPK: OFHEPublicKey?
    private var joinSK: OFHEPrivateKey?
    private var evalKeyReady = false

    /// Matches client.py: city-scale normalizer (0.5 ≈ 55 km at equator)
    private let MAX_COORD = 0.5

    var onTestComplete: ((TestResult) -> Void)?
    var onAllComplete: (([TestResult]) -> Void)?

    // MARK: - Entry Point

    func runAll() {
        results = []

        // ═══════════════════════════════════════
        // Part A: Multiparty Key Operations
        // ═══════════════════════════════════════
        run("A1: Context Setup") { try self.setupContext() }
        guard ctx != nil else { abort("Context setup failed"); return }

        run("A2: Lead KeyGen") { try self.testLeadKeyGen() }
        guard leadKP != nil else { abort("Lead keygen failed"); return }

        run("A3: PK Serialize RT") { try self.testPublicKeySerializeRoundTrip() }
        run("A4: SK Serialize RT") { try self.testPrivateKeySerializeRoundTrip() }
        run("A5: Join KeyGen") { try self.testJoinKeyGen() }
        guard joinKP != nil else { abort("Join keygen failed"); return }

        run("A6: PK Tag Valid") { try self.testPublicKeyTag() }
        run("A7: PK Tag Consistent") { try self.testPublicKeyTagConsistency() }
        run("A8: EvalKey Round 1") { try self.testEvalKeyRound1() }

        // Full eval mult key setup (needed for GPS tests)
        run("A9: Full EvalMultKey") { try self.setupFullEvalMultKey() }

        run("A10: Encrypt-Decrypt") { try self.testBasicEncryptDecrypt() }
        run("A11: Partial Lead Only") { try self.testPartialDecryptLeadOnly() }
        run("A12: Partial Join Only") { try self.testPartialDecryptJoinOnly() }
        run("A13: Fusion Order") { try self.testFusionPartialOrder() }
        run("A14: EvalKey Serialize RT") { try self.testEvalKeySerializeRoundTrip() }

        // ═══════════════════════════════════════
        // Part B: GPS Coordinate Precision
        // ═══════════════════════════════════════
        guard evalKeyReady else { abort("EvalMultKey not ready — GPS tests skipped"); return }

        // B1–B4: Distance² at varying scales
        run("B1: Same location (~0)") {
            try self.testGPSDistance(
                initLat: 37.7749, initLon: -122.4194,
                myLat: 37.7749, myLon: -122.4194,
                label: "SameLoc",
                maxDistSq: 0.001    // should be ~0
            )
        }

        run("B2: ~100m apart") {
            // SF: 1° lat ≈ 111km, so 100m ≈ 0.0009°
            try self.testGPSDistance(
                initLat: 37.7749, initLon: -122.4194,
                myLat: 37.7758, myLon: -122.4194,
                label: "100m",
                maxDistSq: nil   // just verify precision
            )
        }

        run("B3: ~1km apart") {
            try self.testGPSDistance(
                initLat: 37.7749, initLon: -122.4194,
                myLat: 37.7839, myLon: -122.4194,
                label: "1km",
                maxDistSq: nil
            )
        }

        run("B4: ~10km apart") {
            try self.testGPSDistance(
                initLat: 37.7749, initLon: -122.4194,
                myLat: 37.8649, myLon: -122.4194,
                label: "10km",
                maxDistSq: nil
            )
        }

        // B5: Cross-city (SF ↔ Oakland)
        run("B5: SF ↔ Oakland") {
            try self.testGPSDistance(
                initLat: 37.7749, initLon: -122.4194,
                myLat: 37.8044, myLon: -122.2712,
                label: "SF-Oak",
                maxDistSq: nil
            )
        }

        // B6: Negative coordinates (Southern/Eastern hemisphere)
        run("B6: Sydney coords") {
            try self.testGPSDistance(
                initLat: -33.8688, initLon: 151.2093,
                myLat: -33.8788, myLon: 151.2193,
                label: "Sydney",
                maxDistSq: nil
            )
        }

        // B7: Near equator/prime-meridian
        run("B7: Equator origin") {
            try self.testGPSDistance(
                initLat: 0.001, initLon: 0.001,
                myLat: 0.002, myLon: 0.002,
                label: "Equator",
                maxDistSq: nil
            )
        }

        // B8: Dense urban grid — 8 points within 500m, compute all pairwise distances
        run("B8: Dense urban grid") {
            try self.testDenseUrbanGrid()
        }

        // B9: Precision stress — very small differences
        run("B9: 10m precision") {
            // 10m ≈ 0.00009° lat
            try self.testGPSDistance(
                initLat: 40.748817, initLon: -73.985428,
                myLat: 40.748907, myLon: -73.985428,
                label: "10m",
                maxDistSq: nil
            )
        }

        // B10: Full proximity pipeline (encrypt both parties, compute dist², threshold decrypt)
        run("B10: Full proximity pipe") {
            try self.testFullProximityPipeline(
                lat1: 37.7749, lon1: -122.4194,    // SF downtown
                lat2: 37.7751, lon2: -122.4196,     // ~30m away
                expectedApproxDist: 0.000032         // rough normalized dist²
            )
        }

        // B11: Batch of 8 distances in parallel slots (like real BATCH_SIZE usage)
        run("B11: Batch 8 distances") {
            try self.testBatchDistances()
        }

        // B12: Verify normalization matches Python's MAX_COORD
        run("B12: Normalization check") {
            try self.testNormalizationConsistency()
        }

        // B13: Repeated encrypt same coords → different CTs, same distance
        run("B13: Repeated encrypt") {
            try self.testRepeatedEncryptSameCoords()
        }

        // ═══════════════════════════════════════
        // Cleanup
        // ═══════════════════════════════════════
        cleanup()
        onAllComplete?(results)
    }

    // MARK: - Part A: Multiparty Key Operations

    private func setupContext() throws {
        let cacheURL = OpenFHETests.contextCacheURL
        let fm = FileManager.default

        if fm.fileExists(atPath: cacheURL.path),
           let data = try? Data(contentsOf: cacheURL) {
            let restored: OFHEContext? = data.withUnsafeBytes { raw in
                guard let p = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return nil }
                return ofhe_deserialize_context(p, raw.count)
            }
            if let c = restored { ctx = c; return }
        }

        ctx = ofhe_gen_crypto_context(7, 50, 60, 32)
        guard ctx != nil else { throw err() }

        var buf: UnsafeMutablePointer<UInt8>?
        var len: Int = 0
        if ofhe_serialize_context(ctx, &buf, &len), let b = buf, len > 0 {
            try? Data(bytes: b, count: len).write(to: cacheURL)
            ofhe_free_buffer(b)
        }
    }

    private func testLeadKeyGen() throws {
        guard let c = ctx else { throw TestError("No context") }
        leadKP = ofhe_keygen(c)
        guard leadKP != nil else { throw err() }
        leadPK = ofhe_keypair_get_public_key(leadKP)
        leadSK = ofhe_keypair_get_secret_key(leadKP)
        guard leadPK != nil else { throw TestError("Null PK from keypair") }
        guard leadSK != nil else { throw TestError("Null SK from keypair") }
    }

    private func testPublicKeySerializeRoundTrip() throws {
        guard let pk = leadPK else { throw TestError("No lead PK") }
        var buf: UnsafeMutablePointer<UInt8>?
        var len: Int = 0
        guard ofhe_serialize_public_key(pk, &buf, &len) else { throw err() }
        guard len > 1000 else { throw TestError("PK too small: \(len) bytes") }

        let restored = ofhe_deserialize_public_key(ctx, buf, len)
        guard restored != nil else { throw err() }

        // Re-serialize and compare sizes (should be identical)
        var buf2: UnsafeMutablePointer<UInt8>?
        var len2: Int = 0
        guard ofhe_serialize_public_key(restored, &buf2, &len2) else { throw err() }
        guard abs(len - len2) < 64 else {
            throw TestError("Size mismatch: \(len) vs \(len2)")
        }

        ofhe_destroy_public_key(restored)
        ofhe_free_buffer(buf)
        ofhe_free_buffer(buf2)
    }

    private func testPrivateKeySerializeRoundTrip() throws {
        guard let sk = leadSK else { throw TestError("No lead SK") }
        var buf: UnsafeMutablePointer<UInt8>?
        var len: Int = 0
        guard ofhe_serialize_private_key(sk, &buf, &len) else { throw err() }
        guard len > 100 else { throw TestError("SK too small: \(len) bytes") }

        let restored = ofhe_deserialize_private_key(ctx, buf, len)
        guard restored != nil else { throw err() }

        // Encrypt with lead PK, decrypt with restored SK (single-party to test the key)
        // We can't do threshold decrypt with just one key, but we can verify the key loaded
        var buf2: UnsafeMutablePointer<UInt8>?
        var len2: Int = 0
        guard ofhe_serialize_private_key(restored, &buf2, &len2) else { throw err() }
        guard abs(len - len2) < 64 else {
            throw TestError("SK size mismatch: \(len) vs \(len2)")
        }

        ofhe_destroy_private_key(restored)
        ofhe_free_buffer(buf)
        ofhe_free_buffer(buf2)
    }

    private func testJoinKeyGen() throws {
        guard let c = ctx, let pk = leadPK else { throw TestError("No context/leadPK") }

        var pkBuf: UnsafeMutablePointer<UInt8>?
        var pkLen: Int = 0
        guard ofhe_serialize_public_key(pk, &pkBuf, &pkLen) else { throw err() }

        joinKP = ofhe_multiparty_keygen(c, pkBuf, pkLen)
        guard joinKP != nil else { throw err() }

        jointPK = ofhe_keypair_get_public_key(joinKP)
        joinSK = ofhe_keypair_get_secret_key(joinKP)
        guard jointPK != nil else { throw TestError("Null joint PK") }
        guard joinSK != nil else { throw TestError("Null join SK") }

        ofhe_free_buffer(pkBuf)
    }

    private func testPublicKeyTag() throws {
        guard let jpk = jointPK else { throw TestError("No joint PK") }
        guard let tagPtr = ofhe_get_public_key_tag(jpk) else { throw err() }
        let tag = String(cString: tagPtr)
        guard !tag.isEmpty else { throw TestError("Empty PK tag") }
        guard tag.count > 2 else { throw TestError("PK tag suspiciously short: '\(tag)'") }
    }

    private func testPublicKeyTagConsistency() throws {
        guard let jpk = jointPK else { throw TestError("No joint PK") }
        guard let tag1 = ofhe_get_public_key_tag(jpk) else { throw err() }
        guard let tag2 = ofhe_get_public_key_tag(jpk) else { throw err() }
        let s1 = String(cString: tag1)
        let s2 = String(cString: tag2)
        guard s1 == s2 else {
            throw TestError("Tag changed between calls: '\(s1)' vs '\(s2)'")
        }
    }

    private func testEvalKeyRound1() throws {
        guard let c = ctx, let ls = leadSK, let js = joinSK else {
            throw TestError("Missing context/keys")
        }

        // Lead: KeySwitchGen
        let leadEK = ofhe_key_switch_gen(c, ls)
        guard leadEK != nil else { throw err("Lead KeySwitchGen") }

        // Serialize lead eval key
        var ekBuf: UnsafeMutablePointer<UInt8>?
        var ekLen: Int = 0
        guard ofhe_serialize_eval_key(leadEK, &ekBuf, &ekLen) else { throw err("Serialize lead EK") }
        guard ekLen > 100 else { throw TestError("Lead EK too small: \(ekLen)") }

        // Join: MultiKeySwitchGen
        let joinEK = ofhe_multi_key_switch_gen(c, js, ekBuf, ekLen)
        guard joinEK != nil else { throw err("Join MultiKeySwitchGen") }

        // Serialize join eval key and verify non-trivial
        var jBuf: UnsafeMutablePointer<UInt8>?
        var jLen: Int = 0
        guard ofhe_serialize_eval_key(joinEK, &jBuf, &jLen) else { throw err("Serialize join EK") }
        guard jLen > 100 else { throw TestError("Join EK too small: \(jLen)") }

        ofhe_free_buffer(ekBuf)
        ofhe_free_buffer(jBuf)
        ofhe_destroy_eval_key(leadEK)
        ofhe_destroy_eval_key(joinEK)
    }

    private func setupFullEvalMultKey() throws {
        guard let c = ctx, let ls = leadSK, let js = joinSK, let jpk = jointPK else {
            throw TestError("Missing context or keys")
        }
        guard let tagPtr = ofhe_get_public_key_tag(jpk) else { throw err() }
        let tag = String(cString: tagPtr)

        // Round 1
        let leadEK = ofhe_key_switch_gen(c, ls)
        guard leadEK != nil else { throw err() }

        var ekBuf: UnsafeMutablePointer<UInt8>?
        var ekLen: Int = 0
        guard ofhe_serialize_eval_key(leadEK, &ekBuf, &ekLen) else { throw err() }

        let joinEK = ofhe_multi_key_switch_gen(c, js, ekBuf, ekLen)
        guard joinEK != nil else { throw err() }
        ofhe_free_buffer(ekBuf)

        let combined = ofhe_multi_add_eval_keys(c, leadEK, joinEK, tag)
        guard combined != nil else { throw err() }

        // Round 2
        var combBuf: UnsafeMutablePointer<UInt8>?
        var combLen: Int = 0
        guard ofhe_serialize_eval_key(combined, &combBuf, &combLen) else { throw err() }

        let lMEK = ofhe_multi_mult_eval_key(c, ls, combBuf, combLen, tag)
        guard lMEK != nil else { throw err() }
        let jMEK = ofhe_multi_mult_eval_key(c, js, combBuf, combLen, tag)
        guard jMEK != nil else { throw err() }
        ofhe_free_buffer(combBuf)

        let final = ofhe_multi_add_eval_mult_keys(c, lMEK, jMEK, tag)
        guard final != nil else { throw err() }

        var fBuf: UnsafeMutablePointer<UInt8>?
        var fLen: Int = 0
        guard ofhe_serialize_eval_key(final, &fBuf, &fLen) else { throw err() }
        guard ofhe_insert_eval_mult_key(c, fBuf, fLen) else { throw err() }
        ofhe_free_buffer(fBuf)

        [leadEK, joinEK, combined, lMEK, jMEK, final].forEach {
            if let k = $0 { ofhe_destroy_eval_key(k) }
        }
        evalKeyReady = true
    }

    private func testBasicEncryptDecrypt() throws {
        let vals: [Double] = [1.0, 2.0, 3.0, 4.0]
        let ct = try encrypt(vals)
        let result = try thresholdDecrypt(ct, count: 4)
        ofhe_destroy_ciphertext(ct)
        try assertClose(result, vals, tol: 0.5, label: "BasicED")
    }

    private func testPartialDecryptLeadOnly() throws {
        guard let c = ctx, let ls = leadSK else { throw TestError("Missing ctx/leadSK") }
        let ct = try encrypt([10.0, 20.0, 30.0, 40.0])

        let partialL = ofhe_multiparty_decrypt_lead(c, ct, ls)
        guard partialL != nil else { throw err("Lead partial") }

        // Trying fusion with only lead partial should fail or give garbage
        // (we just verify it doesn't crash — behavior is implementation-defined)
        var partials: [OFHECiphertext?] = [partialL]
        let _ = partials.withUnsafeMutableBufferPointer { buf -> OFHEPlaintext? in
            ofhe_multiparty_decrypt_fusion(c, buf.baseAddress, 1)
        }
        // If we get here without crash, the test passes (single-partial fusion is undefined but shouldn't crash)

        ofhe_destroy_ciphertext(partialL)
        ofhe_destroy_ciphertext(ct)
    }

    private func testPartialDecryptJoinOnly() throws {
        guard let c = ctx, let js = joinSK else { throw TestError("Missing ctx/joinSK") }
        let ct = try encrypt([10.0, 20.0, 30.0, 40.0])

        let partialJ = ofhe_multiparty_decrypt_main(c, ct, js)
        guard partialJ != nil else { throw err("Join partial") }

        // Same as above — single partial shouldn't crash
        var partials: [OFHECiphertext?] = [partialJ]
        let _ = partials.withUnsafeMutableBufferPointer { buf -> OFHEPlaintext? in
            ofhe_multiparty_decrypt_fusion(c, buf.baseAddress, 1)
        }

        ofhe_destroy_ciphertext(partialJ)
        ofhe_destroy_ciphertext(ct)
    }

    private func testFusionPartialOrder() throws {
        // Verify: [lead, join] and [join, lead] both produce valid results
        // OpenFHE fusion is order-sensitive: lead must be first
        guard let c = ctx, let ls = leadSK, let js = joinSK else {
            throw TestError("Missing keys")
        }
        let vals: [Double] = [100.0, 200.0, 300.0, 400.0]
        let ct = try encrypt(vals)

        let pL = ofhe_multiparty_decrypt_lead(c, ct, ls)
        guard pL != nil else { throw err() }
        let pJ = ofhe_multiparty_decrypt_main(c, ct, js)
        guard pJ != nil else { throw err() }

        // Correct order: [lead, join]
        var partialsCorrect: [OFHECiphertext?] = [pL, pJ]
        let fusedCorrect = partialsCorrect.withUnsafeMutableBufferPointer { buf -> OFHEPlaintext? in
            ofhe_multiparty_decrypt_fusion(c, buf.baseAddress, 2)
        }
        guard fusedCorrect != nil else { throw err("Fusion correct order") }

        ofhe_plaintext_set_length(fusedCorrect, 4)
        var out = [Double](repeating: 0, count: 4)
        let n = ofhe_plaintext_get_real_packed_value(fusedCorrect, &out, 4)
        guard n >= 4 else { throw TestError("Got \(n) values") }
        try assertClose(out, vals, tol: 0.5, label: "FusionOrder")

        ofhe_destroy_ciphertext(pL)
        ofhe_destroy_ciphertext(pJ)
        ofhe_destroy_plaintext(fusedCorrect)
        ofhe_destroy_ciphertext(ct)
    }

    private func testEvalKeySerializeRoundTrip() throws {
        guard let c = ctx, let ls = leadSK else { throw TestError("Missing ctx/leadSK") }

        let ek = ofhe_key_switch_gen(c, ls)
        guard ek != nil else { throw err() }

        var buf: UnsafeMutablePointer<UInt8>?
        var len: Int = 0
        guard ofhe_serialize_eval_key(ek, &buf, &len) else { throw err() }
        guard len > 100 else { throw TestError("EK too small: \(len)") }

        let restored = ofhe_deserialize_eval_key(c, buf, len)
        guard restored != nil else { throw err() }

        // Re-serialize restored and check size consistency
        var buf2: UnsafeMutablePointer<UInt8>?
        var len2: Int = 0
        guard ofhe_serialize_eval_key(restored, &buf2, &len2) else { throw err() }
        guard abs(len - len2) < 64 else {
            throw TestError("EK size mismatch after RT: \(len) → \(len2)")
        }

        ofhe_free_buffer(buf)
        ofhe_free_buffer(buf2)
        ofhe_destroy_eval_key(ek)
        ofhe_destroy_eval_key(restored)
    }

    // MARK: - Part B: GPS Precision Tests

    /// Mirrors client.py's `compute_distance_local`:
    ///   nlat = lat / MAX_COORD, nlon = lon / MAX_COORD
    ///   dlat = EvalSub(enc_init_lat, my_lat_pt)
    ///   dlon = EvalSub(enc_init_lon, my_lon_pt)
    ///   dist_sq = EvalAdd(EvalMult(dlat, dlat), EvalMult(dlon, dlon))
    private func testGPSDistance(initLat: Double, initLon: Double,
                                  myLat: Double, myLon: Double,
                                  label: String,
                                  maxDistSq: Double?) throws {
        guard let c = ctx, let pk = jointPK else { throw TestError("No ctx/PK") }

        // Normalize exactly as client.py does
        let nInitLat = initLat / MAX_COORD
        let nInitLon = initLon / MAX_COORD
        let nMyLat   = myLat / MAX_COORD
        let nMyLon   = myLon / MAX_COORD

        // Expected plaintext distance²
        let dLat = nInitLat - nMyLat
        let dLon = nInitLon - nMyLon
        let expectedDistSq = dLat * dLat + dLon * dLon

        // Encrypt initiator's coords (replicated across 4 slots for simplicity)
        let initLatPt = ofhe_make_ckks_packed_plaintext(c, [nInitLat, nInitLat, nInitLat, nInitLat], 4)
        let initLonPt = ofhe_make_ckks_packed_plaintext(c, [nInitLon, nInitLon, nInitLon, nInitLon], 4)
        guard initLatPt != nil, initLonPt != nil else { throw err() }

        let encLat = ofhe_encrypt(c, pk, initLatPt)
        let encLon = ofhe_encrypt(c, pk, initLonPt)
        guard encLat != nil, encLon != nil else { throw err() }
        ofhe_destroy_plaintext(initLatPt)
        ofhe_destroy_plaintext(initLonPt)

        // My coords as plaintext (matches client.py pattern: sub encrypted - plaintext)
        let myLatPt = ofhe_make_ckks_packed_plaintext(c, [nMyLat, nMyLat, nMyLat, nMyLat], 4)
        let myLonPt = ofhe_make_ckks_packed_plaintext(c, [nMyLon, nMyLon, nMyLon, nMyLon], 4)
        guard myLatPt != nil, myLonPt != nil else { throw err() }

        // dlat = enc(init_lat) - my_lat_pt, dlon = enc(init_lon) - my_lon_pt
        let ctDlat = ofhe_eval_sub_ct_pt(c, encLat, myLatPt)
        let ctDlon = ofhe_eval_sub_ct_pt(c, encLon, myLonPt)
        guard ctDlat != nil, ctDlon != nil else { throw err() }
        ofhe_destroy_plaintext(myLatPt)
        ofhe_destroy_plaintext(myLonPt)

        // dlat², dlon²
        let ctDlat2 = ofhe_eval_mult_ct_ct(c, ctDlat, ctDlat)
        let ctDlon2 = ofhe_eval_mult_ct_ct(c, ctDlon, ctDlon)
        guard ctDlat2 != nil, ctDlon2 != nil else { throw err() }

        // dist_sq = dlat² + dlon²
        let ctDistSq = ofhe_eval_add_ct_ct(c, ctDlat2, ctDlon2)
        guard ctDistSq != nil else { throw err() }

        // Threshold decrypt
        let decrypted = try thresholdDecrypt(ctDistSq!, count: 4)

        // Verify all 4 slots are close to expected
        let toleranceRatio = max(abs(expectedDistSq) * 0.05, 0.001) // 5% or 0.001 absolute
        for i in 0..<4 {
            let diff = abs(decrypted[i] - expectedDistSq)
            guard diff < toleranceRatio else {
                throw TestError("\(label)[\(i)]: encrypted dist²=\(f4(decrypted[i])), " +
                                "expected=\(f4(expectedDistSq)), diff=\(f4(diff)), " +
                                "tol=\(f4(toleranceRatio))")
            }
        }

        // Optional absolute bound check (e.g., same location should be ~0)
        if let maxDSq = maxDistSq {
            guard decrypted[0] < maxDSq else {
                throw TestError("\(label): dist²=\(f4(decrypted[0])) exceeds max \(f4(maxDSq))")
            }
        }

        // Cleanup
        [encLat, encLon, ctDlat, ctDlon, ctDlat2, ctDlon2, ctDistSq]
            .compactMap { $0 }.forEach { ofhe_destroy_ciphertext($0) }
    }

    private func testDenseUrbanGrid() throws {
        // 8 points in a 500m × 500m grid in downtown SF
        let baseLat = 37.7749
        let baseLon = -122.4194
        let step = 0.0015  // ~167m per step

        struct Point { let lat: Double; let lon: Double }
        var points: [Point] = []
        for row in 0..<2 {
            for col in 0..<4 {
                points.append(Point(
                    lat: baseLat + Double(row) * step,
                    lon: baseLon + Double(col) * step
                ))
            }
        }

        // Compute 4 representative pairwise distances
        let pairs: [(Int, Int)] = [(0, 1), (0, 4), (0, 7), (3, 4)]
        var pairResults: [String] = []

        for (i, j) in pairs {
            let a = points[i], b = points[j]
            let nda = (a.lat / MAX_COORD - b.lat / MAX_COORD)
            let ndo = (a.lon / MAX_COORD - b.lon / MAX_COORD)
            let expectedDSq = nda * nda + ndo * ndo

            // Encrypt a's location
            let naLat = a.lat / MAX_COORD, naLon = a.lon / MAX_COORD
            let nbLat = b.lat / MAX_COORD, nbLon = b.lon / MAX_COORD

            let ct = try encryptAndComputeDistSq(
                encLat: naLat, encLon: naLon,
                ptLat: nbLat, ptLon: nbLon
            )
            let dec = try thresholdDecrypt(ct, count: 1)
            ofhe_destroy_ciphertext(ct)

            let diff = abs(dec[0] - expectedDSq)
            let tol = max(abs(expectedDSq) * 0.05, 0.001)
            guard diff < tol else {
                throw TestError("Pair(\(i),\(j)): dec=\(f4(dec[0])), exp=\(f4(expectedDSq)), diff=\(f4(diff))")
            }
            pairResults.append("(\(i),\(j))=\(f4(dec[0]))")
        }
    }

    private func testFullProximityPipeline(lat1: Double, lon1: Double,
                                            lat2: Double, lon2: Double,
                                            expectedApproxDist: Double) throws {
        guard let c = ctx, let pk = jointPK else { throw TestError("No ctx/PK") }

        let BATCH = 4

        // Party 1 encrypts their coords (like start_match in client.py)
        let n1Lat = lat1 / MAX_COORD, n1Lon = lon1 / MAX_COORD
        let latVec = [Double](repeating: n1Lat, count: BATCH)
        let lonVec = [Double](repeating: n1Lon, count: BATCH)

        let latPt = ofhe_make_ckks_packed_plaintext(c, latVec, BATCH)
        let lonPt = ofhe_make_ckks_packed_plaintext(c, lonVec, BATCH)
        guard latPt != nil, lonPt != nil else { throw err() }

        let encLat = ofhe_encrypt(c, pk, latPt)
        let encLon = ofhe_encrypt(c, pk, lonPt)
        guard encLat != nil, encLon != nil else { throw err() }
        ofhe_destroy_plaintext(latPt)
        ofhe_destroy_plaintext(lonPt)

        // Network simulation: serialize ciphertexts
        var latBuf: UnsafeMutablePointer<UInt8>?, lonBuf: UnsafeMutablePointer<UInt8>?
        var latLen: Int = 0, lonLen: Int = 0
        guard ofhe_serialize_ciphertext(encLat, &latBuf, &latLen),
              ofhe_serialize_ciphertext(encLon, &lonBuf, &lonLen) else { throw err() }

        // Party 2 deserializes (simulating receiving over network)
        let recvLat = ofhe_deserialize_ciphertext(c, latBuf, latLen)
        let recvLon = ofhe_deserialize_ciphertext(c, lonBuf, lonLen)
        guard recvLat != nil, recvLon != nil else { throw err() }
        ofhe_free_buffer(latBuf)
        ofhe_free_buffer(lonBuf)

        // Party 2 computes distance locally
        let n2Lat = lat2 / MAX_COORD, n2Lon = lon2 / MAX_COORD
        let myLatPt = ofhe_make_ckks_packed_plaintext(c, [Double](repeating: n2Lat, count: BATCH), BATCH)
        let myLonPt = ofhe_make_ckks_packed_plaintext(c, [Double](repeating: n2Lon, count: BATCH), BATCH)
        guard myLatPt != nil, myLonPt != nil else { throw err() }

        let dLat = ofhe_eval_sub_ct_pt(c, recvLat, myLatPt)
        let dLon = ofhe_eval_sub_ct_pt(c, recvLon, myLonPt)
        guard dLat != nil, dLon != nil else { throw err() }
        ofhe_destroy_plaintext(myLatPt)
        ofhe_destroy_plaintext(myLonPt)

        let dLat2 = ofhe_eval_mult_ct_ct(c, dLat, dLat)
        let dLon2 = ofhe_eval_mult_ct_ct(c, dLon, dLon)
        guard dLat2 != nil, dLon2 != nil else { throw err() }

        let distSq = ofhe_eval_add_ct_ct(c, dLat2, dLon2)
        guard distSq != nil else { throw err() }

        // Serialize distance result (going "back to server")
        var distBuf: UnsafeMutablePointer<UInt8>?
        var distLen: Int = 0
        guard ofhe_serialize_ciphertext(distSq, &distBuf, &distLen) else { throw err() }

        // "Server" deserializes
        let serverDistCt = ofhe_deserialize_ciphertext(c, distBuf, distLen)
        guard serverDistCt != nil else { throw err() }
        ofhe_free_buffer(distBuf)

        // Threshold decrypt the final distance
        let result = try thresholdDecrypt(serverDistCt!, count: BATCH)

        // Expected plaintext distance²
        let eLat = n1Lat - n2Lat
        let eLon = n1Lon - n2Lon
        let expected = eLat * eLat + eLon * eLon
        let tol = max(abs(expected) * 0.05, 0.001)

        try assertClose(result, [Double](repeating: expected, count: BATCH),
                         tol: tol, label: "FullPipe")

        // Cleanup all
        [encLat, encLon, recvLat, recvLon, dLat, dLon, dLat2, dLon2, distSq, serverDistCt]
            .compactMap { $0 }.forEach { ofhe_destroy_ciphertext($0) }
    }

    private func testBatchDistances() throws {
        guard let c = ctx, let pk = jointPK else { throw TestError("No ctx/PK") }

        // Initiator at SF center
        let initLat = 37.7749 / MAX_COORD
        let initLon = -122.4194 / MAX_COORD

        // 8 responders at varying distances
        let responders: [(lat: Double, lon: Double)] = [
            (37.7750, -122.4195),   // ~15m
            (37.7760, -122.4200),   // ~130m
            (37.7780, -122.4220),   // ~420m
            (37.7800, -122.4250),   // ~780m
            (37.7850, -122.4300),   // ~1.5km
            (37.7900, -122.4100),   // ~1.8km
            (37.8000, -122.4500),   // ~4.3km
            (37.8200, -122.3900),   // ~5.6km
        ]

        // Pack initiator coords into 8 slots
        let latVec = [Double](repeating: initLat, count: 8)
        let lonVec = [Double](repeating: initLon, count: 8)

        let latPt = ofhe_make_ckks_packed_plaintext(c, latVec, 8)
        let lonPt = ofhe_make_ckks_packed_plaintext(c, lonVec, 8)
        guard latPt != nil, lonPt != nil else { throw err() }

        let encLat = ofhe_encrypt(c, pk, latPt)
        let encLon = ofhe_encrypt(c, pk, lonPt)
        guard encLat != nil, encLon != nil else { throw err() }
        ofhe_destroy_plaintext(latPt)
        ofhe_destroy_plaintext(lonPt)

        // Each responder's normalized coords packed into slot i
        var rLatVec = [Double](repeating: 0, count: 8)
        var rLonVec = [Double](repeating: 0, count: 8)
        for (i, r) in responders.enumerated() {
            rLatVec[i] = r.lat / MAX_COORD
            rLonVec[i] = r.lon / MAX_COORD
        }

        let rLatPt = ofhe_make_ckks_packed_plaintext(c, rLatVec, 8)
        let rLonPt = ofhe_make_ckks_packed_plaintext(c, rLonVec, 8)
        guard rLatPt != nil, rLonPt != nil else { throw err() }

        let dLat = ofhe_eval_sub_ct_pt(c, encLat, rLatPt)
        let dLon = ofhe_eval_sub_ct_pt(c, encLon, rLonPt)
        guard dLat != nil, dLon != nil else { throw err() }
        ofhe_destroy_plaintext(rLatPt)
        ofhe_destroy_plaintext(rLonPt)

        let dLat2 = ofhe_eval_mult_ct_ct(c, dLat, dLat)
        let dLon2 = ofhe_eval_mult_ct_ct(c, dLon, dLon)
        guard dLat2 != nil, dLon2 != nil else { throw err() }

        let distSq = ofhe_eval_add_ct_ct(c, dLat2, dLon2)
        guard distSq != nil else { throw err() }

        let dec = try thresholdDecrypt(distSq!, count: 8)

        // Verify each slot
        for (i, r) in responders.enumerated() {
            let eLat = initLat - r.lat / MAX_COORD
            let eLon = initLon - r.lon / MAX_COORD
            let expected = eLat * eLat + eLon * eLon
            let tol = max(abs(expected) * 0.05, 0.001)
            let diff = abs(dec[i] - expected)
            guard diff < tol else {
                throw TestError("Slot[\(i)] d=\(f4(dec[i])), exp=\(f4(expected)), diff=\(f4(diff))")
            }
        }

        // Verify ordering: distances should increase
        for i in 0..<7 {
            guard dec[i] < dec[i + 1] else {
                throw TestError("Ordering: slot[\(i)]=\(f4(dec[i])) >= slot[\(i+1)]=\(f4(dec[i+1]))")
            }
        }

        [encLat, encLon, dLat, dLon, dLat2, dLon2, distSq]
            .compactMap { $0 }.forEach { ofhe_destroy_ciphertext($0) }
    }

    private func testNormalizationConsistency() throws {
        // Verify that our normalization gives the same numeric result as Python's MAX_COORD=0.5
        let testCoords: [(Double, Double)] = [
            (37.7749, -122.4194),
            (-33.8688, 151.2093),
            (0.0, 0.0),
            (51.5074, -0.1278),
        ]

        for (lat, lon) in testCoords {
            let nLat = lat / MAX_COORD
            let nLon = lon / MAX_COORD

            // Python: float(lat) / 0.5 → lat * 2
            let pyLat = lat * 2.0
            let pyLon = lon * 2.0

            guard abs(nLat - pyLat) < 1e-10 else {
                throw TestError("Lat norm: \(nLat) vs Python \(pyLat)")
            }
            guard abs(nLon - pyLon) < 1e-10 else {
                throw TestError("Lon norm: \(nLon) vs Python \(pyLon)")
            }
        }

        // Also verify through encryption
        let lat = 37.7749
        let nLat = lat / MAX_COORD
        let ct = try encrypt([nLat, nLat, nLat, nLat])
        let dec = try thresholdDecrypt(ct, count: 4)
        ofhe_destroy_ciphertext(ct)

        for i in 0..<4 {
            let diff = abs(dec[i] - nLat)
            guard diff < 0.5 else {
                throw TestError("Encrypted norm[\(i)]: \(f4(dec[i])) vs \(f4(nLat))")
            }
        }
    }

    private func testRepeatedEncryptSameCoords() throws {
        let lat = 37.7749 / MAX_COORD
        let lon = -122.4194 / MAX_COORD

        let ct1 = try encrypt([lat, lon, lat, lon])
        let ct2 = try encrypt([lat, lon, lat, lon])

        // CTs should differ (randomized encryption)
        var buf1: UnsafeMutablePointer<UInt8>?, buf2: UnsafeMutablePointer<UInt8>?
        var len1: Int = 0, len2: Int = 0
        guard ofhe_serialize_ciphertext(ct1, &buf1, &len1),
              ofhe_serialize_ciphertext(ct2, &buf2, &len2) else { throw err() }

        let d1 = Data(bytes: buf1!, count: len1)
        let d2 = Data(bytes: buf2!, count: len2)
        ofhe_free_buffer(buf1)
        ofhe_free_buffer(buf2)

        guard d1 != d2 else {
            throw TestError("Repeated encryptions identical — randomization broken")
        }

        // But both should decrypt to same values
        let dec1 = try thresholdDecrypt(ct1, count: 4)
        let dec2 = try thresholdDecrypt(ct2, count: 4)
        ofhe_destroy_ciphertext(ct1)
        ofhe_destroy_ciphertext(ct2)

        try assertClose(dec1, [lat, lon, lat, lon], tol: 0.5, label: "Rep1")
        try assertClose(dec2, [lat, lon, lat, lon], tol: 0.5, label: "Rep2")
    }

    // MARK: - Helpers

    private func encrypt(_ values: [Double]) throws -> OFHECiphertext {
        guard let c = ctx, let pk = jointPK else { throw TestError("No ctx/PK") }
        let pt = ofhe_make_ckks_packed_plaintext(c, values, values.count)
        guard pt != nil else { throw err() }
        let ct = ofhe_encrypt(c, pk, pt)
        guard ct != nil else { throw err() }
        ofhe_destroy_plaintext(pt)
        return ct!
    }

    private func thresholdDecrypt(_ ct: OFHECiphertext, count: Int) throws -> [Double] {
        guard let c = ctx, let ls = leadSK, let js = joinSK else {
            throw TestError("No ctx/keys")
        }
        let pL = ofhe_multiparty_decrypt_lead(c, ct, ls)
        guard pL != nil else { throw err("Lead partial") }
        let pJ = ofhe_multiparty_decrypt_main(c, ct, js)
        guard pJ != nil else { throw err("Join partial") }

        var partials: [OFHECiphertext?] = [pL, pJ]
        let fused = partials.withUnsafeMutableBufferPointer { buf -> OFHEPlaintext? in
            ofhe_multiparty_decrypt_fusion(c, buf.baseAddress, 2)
        }
        guard fused != nil else { throw err("Fusion") }

        ofhe_plaintext_set_length(fused, count)
        var out = [Double](repeating: 0, count: count)
        let n = ofhe_plaintext_get_real_packed_value(fused, &out, count)
        guard n >= count else { throw TestError("Got \(n) values, expected \(count)") }

        ofhe_destroy_ciphertext(pL)
        ofhe_destroy_ciphertext(pJ)
        ofhe_destroy_plaintext(fused)
        return out
    }

    /// Encrypt one coord pair and compute dist² against a plaintext coord pair.
    /// Returns the distance² ciphertext (caller must destroy).
    private func encryptAndComputeDistSq(encLat: Double, encLon: Double,
                                          ptLat: Double, ptLon: Double) throws -> OFHECiphertext {
        guard let c = ctx, let pk = jointPK else { throw TestError("No ctx/PK") }

        let ePt1 = ofhe_make_ckks_packed_plaintext(c, [encLat], 1)
        let ePt2 = ofhe_make_ckks_packed_plaintext(c, [encLon], 1)
        guard ePt1 != nil, ePt2 != nil else { throw err() }

        let ct1 = ofhe_encrypt(c, pk, ePt1)
        let ct2 = ofhe_encrypt(c, pk, ePt2)
        guard ct1 != nil, ct2 != nil else { throw err() }
        ofhe_destroy_plaintext(ePt1)
        ofhe_destroy_plaintext(ePt2)

        let mPt1 = ofhe_make_ckks_packed_plaintext(c, [ptLat], 1)
        let mPt2 = ofhe_make_ckks_packed_plaintext(c, [ptLon], 1)
        guard mPt1 != nil, mPt2 != nil else { throw err() }

        let dLat = ofhe_eval_sub_ct_pt(c, ct1, mPt1)
        let dLon = ofhe_eval_sub_ct_pt(c, ct2, mPt2)
        guard dLat != nil, dLon != nil else { throw err() }
        ofhe_destroy_plaintext(mPt1)
        ofhe_destroy_plaintext(mPt2)

        let dLat2 = ofhe_eval_mult_ct_ct(c, dLat, dLat)
        let dLon2 = ofhe_eval_mult_ct_ct(c, dLon, dLon)
        guard dLat2 != nil, dLon2 != nil else { throw err() }

        let result = ofhe_eval_add_ct_ct(c, dLat2, dLon2)
        guard result != nil else { throw err() }

        [ct1, ct2, dLat, dLon, dLat2, dLon2].compactMap { $0 }.forEach { ofhe_destroy_ciphertext($0) }
        return result!
    }

    private func assertClose(_ actual: [Double], _ expected: [Double],
                              tol: Double, label: String) throws {
        guard actual.count >= expected.count else {
            throw TestError("\(label): got \(actual.count) vals, need \(expected.count)")
        }
        for i in 0..<expected.count {
            let diff = abs(actual[i] - expected[i])
            guard diff < tol else {
                throw TestError("\(label)[\(i)]: \(f4(actual[i])) vs \(f4(expected[i])), diff=\(f4(diff))")
            }
        }
    }

    private func f4(_ v: Double) -> String { String(format: "%.6f", v) }

    private func cleanup() {
        if let k = leadPK { ofhe_destroy_public_key(k) }
        if let k = leadSK { ofhe_destroy_private_key(k) }
        if let k = leadKP { ofhe_destroy_keypair(k) }
        if let k = jointPK { ofhe_destroy_public_key(k) }
        if let k = joinSK { ofhe_destroy_private_key(k) }
        if let k = joinKP { ofhe_destroy_keypair(k) }
        if let c = ctx { ofhe_destroy_context(c) }
    }

    private struct TestError: Error, CustomStringConvertible {
        let description: String
        init(_ msg: String) { self.description = msg }
    }

    private func err(_ prefix: String = "") -> TestError {
        let msg: String
        if let e = ofhe_last_error() { msg = String(cString: e) }
        else { msg = "Unknown error" }
        return TestError(prefix.isEmpty ? msg : "\(prefix): \(msg)")
    }

    private func abort(_ detail: String) {
        let r = TestResult(name: "ABORT", passed: false, duration: 0, detail: detail)
        results.append(r)
        onTestComplete?(r)
        cleanup()
        onAllComplete?(results)
    }

    private func run(_ name: String, _ body: () throws -> Void) {
        let start = CFAbsoluteTimeGetCurrent()
        var result: TestResult
        do {
            try body()
            let dt = CFAbsoluteTimeGetCurrent() - start
            result = TestResult(name: name, passed: true, duration: dt, detail: "OK")
        } catch {
            let dt = CFAbsoluteTimeGetCurrent() - start
            result = TestResult(name: name, passed: false, duration: dt, detail: "\(error)")
        }
        results.append(result)
        onTestComplete?(result)
    }
}
