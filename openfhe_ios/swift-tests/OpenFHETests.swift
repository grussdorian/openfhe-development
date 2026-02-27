import Foundation

/// Comprehensive test suite for all OpenFHE C bridge functions.
/// Every variable is a safe optional — no force unwraps, no crashes.
/// Run from a background thread — FHE ops are slow.
class OpenFHETests {

    struct TestResult {
        let name: String
        let passed: Bool
        let duration: TimeInterval
        let detail: String
    }

    private var results: [TestResult] = []
    private var ctx: OFHEContext?
    private var contextLoadedFromCache = false

    var onTestComplete: ((TestResult) -> Void)?
    var onAllComplete: (([TestResult]) -> Void)?

    // MARK: - Entry Point

    func runAll() {
        results = []

        // 1. Context
        run("Context Create") { try self.testContextCreate() }
        // Annotate the context result with cache status
        if let idx = results.firstIndex(where: { $0.name == "Context Create" && $0.passed }) {
            let r = results[idx]
            let detail = self.contextLoadedFromCache
                ? "Loaded from cache"
                : "Generated fresh (cached for next run)"
            results[idx] = TestResult(name: r.name, passed: r.passed,
                                      duration: r.duration, detail: detail)
        }
        guard ctx != nil else {
            let r = TestResult(name: "ABORT", passed: false, duration: 0,
                               detail: "Context creation failed — cannot continue.")
            results.append(r)
            onTestComplete?(r)
            onAllComplete?(results)
            return
        }

        // 2. Context Serialization Round-Trip
        run("Context Serialize") { try self.testContextSerialize() }

        // 3. Key Generation (Lead)
        var leadKP: OFHEKeyPair?
        var leadPK: OFHEPublicKey?
        var leadSK: OFHEPrivateKey?

        run("Lead KeyGen") {
            let kp = ofhe_keygen(self.ctx)
            guard kp != nil else { throw self.err() }
            leadKP = kp
            leadPK = ofhe_keypair_get_public_key(kp)
            leadSK = ofhe_keypair_get_secret_key(kp)
            guard leadPK != nil, leadSK != nil else { throw self.err() }
        }

        // 4. Public Key Serialization
        var leadPKBuf: UnsafeMutablePointer<UInt8>?
        var leadPKLen: Int = 0

        run("PubKey Serialize") {
            guard leadPK != nil else { throw TestError("No lead PK from prior step") }
            guard ofhe_serialize_public_key(leadPK, &leadPKBuf, &leadPKLen) else { throw self.err() }
            guard leadPKLen > 0 else { throw TestError("Empty buffer") }
        }

        // 5. Multiparty KeyGen (Join)
        var joinKP: OFHEKeyPair?
        var joinSK: OFHEPrivateKey?

        run("Join KeyGen") {
            guard leadPKBuf != nil, leadPKLen > 0 else { throw TestError("No serialized lead PK") }
            let kp = ofhe_multiparty_keygen(self.ctx, leadPKBuf, leadPKLen)
            guard kp != nil else { throw self.err() }
            joinKP = kp
            joinSK = ofhe_keypair_get_secret_key(kp)
            guard joinSK != nil else { throw self.err() }
        }

        // 6. Private Key Serialization Round-Trip
        run("PrivKey Serialize") {
            guard leadSK != nil else { throw TestError("No lead SK") }
            var skBuf: UnsafeMutablePointer<UInt8>?
            var skLen: Int = 0
            guard ofhe_serialize_private_key(leadSK, &skBuf, &skLen) else { throw self.err() }
            let restored = ofhe_deserialize_private_key(self.ctx, skBuf, skLen)
            guard restored != nil else { throw self.err() }
            ofhe_destroy_private_key(restored)
            ofhe_free_buffer(skBuf)
        }

        // 7. Get joint PK and its tag (needed for eval mult key setup)
        let jointPK: OFHEPublicKey? = (joinKP != nil) ? ofhe_keypair_get_public_key(joinKP) : nil
        var jointPKTag: String = ""
        run("Get PK Tag") {
            guard let jpk = jointPK else { throw TestError("No joint PK") }
            guard let tagPtr = ofhe_get_public_key_tag(jpk) else { throw self.err() }
            jointPKTag = String(cString: tagPtr)
            guard !jointPKTag.isEmpty else { throw TestError("Empty PK tag") }
        }

        // 8. Eval Mult Key Setup (2-party threshold)
        var evalKeyOK = false
        run("EvalMultKey Setup") {
            guard let ls = leadSK, let js = joinSK else {
                throw TestError("Missing keys from earlier step")
            }
            try self.testEvalMultKeySetup(leadSK: ls, joinSK: js, jointPKTag: jointPKTag)
            evalKeyOK = true
        }

        // 9. CKKS Plaintext Encoding
        run("CKKS Encode") { try self.testCKKSEncode() }

        // 10. Encrypt
        var ct1: OFHECiphertext?
        var ct2: OFHECiphertext?

        run("Encrypt") {
            guard jointPK != nil else { throw TestError("No joint PK") }
            let vals1: [Double] = [1.0, 2.0, 3.0, 4.0]
            let pt1 = ofhe_make_ckks_packed_plaintext(self.ctx, vals1, vals1.count)
            guard pt1 != nil else { throw self.err() }
            ct1 = ofhe_encrypt(self.ctx, jointPK, pt1)
            guard ct1 != nil else { throw self.err() }
            ofhe_destroy_plaintext(pt1)

            let vals2: [Double] = [5.0, 6.0, 7.0, 8.0]
            let pt2 = ofhe_make_ckks_packed_plaintext(self.ctx, vals2, vals2.count)
            guard pt2 != nil else { throw self.err() }
            ct2 = ofhe_encrypt(self.ctx, jointPK, pt2)
            guard ct2 != nil else { throw self.err() }
            ofhe_destroy_plaintext(pt2)
        }

        // 10. Ciphertext Serialization
        run("CT Serialize") {
            guard ct1 != nil else { throw TestError("No ct1") }
            var ctBuf: UnsafeMutablePointer<UInt8>?
            var ctLen: Int = 0
            guard ofhe_serialize_ciphertext(ct1, &ctBuf, &ctLen) else { throw self.err() }
            guard ctLen > 0 else { throw TestError("Empty CT buffer") }
            let restored = ofhe_deserialize_ciphertext(self.ctx, ctBuf, ctLen)
            guard restored != nil else { throw self.err() }
            ofhe_destroy_ciphertext(restored)
            ofhe_free_buffer(ctBuf)
        }

        // 11. EvalAdd (ct + ct)
        var ctAdd: OFHECiphertext?
        run("EvalAdd ct+ct") {
            guard ct1 != nil, ct2 != nil else { throw TestError("No ciphertexts") }
            ctAdd = ofhe_eval_add_ct_ct(self.ctx, ct1, ct2)
            guard ctAdd != nil else { throw self.err() }
        }

        // 12. EvalAdd (ct + scalar)
        run("EvalAdd ct+scalar") {
            guard ct1 != nil else { throw TestError("No ct1") }
            let r = ofhe_eval_add_ct_double(self.ctx, ct1, 10.0)
            guard r != nil else { throw self.err() }
            ofhe_destroy_ciphertext(r)
        }

        // 13. EvalSub (ct - ct)
        run("EvalSub ct-ct") {
            guard ct1 != nil, ct2 != nil else { throw TestError("No ciphertexts") }
            let r = ofhe_eval_sub_ct_ct(self.ctx, ct1, ct2)
            guard r != nil else { throw self.err() }
            ofhe_destroy_ciphertext(r)
        }

        // 14. EvalSub (ct - pt)
        run("EvalSub ct-pt") {
            guard ct1 != nil else { throw TestError("No ct1") }
            let ptVals: [Double] = [1.0, 1.0, 1.0, 1.0]
            let pt = ofhe_make_ckks_packed_plaintext(self.ctx, ptVals, ptVals.count)
            guard pt != nil else { throw self.err() }
            let r = ofhe_eval_sub_ct_pt(self.ctx, ct1, pt)
            guard r != nil else { throw self.err() }
            ofhe_destroy_ciphertext(r)
            ofhe_destroy_plaintext(pt)
        }

        // 15. EvalMult (ct * ct) — requires eval mult key
        var ctMult: OFHECiphertext?
        run("EvalMult ct*ct") {
            guard ct1 != nil, ct2 != nil else { throw TestError("No ciphertexts") }
            guard evalKeyOK else { throw TestError("Skipped — EvalMultKey Setup failed") }
            ctMult = ofhe_eval_mult_ct_ct(self.ctx, ct1, ct2)
            guard ctMult != nil else { throw self.err() }
        }

        // 16. EvalMult (ct * pt)
        run("EvalMult ct*pt") {
            guard ct1 != nil else { throw TestError("No ct1") }
            let ptVals: [Double] = [2.0, 2.0, 2.0, 2.0]
            let pt = ofhe_make_ckks_packed_plaintext(self.ctx, ptVals, ptVals.count)
            guard pt != nil else { throw self.err() }
            let r = ofhe_eval_mult_ct_pt(self.ctx, ct1, pt)
            guard r != nil else { throw self.err() }
            ofhe_destroy_ciphertext(r)
            ofhe_destroy_plaintext(pt)
        }

        // 17. EvalMult (ct * scalar)
        run("EvalMult ct*scalar") {
            guard ct1 != nil else { throw TestError("No ct1") }
            let r = ofhe_eval_mult_ct_double(self.ctx, ct1, 3.0)
            guard r != nil else { throw self.err() }
            ofhe_destroy_ciphertext(r)
        }

        // 18. EvalAdd (ct + pt)
        run("EvalAdd ct+pt") {
            guard ct1 != nil else { throw TestError("No ct1") }
            let ptVals: [Double] = [10.0, 20.0, 30.0, 40.0]
            let pt = ofhe_make_ckks_packed_plaintext(self.ctx, ptVals, ptVals.count)
            guard pt != nil else { throw self.err() }
            let r = ofhe_eval_add_ct_pt(self.ctx, ct1, pt)
            guard r != nil else { throw self.err() }
            ofhe_destroy_ciphertext(r)
            ofhe_destroy_plaintext(pt)
        }

        // 19. Threshold Decrypt (Lead + Join → Fusion)
        run("Threshold Decrypt") {
            guard let ca = ctAdd, let ls = leadSK, let js = joinSK else {
                throw TestError("Skipped — missing ciphertext or keys")
            }
            try self.testThresholdDecrypt(ct: ca, leadSK: ls, joinSK: js,
                                          expected: [6.0, 8.0, 10.0, 12.0])
        }

        // 20. Threshold Decrypt of Mult result
        run("Decrypt Mult") {
            guard let cm = ctMult, let ls = leadSK, let js = joinSK else {
                throw TestError("Skipped — EvalMult or keys failed")
            }
            try self.testThresholdDecrypt(ct: cm, leadSK: ls, joinSK: js,
                                          expected: [5.0, 12.0, 21.0, 32.0])
        }

        // 21. Error handling
        run("Error Handling") {
            ofhe_clear_error()
            let bad = ofhe_encrypt(self.ctx, nil, nil)
            guard bad == nil else { throw TestError("Should have failed") }
            let errStr = ofhe_last_error()
            guard errStr != nil else { throw TestError("Expected error message") }
        }

        // Cleanup (all nil-safe)
        if let c = ct1 { ofhe_destroy_ciphertext(c) }
        if let c = ct2 { ofhe_destroy_ciphertext(c) }
        if let c = ctAdd { ofhe_destroy_ciphertext(c) }
        if let c = ctMult { ofhe_destroy_ciphertext(c) }
        if let k = leadPK { ofhe_destroy_public_key(k) }
        if let k = leadSK { ofhe_destroy_private_key(k) }
        if let k = leadKP { ofhe_destroy_keypair(k) }
        if let k = jointPK { ofhe_destroy_public_key(k) }
        if let k = joinSK { ofhe_destroy_private_key(k) }
        if let k = joinKP { ofhe_destroy_keypair(k) }
        if let buf = leadPKBuf { ofhe_free_buffer(buf) }
        if let c = ctx { ofhe_destroy_context(c) }

        onAllComplete?(results)
    }

    // MARK: - Individual Tests

    /// Cache file path in the app's Caches directory
    static var contextCacheURL: URL = {
        let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first!
        return caches.appendingPathComponent("openfhe_context.bin")
    }()

    private func testContextCreate() throws {
        let cacheURL = Self.contextCacheURL
        let fm = FileManager.default

        // Try loading from cache first (much faster than generating)
        if fm.fileExists(atPath: cacheURL.path),
           let data = try? Data(contentsOf: cacheURL) {
            let restored: OFHEContext? = data.withUnsafeBytes { rawBuf in
                guard let ptr = rawBuf.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                    return nil
                }
                return ofhe_deserialize_context(ptr, rawBuf.count)
            }
            if let c = restored {
                ctx = c
                contextLoadedFromCache = true
                return
            }
            // Cache corrupted — fall through to regenerate
            try? fm.removeItem(at: cacheURL)
        }

        // Generate fresh (slow path — only runs once)
        ctx = ofhe_gen_crypto_context(7, 50, 60, 32)
        guard ctx != nil else { throw err() }

        // Save to cache for next time
        var buf: UnsafeMutablePointer<UInt8>?
        var len: Int = 0
        if ofhe_serialize_context(ctx, &buf, &len), let b = buf, len > 0 {
            let data = Data(bytes: b, count: len)
            try? data.write(to: cacheURL)
            ofhe_free_buffer(b)
        }
    }

    private func testContextSerialize() throws {
        guard let c = ctx else { throw TestError("No context") }
        var buf: UnsafeMutablePointer<UInt8>?
        var len: Int = 0
        guard ofhe_serialize_context(c, &buf, &len) else { throw err() }
        guard len > 0 else { throw TestError("Empty context buffer") }

        let restored = ofhe_deserialize_context(buf, len)
        guard restored != nil else { throw err() }
        ofhe_destroy_context(restored)
        ofhe_free_buffer(buf)
    }

    private func testEvalMultKeySetup(leadSK: OFHEPrivateKey, joinSK: OFHEPrivateKey, jointPKTag: String) throws {
        guard let c = ctx else { throw TestError("No context") }

        let leadEK = ofhe_key_switch_gen(c, leadSK)
        guard leadEK != nil else { throw err("Lead KeySwitchGen") }

        var ekBuf: UnsafeMutablePointer<UInt8>?
        var ekLen: Int = 0
        guard ofhe_serialize_eval_key(leadEK, &ekBuf, &ekLen) else { throw err("Serialize EK") }

        let joinEK = ofhe_multi_key_switch_gen(c, joinSK, ekBuf, ekLen)
        guard joinEK != nil else { throw err("Join MultiKeySwitchGen") }
        ofhe_free_buffer(ekBuf)

        let combinedEK = ofhe_multi_add_eval_keys(c, leadEK, joinEK, jointPKTag)
        guard combinedEK != nil else { throw err("MultiAddEvalKeys") }

        var combBuf: UnsafeMutablePointer<UInt8>?
        var combLen: Int = 0
        guard ofhe_serialize_eval_key(combinedEK, &combBuf, &combLen) else {
            throw err("Serialize combined EK")
        }

        let leadMEK = ofhe_multi_mult_eval_key(c, leadSK, combBuf, combLen, jointPKTag)
        guard leadMEK != nil else { throw err("Lead MultiMultEvalKey") }

        let joinMEK = ofhe_multi_mult_eval_key(c, joinSK, combBuf, combLen, jointPKTag)
        guard joinMEK != nil else { throw err("Join MultiMultEvalKey") }
        ofhe_free_buffer(combBuf)

        let finalMEK = ofhe_multi_add_eval_mult_keys(c, leadMEK, joinMEK, jointPKTag)
        guard finalMEK != nil else { throw err("MultiAddEvalMultKeys") }

        var finalBuf: UnsafeMutablePointer<UInt8>?
        var finalLen: Int = 0
        guard ofhe_serialize_eval_key(finalMEK, &finalBuf, &finalLen) else {
            throw err("Serialize final MEK")
        }
        guard ofhe_insert_eval_mult_key(c, finalBuf, finalLen) else {
            throw err("InsertEvalMultKey")
        }
        ofhe_free_buffer(finalBuf)

        ofhe_destroy_eval_key(leadEK)
        ofhe_destroy_eval_key(joinEK)
        ofhe_destroy_eval_key(combinedEK)
        ofhe_destroy_eval_key(leadMEK)
        ofhe_destroy_eval_key(joinMEK)
        ofhe_destroy_eval_key(finalMEK)
    }

    private func testCKKSEncode() throws {
        guard let c = ctx else { throw TestError("No context") }
        let values: [Double] = [1.5, 2.5, 3.5, 4.5]
        let pt = ofhe_make_ckks_packed_plaintext(c, values, values.count)
        guard pt != nil else { throw err() }

        var decoded = [Double](repeating: 0, count: 4)
        let count = ofhe_plaintext_get_real_packed_value(pt, &decoded, 4)
        guard count >= 4 else { throw TestError("Got \(count) values, expected 4") }

        for i in 0..<4 {
            let diff = abs(decoded[i] - values[i])
            guard diff < 0.001 else {
                throw TestError("Mismatch at [\(i)]: \(decoded[i]) vs \(values[i])")
            }
        }
        ofhe_destroy_plaintext(pt)
    }

    private func testThresholdDecrypt(ct: OFHECiphertext,
                                       leadSK: OFHEPrivateKey,
                                       joinSK: OFHEPrivateKey,
                                       expected: [Double]) throws {
        guard let c = ctx else { throw TestError("No context") }

        let partialLead = ofhe_multiparty_decrypt_lead(c, ct, leadSK)
        guard partialLead != nil else { throw err("Lead partial decrypt") }

        let partialJoin = ofhe_multiparty_decrypt_main(c, ct, joinSK)
        guard partialJoin != nil else { throw err("Join partial decrypt") }

        var partials: [OFHECiphertext?] = [partialLead, partialJoin]
        let fused = partials.withUnsafeMutableBufferPointer { buf -> OFHEPlaintext? in
            ofhe_multiparty_decrypt_fusion(c, buf.baseAddress, 2)
        }
        guard fused != nil else { throw err("Fusion") }

        ofhe_plaintext_set_length(fused, expected.count)
        var result = [Double](repeating: 0, count: expected.count)
        let n = ofhe_plaintext_get_real_packed_value(fused, &result, expected.count)
        guard n >= expected.count else { throw TestError("Got \(n) values") }

        for i in 0..<expected.count {
            let diff = abs(result[i] - expected[i])
            guard diff < 0.5 else {
                throw TestError("[\(i)]: got \(result[i]), expected \(expected[i]), diff=\(diff)")
            }
        }

        ofhe_destroy_ciphertext(partialLead)
        ofhe_destroy_ciphertext(partialJoin)
        ofhe_destroy_plaintext(fused)
    }

    // MARK: - Helpers

    private struct TestError: Error, CustomStringConvertible {
        let description: String
        init(_ msg: String) { self.description = msg }
    }

    private func err(_ prefix: String = "") -> TestError {
        let msg: String
        if let e = ofhe_last_error() {
            msg = String(cString: e)
        } else {
            msg = "Unknown error"
        }
        return TestError(prefix.isEmpty ? msg : "\(prefix): \(msg)")
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
            result = TestResult(name: name, passed: false, duration: dt,
                                detail: "\(error)")
        }
        results.append(result)
        onTestComplete?(result)
    }
}
