import Foundation

/// Robust FHE test suite — verifies correctness, precision, edge cases,
/// chained operations, serialization round-trips under computation,
/// and memory safety. Reuses the cached crypto context from OpenFHETests.
///
/// All variables are safe optionals. Run from a background thread.
class RobustFHETests {

    typealias TestResult = OpenFHETests.TestResult

    private var results: [TestResult] = []
    private var ctx: OFHEContext?
    private var leadSK: OFHEPrivateKey?
    private var joinSK: OFHEPrivateKey?
    private var jointPK: OFHEPublicKey?
    private var evalKeyReady = false

    var onTestComplete: ((TestResult) -> Void)?
    var onAllComplete: (([TestResult]) -> Void)?

    // MARK: - Entry Point

    func runAll() {
        results = []

        // ── Setup (shared across all tests) ──
        run("Setup Context") { try self.setupContext() }
        guard ctx != nil else { abort("Context setup failed"); return }

        run("Setup Keys") { try self.setupKeys() }
        guard leadSK != nil, joinSK != nil, jointPK != nil else {
            abort("Key setup failed"); return
        }

        run("Setup EvalMultKey") { try self.setupEvalMultKey() }

        // ── 1. Precision Tests ──
        run("Precision: Small values") {
            try self.testEncryptDecrypt(
                values: [0.001, 0.002, 0.003, 0.004],
                tolerance: 0.001,
                label: "Small"
            )
        }

        run("Precision: Large values") {
            try self.testEncryptDecrypt(
                values: [1e6, 2e6, 3e6, 4e6],
                tolerance: 1.0,
                label: "Large"
            )
        }

        run("Precision: Negative values") {
            try self.testEncryptDecrypt(
                values: [-3.14, -2.71, -1.41, -0.57],
                tolerance: 0.01,
                label: "Negative"
            )
        }

        run("Precision: Mixed sign") {
            try self.testEncryptDecrypt(
                values: [-100.0, 0.0, 50.5, 200.0],
                tolerance: 0.5,
                label: "Mixed"
            )
        }

        // ── 2. Zero Vector ──
        run("Zero vector add") {
            let a: [Double] = [1.0, 2.0, 3.0, 4.0]
            let z: [Double] = [0.0, 0.0, 0.0, 0.0]
            try self.testBinaryOp(a, z, expected: a, op: .add, tolerance: 0.5)
        }

        run("Zero vector mult") {
            let a: [Double] = [1.0, 2.0, 3.0, 4.0]
            let z: [Double] = [0.0, 0.0, 0.0, 0.0]
            try self.testBinaryOp(a, z, expected: z, op: .mult, tolerance: 0.5)
        }

        // ── 3. Identity Operations ──
        run("Add then sub = identity") {
            let a: [Double] = [10.0, 20.0, 30.0, 40.0]
            let b: [Double] = [5.0, 5.0, 5.0, 5.0]
            // (a + b) - b should ≈ a
            try self.testChainedAddSub(a, b, expected: a, tolerance: 0.5)
        }

        run("Mult by 1 = identity") {
            let a: [Double] = [7.0, 8.0, 9.0, 10.0]
            try self.testScalarMult(a, scalar: 1.0, expected: a, tolerance: 0.5)
        }

        run("Mult by -1 = negation") {
            let a: [Double] = [3.0, 6.0, 9.0, 12.0]
            try self.testScalarMult(a, scalar: -1.0,
                                    expected: [-3.0, -6.0, -9.0, -12.0],
                                    tolerance: 0.5)
        }

        // ── 4. Chained Operations ──
        run("(a+b) * c") {
            // a=[1,2,3,4], b=[1,1,1,1], c=[2,2,2,2]
            // (a+b)*c = [4,6,8,10]
            try self.testChainedAddThenMult(
                a: [1.0, 2.0, 3.0, 4.0],
                b: [1.0, 1.0, 1.0, 1.0],
                c: [2.0, 2.0, 2.0, 2.0],
                expected: [4.0, 6.0, 8.0, 10.0],
                tolerance: 0.5
            )
        }

        run("a*b + c*d") {
            // a=[1,2,3,4]*b=[2,2,2,2] + c=[1,1,1,1]*d=[3,3,3,3]
            // = [2,4,6,8] + [3,3,3,3] = [5,7,9,11]
            try self.testDotProduct(
                a: [1, 2, 3, 4], b: [2, 2, 2, 2],
                c: [1, 1, 1, 1], d: [3, 3, 3, 3],
                expected: [5, 7, 9, 11],
                tolerance: 0.5
            )
        }

        run("Scalar add + scalar mult") {
            // (a + 10) * 3, a = [1,2,3,4]
            // = [33, 36, 39, 42]
            try self.testScalarChain(
                a: [1.0, 2.0, 3.0, 4.0],
                addScalar: 10.0, multScalar: 3.0,
                expected: [33.0, 36.0, 39.0, 42.0],
                tolerance: 0.5
            )
        }

        // ── 5. Serialization Under Computation ──
        run("Serialize mid-computation") {
            try self.testSerializeMidComputation()
        }

        // ── 6. Multiple Encryptions Same Plaintext ──
        run("Double encrypt differ") {
            // Two encryptions of the same plaintext should produce different ciphertexts
            // but decrypt to the same values
            try self.testDoubleEncrypt()
        }

        // ── 7. Euclidean Distance² (real-world use case) ──
        run("Distance² computation") {
            // d²(a,b) = Σ(a_i - b_i)²
            // a=[1,2,3,4], b=[5,6,7,8] → diffs=[-4,-4,-4,-4] → squares=[16,16,16,16]
            try self.testDistanceSquared(
                a: [1.0, 2.0, 3.0, 4.0],
                b: [5.0, 6.0, 7.0, 8.0],
                expectedSquares: [16.0, 16.0, 16.0, 16.0],
                tolerance: 1.0
            )
        }

        // ── 8. Memory Stress ──
        run("Alloc/free 20 CTs") {
            try self.testMemoryStress(count: 20)
        }

        // ── 9. Large-ish Batch ──
        run("Batch 32 slots") {
            var vals = [Double](repeating: 0, count: 32)
            for i in 0..<32 { vals[i] = Double(i) }
            try self.testEncryptDecrypt(values: vals, tolerance: 0.5, label: "Batch32")
        }

        // ── 10. Commutativity ──
        run("Add commutative") {
            let a: [Double] = [1.0, 2.0, 3.0, 4.0]
            let b: [Double] = [5.0, 6.0, 7.0, 8.0]
            try self.testCommutativity(a, b, op: .add, tolerance: 0.5)
        }

        run("Mult commutative") {
            let a: [Double] = [1.0, 2.0, 3.0, 4.0]
            let b: [Double] = [5.0, 6.0, 7.0, 8.0]
            guard self.evalKeyReady else { throw TestError("EvalMultKey not ready") }
            try self.testCommutativity(a, b, op: .mult, tolerance: 0.5)
        }

        // ── Cleanup ──
        cleanup()
        onAllComplete?(results)
    }

    // MARK: - Setup

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

    private func setupKeys() throws {
        guard let c = ctx else { throw TestError("No context") }

        let leadKP = ofhe_keygen(c)
        guard leadKP != nil else { throw err() }
        let lPK = ofhe_keypair_get_public_key(leadKP)
        leadSK = ofhe_keypair_get_secret_key(leadKP)
        guard lPK != nil, leadSK != nil else { throw err() }

        var pkBuf: UnsafeMutablePointer<UInt8>?
        var pkLen: Int = 0
        guard ofhe_serialize_public_key(lPK, &pkBuf, &pkLen) else { throw err() }

        let joinKP = ofhe_multiparty_keygen(c, pkBuf, pkLen)
        guard joinKP != nil else { throw err() }
        joinSK = ofhe_keypair_get_secret_key(joinKP)
        jointPK = ofhe_keypair_get_public_key(joinKP)
        guard joinSK != nil, jointPK != nil else { throw err() }

        ofhe_free_buffer(pkBuf)
        ofhe_destroy_public_key(lPK)
        ofhe_destroy_keypair(leadKP)
        ofhe_destroy_keypair(joinKP)
    }

    private func setupEvalMultKey() throws {
        guard let c = ctx, let ls = leadSK, let js = joinSK, let jpk = jointPK else {
            throw TestError("Missing context or keys")
        }

        guard let tagPtr = ofhe_get_public_key_tag(jpk) else { throw err() }
        let tag = String(cString: tagPtr)

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

    // MARK: - Encrypt / Decrypt Helpers

    private func encrypt(_ values: [Double]) throws -> OFHECiphertext {
        guard let c = ctx, let pk = jointPK else { throw TestError("No context/PK") }
        let pt = ofhe_make_ckks_packed_plaintext(c, values, values.count)
        guard pt != nil else { throw err() }
        let ct = ofhe_encrypt(c, pk, pt)
        guard ct != nil else { throw err() }
        ofhe_destroy_plaintext(pt)
        return ct!
    }

    private func decrypt(_ ct: OFHECiphertext, count: Int) throws -> [Double] {
        guard let c = ctx, let ls = leadSK, let js = joinSK else {
            throw TestError("No context/keys")
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

    private func assertClose(_ actual: [Double], _ expected: [Double],
                             tolerance: Double, label: String) throws {
        guard actual.count >= expected.count else {
            throw TestError("\(label): got \(actual.count) values, expected \(expected.count)")
        }
        for i in 0..<expected.count {
            let diff = abs(actual[i] - expected[i])
            guard diff < tolerance else {
                throw TestError("\(label)[\(i)]: got \(String(format: "%.4f", actual[i])), " +
                                "expected \(String(format: "%.4f", expected[i])), diff=\(String(format: "%.4f", diff))")
            }
        }
    }

    // MARK: - Test Implementations

    private func testEncryptDecrypt(values: [Double], tolerance: Double, label: String) throws {
        let ct = try encrypt(values)
        let result = try decrypt(ct, count: values.count)
        ofhe_destroy_ciphertext(ct)
        try assertClose(result, values, tolerance: tolerance, label: label)
    }

    enum BinOp { case add, sub, mult }

    private func testBinaryOp(_ a: [Double], _ b: [Double], expected: [Double],
                              op: BinOp, tolerance: Double) throws {
        guard let c = ctx else { throw TestError("No context") }
        let ctA = try encrypt(a)
        let ctB = try encrypt(b)

        var ctR: OFHECiphertext?
        switch op {
        case .add:  ctR = ofhe_eval_add_ct_ct(c, ctA, ctB)
        case .sub:  ctR = ofhe_eval_sub_ct_ct(c, ctA, ctB)
        case .mult: ctR = ofhe_eval_mult_ct_ct(c, ctA, ctB)
        }
        guard let r = ctR else { throw err() }

        let result = try decrypt(r, count: expected.count)
        ofhe_destroy_ciphertext(ctA)
        ofhe_destroy_ciphertext(ctB)
        ofhe_destroy_ciphertext(r)
        try assertClose(result, expected, tolerance: tolerance, label: "\(op)")
    }

    private func testChainedAddSub(_ a: [Double], _ b: [Double],
                                    expected: [Double], tolerance: Double) throws {
        guard let c = ctx else { throw TestError("No context") }
        let ctA = try encrypt(a)
        let ctB = try encrypt(b)
        let ctSum = ofhe_eval_add_ct_ct(c, ctA, ctB)
        guard ctSum != nil else { throw err() }
        let ctResult = ofhe_eval_sub_ct_ct(c, ctSum, ctB)
        guard ctResult != nil else { throw err() }

        let result = try decrypt(ctResult!, count: expected.count)
        [ctA, ctB, ctSum, ctResult].compactMap { $0 }.forEach { ofhe_destroy_ciphertext($0) }
        try assertClose(result, expected, tolerance: tolerance, label: "AddSub")
    }

    private func testScalarMult(_ a: [Double], scalar: Double,
                                expected: [Double], tolerance: Double) throws {
        guard let c = ctx else { throw TestError("No context") }
        let ctA = try encrypt(a)
        let ctR = ofhe_eval_mult_ct_double(c, ctA, scalar)
        guard ctR != nil else { throw err() }

        let result = try decrypt(ctR!, count: expected.count)
        ofhe_destroy_ciphertext(ctA)
        ofhe_destroy_ciphertext(ctR)
        try assertClose(result, expected, tolerance: tolerance, label: "ScalarMult")
    }

    private func testChainedAddThenMult(a: [Double], b: [Double], c cVals: [Double],
                                         expected: [Double], tolerance: Double) throws {
        guard let ctx = ctx else { throw TestError("No context") }
        let ctA = try encrypt(a)
        let ctB = try encrypt(b)
        let ctC = try encrypt(cVals)

        let ctSum = ofhe_eval_add_ct_ct(ctx, ctA, ctB)
        guard ctSum != nil else { throw err() }
        guard evalKeyReady else { throw TestError("No eval mult key") }
        let ctR = ofhe_eval_mult_ct_ct(ctx, ctSum, ctC)
        guard ctR != nil else { throw err() }

        let result = try decrypt(ctR!, count: expected.count)
        [ctA, ctB, ctC, ctSum, ctR].compactMap { $0 }.forEach { ofhe_destroy_ciphertext($0) }
        try assertClose(result, expected, tolerance: tolerance, label: "(a+b)*c")
    }

    private func testDotProduct(a: [Double], b: [Double], c: [Double], d: [Double],
                                expected: [Double], tolerance: Double) throws {
        guard let ctx = ctx else { throw TestError("No context") }
        guard evalKeyReady else { throw TestError("No eval mult key") }

        let ctA = try encrypt(a)
        let ctB = try encrypt(b)
        let ctC = try encrypt(c)
        let ctD = try encrypt(d)

        let ctAB = ofhe_eval_mult_ct_ct(ctx, ctA, ctB)
        guard ctAB != nil else { throw err() }
        let ctCD = ofhe_eval_mult_ct_ct(ctx, ctC, ctD)
        guard ctCD != nil else { throw err() }
        let ctR = ofhe_eval_add_ct_ct(ctx, ctAB, ctCD)
        guard ctR != nil else { throw err() }

        let result = try decrypt(ctR!, count: expected.count)
        [ctA, ctB, ctC, ctD, ctAB, ctCD, ctR].compactMap { $0 }.forEach { ofhe_destroy_ciphertext($0) }
        try assertClose(result, expected, tolerance: tolerance, label: "a*b+c*d")
    }

    private func testScalarChain(a: [Double], addScalar: Double, multScalar: Double,
                                 expected: [Double], tolerance: Double) throws {
        guard let ctx = ctx else { throw TestError("No context") }
        let ctA = try encrypt(a)

        let ctAdded = ofhe_eval_add_ct_double(ctx, ctA, addScalar)
        guard ctAdded != nil else { throw err() }
        let ctR = ofhe_eval_mult_ct_double(ctx, ctAdded, multScalar)
        guard ctR != nil else { throw err() }

        let result = try decrypt(ctR!, count: expected.count)
        [ctA, ctAdded, ctR].compactMap { $0 }.forEach { ofhe_destroy_ciphertext($0) }
        try assertClose(result, expected, tolerance: tolerance, label: "ScalarChain")
    }

    private func testSerializeMidComputation() throws {
        guard let c = ctx else { throw TestError("No context") }
        let a: [Double] = [10.0, 20.0, 30.0, 40.0]
        let b: [Double] = [1.0, 2.0, 3.0, 4.0]
        let ctA = try encrypt(a)
        let ctB = try encrypt(b)
        let ctSum = ofhe_eval_add_ct_ct(c, ctA, ctB)
        guard ctSum != nil else { throw err() }

        // Serialize the intermediate result
        var buf: UnsafeMutablePointer<UInt8>?
        var len: Int = 0
        guard ofhe_serialize_ciphertext(ctSum, &buf, &len) else { throw err() }
        guard len > 0 else { throw TestError("Empty serialized CT") }

        // Deserialize and decrypt
        let restored = ofhe_deserialize_ciphertext(c, buf, len)
        guard restored != nil else { throw err() }
        ofhe_free_buffer(buf)

        let result = try decrypt(restored!, count: 4)
        [ctA, ctB, ctSum, restored].compactMap { $0 }.forEach { ofhe_destroy_ciphertext($0) }
        try assertClose(result, [11.0, 22.0, 33.0, 44.0], tolerance: 0.5,
                        label: "SerMidComp")
    }

    private func testDoubleEncrypt() throws {
        let vals: [Double] = [42.0, 43.0, 44.0, 45.0]
        let ct1 = try encrypt(vals)
        let ct2 = try encrypt(vals)

        // Serialize both — they should differ (randomized encryption)
        var buf1: UnsafeMutablePointer<UInt8>?, buf2: UnsafeMutablePointer<UInt8>?
        var len1: Int = 0, len2: Int = 0
        guard ofhe_serialize_ciphertext(ct1, &buf1, &len1),
              ofhe_serialize_ciphertext(ct2, &buf2, &len2) else { throw err() }

        let data1 = Data(bytes: buf1!, count: len1)
        let data2 = Data(bytes: buf2!, count: len2)
        ofhe_free_buffer(buf1)
        ofhe_free_buffer(buf2)

        guard data1 != data2 else {
            throw TestError("Two encryptions produced identical ciphertexts — randomization broken")
        }

        // Both should decrypt to same values
        let r1 = try decrypt(ct1, count: 4)
        let r2 = try decrypt(ct2, count: 4)
        ofhe_destroy_ciphertext(ct1)
        ofhe_destroy_ciphertext(ct2)
        try assertClose(r1, vals, tolerance: 0.5, label: "Enc1")
        try assertClose(r2, vals, tolerance: 0.5, label: "Enc2")
    }

    private func testDistanceSquared(a: [Double], b: [Double],
                                     expectedSquares: [Double], tolerance: Double) throws {
        guard let c = ctx else { throw TestError("No context") }
        guard evalKeyReady else { throw TestError("No eval mult key") }

        let ctA = try encrypt(a)
        let ctB = try encrypt(b)

        // diff = a - b
        let ctDiff = ofhe_eval_sub_ct_ct(c, ctA, ctB)
        guard ctDiff != nil else { throw err() }

        // diff² = diff * diff
        let ctSq = ofhe_eval_mult_ct_ct(c, ctDiff, ctDiff)
        guard ctSq != nil else { throw err() }

        let result = try decrypt(ctSq!, count: expectedSquares.count)
        [ctA, ctB, ctDiff, ctSq].compactMap { $0 }.forEach { ofhe_destroy_ciphertext($0) }
        try assertClose(result, expectedSquares, tolerance: tolerance, label: "Dist²")
    }

    private func testMemoryStress(count: Int) throws {
        var ciphertexts: [OFHECiphertext] = []
        let vals: [Double] = [1.0, 2.0, 3.0, 4.0]

        for _ in 0..<count {
            let ct = try encrypt(vals)
            ciphertexts.append(ct)
        }

        // Verify last one still decrypts correctly
        let result = try decrypt(ciphertexts.last!, count: 4)
        try assertClose(result, vals, tolerance: 0.5, label: "Stress")

        // Free all
        ciphertexts.forEach { ofhe_destroy_ciphertext($0) }
    }

    private func testCommutativity(_ a: [Double], _ b: [Double],
                                    op: BinOp, tolerance: Double) throws {
        guard let c = ctx else { throw TestError("No context") }
        let ctA = try encrypt(a)
        let ctB = try encrypt(b)

        var ct1: OFHECiphertext?, ct2: OFHECiphertext?
        switch op {
        case .add:
            ct1 = ofhe_eval_add_ct_ct(c, ctA, ctB)
            ct2 = ofhe_eval_add_ct_ct(c, ctB, ctA)
        case .mult:
            ct1 = ofhe_eval_mult_ct_ct(c, ctA, ctB)
            ct2 = ofhe_eval_mult_ct_ct(c, ctB, ctA)
        case .sub:
            throw TestError("Sub is not commutative")
        }
        guard let r1 = ct1, let r2 = ct2 else { throw err() }

        let v1 = try decrypt(r1, count: a.count)
        let v2 = try decrypt(r2, count: a.count)
        [ctA, ctB, r1, r2].forEach { ofhe_destroy_ciphertext($0) }

        // v1 and v2 should be approximately equal
        try assertClose(v1, v2, tolerance: tolerance, label: "Commute-\(op)")
    }

    // MARK: - Cleanup

    private func cleanup() {
        if let k = leadSK { ofhe_destroy_private_key(k) }
        if let k = joinSK { ofhe_destroy_private_key(k) }
        if let k = jointPK { ofhe_destroy_public_key(k) }
        if let c = ctx { ofhe_destroy_context(c) }
    }

    // MARK: - Helpers

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
