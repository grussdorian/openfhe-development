import SwiftUI
import Combine

enum TestSuite: String, CaseIterable, Identifiable {
    case api = "API Tests"
    case robust = "Robust Tests"
    case multiGPS = "Keys + GPS"
    var id: String { rawValue }
}

struct ContentView: View {
    @StateObject private var vm = FHETestViewModel()

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                // Suite picker
                Picker("Suite", selection: $vm.selectedSuite) {
                    ForEach(TestSuite.allCases) { suite in
                        Text(suite.rawValue).tag(suite)
                    }
                }
                .pickerStyle(.segmented)
                .padding(.horizontal)
                .padding(.top, 8)
                .disabled(vm.running)

                // Summary bar
                HStack {
                    Label("\(vm.passed)", systemImage: "checkmark.circle.fill")
                        .foregroundColor(.green)
                    Label("\(vm.failed)", systemImage: "xmark.circle.fill")
                        .foregroundColor(.red)
                    Spacer()
                    if vm.running {
                        ProgressView()
                            .padding(.trailing, 4)
                        Text(vm.statusMessage)
                            .foregroundColor(.secondary)
                    } else if vm.results.isEmpty {
                        Text("Tap Run to start")
                            .foregroundColor(.secondary)
                    } else {
                        Text(String(format: "%.1fs total", vm.totalTime))
                            .foregroundColor(.secondary)
                    }
                }
                .font(.headline)
                .padding()
                .background(Color(.systemGroupedBackground))

                // First-run banner
                if vm.isFirstRun {
                    HStack(spacing: 8) {
                        Image(systemName: "info.circle.fill")
                            .foregroundColor(.blue)
                        Text(vm.running
                             ? "Generating crypto parameters — this only happens once..."
                             : "First run generates crypto parameters (~5-10s). Subsequent runs load from cache and are much faster.")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    .padding(.horizontal)
                    .padding(.vertical, 8)
                    .background(Color(.systemBlue).opacity(0.08))
                    .cornerRadius(8)
                    .padding(.horizontal)
                    .padding(.top, 8)
                }

                // Test results — ScrollView instead of List for reliable scrolling
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 8) {
                        ForEach(vm.results) { result in
                            HStack {
                                Image(systemName: result.passed ? "checkmark.circle.fill" : "xmark.circle.fill")
                                    .foregroundColor(result.passed ? .green : .red)

                                VStack(alignment: .leading, spacing: 2) {
                                    Text(result.name)
                                        .font(.body.weight(.medium))
                                    if !result.passed {
                                        Text(result.detail)
                                            .font(.caption)
                                            .foregroundColor(.red)
                                    } else if result.detail != "OK" {
                                        Text(result.detail)
                                            .font(.caption)
                                            .foregroundColor(.secondary)
                                    }
                                }

                                Spacer()

                                Text(String(format: "%.2fs", result.duration))
                                    .font(.caption.monospacedDigit())
                                    .foregroundColor(.secondary)
                            }
                            .padding(.horizontal)
                            .padding(.vertical, 6)
                        }
                    }
                    .padding(.top, 8)
                }
            }
            .navigationTitle("OpenFHE Tests")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: { vm.runTests() }) {
                        Label("Run", systemImage: "play.fill")
                    }
                    .disabled(vm.running)
                }
            }
        }
    }
}

// MARK: - ViewModel

class FHETestViewModel: ObservableObject {
    @Published var results: [TestRow] = []
    @Published var running = false
    @Published var passed = 0
    @Published var failed = 0
    @Published var totalTime: TimeInterval = 0
    @Published var statusMessage = "Running..."
    @Published var isFirstRun: Bool
    @Published var selectedSuite: TestSuite = .api

    /// Cache path — computed independently of OpenFHETests to avoid
    /// touching OpenFHE symbols at ViewModel init time.
    private static let cacheURL: URL = {
        let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first!
        return caches.appendingPathComponent("openfhe_context.bin")
    }()

    init() {
        isFirstRun = !FileManager.default.fileExists(atPath: Self.cacheURL.path)
    }

    struct TestRow: Identifiable {
        let id = UUID()
        let name: String
        let passed: Bool
        let duration: TimeInterval
        let detail: String
    }

    func runTests() {
        results = []
        passed = 0
        failed = 0
        totalTime = 0
        running = true
        statusMessage = isFirstRun
            ? "Generating crypto params (one-time)..."
            : "Running..."

        let suite = selectedSuite

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let startAll = CFAbsoluteTimeGetCurrent()

            let onResult: (OpenFHETests.TestResult) -> Void = { result in
                DispatchQueue.main.async {
                    guard let self = self else { return }
                    let row = TestRow(name: result.name, passed: result.passed,
                                     duration: result.duration, detail: result.detail)
                    self.results.append(row)
                    if result.passed { self.passed += 1 } else { self.failed += 1 }
                    // After context creation finishes, switch to normal status
                    if result.name.contains("Context") {
                        self.statusMessage = "Running..."
                        self.isFirstRun = false
                    }
                }
            }

            let onDone: ([OpenFHETests.TestResult]) -> Void = { _ in
                DispatchQueue.main.async {
                    guard let self = self else { return }
                    self.totalTime = CFAbsoluteTimeGetCurrent() - startAll
                    self.running = false
                }
            }

            switch suite {
            case .api:
                let tests = OpenFHETests()
                tests.onTestComplete = onResult
                tests.onAllComplete = onDone
                tests.runAll()

            case .robust:
                let tests = RobustFHETests()
                tests.onTestComplete = onResult
                tests.onAllComplete = onDone
                tests.runAll()

            case .multiGPS:
                let tests = MultipartyGPSTests()
                tests.onTestComplete = onResult
                tests.onAllComplete = onDone
                tests.runAll()
            }
        }
    }
}

#Preview {
    ContentView()
}
