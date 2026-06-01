package com.example.openfhedemo

import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.view.Gravity
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import kotlin.concurrent.thread

/**
 * Test runner Activity that executes all three OpenFHE test suites
 * (OpenFHETests, RobustFHETests, MultipartyGPSTests) on a background thread
 * and displays results in a scrollable list.
 */
class TestRunnerActivity : AppCompatActivity() {

    private lateinit var statusText: TextView
    private lateinit var resultsContainer: LinearLayout
    private lateinit var summaryText: TextView
    private lateinit var runButton: Button

    private var totalPassed = 0
    private var totalFailed = 0
    private var totalTests = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // ── Build layout programmatically ──
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }

        // Handle System Insets (Status bar, Notch, etc.) to prevent obstruction
        ViewCompat.setOnApplyWindowInsetsListener(root) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            val density = resources.displayMetrics.density
            val padding = (24 * density).toInt()
            v.updatePadding(
                left = systemBars.left + padding,
                top = systemBars.top + padding,
                right = systemBars.right + padding,
                bottom = systemBars.bottom + padding
            )
            insets
        }

        // Title
        root.addView(TextView(this).apply {
            text = "OpenFHE Test Runner"
            textSize = 22f
            setTypeface(null, Typeface.BOLD)
            gravity = Gravity.CENTER
            setPadding(0, 0, 0, 16)
        })

        // Status
        statusText = TextView(this).apply {
            text = "Ready"
            textSize = 14f
            setTextColor(Color.DKGRAY)
            setPadding(0, 0, 0, 12)
        }
        root.addView(statusText)

        // Run button
        runButton = Button(this).apply {
            text = "Run All Tests"
            setOnClickListener { startTests() }
        }
        root.addView(runButton)

        // Summary
        summaryText = TextView(this).apply {
            textSize = 16f
            setTypeface(null, Typeface.BOLD)
            setPadding(0, 16, 0, 8)
        }
        root.addView(summaryText)

        // Scrollable results
        resultsContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        val scroll = ScrollView(this).apply {
            addView(resultsContainer)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f
            )
        }
        root.addView(scroll)

        setContentView(root)
    }

    private fun startTests() {
        runButton.isEnabled = false
        resultsContainer.removeAllViews()
        totalPassed = 0
        totalFailed = 0
        totalTests = 0
        summaryText.text = ""

        val cacheDir = cacheDir

        thread(name = "FHE-Tests") {
            runSuite("OpenFHETests", OpenFHETests(cacheDir))
            runSuite("RobustFHETests", RobustFHETests(cacheDir))
            runSuite("MultipartyGPSTests", MultipartyGPSTests(cacheDir))

            runOnUiThread {
                val failed = totalFailed
                val total = totalTests
                val color = if (failed == 0) COLOR_PASS else COLOR_FAIL
                summaryText.setTextColor(color)
                summaryText.text = "Done: $totalPassed/$total passed" +
                        if (failed > 0) ", $failed FAILED" else " — All pass!"
                statusText.text = "Complete"
                runButton.isEnabled = true
            }
        }
    }

    private fun runSuite(suiteName: String, suite: Any) {
        runOnUiThread {
            statusText.text = "Running $suiteName..."
            addSectionHeader(suiteName)
        }

        val latch = java.util.concurrent.CountDownLatch(1)

        val onTest: (OpenFHETests.TestResult) -> Unit = { result ->
            runOnUiThread { addResultRow(result) }
            totalTests++
            if (result.passed) totalPassed++ else totalFailed++
        }

        val onAll: (List<OpenFHETests.TestResult>) -> Unit = { _ ->
            latch.countDown()
        }

        when (suite) {
            is OpenFHETests -> {
                suite.onTestComplete = onTest
                suite.onAllComplete = onAll
                suite.runAll()
            }
            is RobustFHETests -> {
                suite.onTestComplete = onTest
                suite.onAllComplete = onAll
                suite.runAll()
            }
            is MultipartyGPSTests -> {
                suite.onTestComplete = onTest
                suite.onAllComplete = onAll
                suite.runAll()
            }
        }

        latch.await()
    }

    private fun addSectionHeader(title: String) {
        resultsContainer.addView(TextView(this).apply {
            text = "━━━ $title ━━━"
            textSize = 16f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#333333"))
            setPadding(0, 24, 0, 8)
        })
    }

    private fun addResultRow(result: OpenFHETests.TestResult) {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 4, 0, 4)
        }

        row.addView(TextView(this).apply {
            text = if (result.passed) "✓" else "✗"
            textSize = 16f
            setTextColor(if (result.passed) COLOR_PASS else COLOR_FAIL)
            setTypeface(null, Typeface.BOLD)
            setPadding(0, 0, 12, 0)
        })

        val info = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        info.addView(TextView(this).apply {
            text = result.name
            textSize = 14f
            setTypeface(null, Typeface.BOLD)
            setTextColor(if (result.passed) Color.DKGRAY else COLOR_FAIL)
        })

        val dtStr = "%.3fs".format(result.duration)
        val detailStr = if (result.detail == "OK") dtStr else "$dtStr — ${result.detail}"
        info.addView(TextView(this).apply {
            text = detailStr
            textSize = 11f
            setTextColor(if (result.passed) Color.GRAY else COLOR_FAIL_DETAIL)
            maxLines = 3
        })

        row.addView(info)
        resultsContainer.addView(row)
    }

    companion object {
        private val COLOR_PASS = Color.parseColor("#2E7D32")
        private val COLOR_FAIL = Color.parseColor("#C62828")
        private val COLOR_FAIL_DETAIL = Color.parseColor("#D32F2F")
    }
}
