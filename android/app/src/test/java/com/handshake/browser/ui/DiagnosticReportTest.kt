package com.handshake.browser.ui

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DiagnosticReportTest {
    @Test
    fun markdownIncludesOperationalFieldsAndEscapesCodeFences() {
        val report = DiagnosticReport.markdown(
            buildLabel = "debug 0.2.2 (13)",
            rustCore = "hns-browser-rust-core/0.2.2",
            rustDiagnostics = """{"securityDefault":"fail-closed","note":"```"}""",
            syncStatus = """{"status":"up_to_date","bestHeight":1}""",
            proxyOverrideSupported = true,
            thirdPartyCookiesBlocked = true,
            gatewayEvents = "123 native_response welcome 502 HNS_Nameserver_Unavailable",
            generatedAtMillis = 0,
        )

        assertTrue(report.contains("# HNS Browser Diagnostic Bundle"))
        assertTrue(report.contains("Generated: 1970-01-01T00:00:00Z"))
        assertTrue(report.contains("Build: debug 0.2.2 (13)"))
        assertTrue(report.contains("Rust core: hns-browser-rust-core/0.2.2"))
        assertTrue(report.contains("Proxy override supported: true"))
        assertTrue(report.contains("""{"status":"up_to_date","bestHeight":1}"""))
        assertTrue(report.contains("123 native_response welcome 502 HNS_Nameserver_Unavailable"))
        assertTrue(report.contains("` ` `"))
        assertFalse(report.contains("\"note\":\"```\""))
    }
}
