package com.networkmonitor.secure_network_monitor.dualsight.controller;

import com.networkmonitor.secure_network_monitor.dualsight.model.CodeChange;
import com.networkmonitor.secure_network_monitor.dualsight.model.TestCaseInfo;
import com.networkmonitor.secure_network_monitor.dualsight.service.DualSightService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * REST API controller for DualSight regression testing features.
 */
@RestController
@RequestMapping("/api/dualsight")
public class DualSightController {

    @Autowired
    private DualSightService dualSightService;

    /**
     * Get all registered test cases.
     */
    @GetMapping("/testcases")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<List<TestCaseInfo>> getAllTestCases() {
        return ResponseEntity.ok(dualSightService.getPrioritizedTestCases());
    }

    /**
     * Get prioritized test case list after change detection.
     */
    @GetMapping("/prioritized")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<List<TestCaseInfo>> getPrioritizedTests() {
        return ResponseEntity.ok(dualSightService.getPrioritizedTestCases());
    }

    /**
     * Get recent test execution results.
     */
    @GetMapping("/results")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<?> getRecentResults() {
        return ResponseEntity.ok(dualSightService.getRecentResults());
    }

    /**
     * Get DualSight dashboard statistics.
     */
    @GetMapping("/stats")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Map<String, Object>> getStats() {
        return ResponseEntity.ok(dualSightService.getDashboardStats());
    }

    /**
     * Get detected code changes from the last scan.
     */
    @GetMapping("/changes")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<List<CodeChange>> getChanges() {
        return ResponseEntity.ok(dualSightService.getDetectedChanges());
    }

    /**
     * Trigger a new change detection scan.
     */
    @PostMapping("/scan")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> triggerScan() {
        Map<String, Object> result = dualSightService.performScan();
        return ResponseEntity.ok(result);
    }

    /**
     * Update the code baseline snapshot.
     */
    @PostMapping("/baseline")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> updateBaseline() {
        int filesProcessed = dualSightService.updateBaseline();
        return ResponseEntity.ok(Map.of(
                "message", "Baseline updated successfully",
                "filesProcessed", filesProcessed
        ));
    }

    /**
     * Trigger Live Test Runner via native executing and streaming HTTP response.
     * After tests complete, automatically parses surefire reports and updates DB.
     */
    @GetMapping(value = "/run-tests", produces = org.springframework.http.MediaType.TEXT_PLAIN_VALUE)
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody> runLiveTests() {
        org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody responseBody = out -> {
            try {
                ProcessBuilder builder = new ProcessBuilder();
                if (System.getProperty("os.name").toLowerCase().contains("win")) {
                    builder.command("cmd.exe", "/c", "mvnw.cmd test");
                } else {
                    builder.command("sh", "-c", "./mvnw test");
                }
                builder.directory(new java.io.File(System.getProperty("user.dir")));
                builder.redirectErrorStream(true);

                Process process = builder.start();
                try (java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        out.write((line + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
                        out.flush();
                    }
                }
                int exitCode = process.waitFor();
                out.write(("\n[PROCESS COMPLETE] Exit Code: " + exitCode + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
                out.flush();

                // Parse surefire reports and update DB with PASS/FAIL results
                Map<String, Object> parseResult = dualSightService.updateTestResultsFromSurefireReports();
                out.write(("[RESULTS UPDATED] " + parseResult.toString() + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
                out.flush();
            } catch (Exception e) {
                out.write(("\n[ERROR] " + e.getMessage() + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
                out.flush();
            }
        };
        return ResponseEntity.ok()
                .header(org.springframework.http.HttpHeaders.CONTENT_TYPE, org.springframework.http.MediaType.TEXT_PLAIN_VALUE)
                .body(responseBody);
    }

    /**
     * Manually trigger parsing of surefire reports and update test results in DB.
     */
    @PostMapping("/update-results")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> updateResults() {
        return ResponseEntity.ok(dualSightService.updateTestResultsFromSurefireReports());
    }
}
