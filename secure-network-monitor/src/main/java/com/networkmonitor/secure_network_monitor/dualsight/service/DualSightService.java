package com.networkmonitor.secure_network_monitor.dualsight.service;

import com.networkmonitor.secure_network_monitor.dualsight.model.CodeChange;
import com.networkmonitor.secure_network_monitor.dualsight.model.TestCaseInfo;
import com.networkmonitor.secure_network_monitor.dualsight.entity.TestResultEntity;
import com.networkmonitor.secure_network_monitor.dualsight.repository.TestCaseEntityRepository;
import com.networkmonitor.secure_network_monitor.dualsight.repository.TestResultEntityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * DualSight Orchestrator Service.
 * Ties together change detection, test case registry, and prioritization
 * to produce the final dashboard data.
 */
@Service
public class DualSightService {

    @Autowired
    private ChangeDetectionService changeDetectionService;

    @Autowired
    private TestCaseRegistry testCaseRegistry;

    @Autowired
    private TestPrioritizer testPrioritizer;

    @Autowired
    private TestCaseEntityRepository testCaseRepository;

    @Autowired
    private TestResultEntityRepository testResultRepository;

    // Cached results from last scan
    private List<CodeChange> lastDetectedChanges = new ArrayList<>();
    private List<TestCaseInfo> lastPrioritizedTests = new ArrayList<>();
    private LocalDateTime lastScanTime;

    /**
     * Gets the source root path for the project's Java files.
     */
    private String getSourceRoot() {
        // Use relative path from working directory
        return "src/main/java/com/networkmonitor/secure_network_monitor";
    }

    /**
     * Performs a full scan: detect changes → prioritize tests.
     *
     * @return map containing scan results
     */
    public Map<String, Object> performScan() {
        Map<String, Object> result = new HashMap<>();

        // 1. Detect code changes
        String sourceRoot = getSourceRoot();
        lastDetectedChanges = changeDetectionService.detectChanges(sourceRoot);

        // 2. Get all registered test cases
        List<TestCaseInfo> allTests = testCaseRegistry.getAllTestCases();

        // 3. Prioritize based on changes
        lastPrioritizedTests = testPrioritizer.prioritize(allTests, lastDetectedChanges);

        // 4. Update scan time
        lastScanTime = LocalDateTime.now();

        result.put("changesDetected", lastDetectedChanges.size());
        result.put("totalTests", lastPrioritizedTests.size());
        result.put("highPriority", lastPrioritizedTests.stream()
                .filter(t -> t.getPriority() == TestCaseInfo.PriorityLevel.HIGH).count());
        result.put("mediumPriority", lastPrioritizedTests.stream()
                .filter(t -> t.getPriority() == TestCaseInfo.PriorityLevel.MEDIUM).count());
        result.put("lowPriority", lastPrioritizedTests.stream()
                .filter(t -> t.getPriority() == TestCaseInfo.PriorityLevel.LOW).count());
        result.put("scanTime", lastScanTime.toString());

        return result;
    }

    /**
     * Updates the code baseline snapshot.
     *
     * @return number of files processed
     */
    public int updateBaseline() {
        return changeDetectionService.updateBaseline(getSourceRoot());
    }

    /**
     * Returns comprehensive statistics for the DualSight dashboard.
     */
    public Map<String, Object> getDashboardStats() {
        Map<String, Object> stats = new HashMap<>();

        // Test counts
        long totalTests = testCaseRepository.count();
        long blackBoxCount = testCaseRepository.countByTestType("BLACK_BOX");
        long whiteBoxCount = testCaseRepository.countByTestType("WHITE_BOX");

        // Result counts
        long totalResults = testResultRepository.count();
        long passedCount = testResultRepository.countPassed();
        long failedCount = testResultRepository.countFailed();

        // Tests by component
        Map<String, Long> testsByComponent = testCaseRepository.getTestCountByComponent().stream()
                .filter(obj -> obj[0] != null)
                .collect(Collectors.toMap(obj -> (String) obj[0], obj -> (Long) obj[1]));

        stats.put("totalTests", totalTests);
        stats.put("blackBoxCount", blackBoxCount);
        stats.put("whiteBoxCount", whiteBoxCount);
        stats.put("totalResults", totalResults);
        stats.put("passedCount", passedCount);
        stats.put("failedCount", failedCount);
        stats.put("testsByComponent", testsByComponent);
        stats.put("changesDetected", lastDetectedChanges != null ? lastDetectedChanges.size() : 0);
        stats.put("lastScanTime", lastScanTime != null ? lastScanTime.toString() : "Never");
        stats.put("passRate", totalResults > 0 ? String.format("%.1f", (passedCount * 100.0 / totalResults)) : "N/A");

        return stats;
    }

    /**
     * Returns the prioritized test case list.
     */
    public List<TestCaseInfo> getPrioritizedTestCases() {
        if (lastPrioritizedTests == null || lastPrioritizedTests.isEmpty()) {
            return testCaseRegistry.getAllTestCases();
        }
        return lastPrioritizedTests;
    }

    /**
     * Returns detected code changes from the last scan.
     */
    public List<CodeChange> getDetectedChanges() {
        return lastDetectedChanges != null ? lastDetectedChanges : new ArrayList<>();
    }

    /**
     * Returns recent test results.
     */
    public List<TestResultEntity> getRecentResults() {
        return testResultRepository.findTop50ByOrderByRunTimestampDesc();
    }

    /**
     * Parses Maven Surefire XML reports and updates each TestCaseEntity's
     * lastRunStatus to PASS or FAIL based on the actual test results.
     * This bridges the gap between the external Maven test process and the dashboard DB.
     */
    public Map<String, Object> updateTestResultsFromSurefireReports() {
        Map<String, Object> summary = new java.util.HashMap<>();
        int updated = 0;
        int passed = 0;
        int failed = 0;

        java.io.File reportsDir = new java.io.File(System.getProperty("user.dir"), "target/surefire-reports");
        if (!reportsDir.exists() || !reportsDir.isDirectory()) {
            summary.put("error", "Surefire reports directory not found");
            return summary;
        }

        // Find all TEST-*.xml files
        java.io.File[] xmlFiles = reportsDir.listFiles((dir, name) -> name.startsWith("TEST-") && name.endsWith(".xml"));
        if (xmlFiles == null || xmlFiles.length == 0) {
            summary.put("error", "No surefire XML reports found");
            return summary;
        }

        try {
            javax.xml.parsers.DocumentBuilderFactory factory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
            javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();

            for (java.io.File xmlFile : xmlFiles) {
                try {
                    org.w3c.dom.Document doc = builder.parse(xmlFile);
                    doc.getDocumentElement().normalize();

                    // Each <testcase> element represents one test method
                    org.w3c.dom.NodeList testcases = doc.getElementsByTagName("testcase");
                    for (int i = 0; i < testcases.getLength(); i++) {
                        org.w3c.dom.Element tc = (org.w3c.dom.Element) testcases.item(i);
                        String methodName = tc.getAttribute("name");
                        String className = tc.getAttribute("classname");
                        // Extract simple class name from FQCN
                        String simpleClassName = className.contains(".")
                                ? className.substring(className.lastIndexOf('.') + 1)
                                : className;

                        // Check if there's a <failure> or <error> child element
                        boolean hasFailed = tc.getElementsByTagName("failure").getLength() > 0
                                         || tc.getElementsByTagName("error").getLength() > 0;

                        String status = hasFailed ? "FAIL" : "PASS";

                        // Find the matching TestCaseEntity by methodName
                        java.util.Optional<com.networkmonitor.secure_network_monitor.dualsight.entity.TestCaseEntity> entityOpt =
                                testCaseRepository.findByMethodName(methodName);
                        if (entityOpt.isPresent()) {
                            com.networkmonitor.secure_network_monitor.dualsight.entity.TestCaseEntity entity = entityOpt.get();
                            entity.setLastRunStatus(status);
                            entity.setLastRunTimestamp(java.time.LocalDateTime.now());
                            entity.setTotalRuns(entity.getTotalRuns() != null ? entity.getTotalRuns() + 1 : 1);
                            if (hasFailed) {
                                entity.setFailureCount(entity.getFailureCount() != null ? entity.getFailureCount() + 1 : 1);
                                failed++;
                            } else {
                                passed++;
                            }

                            // Parse execution time
                            String timeStr = tc.getAttribute("time");
                            if (timeStr != null && !timeStr.isEmpty()) {
                                try {
                                    entity.setLastRunDurationMs((long)(Double.parseDouble(timeStr) * 1000));
                                } catch (NumberFormatException ignore) {}
                            }

                            testCaseRepository.save(entity);
                            updated++;

                            // Also save a TestResultEntity for detailed history
                            TestResultEntity result = new TestResultEntity();
                            result.setTestCaseName(entity.getTestName());
                            result.setTestClassName(simpleClassName);
                            result.setPassed(!hasFailed);
                            if (hasFailed) {
                                org.w3c.dom.NodeList failures = tc.getElementsByTagName("failure");
                                if (failures.getLength() > 0) {
                                    result.setFailureMessage(((org.w3c.dom.Element) failures.item(0)).getAttribute("message"));
                                } else {
                                    org.w3c.dom.NodeList errors = tc.getElementsByTagName("error");
                                    if (errors.getLength() > 0) {
                                        result.setFailureMessage(((org.w3c.dom.Element) errors.item(0)).getAttribute("message"));
                                    }
                                }
                            }
                            if (timeStr != null && !timeStr.isEmpty()) {
                                try {
                                    result.setExecutionTimeMs((long)(Double.parseDouble(timeStr) * 1000));
                                } catch (NumberFormatException ignore) {}
                            }
                            testResultRepository.save(result);
                        }
                    }
                } catch (Exception e) {
                    // Skip individual file parse errors
                }
            }
        } catch (Exception e) {
            summary.put("error", e.getMessage());
        }

        summary.put("updated", updated);
        summary.put("passed", passed);
        summary.put("failed", failed);
        return summary;
    }
}
