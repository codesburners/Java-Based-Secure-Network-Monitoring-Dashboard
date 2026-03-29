package com.networkmonitor.secure_network_monitor.dualsight.service;

import com.networkmonitor.secure_network_monitor.dualsight.entity.TestCaseEntity;
import com.networkmonitor.secure_network_monitor.dualsight.model.CodeChange;
import com.networkmonitor.secure_network_monitor.dualsight.model.TestCaseInfo;
import com.networkmonitor.secure_network_monitor.dualsight.repository.TestCaseEntityRepository;
import com.networkmonitor.secure_network_monitor.dualsight.repository.TestResultEntityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;


/**
 * DualSight Test Prioritizer.
 * Uses a weighted scoring formula to prioritize test cases based on:
 * - Change Impact (0.4): How many methods changed in the target component
 * - Fault History (0.3): How many times this test has failed recently
 * - Component Criticality (0.3): Configurable weights per component
 *
 * Priority Score = (Change Impact × 0.4) + (Fault History × 0.3) + (Component Criticality × 0.3)
 */
@Service
public class TestPrioritizer {

    @Autowired
    private TestCaseEntityRepository testCaseRepository;

    @Autowired
    private TestResultEntityRepository testResultRepository;

    // Component criticality weights (higher = more critical)
    private static final Map<String, Double> COMPONENT_CRITICALITY = new HashMap<>();
    static {
        COMPONENT_CRITICALITY.put("AuthController", 1.0);       // Security - highest priority
        COMPONENT_CRITICALITY.put("JwtTokenProvider", 1.0);     // Security
        COMPONENT_CRITICALITY.put("LoginAttemptService", 0.9);  // Security
        COMPONENT_CRITICALITY.put("ThreatIntelService", 0.85);  // Threat detection
        COMPONENT_CRITICALITY.put("NetworkMonitorController", 0.8); // Core functionality
        COMPONENT_CRITICALITY.put("PacketRepository", 0.75);    // Data layer
        COMPONENT_CRITICALITY.put("DashboardService", 0.6);     // Dashboard logic
        COMPONENT_CRITICALITY.put("DashboardWebController", 0.5); // Web pages
    }

    private static final double WEIGHT_CHANGE_IMPACT = 0.4;
    private static final double WEIGHT_FAULT_HISTORY = 0.3;
    private static final double WEIGHT_CRITICALITY = 0.3;

    /**
     * Prioritizes test cases based on detected code changes.
     *
     * @param testCases list of all test cases
     * @param codeChanges list of detected code changes
     * @return sorted list with priority scores and levels assigned
     */
    public List<TestCaseInfo> prioritize(List<TestCaseInfo> testCases, List<CodeChange> codeChanges) {
        // Build a map: componentName -> number of methods changed
        Map<String, Integer> changeImpactMap = new HashMap<>();
        for (CodeChange change : codeChanges) {
            String className = change.getClassName();
            int methodCount = change.getChangedMethods().size();
            changeImpactMap.merge(className, methodCount, Integer::sum);
        }

        // Score each test case
        for (TestCaseInfo testCase : testCases) {
            double score = calculatePriorityScore(testCase, changeImpactMap);
            testCase.setPriorityScore(score);
            testCase.setPriority(scoreToPriorityLevel(score));

            // Persist the updated scores
            updateEntityScore(testCase);
        }

        // Sort by priority score (highest first)
        testCases.sort((a, b) -> Double.compare(b.getPriorityScore(), a.getPriorityScore()));

        return testCases;
    }

    /**
     * Calculates the priority score for a single test case.
     */
    private double calculatePriorityScore(TestCaseInfo testCase, Map<String, Integer> changeImpactMap) {
        // 1. Change Impact Score (0-100)
        double changeImpactScore = 0;
        String targetComponent = testCase.getTargetComponent();
        if (changeImpactMap.containsKey(targetComponent)) {
            int methodsChanged = changeImpactMap.get(targetComponent);
            changeImpactScore = Math.min(100, methodsChanged * 25.0); // 4+ methods = max score
        }

        // 2. Fault History Score (0-100)
        double faultHistoryScore = 0;
        if (testCase.getName() != null) {
            long failures = testResultRepository.countFailuresByTestCaseName(testCase.getName());
            faultHistoryScore = Math.min(100, failures * 20.0); // 5+ failures = max score
        }

        // 3. Component Criticality Score (0-100)
        double criticalityScore = COMPONENT_CRITICALITY.getOrDefault(targetComponent, 0.5) * 100;

        // Weighted final score
        return (changeImpactScore * WEIGHT_CHANGE_IMPACT) +
               (faultHistoryScore * WEIGHT_FAULT_HISTORY) +
               (criticalityScore * WEIGHT_CRITICALITY);
    }

    /**
     * Maps a numeric score to a priority level.
     */
    private TestCaseInfo.PriorityLevel scoreToPriorityLevel(double score) {
        if (score >= 60) return TestCaseInfo.PriorityLevel.HIGH;
        if (score >= 30) return TestCaseInfo.PriorityLevel.MEDIUM;
        return TestCaseInfo.PriorityLevel.LOW;
    }

    /**
     * Persists the updated priority score to the database.
     */
    private void updateEntityScore(TestCaseInfo testCase) {
        if (testCase.getId() != null) {
            Optional<TestCaseEntity> entityOpt = testCaseRepository.findById(testCase.getId());
            if (entityOpt.isPresent()) {
                TestCaseEntity entity = entityOpt.get();
                entity.setPriorityScore(testCase.getPriorityScore());
                entity.setPriorityLevel(testCase.getPriority().name());
                testCaseRepository.save(entity);
            }
        }
    }
}
