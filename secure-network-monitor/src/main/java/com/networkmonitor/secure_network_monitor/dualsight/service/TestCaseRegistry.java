package com.networkmonitor.secure_network_monitor.dualsight.service;


import com.networkmonitor.secure_network_monitor.dualsight.annotation.TestType;
import com.networkmonitor.secure_network_monitor.dualsight.entity.TestCaseEntity;
import com.networkmonitor.secure_network_monitor.dualsight.model.TestCaseInfo;
import com.networkmonitor.secure_network_monitor.dualsight.repository.TestCaseEntityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.util.*;

/**
 * DualSight Test Case Registry.
 * Discovers and registers all test cases annotated with @DualSightTest,
 * classifying them as BLACK_BOX or WHITE_BOX and mapping them to target components.
 */
@Service
public class TestCaseRegistry {

    @Autowired
    private TestCaseEntityRepository testCaseRepository;

    /**
     * Hardcoded registry of test classes and their metadata.
     * In a production system, this would use classpath scanning.
     */
    private static final List<TestRegistration> TEST_REGISTRATIONS = Arrays.asList(
            // Black-Box Tests
            new TestRegistration("Login with valid credentials", "AuthControllerBlackBoxTest",
                    "testLoginWithValidCredentials", TestType.BLACK_BOX, "AuthController"),
            new TestRegistration("Login with invalid password", "AuthControllerBlackBoxTest",
                    "testLoginWithInvalidPassword", TestType.BLACK_BOX, "AuthController"),
            new TestRegistration("Login with non-existent user", "AuthControllerBlackBoxTest",
                    "testLoginWithNonExistentUser", TestType.BLACK_BOX, "AuthController"),
            new TestRegistration("Account lockout after failures", "AuthControllerBlackBoxTest",
                    "testAccountLockoutAfterFailures", TestType.BLACK_BOX, "AuthController"),

            new TestRegistration("Get dashboard stats without auth", "NetworkMonitorBlackBoxTest",
                    "testGetStatsWithoutAuth", TestType.BLACK_BOX, "NetworkMonitorController"),
            new TestRegistration("Get dashboard stats with auth", "NetworkMonitorBlackBoxTest",
                    "testGetStatsWithAuth", TestType.BLACK_BOX, "NetworkMonitorController"),
            new TestRegistration("Get recent packets with auth", "NetworkMonitorBlackBoxTest",
                    "testGetRecentPacketsWithAuth", TestType.BLACK_BOX, "NetworkMonitorController"),
            new TestRegistration("Upload PCAP without admin role", "NetworkMonitorBlackBoxTest",
                    "testUploadPcapWithoutAdminRole", TestType.BLACK_BOX, "NetworkMonitorController"),

            new TestRegistration("Login page loads", "DashboardWebBlackBoxTest",
                    "testLoginPageLoads", TestType.BLACK_BOX, "DashboardWebController"),
            new TestRegistration("Dashboard page loads", "DashboardWebBlackBoxTest",
                    "testDashboardPageLoads", TestType.BLACK_BOX, "DashboardWebController"),
            new TestRegistration("DualSight page loads", "DashboardWebBlackBoxTest",
                    "testDualSightPageLoads", TestType.BLACK_BOX, "DashboardWebController"),

            // White-Box Tests — LoginAttemptService (5 actual test methods)
            new TestRegistration("LoginAttempt - success clears counter", "LoginAttemptServiceWhiteBoxTest",
                    "testLoginSucceededClearsAttempts", TestType.WHITE_BOX, "LoginAttemptService"),
            new TestRegistration("LoginAttempt - failure increments counter", "LoginAttemptServiceWhiteBoxTest",
                    "testLoginFailedIncrementsCounter", TestType.WHITE_BOX, "LoginAttemptService"),
            new TestRegistration("LoginAttempt - blocked after max failures", "LoginAttemptServiceWhiteBoxTest",
                    "testIsBlockedAfterMaxAttempts", TestType.WHITE_BOX, "LoginAttemptService"),
            new TestRegistration("LoginAttempt - unknown user not blocked", "LoginAttemptServiceWhiteBoxTest",
                    "testIsBlockedReturnsFalseForUnknownUser", TestType.WHITE_BOX, "LoginAttemptService"),
            new TestRegistration("LoginAttempt - success clears both caches", "LoginAttemptServiceWhiteBoxTest",
                    "testLoginSucceededClearsBothCaches", TestType.WHITE_BOX, "LoginAttemptService"),

            // White-Box Tests — ThreatIntelService (5 actual test methods)
            new TestRegistration("ThreatIntel - private IP 192.168.x", "ThreatIntelServiceWhiteBoxTest",
                    "testPrivateIpReturnsPrivate", TestType.WHITE_BOX, "ThreatIntelService"),
            new TestRegistration("ThreatIntel - private IP 10.x", "ThreatIntelServiceWhiteBoxTest",
                    "testPrivateIp10RangeReturnsPrivate", TestType.WHITE_BOX, "ThreatIntelService"),
            new TestRegistration("ThreatIntel - null IP handling", "ThreatIntelServiceWhiteBoxTest",
                    "testNullIpReturnsPrivate", TestType.WHITE_BOX, "ThreatIntelService"),
            new TestRegistration("ThreatIntel - N/A IP handling", "ThreatIntelServiceWhiteBoxTest",
                    "testNAIpReturnsPrivate", TestType.WHITE_BOX, "ThreatIntelService"),
            new TestRegistration("ThreatIntel - API failure handling", "ThreatIntelServiceWhiteBoxTest",
                    "testPublicIpWithFailedApiReturnsCheckError", TestType.WHITE_BOX, "ThreatIntelService"),

            // White-Box Tests — DashboardService (3 actual test methods)
            new TestRegistration("Dashboard - empty database stats", "DashboardServiceWhiteBoxTest",
                    "testGetStatsWithEmptyDatabase", TestType.WHITE_BOX, "DashboardService"),
            new TestRegistration("Dashboard - stats with packets", "DashboardServiceWhiteBoxTest",
                    "testGetStatsWithPackets", TestType.WHITE_BOX, "DashboardService"),
            new TestRegistration("Dashboard - recent packets delegation", "DashboardServiceWhiteBoxTest",
                    "testGetRecentPacketsDelegation", TestType.WHITE_BOX, "DashboardService"),

            // White-Box Tests — JwtTokenProvider (6 actual test methods)
            new TestRegistration("JWT - token creation", "JwtTokenProviderWhiteBoxTest",
                    "testTokenCreation", TestType.WHITE_BOX, "JwtTokenProvider"),
            new TestRegistration("JWT - token validation", "JwtTokenProviderWhiteBoxTest",
                    "testTokenValidation", TestType.WHITE_BOX, "JwtTokenProvider"),
            new TestRegistration("JWT - invalid token rejected", "JwtTokenProviderWhiteBoxTest",
                    "testInvalidTokenRejected", TestType.WHITE_BOX, "JwtTokenProvider"),
            new TestRegistration("JWT - null token rejected", "JwtTokenProviderWhiteBoxTest",
                    "testNullTokenRejected", TestType.WHITE_BOX, "JwtTokenProvider"),
            new TestRegistration("JWT - username extraction", "JwtTokenProviderWhiteBoxTest",
                    "testUsernameExtraction", TestType.WHITE_BOX, "JwtTokenProvider"),
            new TestRegistration("JWT - role extraction", "JwtTokenProviderWhiteBoxTest",
                    "testRoleExtraction", TestType.WHITE_BOX, "JwtTokenProvider"),

            // White-Box Tests — PacketRepository (4 actual test methods)
            new TestRegistration("Repository - protocol distribution", "PacketRepositoryWhiteBoxTest",
                    "testProtocolDistribution", TestType.WHITE_BOX, "PacketRepository"),
            new TestRegistration("Repository - top source IPs", "PacketRepositoryWhiteBoxTest",
                    "testTopSourceIps", TestType.WHITE_BOX, "PacketRepository"),
            new TestRegistration("Repository - threat IP filtering", "PacketRepositoryWhiteBoxTest",
                    "testTopThreatIps", TestType.WHITE_BOX, "PacketRepository"),
            new TestRegistration("Repository - total packet length sum", "PacketRepositoryWhiteBoxTest",
                    "testTotalPacketLengthSum", TestType.WHITE_BOX, "PacketRepository")
    );

    /**
     * Initializes the test case registry by syncing hardcoded registrations to the database.
     * Removes stale entries and ensures all registrations match actual test methods.
     */
    @PostConstruct
    public void initializeRegistry() {
        // Collect valid method names from current registrations
        Set<String> validMethodNames = new HashSet<>();
        for (TestRegistration reg : TEST_REGISTRATIONS) {
            validMethodNames.add(reg.methodName);
        }

        // Remove stale entries (method names that no longer exist in registrations)
        List<TestCaseEntity> allExisting = testCaseRepository.findAll();
        for (TestCaseEntity entity : allExisting) {
            if (entity.getMethodName() == null || !validMethodNames.contains(entity.getMethodName())) {
                testCaseRepository.delete(entity);
            }
        }

        // Add or update registrations
        for (TestRegistration reg : TEST_REGISTRATIONS) {
            Optional<TestCaseEntity> existing = testCaseRepository
                    .findByMethodName(reg.methodName);

            if (!existing.isPresent()) {
                TestCaseEntity entity = new TestCaseEntity();
                entity.setTestName(reg.name);
                entity.setClassName(reg.className);
                entity.setMethodName(reg.methodName);
                entity.setTestType(reg.type.name());
                entity.setTargetComponent(reg.component);
                entity.setPriorityLevel("MEDIUM");
                entity.setPriorityScore(50.0);
                testCaseRepository.save(entity);
            }
        }
    }

    /**
     * Returns all registered test cases as model objects.
     */
    public List<TestCaseInfo> getAllTestCases() {
        List<TestCaseInfo> testCases = new ArrayList<>();
        for (TestCaseEntity entity : testCaseRepository.findAll()) {
            testCases.add(entityToModel(entity));
        }
        return testCases;
    }

    /**
     * Returns test cases filtered by type.
     */
    public List<TestCaseInfo> getTestCasesByType(TestType type) {
        List<TestCaseInfo> testCases = new ArrayList<>();
        for (TestCaseEntity entity : testCaseRepository.findByTestType(type.name())) {
            testCases.add(entityToModel(entity));
        }
        return testCases;
    }

    /**
     * Returns test cases for a specific component.
     */
    public List<TestCaseInfo> getTestCasesForComponent(String component) {
        List<TestCaseInfo> testCases = new ArrayList<>();
        for (TestCaseEntity entity : testCaseRepository.findByTargetComponent(component)) {
            testCases.add(entityToModel(entity));
        }
        return testCases;
    }

    private TestCaseInfo entityToModel(TestCaseEntity entity) {
        TestCaseInfo info = new TestCaseInfo();
        info.setId(entity.getId());
        info.setName(entity.getTestName());
        info.setClassName(entity.getClassName());
        info.setMethodName(entity.getMethodName());
        info.setType(TestType.valueOf(entity.getTestType()));
        info.setTargetComponent(entity.getTargetComponent());
        info.setPriority(TestCaseInfo.PriorityLevel.valueOf(
                entity.getPriorityLevel() != null ? entity.getPriorityLevel() : "MEDIUM"));
        info.setPriorityScore(entity.getPriorityScore() != null ? entity.getPriorityScore() : 50.0);
        info.setLastRunStatus(entity.getLastRunStatus());
        info.setLastRunDurationMs(entity.getLastRunDurationMs());
        info.setLastRunTimestamp(entity.getLastRunTimestamp() != null ?
                entity.getLastRunTimestamp().atZone(java.time.ZoneId.systemDefault()).toInstant().toEpochMilli() : null);
        return info;
    }

    /**
     * Internal class for hardcoded test registrations.
     */
    private static class TestRegistration {
        final String name;
        final String className;
        final String methodName;
        final TestType type;
        final String component;

        TestRegistration(String name, String className, String methodName, TestType type, String component) {
            this.name = name;
            this.className = className;
            this.methodName = methodName;
            this.type = type;
            this.component = component;
        }
    }
}
