package com.networkmonitor.secure_network_monitor.whitebox;

import com.networkmonitor.secure_network_monitor.dualsight.annotation.DualSightTest;
import com.networkmonitor.secure_network_monitor.dualsight.annotation.TestType;
import com.networkmonitor.secure_network_monitor.service.ThreatIntelService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * WHITE-BOX unit tests for ThreatIntelService.
 * Tests the internal IP classification logic including private IP detection,
 * null handling, and confidence score thresholds.
 */
@SpringBootTest
@DualSightTest(type = TestType.WHITE_BOX, component = "ThreatIntelService",
        description = "Tests internal IP reputation classification logic")
public class ThreatIntelServiceWhiteBoxTest {

    @Autowired
    private ThreatIntelService threatIntelService;

    @org.springframework.boot.test.mock.mockito.MockBean
    private com.networkmonitor.secure_network_monitor.encryption.EncryptionService encryptionService;

    /**
     * White-box: Test the private IP detection branch (192.168.x.x).
     * The code checks startsWith("192.168.") internally.
     */
    @Test
    public void testPrivateIpReturnsPrivate() {
        String result = threatIntelService.checkIpReputation("192.168.1.1");
        assertEquals("Private", result,
                "192.168.x.x addresses should be classified as Private");
    }

    /**
     * White-box: Test the private IP detection branch (10.x.x.x).
     * The code checks startsWith("10.") internally.
     */
    @Test
    public void testPrivateIp10RangeReturnsPrivate() {
        String result = threatIntelService.checkIpReputation("10.0.0.1");
        assertEquals("Private", result,
                "10.x.x.x addresses should be classified as Private");
    }

    /**
     * White-box: Test null IP handling.
     * The code has explicit null check: ip == null.
     */
    @Test
    public void testNullIpReturnsPrivate() {
        String result = threatIntelService.checkIpReputation(null);
        assertEquals("Private", result,
                "Null IP should return Private (guards the API from being called)");
    }

    /**
     * White-box: Test "N/A" IP handling.
     * The code checks ip.equals("N/A").
     */
    @Test
    public void testNAIpReturnsPrivate() {
        String result = threatIntelService.checkIpReputation("N/A");
        assertEquals("Private", result,
                "'N/A' IP should return Private");
    }

    /**
     * White-box: Test that public IPs that fail API calls return "Check Error".
     * Since we're using a test/invalid API key, external calls will fail.
     * This tests the catch block in checkIpReputation.
     */
    @Test
    public void testPublicIpWithFailedApiReturnsCheckError() {
        String result = threatIntelService.checkIpReputation("8.8.8.8");
        assertEquals("Check Error", result,
                "Failed API call should return 'Check Error' (tests the catch block)");
    }
}
