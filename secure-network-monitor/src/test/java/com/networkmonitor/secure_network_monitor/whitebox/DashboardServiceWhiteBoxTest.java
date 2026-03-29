package com.networkmonitor.secure_network_monitor.whitebox;

import com.networkmonitor.secure_network_monitor.dualsight.annotation.DualSightTest;
import com.networkmonitor.secure_network_monitor.dualsight.annotation.TestType;
import com.networkmonitor.secure_network_monitor.entity.NetworkPacket;
import com.networkmonitor.secure_network_monitor.repository.PacketRepository;
import com.networkmonitor.secure_network_monitor.service.DashboardService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * WHITE-BOX unit tests for DashboardService.
 * Tests the internal aggregation logic, average calculation,
 * and delegation to PacketRepository.
 */
@SpringBootTest
@DualSightTest(type = TestType.WHITE_BOX, component = "DashboardService",
        description = "Tests internal dashboard data aggregation logic")
public class DashboardServiceWhiteBoxTest {

    @Autowired
    private DashboardService dashboardService;

    @Autowired
    private PacketRepository packetRepository;

    @org.springframework.boot.test.mock.mockito.MockBean
    private com.networkmonitor.secure_network_monitor.encryption.EncryptionService encryptionService;

    /**
     * White-box: Test getDashboardStatistics() with empty database.
     * Verifies the zero-division guard: avgSize = 0 when totalPackets = 0.
     */
    @Test
    public void testGetStatsWithEmptyDatabase() {
        // Clean slate
        packetRepository.deleteAll();

        Map<String, Object> stats = dashboardService.getDashboardStatistics();

        assertEquals(0L, stats.get("totalPackets"),
                "Total packets should be 0 with empty DB");
        assertEquals("0.00", stats.get("averagePacketSize"),
                "Average packet size should be 0.00 (zero-division guard)");
        assertNotNull(stats.get("protocolDistribution"));
        assertNotNull(stats.get("topSourceIps"));
    }

    /**
     * White-box: Test getDashboardStatistics() with actual packets.
     * Verifies the aggregation formulas produce correct results.
     */
    @Test
    public void testGetStatsWithPackets() {
        packetRepository.deleteAll();

        // Insert test packets with known values
        NetworkPacket p1 = new NetworkPacket();
        p1.setSourceIp("1.2.3.4");
        p1.setDestinationIp("5.6.7.8");
        p1.setProtocol("TCP");
        p1.setPacketLength(100);
        p1.setSourcePort(443);
        p1.setDestinationPort(8080);
        p1.setTimestamp(System.currentTimeMillis());
        p1.setReputation("Benign");

        NetworkPacket p2 = new NetworkPacket();
        p2.setSourceIp("1.2.3.4");
        p2.setDestinationIp("9.10.11.12");
        p2.setProtocol("UDP(17)");
        p2.setPacketLength(200);
        p2.setSourcePort(53);
        p2.setDestinationPort(1234);
        p2.setTimestamp(System.currentTimeMillis());
        p2.setReputation("Benign");

        packetRepository.save(p1);
        packetRepository.save(p2);

        Map<String, Object> stats = dashboardService.getDashboardStatistics();

        assertEquals(2L, stats.get("totalPackets"), "Should have 2 packets");
        // Average = (100 + 200) / 2 = 150.00
        assertEquals("150.00", stats.get("averagePacketSize"),
                "Average should be (100+200)/2 = 150.00");

        // Cleanup
        packetRepository.deleteAll();
    }

    /**
     * White-box: Test getRecentPackets() delegates to repository correctly.
     */
    @Test
    public void testGetRecentPacketsDelegation() {
        List<NetworkPacket> packets = dashboardService.getRecentPackets();
        assertNotNull(packets, "getRecentPackets should never return null");
    }
}
