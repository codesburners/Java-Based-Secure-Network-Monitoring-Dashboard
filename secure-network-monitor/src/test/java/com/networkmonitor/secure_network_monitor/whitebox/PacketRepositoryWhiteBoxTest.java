package com.networkmonitor.secure_network_monitor.whitebox;

import com.networkmonitor.secure_network_monitor.dualsight.annotation.DualSightTest;
import com.networkmonitor.secure_network_monitor.dualsight.annotation.TestType;
import com.networkmonitor.secure_network_monitor.entity.NetworkPacket;
import com.networkmonitor.secure_network_monitor.repository.PacketRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * WHITE-BOX unit tests for PacketRepository.
 * Tests the custom JPQL queries directly to verify
 * correct aggregation, filtering, and ordering logic.
 */
@SpringBootTest
@DualSightTest(type = TestType.WHITE_BOX, component = "PacketRepository",
        description = "Tests custom repository queries for data aggregation")
public class PacketRepositoryWhiteBoxTest {

    @Autowired
    private PacketRepository packetRepository;

    @org.springframework.boot.test.mock.mockito.MockBean
    private com.networkmonitor.secure_network_monitor.encryption.EncryptionService encryptionService;

    @BeforeEach
    public void setUp() {
        packetRepository.deleteAll();

        // Insert test data with known values
        savePacket("1.1.1.1", "2.2.2.2", "TCP", 100, "Known Attacker");
        savePacket("1.1.1.1", "2.2.2.2", "TCP", 200, "Known Attacker");
        savePacket("3.3.3.3", "4.4.4.4", "UDP(17)", 150, "Suspicious");
        savePacket("5.5.5.5", "6.6.6.6", "TCP", 300, "Benign");
        savePacket("5.5.5.5", "6.6.6.6", "UDP(17)", 250, "Benign");
    }

    /**
     * White-box: Test the JPQL GROUP BY query for protocol distribution.
     * Query: SELECT p.protocol, COUNT(p) FROM NetworkPacket GROUP BY p.protocol
     */
    @Test
    public void testProtocolDistribution() {
        List<Object[]> distribution = packetRepository.getProtocolDistribution();

        assertFalse(distribution.isEmpty(), "Should have protocol distribution data");
        // We inserted 3 TCP and 2 UDP packets
        boolean hasTcp = false;
        boolean hasUdp = false;
        for (Object[] row : distribution) {
            String protocol = (String) row[0];
            long count = (Long) row[1];
            if ("TCP".equals(protocol)) {
                assertEquals(3L, count, "TCP should have 3 packets");
                hasTcp = true;
            } else if ("UDP(17)".equals(protocol)) {
                assertEquals(2L, count, "UDP should have 2 packets");
                hasUdp = true;
            }
        }
        assertTrue(hasTcp, "Should have TCP in distribution");
        assertTrue(hasUdp, "Should have UDP in distribution");
    }

    /**
     * White-box: Test the ORDER BY DESC query for top source IPs.
     * Query: SELECT p.sourceIp, COUNT(p) ... ORDER BY COUNT(p) DESC
     */
    @Test
    public void testTopSourceIps() {
        List<Object[]> topIps = packetRepository.getTopSourceIps();

        assertFalse(topIps.isEmpty(), "Should have top source IPs");
        // 1.1.1.1 has 2 packets, 5.5.5.5 has 2, 3.3.3.3 has 1
        String topIp = (String) topIps.get(0)[0];
        long topCount = (Long) topIps.get(0)[1];
        assertEquals(2L, topCount, "Top IP should have 2 packets");
    }

    /**
     * White-box: Test the WHERE reputation filter in threat IP query.
     * Query: WHERE reputation = 'Known Attacker' OR reputation = 'Suspicious'
     * This should EXCLUDE 'Benign' packets.
     */
    @Test
    public void testTopThreatIps() {
        List<Object[]> threatIps = packetRepository.getTopThreatIps();

        assertFalse(threatIps.isEmpty(), "Should have threat IPs");
        // 1.1.1.1 has 2 "Known Attacker", 3.3.3.3 has 1 "Suspicious"
        // Benign IPs (5.5.5.5) should NOT appear
        for (Object[] row : threatIps) {
            String ip = (String) row[0];
            assertNotEquals("5.5.5.5", ip,
                    "Benign IPs should be excluded from threat list");
        }
    }

    /**
     * White-box: Test the SUM query for total packet length.
     * Query: SELECT SUM(p.packetLength) FROM NetworkPacket p
     */
    @Test
    public void testTotalPacketLengthSum() {
        Long totalLength = packetRepository.getTotalPacketLengthSum();

        assertNotNull(totalLength, "Total length should not be null");
        // 100 + 200 + 150 + 300 + 250 = 1000
        assertEquals(1000L, totalLength,
                "Total packet length should be 100+200+150+300+250 = 1000");
    }

    // Helper method
    private void savePacket(String srcIp, String dstIp, String protocol, int length, String reputation) {
        NetworkPacket p = new NetworkPacket();
        p.setSourceIp(srcIp);
        p.setDestinationIp(dstIp);
        p.setProtocol(protocol);
        p.setPacketLength(length);
        p.setSourcePort(80);
        p.setDestinationPort(443);
        p.setTimestamp(System.currentTimeMillis());
        p.setReputation(reputation);
        packetRepository.save(p);
    }
}
