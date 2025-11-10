package com.networkmonitor.secure_network_monitor.repository;

import com.networkmonitor.secure_network_monitor.entity.NetworkPacket;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PacketRepository extends JpaRepository<NetworkPacket, Long> {

    /**
     * Finds the 100 most recent packets. Used by the "Recent Packets" table.
     */
    List<NetworkPacket> findTop100ByOrderByTimestampDesc();

    /**
     * Gets the total count of all packets in the database.
     */
    @Query("SELECT COUNT(p) FROM NetworkPacket p")
    long getTotalPacketCount();

    /**
     * Gets a count of packets grouped by protocol. Used by the Protocol Chart.
     */
    @Query("SELECT p.protocol, COUNT(p) FROM NetworkPacket p GROUP BY p.protocol")
    List<Object[]> getProtocolDistribution();

    /**
     * Gets the top source IPs by packet count. Used by the Top Traffic Chart.
     */
    @Query("SELECT p.sourceIp, COUNT(p) FROM NetworkPacket p WHERE p.sourceIp != 'Unknown' GROUP BY p.sourceIp ORDER BY COUNT(p) DESC")
    List<Object[]> getTopSourceIps();

    /**
     * Counts packets for a specific protocol (if needed).
     */
    long countByProtocol(String protocol);

    /**
     * Calculates the total size of all packets for the "Average Packet Size" stat.
     */
    @Query("SELECT SUM(p.packetLength) FROM NetworkPacket p")
    Long getTotalPacketLengthSum();

    /**
     * --- THIS QUERY NOW WORKS! ---
     * It reads the 'reputation' column that PcapProcessingService saved to the DB.
     * This query powers your "Top Threats" chart.
     */
    @Query("SELECT p.sourceIp, COUNT(p) FROM NetworkPacket p " +
            "WHERE p.reputation = 'Known Attacker' OR p.reputation = 'Suspicious' " +
            "GROUP BY p.sourceIp " +
            "ORDER BY COUNT(p) DESC")
    List<Object[]> getTopThreatIps();
}

