package com.networkmonitor.secure_network_monitor.repository;

import com.networkmonitor.secure_network_monitor.entity.NetworkPacket;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PacketRepository extends JpaRepository<NetworkPacket, Long> {

    List<NetworkPacket> findTop100ByOrderByTimestampDesc();

    @Query("SELECT COUNT(p) FROM NetworkPacket p")
    long getTotalPacketCount();

    @Query("SELECT p.protocol, COUNT(p) FROM NetworkPacket p GROUP BY p.protocol")
    List<Object[]> getProtocolDistribution();

    @Query("SELECT p.sourceIp, COUNT(p) FROM NetworkPacket p WHERE p.sourceIp != 'Unknown' GROUP BY p.sourceIp ORDER BY COUNT(p) DESC")
    List<Object[]> getTopSourceIps();

    long countByProtocol(String protocol);

    @Query("SELECT SUM(p.packetLength) FROM NetworkPacket p")
    Long getTotalPacketLengthSum();


    @Query("SELECT p.sourceIp, COUNT(p) FROM NetworkPacket p " +
            "WHERE p.reputation = 'Known Attacker' OR p.reputation = 'Suspicious' " +
            "GROUP BY p.sourceIp " +
            "ORDER BY COUNT(p) DESC")
    List<Object[]> getTopThreatIps();

}