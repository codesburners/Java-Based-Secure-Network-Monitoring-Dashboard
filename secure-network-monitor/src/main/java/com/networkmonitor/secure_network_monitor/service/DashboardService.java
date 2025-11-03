package com.networkmonitor.secure_network_monitor.service;

import com.networkmonitor.secure_network_monitor.entity.NetworkPacket;
import com.networkmonitor.secure_network_monitor.repository.PacketRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class DashboardService {

    @Autowired
    private PacketRepository packetRepository;

    public Map<String, Object> getDashboardStatistics() {
        Map<String, Object> stats = new HashMap<>();

        long totalPackets = packetRepository.count();
        List<NetworkPacket> recentPackets = packetRepository.findTop100ByOrderByTimestampDesc();

        // --- Protocol Distribution ---
        Map<String, Long> protocolDistribution = packetRepository.getProtocolDistribution().stream()
                .filter(obj -> obj[0] != null)
                .collect(Collectors.toMap(
                        obj -> (String) obj[0],
                        obj -> (Long) obj[1]
                ));

        // --- Top Source IPs (All Traffic) ---
        Map<String, Long> topSourceIps = packetRepository.getTopSourceIps().stream()
                .filter(obj -> obj[0] != null)
                .limit(10)
                .collect(Collectors.toMap(
                        obj -> (String) obj[0],
                        obj -> (Long) obj[1]
                ));

        // --- REQUIRED CHANGE: Add Top Threats (Known Attackers) ---
        Map<String, Long> topThreatIps = packetRepository.getTopThreatIps().stream()
                .filter(obj -> obj[0] != null) // Filter null IPs
                .limit(10) // Get top 10
                .collect(Collectors.toMap(
                        obj -> (String) obj[0],
                        obj -> (Long) obj[1]
                ));
        // --- END OF CHANGE ---

        Long totalLengthSum = packetRepository.getTotalPacketLengthSum();
        if (totalLengthSum == null) {
            totalLengthSum = 0L;
        }
        double avgSize = (totalPackets == 0) ? 0 : (double) totalLengthSum / totalPackets;

        stats.put("totalPackets", totalPackets);
        stats.put("protocolDistribution", protocolDistribution);
        stats.put("topSourceIps", topSourceIps);
        stats.put("recentPacketCount", recentPackets.size());
        stats.put("averagePacketSize", String.format("%.2f", avgSize));

        // --- REQUIRED CHANGE: Add the new stats to the map ---
        stats.put("topThreatIps", topThreatIps);
        // --- END OF CHANGE ---

        return stats;
    }

    public List<NetworkPacket> getRecentPackets() {
        return packetRepository.findTop100ByOrderByTimestampDesc();
    }
}