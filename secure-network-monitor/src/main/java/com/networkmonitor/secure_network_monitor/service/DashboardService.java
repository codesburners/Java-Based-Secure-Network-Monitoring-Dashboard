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

        // --- START OF NPE FIX ---
        // Filter out any rows where the key (obj[0]) is null before collecting
        Map<String, Long> protocolDistribution = packetRepository.getProtocolDistribution().stream()
                .filter(obj -> obj[0] != null) // <-- Add this line
                .collect(Collectors.toMap(
                        obj -> (String) obj[0],
                        obj -> (Long) obj[1]
                ));

        Map<String, Long> topSourceIps = packetRepository.getTopSourceIps().stream()
                .filter(obj -> obj[0] != null) // <-- Add this line
                .limit(10)
                .collect(Collectors.toMap(
                        obj -> (String) obj[0],
                        obj -> (Long) obj[1]
                ));
        // --- END OF NPE FIX ---

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

        return stats;
    }

    public List<NetworkPacket> getRecentPackets() {
        return packetRepository.findTop100ByOrderByTimestampDesc();
    }
}