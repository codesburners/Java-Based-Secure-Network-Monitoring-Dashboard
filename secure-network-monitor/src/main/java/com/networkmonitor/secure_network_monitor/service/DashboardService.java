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

    // --- NO LONGER NEEDED HERE ---
    // The ThreatIntelService is only needed in the PcapProcessingService now.
    // @Autowired
    // private ThreatIntelService threatIntelService;

    public Map<String, Object> getDashboardStatistics() {
        Map<String, Object> stats = new HashMap<>();

        long totalPackets = packetRepository.count();

        // --- Protocol Distribution ---
        Map<String, Long> protocolDistribution = packetRepository.getProtocolDistribution().stream()
                .filter(obj -> obj[0] != null)
                .collect(Collectors.toMap(obj -> (String) obj[0], obj -> (Long) obj[1]));

        // --- Top Source IPs (All Traffic) ---
        Map<String, Long> topSourceIps = packetRepository.getTopSourceIps().stream()
                .filter(obj -> obj[0] != null)
                .limit(10)
                .collect(Collectors.toMap(obj -> (String) obj[0], obj -> (Long) obj[1]));

        // --- THIS IS THE FIX ---
        // 1. No more live, slow, rate-limited API calls!
        // 2. Just call the repository method that reads the reputation from the DB.
        Map<String, Long> topThreatIps = packetRepository.getTopThreatIps().stream()
                .filter(obj -> obj[0] != null)
                .limit(10)
                .collect(Collectors.toMap(
                        obj -> (String) obj[0],
                        obj -> (Long) obj[1]
                ));
        // --- END OF FIX ---

        Long totalLengthSum = packetRepository.getTotalPacketLengthSum();
        if (totalLengthSum == null) { totalLengthSum = 0L; }
        double avgSize = (totalPackets == 0) ? 0 : (double) totalLengthSum / totalPackets;

        stats.put("totalPackets", totalPackets);
        stats.put("protocolDistribution", protocolDistribution);
        stats.put("topSourceIps", topSourceIps);
        stats.put("recentPacketCount", packetRepository.count()); // Use total count for this
        stats.put("averagePacketSize", String.format("%.2f", avgSize));
        stats.put("topThreatIps", topThreatIps); // This now has the correct data!

        return stats;
    }

    /**
     * This method now returns the packets WITH the reputation
     * that was saved in the database. No live API call needed.
     */
    public List<NetworkPacket> getRecentPackets() {
        // This list of packets will already have the .reputation field
        // filled in from the database, because we saved it.
        return packetRepository.findTop100ByOrderByTimestampDesc();
    }
}

