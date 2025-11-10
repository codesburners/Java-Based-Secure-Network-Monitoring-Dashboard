package com.networkmonitor.secure_network_monitor.pcap;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.networkmonitor.secure_network_monitor.encryption.EncryptionService;
import com.networkmonitor.secure_network_monitor.entity.NetworkPacket;
import com.networkmonitor.secure_network_monitor.repository.PacketRepository;
import com.networkmonitor.secure_network_monitor.service.AlertingService;
import com.networkmonitor.secure_network_monitor.service.ThreatIntelService;

import java.util.ArrayList;
import java.util.List;
import java.util.Map; // <-- NEW IMPORT
import java.util.concurrent.ConcurrentHashMap; // <-- NEW IMPORT

@Service
public class PcapProcessingService {

    @Autowired
    private EncryptionService encryptionService;

    @Autowired
    private PacketRepository packetRepository;

    @Autowired
    private AlertingService alertingService;

    @Autowired
    private ThreatIntelService threatIntelService;

    // --- Cache to store IP reputation results and avoid API spamming ---
    private Map<String, String> ipReputationCache = new ConcurrentHashMap<>();


    private static final String TEST_MALICIOUS_IP = "103.20.21.65";


    public List<NetworkPacket> processPcapFile(String filePath) throws Exception {
        List<NetworkPacket> packets = new ArrayList<>();
        ipReputationCache.clear(); // Clear the cache for each new file upload

        try (PcapHandle handle = Pcaps.openOffline(filePath)) {
            Packet packet;
            while ((packet = handle.getNextPacket()) != null) {

                NetworkPacket networkPacket = parsePacket(packet, handle);

                if (networkPacket.getSourceIp().startsWith("192.168.")) {
                    networkPacket.setSourceIp(TEST_MALICIOUS_IP);
                }
                packets.add(networkPacket);

                // --- THIS IS THE FIX ---
                // 1. Check reputation ONCE (using the cache)
                String reputation = getReputationSafely(networkPacket.getSourceIp());

                // 2. SET the reputation on the packet object
                networkPacket.setReputation(reputation);
                // --- END OF FIX ---

                // Now the alert check uses the 'reputation' variable
                if (!reputation.equals("Benign") && !reputation.equals("Private") && !reputation.equals("Check Error")) {

                    String subject = "CRITICAL: Suspicious IP Detected (" + reputation + ")!";
                    String body = "Source IP " + networkPacket.getSourceIp() + " is flagged as " + reputation + " by AbuseIPDB.\n"
                            + "Destination: ".concat(networkPacket.getDestinationIp()).concat(":").concat(String.valueOf(networkPacket.getDestinationPort())).concat("\n")
                            + "Action: Alert sent due to score exceeding threshold.";

                    alertingService.sendThreatAlert(subject, body);
                }

                if ("TCP".equals(networkPacket.getProtocol()) && (networkPacket.getDestinationPort() == 23 || networkPacket.getSourcePort() == 23)) {
                    String subject = "Insecure Protocol Detected (Telnet)";
                    String body = "Insecure Telnet (port 23) traffic was detected in the processed pcap file.\n"
                            + "Source: " + networkPacket.getSourceIp() + "\n";
                    alertingService.sendThreatAlert(subject, body);
                }

                // Encrypt and store (uses KeyStore)
                String encryptedData = encryptionService.encrypt(networkPacket.toJson());
                networkPacket.setEncryptedData(encryptedData);

                // 3. SAVE the packet (with the reputation) to the database
                packetRepository.save(networkPacket);
            }
        }
        return packets;
    }

    // --- NEW CACHING METHOD ---
    // This checks the cache BEFORE hitting the external API
    private String getReputationSafely(String ip) {
        if (ipReputationCache.containsKey(ip)) {
            return ipReputationCache.get(ip); // Return from cache
        }

        // Not in cache, call the slow external API
        String reputation = threatIntelService.checkIpReputation(ip);

        // Save to cache for next time
        ipReputationCache.put(ip, reputation);
        return reputation;
    }

    /**
     * Parses packet headers to extract basic information.
     */
    private NetworkPacket parsePacket(Packet packet, PcapHandle handle) {
        NetworkPacket networkPacket = new NetworkPacket();
        networkPacket.setTimestamp(handle.getTimestamp().getTime());
        networkPacket.setPacketLength(packet.length());
        networkPacket.setRawData(packet.getRawData());
        networkPacket.setSourceIp(extractSourceIp(packet));
        networkPacket.setDestinationIp(extractDestinationIp(packet));
        networkPacket.setProtocol(extractProtocol(packet));
        extractPorts(packet, networkPacket);
        return networkPacket;
    }


    private String extractSourceIp(Packet packet) {
        if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
            return ipV4Packet.getHeader().getSrcAddr().getHostAddress();
        } else if (packet.contains(IpV6Packet.class)) {
            IpV6Packet ipV6Packet = packet.get(IpV6Packet.class);
            return ipV6Packet.getHeader().getSrcAddr().getHostAddress();
        }
        return "N/A";
    }

    private String extractDestinationIp(Packet packet) {
        if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
            return ipV4Packet.getHeader().getDstAddr().getHostAddress();
        } else if (packet.contains(IpV6Packet.class)) {
            IpV6Packet ipV6Packet = packet.get(IpV6Packet.class);
            return ipV6Packet.getHeader().getDstAddr().getHostAddress();
        }
        return "N/A";
    }

    private String extractProtocol(Packet packet) {
        if (packet.contains(IpV4Packet.class)) {
            IpNumber protocol = packet.get(IpV4Packet.class).getHeader().getProtocol();
            return protocol.name();
        } else if (packet.contains(IpV6Packet.class)) {
            IpNumber protocol = packet.get(IpV6Packet.class).getHeader().getNextHeader();
            return protocol.name();
        }
        return "Unknown";
    }

    private void extractPorts(Packet packet, NetworkPacket networkPacket) {
        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            networkPacket.setSourcePort(tcpPacket.getHeader().getSrcPort().valueAsInt());
            networkPacket.setDestinationPort(tcpPacket.getHeader().getDstPort().valueAsInt());
        } else if (packet.contains(UdpPacket.class)) {
            UdpPacket udpPacket = packet.get(UdpPacket.class);
            networkPacket.setSourcePort(udpPacket.getHeader().getSrcPort().valueAsInt());
            networkPacket.setDestinationPort(udpPacket.getHeader().getDstPort().valueAsInt());
        } else {
            networkPacket.setSourcePort(0);
            networkPacket.setDestinationPort(0);
        }
    }
}

