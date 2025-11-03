package com.networkmonitor.secure_network_monitor.pcap;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
// --- Imports for IP and Protocol ---
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.namednumber.IpNumber;
// --- Imports for Ports (New) ---
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import com.networkmonitor.secure_network_monitor.encryption.EncryptionService;
import com.networkmonitor.secure_network_monitor.entity.NetworkPacket;
import com.networkmonitor.secure_network_monitor.repository.PacketRepository;
import com.networkmonitor.secure_network_monitor.service.AlertingService; // <-- 1. IMPORT AlertingService

// --- REQUIRED IMPORT: Add the new service ---
import com.networkmonitor.secure_network_monitor.service.ThreatIntelService;

import java.util.ArrayList;
import java.util.List;

@Service
public class PcapProcessingService {

    @Autowired
    private EncryptionService  encryptionService;

    @Autowired
    private PacketRepository packetRepository;

    // TODO: FIX THIS! Load this from application.properties or environment variable
    private static final String ENCRYPTION_PASSWORD = "your-secure-password";

    public List<NetworkPacket> processPcapFile(String filePath) throws Exception {
        List<NetworkPacket> packets = new ArrayList<>();

        try (PcapHandle handle = Pcaps.openOffline(filePath)) {
            Packet packet;
            while ((packet = handle.getNextPacket()) != null) {

                // --- FIX 1: Pass the 'handle' to the parsePacket method ---
                NetworkPacket networkPacket = parsePacket(packet, handle);
                packets.add(networkPacket);

                // Encrypt and store
                String encryptedData = encryptionService.encrypt(
                        networkPacket.toJson(), ENCRYPTION_PASSWORD
                );
                networkPacket.setEncryptedData(encryptedData);
                packetRepository.save(networkPacket);
            }
        } // The 'try-with-resources' will automatically call handle.close()

        return packets;
    }

    /**
     * This method now uses the other helper methods to parse the packet.
     */
    // --- FIX 2: Accept 'PcapHandle handle' as a parameter ---
    private NetworkPacket parsePacket(Packet packet, PcapHandle handle) {
        NetworkPacket networkPacket = new NetworkPacket();

        // --- FIX 3: Get the timestamp from the 'handle', not the 'packet' ---
// This is the corrected line
        networkPacket.setTimestamp(handle.getTimestamp().getTime());

        networkPacket.setPacketLength(packet.length());
        networkPacket.setRawData(packet.getRawData());
        networkPacket.setSourceIp(extractSourceIp(packet));
        networkPacket.setDestinationIp(extractDestinationIp(packet));
        networkPacket.setProtocol(extractProtocol(packet));

        // --- BONUS: Extract Port Numbers ---
        extractPorts(packet, networkPacket);

        return networkPacket;
    }

    /**
     * REAL IMPLEMENTATION to find the Source IP
     */
    private String extractSourceIp(Packet packet) {
        if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
            return ipV4Packet.getHeader().getSrcAddr().getHostAddress();
        } else if (packet.contains(IpV6Packet.class)) {
            IpV6Packet ipV6Packet = packet.get(IpV6Packet.class);
            return ipV6Packet.getHeader().getSrcAddr().getHostAddress();
        }
        return "N/A"; // Not an IP packet
    }

    /**
     * REAL IMPLEMENTATION to find the Destination IP
     */
    private String extractDestinationIp(Packet packet) {
        if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
            return ipV4Packet.getHeader().getDstAddr().getHostAddress();
        } else if (packet.contains(IpV6Packet.class)) {
            IpV6Packet ipV6Packet = packet.get(IpV6Packet.class);
            return ipV6Packet.getHeader().getDstAddr().getHostAddress();
        }
        return "N/A"; // Not an IP packet
    }

    /**
     * REAL IMPLEMENTATION to find the Protocol (TCP, UDP, etc.)
     */
    private String extractProtocol(Packet packet) {
        //
        if (packet.contains(IpV4Packet.class)) {
            IpNumber protocol = packet.get(IpV4Packet.class).getHeader().getProtocol();
            return protocol.name(); // This will return "TCP", "UDP", "ICMPv4", etc.
        } else if (packet.contains(IpV6Packet.class)) {
            IpNumber protocol = packet.get(IpV6Packet.class).getHeader().getNextHeader();
            return protocol.name(); // Same for IPv6
        }
        return "Unknown"; // Not an IP packet
    }

    /**
     * BONUS: REAL IMPLEMENTATION to find Source and Destination Ports
     */
    private void extractPorts(Packet packet, NetworkPacket networkPacket) {
        //
        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            networkPacket.setSourcePort(tcpPacket.getHeader().getSrcPort().valueAsInt());
            networkPacket.setDestinationPort(tcpPacket.getHeader().getDstPort().valueAsInt());
        } else if (packet.contains(UdpPacket.class)) {
            UdpPacket udpPacket = packet.get(UdpPacket.class);
            networkPacket.setSourcePort(udpPacket.getHeader().getSrcPort().valueAsInt());
            networkPacket.setDestinationPort(udpPacket.getHeader().getDstPort().valueAsInt());
        } else {
            // Not a TCP or UDP packet, so ports are not applicable
            networkPacket.setSourcePort(0);
            networkPacket.setDestinationPort(0);
        }
    }
}