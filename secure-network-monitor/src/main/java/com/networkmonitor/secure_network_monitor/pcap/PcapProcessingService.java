package com.networkmonitor.secure_network_monitor.pcap;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.networkmonitor.secure_network_monitor.encryption.EncryptionService;
import com.networkmonitor.secure_network_monitor.entity.NetworkPacket;
import com.networkmonitor.secure_network_monitor.repository.PacketRepository;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

@Service
public class PcapProcessingService {

    @Autowired
    private EncryptionService  encryptionService;

    @Autowired
    private PacketRepository packetRepository;

    private static final String ENCRYPTION_PASSWORD = "your-secure-password";

    public List<NetworkPacket> processPcapFile(String filePath) throws Exception {
        List<NetworkPacket> packets = new ArrayList<>();
        PcapHandle handle = Pcaps.openOffline(filePath);

        Packet packet;
        while ((packet = handle.getNextPacket()) != null) {
            NetworkPacket networkPacket = parsePacket(packet);
            packets.add(networkPacket);

            // Encrypt and store
            String encryptedData = encryptionService.encrypt(
                    networkPacket.toJson(), ENCRYPTION_PASSWORD
            );
            networkPacket.setEncryptedData(encryptedData);
            packetRepository.save(networkPacket);
        }

        handle.close();
        return packets;
    }

    private NetworkPacket parsePacket(Packet packet) {
        NetworkPacket networkPacket = new NetworkPacket();
        networkPacket.setTimestamp(System.currentTimeMillis());
        networkPacket.setPacketLength(packet.length());
        networkPacket.setSourceIp(extractSourceIp(packet));
        networkPacket.setDestinationIp(extractDestinationIp(packet));
        networkPacket.setProtocol(extractProtocol(packet));
        networkPacket.setRawData(packet.getRawData());

        return networkPacket;
    }

    private String extractSourceIp(Packet packet) {
        // Implementation for extracting source IP
        return "192.168.1.1"; // Simplified
    }

    private String extractDestinationIp(Packet packet) {
        // Implementation for extracting destination IP
        return "192.168.1.2"; // Simplified
    }

    private String extractProtocol(Packet packet) {
        // Implementation for extracting protocol
        return "TCP"; // Simplified
    }
}