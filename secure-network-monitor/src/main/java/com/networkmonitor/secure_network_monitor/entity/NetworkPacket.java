package com.networkmonitor.secure_network_monitor.entity;

import javax.persistence.*;  // CHANGED FROM jakarta.persistence
import java.time.LocalDateTime;

@Entity
@Table(name = "network_packets")
public class NetworkPacket {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "packet_timestamp")
    private Long timestamp;

    @Column(name = "source_ip", length = 45)
    private String sourceIp;

    @Column(name = "destination_ip", length = 45)
    private String destinationIp;

    @Column(name = "packet_protocol", length = 20)
    private String protocol;

    // --- NEW FIELD ---
    @Column(name = "source_port")
    private Integer sourcePort;

    // --- NEW FIELD ---
    @Column(name = "destination_port")
    private Integer destinationPort;

    @Column(name = "packet_length")
    private Integer packetLength;

    @Column(name = "encrypted_data", columnDefinition = "TEXT")
    private String encryptedData;

    @Lob
    @Column(name = "raw_packet_data")
    private byte[] rawData;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    // Constructors
    public NetworkPacket() {
        this.createdAt = LocalDateTime.now();
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Long getTimestamp() { return timestamp; }
    public void setTimestamp(Long timestamp) { this.timestamp = timestamp; }

    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }

    public String getDestinationIp() { return destinationIp; }
    public void setDestinationIp(String destinationIp) { this.destinationIp = destinationIp; }

    public String getProtocol() { return protocol; }
    public void setProtocol(String protocol) { this.protocol = protocol; }

    // --- NEW GETTERS AND SETTERS ---
    public Integer getSourcePort() { return sourcePort; }
    public void setSourcePort(Integer sourcePort) { this.sourcePort = sourcePort; }

    public Integer getDestinationPort() { return destinationPort; }
    public void setDestinationPort(Integer destinationPort) { this.destinationPort = destinationPort; }
    // --- END NEW GETTERS AND SETTERS ---

    public Integer getPacketLength() { return packetLength; }
    public void setPacketLength(Integer packetLength) { this.packetLength = packetLength; }

    public String getEncryptedData() { return encryptedData; }
    public void setEncryptedData(String encryptedData) { this.encryptedData = encryptedData; }

    public byte[] getRawData() { return rawData; }
    public void setRawData(byte[] rawData) { this.rawData = rawData; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }


    /**
     * UPDATED to include ports for encryption
     */
    public String toJson() {
        return String.format(
                "{\"timestamp\":%d,\"sourceIp\":\"%s\",\"destinationIp\":\"%s\",\"protocol\":\"%s\",\"sourcePort\":%d,\"destinationPort\":%d,\"packetLength\":%d}",
                timestamp, sourceIp, destinationIp, protocol, sourcePort, destinationPort, packetLength
        );
    }
}