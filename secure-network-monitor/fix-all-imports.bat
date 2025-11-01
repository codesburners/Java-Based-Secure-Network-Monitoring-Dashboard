@echo off
echo Fixing all imports for Spring Boot 2.7.x...

echo 1. Fixing NetworkPacket.java...
(
echo package com.networkmonitor.secure_network_monitor.entity;
echo.
echo import javax.persistence.*;
echo import java.time.LocalDateTime;
echo.
echo @Entity
echo @Table^(name = "network_packets"^)
echo public class NetworkPacket {
echo     @Id
echo     @GeneratedValue^(strategy = GenerationType.IDENTITY^)
echo     private Long id;
echo     
echo     @Column^(name = "timestamp"^)
echo     private Long timestamp;
echo     
echo     @Column^(name = "source_ip", length = 45^)
echo     private String sourceIp;
echo     
echo     @Column^(name = "destination_ip", length = 45^)
echo     private String destinationIp;
echo     
echo     @Column^(name = "protocol", length = 20^)
echo     private String protocol;
echo     
echo     @Column^(name = "packet_length"^)
echo     private Integer packetLength;
echo     
echo     @Column^(name = "encrypted_data", columnDefinition = "TEXT"^)
echo     private String encryptedData;
echo     
echo     @Lob
echo     @Column^(name = "raw_data"^)
echo     private byte[] rawData;
echo     
echo     @Column^(name = "created_at"^)
echo     private LocalDateTime createdAt;
echo     
echo     public NetworkPacket^(^) {
echo         this.createdAt = LocalDateTime.now^(^);
echo     }
echo     
echo     public Long getId^(^) { return id; }
echo     public void setId^(Long id^) { this.id = id; }
echo     
echo     public Long getTimestamp^(^) { return timestamp; }
echo     public void setTimestamp^(Long timestamp^) { this.timestamp = timestamp; }
echo     
echo     public String getSourceIp^(^) { return sourceIp; }
echo     public void setSourceIp^(String sourceIp^) { this.sourceIp = sourceIp; }
echo     
echo     public String getDestinationIp^(^) { return destinationIp; }
echo     public void setDestinationIp^(String destinationIp^) { this.destinationIp = destinationIp; }
echo     
echo     public String getProtocol^(^) { return protocol; }
echo     public void setProtocol^(String protocol^) { this.protocol = protocol; }
echo     
echo     public Integer getPacketLength^(^) { return packetLength; }
echo     public void setPacketLength^(Integer packetLength^) { this.packetLength = packetLength; }
echo     
echo     public String getEncryptedData^(^) { return encryptedData; }
echo     public void setEncryptedData^(String encryptedData^) { this.encryptedData = encryptedData; }
echo     
echo     public byte[] getRawData^(^) { return rawData; }
echo     public void setRawData^(byte[] rawData^) { this.rawData = rawData; }
echo     
echo     public LocalDateTime getCreatedAt^(^) { return createdAt; }
echo     public void setCreatedAt^(LocalDateTime createdAt^) { this.createdAt = createdAt; }
echo     
echo     public String toJson^(^) {
echo         return String.format^(
echo             "{\"timestamp\":%%d,\"sourceIp\":\"%%s\",\"destinationIp\":\"%%s\",\"protocol\":\"%%s\",\"packetLength\":%%d}",
echo             timestamp, sourceIp, destinationIp, protocol, packetLength
echo         ^);
echo     }
echo }
) > src\main\java\com\networkmonitor\secure_network_monitor\entity\NetworkPacket.java

echo 2. Fixing JWT imports in JwtTokenProvider.java...
powershell -Command "(Get-Content 'src\main\java\com\networkmonitor\secure_network_monitor\security\JwtTokenProvider.java') -replace 'jakarta.servlet', 'javax.servlet' | Set-Content 'src\main\java\com\networkmonitor\secure_network_monitor\security\JwtTokenProvider.java'"
powershell -Command "(Get-Content 'src\main\java\com\networkmonitor\secure_network_monitor\security\JwtTokenProvider.java') -replace 'import io.jsonwebtoken.security.Keys;', '' | Set-Content 'src\main\java\com\networkmonitor\secure_network_monitor\security\JwtTokenProvider.java'"
powershell -Command "(Get-Content 'src\main\java\com\networkmonitor\secure_network_monitor\security\JwtTokenProvider.java') -replace 'private final SecretKey secretKey = Keys.hmacShaKeyFor', 'private final String secretKey' | Set-Content 'src\main\java\com\networkmonitor\secure_network_monitor\security\JwtTokenProvider.java'"
powershell -Command "(Get-Content 'src\main\java\com\networkmonitor\secure_network_monitor\security\JwtTokenProvider.java') -replace 'parserBuilder', 'parser' | Set-Content 'src\main\java\com\networkmonitor\secure_network_monitor\security\JwtTokenProvider.java'"
powershell -Command "(Get-Content 'src\main\java\com\networkmonitor\secure_network_monitor\security\JwtTokenProvider.java') -replace '.setSigningKey^(secretKey^)', '.setSigningKey^(secretKey.getBytes^(^^)^)' | Set-Content 'src\main\java\com\networkmonitor\secure_network_monitor\security\JwtTokenProvider.java'"

echo 3. Fixing SecurityConfig.java...
powershell -Command "(Get-Content 'src\main\java\com\networkmonitor\secure_network_monitor\config\SecurityConfig.java') -replace 'requestMatchers', 'antMatchers' | Set-Content 'src\main\java\com\networkmonitor\secure_network_monitor\config\SecurityConfig.java'"
powershell -Command "(Get-Content 'src\main\java\com\networkmonitor\secure_network_monitor\config\SecurityConfig.java') -replace 'authorizeHttpRequests', 'authorizeRequests' | Set-Content 'src\main\java\com\networkmonitor\secure_network_monitor\config\SecurityConfig.java'"

echo.
echo ✅ All imports fixed! Now run: mvn clean compile
pause