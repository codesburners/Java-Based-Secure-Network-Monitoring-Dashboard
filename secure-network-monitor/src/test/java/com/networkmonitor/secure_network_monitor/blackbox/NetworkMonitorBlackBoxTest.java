package com.networkmonitor.secure_network_monitor.blackbox;

import com.networkmonitor.secure_network_monitor.dualsight.annotation.DualSightTest;
import com.networkmonitor.secure_network_monitor.dualsight.annotation.TestType;
import com.networkmonitor.secure_network_monitor.security.JwtTokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Arrays;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * BLACK-BOX tests for NetworkMonitorController.
 * Tests the dashboard stats and packet retrieval APIs as a black-box.
 */
@SpringBootTest
@AutoConfigureMockMvc
@DualSightTest(type = TestType.BLACK_BOX, component = "NetworkMonitorController",
        description = "Tests network monitoring API endpoints as a black-box")
public class NetworkMonitorBlackBoxTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @org.springframework.boot.test.mock.mockito.MockBean
    private com.networkmonitor.secure_network_monitor.encryption.EncryptionService encryptionService;

    private String adminToken;

    @BeforeEach
    public void setUp() {
        // Generate a valid admin token for authenticated requests
        adminToken = jwtTokenProvider.createToken("testadmin", Arrays.asList("ROLE_USER", "ROLE_ADMIN"));
    }

    /**
     * Test: Accessing dashboard stats without authentication should fail.
     */
    @Test
    public void testGetStatsWithoutAuth() throws Exception {
        mockMvc.perform(get("/api/dashboard/stats"))
                .andExpect(status().isForbidden());
    }

    /**
     * Test: Accessing dashboard stats with valid JWT should return 200 and JSON.
     */
    @Test
    public void testGetStatsWithAuth() throws Exception {
        mockMvc.perform(get("/api/dashboard/stats")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalPackets").exists())
                .andExpect(jsonPath("$.protocolDistribution").exists())
                .andExpect(jsonPath("$.topSourceIps").exists());
    }

    /**
     * Test: Getting recent packets with valid JWT should return 200.
     */
    @Test
    public void testGetRecentPacketsWithAuth() throws Exception {
        mockMvc.perform(get("/api/packets/recent")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());
    }

    /**
     * Test: Uploading PCAP without admin role should fail.
     */
    @Test
    public void testUploadPcapWithoutAdminRole() throws Exception {
        // Create a token with only USER role (not ADMIN)
        String userOnlyToken = jwtTokenProvider.createToken("regularuser", Arrays.asList("ROLE_USER"));

        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart("/api/upload-pcap")
                        .file(new org.springframework.mock.web.MockMultipartFile("file", "test.pcap", "application/octet-stream", "dummy".getBytes()))
                        .header("Authorization", "Bearer " + userOnlyToken))
                .andExpect(status().isForbidden());
    }
}
