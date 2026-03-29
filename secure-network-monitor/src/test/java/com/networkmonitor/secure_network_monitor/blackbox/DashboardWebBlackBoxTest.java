package com.networkmonitor.secure_network_monitor.blackbox;

import com.networkmonitor.secure_network_monitor.dualsight.annotation.DualSightTest;
import com.networkmonitor.secure_network_monitor.dualsight.annotation.TestType;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * BLACK-BOX tests for web page endpoints.
 * Tests that the Thymeleaf pages are accessible and return HTML.
 */
@SpringBootTest
@AutoConfigureMockMvc
@DualSightTest(type = TestType.BLACK_BOX, component = "DashboardWebController", description = "Tests web page accessibility as a black-box")
public class DashboardWebBlackBoxTest {

    @Autowired
    private MockMvc mockMvc;

    @org.springframework.boot.test.mock.mockito.MockBean
    private com.networkmonitor.secure_network_monitor.encryption.EncryptionService encryptionService;

    /**
     * Test: Login page should load and return 200 with HTML.
     */
    @Test
    public void testLoginPageLoads() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("text/html"));
    }

    /**
     * Test: Dashboard page should load and return 200 with HTML.
     */
    @Test
    public void testDashboardPageLoads() throws Exception {
        mockMvc.perform(get("/dashboard"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("text/html"));
    }

    /**
     * Test: DualSight page should load and return 200 with HTML.
     */
    @Test
    public void testDualSightPageLoads() throws Exception {
        mockMvc.perform(get("/dualsight"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("text/html"));
    }

    public String testDualSightDetection() {
        return "DualSight can see me!";
    }

}
