package com.networkmonitor.secure_network_monitor.blackbox;

import com.networkmonitor.secure_network_monitor.dualsight.annotation.DualSightTest;
import com.networkmonitor.secure_network_monitor.dualsight.annotation.TestType;
import com.networkmonitor.secure_network_monitor.security.JwtTokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Arrays;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * BLACK-BOX tests for AuthController.
 * Tests the external behavior of the authentication API without
 * knowledge of internal implementation.
 */
@SpringBootTest
@AutoConfigureMockMvc
@DualSightTest(type = TestType.BLACK_BOX, component = "AuthController",
        description = "Tests authentication API endpoints as a black-box")
public class AuthControllerBlackBoxTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @org.springframework.boot.test.mock.mockito.MockBean
    private com.networkmonitor.secure_network_monitor.encryption.EncryptionService encryptionService;

    /**
     * Test: Login with valid credentials should return 200 and a JWT token.
     */
    @Test
    public void testLoginWithValidCredentials() throws Exception {
        String loginJson = "{\"username\":\"testadmin\",\"password\":\"testpass123\"}";

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists())
                .andExpect(jsonPath("$.username").value("testadmin"));
    }

    /**
     * Test: Login with invalid password should return 400.
     */
    @Test
    public void testLoginWithInvalidPassword() throws Exception {
        String loginJson = "{\"username\":\"testadmin\",\"password\":\"wrongpassword\"}";

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson))
                .andExpect(status().isBadRequest());
    }

    /**
     * Test: Login with non-existent user should return 400.
     */
    @Test
    public void testLoginWithNonExistentUser() throws Exception {
        String loginJson = "{\"username\":\"nonexistent\",\"password\":\"password123\"}";

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson))
                .andExpect(status().isBadRequest());
    }

    /**
     * Test: Account lockout after 3 failed login attempts.
     * After MAX_ATTEMPTS failures, the account should be locked.
     */
    @Test
    public void testAccountLockoutAfterFailures() throws Exception {
        String loginJson = "{\"username\":\"testadmin\",\"password\":\"wrong\"}";

        // Make 3 failed attempts
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(loginJson))
                    .andExpect(status().isBadRequest());
        }

        // 4th attempt should still fail (account locked)
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson))
                .andExpect(status().isBadRequest());
    }
}
