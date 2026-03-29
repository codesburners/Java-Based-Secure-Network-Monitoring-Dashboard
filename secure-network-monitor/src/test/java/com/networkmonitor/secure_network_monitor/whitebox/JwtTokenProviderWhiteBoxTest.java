package com.networkmonitor.secure_network_monitor.whitebox;

import com.networkmonitor.secure_network_monitor.dualsight.annotation.DualSightTest;
import com.networkmonitor.secure_network_monitor.dualsight.annotation.TestType;
import com.networkmonitor.secure_network_monitor.security.JwtTokenProvider;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * WHITE-BOX unit tests for JwtTokenProvider.
 * Tests the internal JWT creation, validation, and claim extraction logic
 * with knowledge of the secret key and token structure.
 */
@SpringBootTest
@DualSightTest(type = TestType.WHITE_BOX, component = "JwtTokenProvider",
        description = "Tests internal JWT token creation, validation, and parsing")
public class JwtTokenProviderWhiteBoxTest {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @org.springframework.boot.test.mock.mockito.MockBean
    private com.networkmonitor.secure_network_monitor.encryption.EncryptionService encryptionService;

    /**
     * White-box: Test token creation produces a non-null, valid JWT.
     * Verifies the Jwts.builder() pipeline works correctly.
     */
    @Test
    public void testTokenCreation() {
        String token = jwtTokenProvider.createToken("testuser", Arrays.asList("ROLE_USER"));

        assertNotNull(token, "Token should not be null");
        assertFalse(token.isEmpty(), "Token should not be empty");
        // JWT tokens have 3 parts separated by dots
        assertEquals(3, token.split("\\.").length,
                "JWT should have 3 parts (header.payload.signature)");
    }

    /**
     * White-box: Test that a freshly created token validates successfully.
     * Tests the Jwts.parser().setSigningKey().parseClaimsJws() pipeline.
     */
    @Test
    public void testTokenValidation() {
        String token = jwtTokenProvider.createToken("testuser", Arrays.asList("ROLE_USER"));

        assertTrue(jwtTokenProvider.validateToken(token),
                "Freshly created token should be valid");
    }

    /**
     * White-box: Test that an invalid/tampered token is rejected.
     * Tests the catch(JwtException) branch.
     */
    @Test
    public void testInvalidTokenRejected() {
        assertFalse(jwtTokenProvider.validateToken("invalid.token.here"),
                "Invalid token should fail validation (JwtException path)");
    }

    /**
     * White-box: Test that null token is rejected.
     * Tests the catch(IllegalArgumentException) branch.
     */
    @Test
    public void testNullTokenRejected() {
        assertFalse(jwtTokenProvider.validateToken(null),
                "Null token should fail validation (IllegalArgumentException path)");
    }

    /**
     * White-box: Test username extraction from token claims.
     * Verifies Claims.getSubject() returns the correct username.
     */
    @Test
    public void testUsernameExtraction() {
        String token = jwtTokenProvider.createToken("admin", Arrays.asList("ROLE_ADMIN"));

        String username = jwtTokenProvider.getUsername(token);
        assertEquals("admin", username,
                "Extracted username should match the one used in creation");
    }

    /**
     * White-box: Test role extraction from token claims.
     * Verifies the custom "roles" claim is correctly stored and retrieved.
     */
    @Test
    public void testRoleExtraction() {
        List<String> roles = Arrays.asList("ROLE_USER", "ROLE_ADMIN");
        String token = jwtTokenProvider.createToken("admin", roles);

        List<String> extractedRoles = jwtTokenProvider.getRoles(token);
        assertEquals(2, extractedRoles.size(), "Should have 2 roles");
        assertTrue(extractedRoles.contains("ROLE_USER"), "Should contain ROLE_USER");
        assertTrue(extractedRoles.contains("ROLE_ADMIN"), "Should contain ROLE_ADMIN");
    }
}
