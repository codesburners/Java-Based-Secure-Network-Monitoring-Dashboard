package com.networkmonitor.secure_network_monitor.whitebox;

import com.networkmonitor.secure_network_monitor.dualsight.annotation.DualSightTest;
import com.networkmonitor.secure_network_monitor.dualsight.annotation.TestType;
import com.networkmonitor.secure_network_monitor.service.LoginAttemptService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * WHITE-BOX unit tests for LoginAttemptService.
 * Tests internal logic including counter management, blocking logic,
 * and time-based expiry with knowledge of the implementation.
 */
@DualSightTest(type = TestType.WHITE_BOX, component = "LoginAttemptService",
        description = "Tests internal login attempt tracking and lockout logic")
public class LoginAttemptServiceWhiteBoxTest {

    private LoginAttemptService loginAttemptService;

    @BeforeEach
    public void setUp() {
        loginAttemptService = new LoginAttemptService();
    }

    /**
     * White-box: Verify loginSucceeded() clears the internal attempts counter.
     * Tests the cache clearing logic directly.
     */
    @Test
    public void testLoginSucceededClearsAttempts() {
        String user = "testuser";

        // Add some failed attempts
        loginAttemptService.loginFailed(user);
        loginAttemptService.loginFailed(user);

        // Now succeed
        loginAttemptService.loginSucceeded(user);

        // Should not be blocked anymore
        assertFalse(loginAttemptService.isBlocked(user),
                "User should not be blocked after successful login");
    }

    /**
     * White-box: Verify loginFailed() increments the internal counter.
     * After MAX_ATTEMPTS (3), the account should be locked.
     */
    @Test
    public void testLoginFailedIncrementsCounter() {
        String user = "failuser";

        // First two failures should not block
        loginAttemptService.loginFailed(user);
        assertFalse(loginAttemptService.isBlocked(user), "1 failure should not block");

        loginAttemptService.loginFailed(user);
        assertFalse(loginAttemptService.isBlocked(user), "2 failures should not block");

        // Third failure triggers lockout (MAX_ATTEMPTS = 3)
        loginAttemptService.loginFailed(user);
        assertTrue(loginAttemptService.isBlocked(user),
                "3 failures should trigger lockout (MAX_ATTEMPTS)");
    }

    /**
     * White-box: Verify isBlocked() returns true after exactly MAX_ATTEMPTS failures.
     * Tests the >= comparison in the blocking logic.
     */
    @Test
    public void testIsBlockedAfterMaxAttempts() {
        String user = "blockeduser";

        for (int i = 0; i < LoginAttemptService.MAX_ATTEMPTS; i++) {
            loginAttemptService.loginFailed(user);
        }

        assertTrue(loginAttemptService.isBlocked(user),
                "Account should be blocked after MAX_ATTEMPTS failures");
    }

    /**
     * White-box: Verify isBlocked() returns false when lockTimestamp is null.
     * Tests the null-check path in isBlocked().
     */
    @Test
    public void testIsBlockedReturnsFalseForUnknownUser() {
        assertFalse(loginAttemptService.isBlocked("unknownuser"),
                "Unknown user should never be blocked (null lockTimestamp path)");
    }

    /**
     * White-box: Verify that loginSucceeded clears both caches.
     */
    @Test
    public void testLoginSucceededClearsBothCaches() {
        String user = "cacheuser";

        // Trigger lockout
        for (int i = 0; i < 3; i++) {
            loginAttemptService.loginFailed(user);
        }
        assertTrue(loginAttemptService.isBlocked(user));

        // Success should clear both attemptsCache and lockTimestampCache
        loginAttemptService.loginSucceeded(user);
        assertFalse(loginAttemptService.isBlocked(user),
                "loginSucceeded should clear both caches");

        // Verify counter is reset - one failure should not block again
        loginAttemptService.loginFailed(user);
        assertFalse(loginAttemptService.isBlocked(user),
                "Counter should be reset; one failure should not block");
    }
}
