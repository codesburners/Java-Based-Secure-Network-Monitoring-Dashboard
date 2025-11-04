package com.networkmonitor.secure_network_monitor.service;

import org.springframework.stereotype.Service;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class LoginAttemptService {

    public static final int MAX_ATTEMPTS = 3;
    private static final long LOCK_TIME_DURATION = 5 * 60 * 1000; // 5 minutes

    // Stores: <Username, Failed Attempts>
    private final Map<String, Integer> attemptsCache = new ConcurrentHashMap<>();
    // Stores: <Username, Lock Expiration Timestamp>
    private final Map<String, Long> lockTimestampCache = new ConcurrentHashMap<>();

    /**
     * Called on a successful login.
     */
    public void loginSucceeded(String key) {
        attemptsCache.remove(key);
        lockTimestampCache.remove(key);
    }

    /**
     * Called on a failed login.
     */
    public void loginFailed(String key) {
        int attempts = attemptsCache.getOrDefault(key, 0) + 1;
        attemptsCache.put(key, attempts);

        if (attempts >= MAX_ATTEMPTS) {
            // Lock the account
            lockTimestampCache.put(key, System.currentTimeMillis() + LOCK_TIME_DURATION);
        }
    }

    /**
     * Checked by SecurityConfig before every login attempt.
     */
    public boolean isBlocked(String key) {
        Long lockTimestamp = lockTimestampCache.get(key);
        if (lockTimestamp == null) {
            return false; // Not locked
        }

        // Check if the lock time has expired
        if (System.currentTimeMillis() > lockTimestamp) {
            // Time's up. Unlock the account.
            attemptsCache.remove(key);
            lockTimestampCache.remove(key);
            return false;
        }

        return true; // Still locked
    }
}