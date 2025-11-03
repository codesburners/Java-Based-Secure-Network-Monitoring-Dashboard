package com.networkmonitor.secure_network_monitor.service;

import org.springframework.stereotype.Service;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class LoginAttemptService {

    public static final int MAX_ATTEMPTS = 3;
    // We use ConcurrentHashMap for thread safety
    private Map<String, Integer> attemptsCache = new ConcurrentHashMap<>();

    /**
     * Called when a user login SUCCEEDS.
     */
    public void loginSucceeded(String username) {
        // Reset the counter for this user
        attemptsCache.remove(username);
    }

    /**
     * Called when a user login FAILS.
     */
    public void loginFailed(String username) {
        int attempts = attemptsCache.getOrDefault(username, 0);
        attempts++;
        attemptsCache.put(username, attempts);
    }

    /**
     * Checks if a user is blocked/locked.
     */
    public boolean isBlocked(String username) {
        return attemptsCache.getOrDefault(username, 0) >= MAX_ATTEMPTS;
    }
}