package com.networkmonitor.secure_network_monitor.security;

import com.networkmonitor.secure_network_monitor.service.AlertingService;
import com.networkmonitor.secure_network_monitor.service.LoginAttemptService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationListener {

    @Autowired
    private LoginAttemptService loginAttemptService;

    @Autowired
    private AlertingService alertingService; // Your email service

    /**
     * This method listens for any SUCCESSFUL login.
     */
    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        String username = event.getAuthentication().getName();
        loginAttemptService.loginSucceeded(username);
    }

    /**
     * This method listens for any FAILED login (e.g., bad password).
     */
    @EventListener
    public void onAuthenticationFailure(AuthenticationFailureBadCredentialsEvent event) {
        String username = event.getAuthentication().getName();
        
        // 1. Record the failed attempt
        loginAttemptService.loginFailed(username);

        // 2. Check if the user is now blocked
        if (loginAttemptService.isBlocked(username)) {
            
            // 3. Send the alert email!
            String subject = "Multiple Failed Logins Detected";
            String body = "The account '" + username + "' has been locked due to " 
                        + LoginAttemptService.MAX_ATTEMPTS + " failed login attempts.";
            
            alertingService.sendThreatAlert(subject, body);
        }
    }
}