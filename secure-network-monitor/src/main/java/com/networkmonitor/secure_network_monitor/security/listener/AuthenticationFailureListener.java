package com.networkmonitor.secure_network_monitor.security.listener;

import com.networkmonitor.secure_network_monitor.service.LoginAttemptService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationFailureListener implements ApplicationListener<AuthenticationFailureBadCredentialsEvent> {

    @Autowired
    private LoginAttemptService loginAttemptService;

    @Override
    public void onApplicationEvent(AuthenticationFailureBadCredentialsEvent event) {
        // Get the username from the failed event
        String username = (String) event.getAuthentication().getPrincipal();

        // Tell the service that this user just failed to log in
        loginAttemptService.loginFailed(username);
    }
}