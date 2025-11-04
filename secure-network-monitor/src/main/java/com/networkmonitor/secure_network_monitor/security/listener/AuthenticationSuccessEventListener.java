package com.networkmonitor.secure_network_monitor.security.listener;

import com.networkmonitor.secure_network_monitor.service.LoginAttemptService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationSuccessEventListener implements ApplicationListener<AuthenticationSuccessEvent> {

    @Autowired
    private LoginAttemptService loginAttemptService;

    @Override
    public void onApplicationEvent(AuthenticationSuccessEvent event) {
        // Get the username from the successful event
        String username = event.getAuthentication().getName();

        // Tell the service to reset the count for this user
        loginAttemptService.loginSucceeded(username);
    }
}