package com.networkmonitor.secure_network_monitor.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
public class AlertingService {

    @Autowired
    private JavaMailSender mailSender; // Auto-configured by Spring Boot

    @Value("${spring.mail.username}")
    private String fromEmail;

    @Value("${alert.admin.email}")
    private String adminEmail;

    /**
     * Sends an email alert.
     * This method is marked @Async to run in a separate thread,
     * so it doesn't slow down your packet processing.
     */
    @Async
    public void sendThreatAlert(String subject, String body) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(adminEmail);
            message.setSubject("! NETWORK MONITOR ALERT: " + subject);
            message.setText(body);

            mailSender.send(message);
            System.out.println("Alert email sent successfully to " + adminEmail);
        } catch (Exception e) {
            System.err.println("Error sending email: " + e.getMessage());
        }
    }


}