package com.networkmonitor.secure_network_monitor;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync; // <-- IMPORT THIS

@SpringBootApplication
@EnableAsync // <-- ADD THIS ANNOTATION
public class SecureNetworkMonitorApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecureNetworkMonitorApplication.class, args);
		System.out.println("Secure Network Monitor Application Started Successfully.");
	}
}