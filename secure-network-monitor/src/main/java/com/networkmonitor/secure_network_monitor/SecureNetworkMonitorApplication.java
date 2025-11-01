package com.networkmonitor.secure_network_monitor;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SecureNetworkMonitorApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecureNetworkMonitorApplication.class, args);
		System.out.println("Secure Network Monitor Application Started Successfully.");
	}
}