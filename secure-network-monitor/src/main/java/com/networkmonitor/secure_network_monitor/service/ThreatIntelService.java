package com.networkmonitor.secure_network_monitor.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@Service
public class ThreatIntelService {

    // Injects the API key from application.properties
    @Value("${abuseipdb.api.key}")
    private String apiKey;

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Checks the reputation of an IP address using the AbuseIPDB API.
     * @param ip The IP address to check.
     * @return A string (e.g., "Suspicious", "Benign")
     */
    public String checkIpReputation(String ip) {
        // Don't check private or unassigned IPs
        if (ip == null || ip.equals("N/A") || ip.startsWith("192.168.") || ip.startsWith("10.")) {
            return "Private";
        }

        String url = "https://api.abuseipdb.com/api/v2/check?ipAddress=" + ip;

        // Set up the request headers
        HttpHeaders headers = new HttpHeaders();
        headers.set("Key", apiKey);
        headers.set("Accept", "application/json");

        HttpEntity<String> entity = new HttpEntity<>(headers);

        try {
            // Make the API call
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);

            // Parse the JSON response
            JsonNode root = objectMapper.readTree(response.getBody());
            int confidenceScore = root.path("data").path("abuseConfidenceScore").asInt(0);

            // Return a simple, human-readable reputation
            if (confidenceScore > 75) {
                return "Known Attacker";
            } else if (confidenceScore > 25) {
                return "Suspicious";
            } else {
                return "Benign";
            }

        } catch (Exception e) {
            System.err.println("Error checking IP reputation for " + ip + ": " + e.getMessage());
            return "Check Error"; // Return "Error" if the API call fails
        }
    }
}