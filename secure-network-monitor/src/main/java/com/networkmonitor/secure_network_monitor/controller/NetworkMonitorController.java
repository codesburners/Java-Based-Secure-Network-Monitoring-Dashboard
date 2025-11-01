package com.networkmonitor.secure_network_monitor.controller;

import com.networkmonitor.secure_network_monitor.pcap.PcapProcessingService;
import com.networkmonitor.secure_network_monitor.service.DashboardService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

// --- Import these ---
import java.nio.file.Files;
import java.nio.file.Path;
// --- End Imports ---

import java.util.Map;

@RestController
@RequestMapping("/api")
public class NetworkMonitorController {

    @Autowired
    private PcapProcessingService pcapService;

    @Autowired
    private DashboardService dashboardService;

    @PostMapping("/upload-pcap")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> uploadPcapFile(@RequestParam("file") MultipartFile file) {

        // --- IMPROVED FILE HANDLING ---
        Path tempFile = null;
        try {
            // Create a secure, cross-platform temporary file
            tempFile = Files.createTempFile("pcap-upload-", file.getOriginalFilename());
            file.transferTo(tempFile);

            // Process PCAP file using its absolute path
            pcapService.processPcapFile(tempFile.toAbsolutePath().toString());

            return ResponseEntity.ok().body("File processed successfully");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error processing file: " + e.getMessage());
        } finally {
            // Clean up the temporary file after processing
            if (tempFile != null) {
                try {
                    Files.delete(tempFile);
                } catch (Exception e) {
                    // Log the error, but don't block the response
                    System.err.println("Could not delete temp file: " + e.getMessage());
                }
            }
        }
        // --- END OF IMPROVEMENT ---
    }

    @GetMapping("/dashboard/stats")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Map<String, Object>> getDashboardStats() {
        Map<String, Object> stats = dashboardService.getDashboardStatistics();
        return ResponseEntity.ok(stats);
    }

    @GetMapping("/packets/recent")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<?> getRecentPackets() {
        return ResponseEntity.ok(dashboardService.getRecentPackets());
    }
}