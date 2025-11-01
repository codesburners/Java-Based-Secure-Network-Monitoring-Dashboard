package com.networkmonitor.secure_network_monitor.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DashboardWebController {

    @GetMapping("/login")
    public String getLoginPage() {
        return "login"; // Serves login.html
    }

    @GetMapping("/dashboard")
    public String getDashboardPage() {
        return "dashboard"; // Serves dashboard.html
    }

    @GetMapping("/")
    public String getRoot() {
        return "redirect:/login"; // Redirect root ("/") to the login page
    }
}