package com.networkmonitor.secure_network_monitor.dualsight.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Web controller serving the DualSight dashboard page.
 */
@Controller
public class DualSightWebController {

    @GetMapping("/dualsight")
    public String dualsightDashboard() {
        return "dualsight";
    }
}
