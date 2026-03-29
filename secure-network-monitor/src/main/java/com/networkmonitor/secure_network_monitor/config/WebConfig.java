package com.networkmonitor.secure_network_monitor.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.AsyncSupportConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void configureAsyncSupport(AsyncSupportConfigurer configurer) {
        // Enforce a strict 10-minute timeout for all asynchronous requests
        // This prevents Tomcat from cutting off StreamingResponseBody channels (like Live Test Runner)
        configurer.setDefaultTimeout(600000L); 
    }
}
