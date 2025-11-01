package com.networkmonitor.secure_network_monitor.security;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

public interface JwtTokenFilter1 {
    void doFilter(ServletRequest req, ServletResponse res, FilterChain filterChain)
            throws IOException, ServletException;
}
