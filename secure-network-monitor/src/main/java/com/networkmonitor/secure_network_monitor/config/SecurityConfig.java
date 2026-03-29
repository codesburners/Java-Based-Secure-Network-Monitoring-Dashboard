package com.networkmonitor.secure_network_monitor.config;

import com.networkmonitor.secure_network_monitor.security.JwtTokenFilter;
// --- IMPORT YOUR NEW SERVICES ---
import com.networkmonitor.secure_network_monitor.service.LoginAttemptService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value; // <-- NEW IMPORT
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.LockedException; // <-- NEW IMPORT
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
// --- NEW USER IMPORTS ---
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
// --- END NEW USER IMPORTS ---
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Autowired
    private JwtTokenFilter jwtTokenFilter;

    // --- 1. INJECT YOUR NEW SERVICES AND PROPERTIES ---
    @Autowired
    private LoginAttemptService loginAttemptService;

    @Value("${admin.username}")
    private String adminUsername;

    @Value("${admin.password}")
    private String adminPassword;
    // --- END OF NEW INJECTIONS ---


    // This bean is required by your AuthController to process the login
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    // This is the main security filter chain
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/", "/login", "/dashboard", "/dualsight").permitAll()
                .antMatchers("/js/**", "/css/**").permitAll()
                .antMatchers("/api/auth/login").permitAll()
                .antMatchers("/h2-console/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class)
                .headers().frameOptions().sameOrigin();

        return http.build();
    }

    // This bean hashes the passwords
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    // --- 2. ADD THIS NEW BEAN TO REPLACE YOUR OLD HARDCODED USER ---
    /**
     * This is the new UserDetailsService that:
     * 1. Checks for a locked account.
     * 2. Loads the admin user from application.properties.
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> { // Lambda for the UserDetailsService interface

            // 1. Check if the account is locked FIRST
            if (loginAttemptService.isBlocked(username)) {
                // This exception will be shown to the user
                throw new LockedException("This account has been locked due to 3 failed login attempts.");
            }

            // 2. Check if the username matches the one from application.properties
            if (adminUsername.equals(username)) {

                // 3. Create the Spring Security User object
                return User.withUsername(adminUsername)
                        .password(passwordEncoder().encode(adminPassword)) // Use the existing passwordEncoder bean
                        .roles("USER", "ADMIN") // Give your user roles
                        .build();
            } else {
                // 4. If no user is found
                throw new UsernameNotFoundException("User not found: " + username);
            }
        };
    }
    // --- END OF NEW BEAN ---
}