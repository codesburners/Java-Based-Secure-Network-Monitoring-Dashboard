package com.networkmonitor.secure_network_monitor.config;

import com.networkmonitor.secure_network_monitor.security.JwtTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity; // <-- MODERN
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true) // <-- MODERN
public class SecurityConfig {

    @Autowired
    private JwtTokenFilter jwtTokenFilter;

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
                // --- THIS IS THE FIX ---
                // Use authorizeRequests() and antMatchers()
                .authorizeRequests()
                .antMatchers("/", "/login", "/dashboard").permitAll()
                .antMatchers("/js/**", "/css/**").permitAll() // Make sure your JS/CSS is permitted
                .antMatchers("/api/auth/login").permitAll()   // Allow login API
                .antMatchers("/h2-console/**").permitAll()    // Allow H2 console
                .anyRequest().authenticated()                 // Secure all other APIs
                // --- END OF FIX ---
                .and()
                .addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class)
                .headers().frameOptions().sameOrigin();

        return http.build();
    }

    // This bean defines your test users
    @Bean
    public UserDetailsService userDetailsService() {
        // A regular user
        UserDetails user = User.builder()
                .username("user")
                .password(passwordEncoder().encode("password"))
                .roles("USER")
                .build();

        // An admin user (can access everything)
        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("admin"))
                .roles("USER", "ADMIN") // Admin has both roles
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }

    // This bean hashes the passwords
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}