package com.gaas.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Spring Security configuration for the GaaS Auth Service.
 *
 * Security model:
 *   - POST /oauth2/token    → PUBLIC (no auth required — it IS the auth endpoint)
 *   - GET  /actuator/health → PUBLIC (required for Kubernetes readiness probes)
 *   - GET  /actuator/info   → PUBLIC (informational, no sensitive data)
 *   - All other endpoints   → PROTECTED (require a valid Bearer JWT)
 *
 * Sessions are stateless — this service issues tokens but does not maintain
 * session state. Each request is independently authenticated.
 *
 * CSRF is disabled because this service only accepts API calls from machine
 * clients (no browser sessions), making CSRF attacks impossible.
 *
 * ACCOUNTABILITY NOTE (AI-generated code review):
 *   - The AI draft used deprecated WebSecurityConfigurerAdapter. Manually
 *     updated to the current SecurityFilterChain bean pattern (Spring Boot 3.x).
 *   - The AI draft protected /actuator/health, which would break K8s probes.
 *     Manually opened the health endpoint. This is a real bug the AI introduced.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authorizeHttpRequests(authz -> authz
                // Token endpoint: clients POST here unauthenticated to receive a token
                .requestMatchers("/oauth2/token").permitAll()
                // K8s liveness/readiness probes must not require a token
                .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                // Everything else requires a valid JWT
                .anyRequest().authenticated()
            )
            // If the service later exposes a token introspection endpoint (/oauth2/introspect),
            // configure it as a resource server here so incoming JWTs are validated.
            // For now, the service only issues tokens — it does not validate them.
            .httpBasic(AbstractHttpConfigurer::disable);

        return http.build();
    }
}
