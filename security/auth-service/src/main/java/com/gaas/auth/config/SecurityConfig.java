package com.gaas.auth.config;

// @Bean marks a method as producing a Spring-managed bean.
// The returned object is registered in the Spring IoC container and can be injected elsewhere.
import org.springframework.context.annotation.Bean;

// @Configuration marks this class as a source of bean definitions,
// equivalent to a Spring XML <beans> file but in Java.
import org.springframework.context.annotation.Configuration;

// HttpSecurity is the fluent builder API for configuring HTTP security rules.
// It controls which endpoints are protected, how CSRF is handled, and session policy.
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

// @EnableWebSecurity activates Spring Security's web security support and
// registers the SecurityFilterChain defined here into the servlet filter chain.
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

// AbstractHttpConfigurer is the base class for disabling specific Spring Security
// configurers — used here to disable CSRF and HTTP Basic auth entirely.
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

// SessionCreationPolicy.STATELESS tells Spring Security never to create an HTTP session.
// Each request must carry its own credentials (in this case, client_id + client_secret).
import org.springframework.security.config.http.SessionCreationPolicy;

// SecurityFilterChain is the interface that represents the ordered list of
// servlet filters that Spring Security applies to every incoming HTTP request.
import org.springframework.security.web.SecurityFilterChain;

// @EnableConfigurationProperties activates @ConfigurationProperties scanning.
// Without this, Spring does not bind gaas.idp.* properties into IdpProperties.
// Placed here (on a @Configuration class) rather than on AuthServiceApplication
// to keep it co-located with the security configuration that uses IdP settings.
import org.springframework.boot.context.properties.EnableConfigurationProperties;

// IdpProperties is the @ConfigurationProperties record for gaas.idp.* settings.
// This import + @EnableConfigurationProperties makes it available as a Spring bean.
import com.gaas.auth.config.IdpProperties;

/**
 * ============================================================
 * Spring Security Configuration for GaaS Auth Service
 * ============================================================
 *
 * PURPOSE:
 *   This class defines which HTTP endpoints are public vs. protected,
 *   disables features that don't apply to a machine-to-machine API server,
 *   and configures a stateless security model.
 *
 * SECURITY MODEL:
 *   ┌─────────────────────────────────────────────────────┐
 *   │  POST /oauth2/token     → PUBLIC (IS the auth step) │
 *   │  GET  /actuator/health  → PUBLIC (K8s readiness)    │
 *   │  GET  /actuator/info    → PUBLIC (informational)    │
 *   │  All other endpoints    → PROTECTED (JWT required)  │
 *   └─────────────────────────────────────────────────────┘
 *
 * WHY CSRF IS DISABLED:
 *   CSRF (Cross-Site Request Forgery) attacks require a browser session — the
 *   attacker tricks a logged-in browser into making a forged request. This
 *   service has no browser sessions (STATELESS) and is called by machine clients
 *   using client secrets, not cookies. CSRF protection would add overhead with
 *   zero security benefit here.
 *
 * WHY SESSIONS ARE STATELESS:
 *   This service issues tokens but does not authenticate the token on subsequent
 *   requests. Each token request is independently authenticated via client_id
 *   and client_secret. HTTP sessions (cookies, JSESSIONID) are unnecessary and
 *   would consume server memory without benefit.
 *
 * WHY HTTP BASIC IS DISABLED:
 *   HTTP Basic auth sends credentials in the Authorization header as
 *   "Basic base64(user:pass)". This service uses form-encoded parameters
 *   per RFC 6749 (grant_type, client_id, client_secret), not HTTP Basic.
 *   Leaving Basic enabled would be confusing and slightly broadens the attack surface.
 *
 * ACCOUNTABILITY NOTE (AI-generated code review):
 *   - The AI draft used deprecated WebSecurityConfigurerAdapter (removed in Spring Boot 3.x).
 *     Manually updated to the SecurityFilterChain bean pattern required by Spring Boot 3.x.
 *   - The AI draft protected /actuator/health, which would block Kubernetes liveness
 *     and readiness probes, causing pods to be killed in a crash loop. Fixed manually.
 */
// @EnableConfigurationProperties: activates IdpProperties as a Spring-managed bean.
// Spring reads all gaas.idp.* properties from application.properties and binds them
// into the IdpProperties record. Without this, IdpProperties cannot be injected.
@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(IdpProperties.class)
public class SecurityConfig {

    /**
     * Defines the security filter chain applied to every HTTP request.
     *
     * Spring Security calls this method once at startup and inserts the
     * returned SecurityFilterChain into the servlet filter pipeline. Every
     * incoming request passes through these filters before reaching any controller.
     *
     * @param http The HttpSecurity builder provided by Spring Security
     * @return     The configured SecurityFilterChain bean
     * @throws Exception if the security configuration is invalid
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Disable CSRF protection — not needed for stateless machine-to-machine APIs.
            // See class Javadoc for reasoning.
            .csrf(AbstractHttpConfigurer::disable)

            // Configure session management: STATELESS means Spring Security never
            // creates or uses an HTTP session (no JSESSIONID cookie, no memory overhead).
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )

            // Configure which URLs require authentication and which are open.
            // Rules are evaluated in order — first matching rule wins.
            .authorizeHttpRequests(authz -> authz

                // ---- PUBLIC ENDPOINTS (no token required) ----

                // /oauth2/token is the M2M token issuance endpoint.
                // Machine clients call this with client_id + client_secret to get a JWT.
                // Protecting it would make it impossible to obtain a token (catch-22).
                .requestMatchers("/oauth2/token").permitAll()

                // /auth/authorize starts the U2M Authorization Code + PKCE flow.
                // Called by user-facing apps before login — no token exists yet.
                // This endpoint redirects the user's browser to Keycloak login.
                .requestMatchers("/auth/authorize").permitAll()

                // /auth/callback receives the authorization code from Keycloak.
                // Keycloak redirects the user's browser here after successful login.
                // No authentication token required — the auth code IS the authentication.
                .requestMatchers("/auth/callback").permitAll()

                // Kubernetes kubelet calls /actuator/health as a liveness and readiness probe.
                // If this endpoint requires a token, the kubelet probe fails and the pod
                // enters a crash loop. Must always be public.
                .requestMatchers("/actuator/health", "/actuator/info").permitAll()

                // ---- PROTECTED ENDPOINTS (Keycloak JWT Bearer token required) ----
                // All other endpoints require a valid JWT Bearer token from Keycloak.
                // Spring Security validates the token against Keycloak's JWKS endpoint
                // (configured in application.properties:
                //   spring.security.oauth2.resourceserver.jwt.jwk-set-uri).
                // This protects any future admin or management endpoints added to the service.
                .anyRequest().authenticated()
            )

            // ---- JWT Resource Server configuration ----
            // Activates JWT Bearer token validation for protected endpoints.
            // When a request arrives with: Authorization: Bearer <token>
            //   1. Spring Security fetches Keycloak's public keys from jwk-set-uri
            //   2. Verifies the JWT signature with the matching RSA/EC key
            //   3. Validates exp, iss, aud claims
            //   4. Sets the authenticated principal in SecurityContext
            //
            // The JWT decoder is auto-configured from application.properties:
            //   spring.security.oauth2.resourceserver.jwt.jwk-set-uri=<keycloak-jwks>
            // No additional configuration needed here — Spring Boot handles discovery.
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> {
                    // JWT decoder auto-configured from spring.security.oauth2.resourceserver.jwt.*
                    // If we needed custom claim validation (e.g., checking a custom `tenant_id`
                    // claim), we could add a JwtDecoder bean here with custom validators.
                })
            )

            // Disable HTTP Basic authentication entirely.
            // This service uses form-encoded OAuth parameters, not Basic auth headers.
            // Keeping Basic enabled would show a browser login popup if someone
            // navigates to the service in a browser, which is confusing.
            .httpBasic(AbstractHttpConfigurer::disable);

        // Build and return the fully configured security filter chain.
        // Spring registers this bean automatically with the servlet container.
        return http.build();
    }
}
