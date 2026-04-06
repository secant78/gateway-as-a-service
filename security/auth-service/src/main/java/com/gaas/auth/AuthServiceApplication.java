package com.gaas.auth;

// SpringApplication is the bootstrap class that launches the entire Spring context.
// It scans for @Component, @Service, @Controller, @Configuration beans automatically.
import org.springframework.boot.SpringApplication;

// @SpringBootApplication is a convenience annotation that combines:
//   @Configuration       — marks this class as a source of bean definitions
//   @EnableAutoConfiguration — tells Spring Boot to auto-configure beans based on classpath
//   @ComponentScan       — scans all sub-packages of com.gaas.auth for Spring beans
import org.springframework.boot.autoconfigure.SpringBootApplication;

// @EnableScheduling activates Spring's task scheduling framework.
// Without this annotation, @Scheduled methods (like JwtService.scheduledKeyRotationCheck)
// are silently ignored — the annotation is required, not optional.
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * ============================================================
 * GaaS Authorization Service — Application Entry Point
 * ============================================================
 *
 * PURPOSE:
 *   This is the main class that boots the entire Spring application.
 *   It mimics a home-built authorization server (similar to Best Buy's
 *   internal token service) for the Enterprise Gateway-as-a-Service project.
 *
 * WHAT THIS SERVICE DOES:
 *   Issues signed JWTs to machine clients (services, CI pipelines, tenant apps)
 *   using the OAuth 2.0 Client Credentials Grant — a machine-to-machine flow
 *   where there is no human user involved. Clients authenticate with a
 *   client_id and client_secret to receive a short-lived Bearer token.
 *
 * REQUEST FLOW:
 *   1. Client POSTs to /oauth2/token with client_id + client_secret
 *   2. TokenController validates the client against the in-memory registry
 *   3. TokenController calls JwtService.issueToken()
 *   4. JwtService signs the JWT with the HMAC-SHA256 key loaded from Vault
 *   5. Signed JWT is returned to the client as {"access_token": "..."}
 *   6. Client includes the JWT as "Authorization: Bearer <token>" on API calls
 *   7. APISIX's jwt-auth plugin validates the token before forwarding to tenant services
 *
 * KEY DESIGN DECISIONS:
 *   - Port 8081 (avoids conflicts with APISIX admin 9080, Vault 8200, dashboard 9000)
 *   - Signing key loaded from HashiCorp Vault at startup and rotated every 30 min
 *   - No database — client registry is in-memory (replace with Vault KV in production)
 *   - Stateless — no sessions, no state between requests
 *
 * IMPORTANT ANNOTATIONS:
 *   @SpringBootApplication — enables auto-configuration and component scanning
 *   @EnableScheduling      — required for JwtService's 30-minute key rotation check
 */
@SpringBootApplication
@EnableScheduling
public class AuthServiceApplication {

    /**
     * Standard Java entry point.
     * SpringApplication.run() bootstraps the Spring IoC container,
     * starts the embedded Tomcat server on port 8081, and initializes
     * all beans (including JwtService, which loads the Vault signing key
     * via @PostConstruct before the server accepts any requests).
     *
     * @param args Command-line arguments passed to the JVM (not used directly;
     *             Spring Boot uses them for property overrides, e.g., --server.port=9090)
     */
    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }
}
