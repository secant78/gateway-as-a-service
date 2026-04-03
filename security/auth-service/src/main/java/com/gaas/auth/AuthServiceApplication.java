package com.gaas.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Entry point for the GaaS Authorization Service.
 *
 * This service mimics a home-built authorization server (similar to Best Buy's
 * internal token service). It issues JWTs via the OAuth 2.0 Client Credentials
 * Grant — the machine-to-machine flow where no user interaction is involved.
 *
 * Architecture:
 *   POST /oauth2/token  → TokenController → JwtService → signed JWT
 *   Signing key stored in Vault at secret/gaas/jwt-signing-key
 *   Key rotation driven by Vault lease TTL; JwtService refreshes automatically
 */
@SpringBootApplication
@EnableScheduling  // Required for the signing key refresh scheduler in JwtService
public class AuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }
}
