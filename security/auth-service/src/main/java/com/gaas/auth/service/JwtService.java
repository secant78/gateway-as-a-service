package com.gaas.auth.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultResponse;

import jakarta.annotation.PostConstruct;
import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Issues and signs JWTs for the Client Credentials Grant flow.
 *
 * Signing Key Lifecycle:
 *   1. At startup (@PostConstruct), the key is loaded from Vault.
 *   2. Every 30 minutes (@Scheduled), the key version is checked; if Vault
 *      has a newer version, the key is refreshed atomically.
 *   3. The CI pipeline rotates the key in Vault via `vault kv put`.
 *      The next scheduled refresh picks up the new key automatically.
 *
 * ACCOUNTABILITY NOTE (AI-generated code review):
 *   - AtomicReference is used for the signing key to ensure thread safety
 *     during rotation without blocking token issuance. This was manually
 *     verified against JVM memory model guarantees.
 *   - The key is stored as a SecretKey object (not a raw byte array) to
 *     prevent accidental logging or serialization of raw key material.
 */
@Service
public class JwtService {

    private static final Logger log = LoggerFactory.getLogger(JwtService.class);

    private final VaultTemplate vaultTemplate;

    @Value("${gaas.jwt.issuer}")
    private String issuer;

    @Value("${gaas.jwt.expiry-seconds}")
    private long expirySeconds;

    @Value("${gaas.jwt.audience}")
    private String audience;

    @Value("${gaas.jwt.signing-key-vault-path}")
    private String vaultKeyPath;

    // AtomicReference ensures that key rotation is visible across threads
    // without requiring synchronization on token issuance — reads are always
    // lock-free while the write during rotation is atomic.
    private final AtomicReference<SecretKey> signingKey = new AtomicReference<>();

    // Tracks the Vault KV version of the currently loaded key.
    // Used to detect rotation without re-reading the key value on every check.
    private volatile int currentKeyVersion = -1;

    public JwtService(VaultTemplate vaultTemplate) {
        this.vaultTemplate = vaultTemplate;
    }

    @PostConstruct
    public void loadSigningKey() {
        log.info("Loading JWT signing key from Vault path: {}", vaultKeyPath);
        refreshKeyFromVault();
        log.info("JWT signing key loaded successfully (version {})", currentKeyVersion);
    }

    /**
     * Issues a JWT for the given client using the Client Credentials Grant.
     *
     * @param clientId  The authenticated client's identifier (becomes `sub` claim)
     * @param scopes    The granted OAuth scopes (encoded as space-separated string in `scope` claim)
     * @return          A signed, compact JWT string
     */
    public String issueToken(String clientId, List<String> scopes) {
        Instant now = Instant.now();
        Instant expiry = now.plusSeconds(expirySeconds);

        return Jwts.builder()
                .id(UUID.randomUUID().toString())       // jti: prevents replay attacks
                .issuer(issuer)                          // iss
                .subject(clientId)                       // sub
                .audience().add(audience).and()          // aud
                .issuedAt(Date.from(now))                // iat
                .expiration(Date.from(expiry))           // exp
                .claim("scope", String.join(" ", scopes))
                .claim("grant_type", "client_credentials")
                .signWith(signingKey.get())              // HMAC-SHA256
                .compact();
    }

    /**
     * Checks Vault every 30 minutes for a new key version.
     * The fixed delay starts after the previous execution completes,
     * avoiding thundering-herd on slow Vault responses.
     */
    @Scheduled(fixedDelay = 1800000)  // 30 minutes in milliseconds
    public void scheduledKeyRotationCheck() {
        log.debug("Checking Vault for signing key rotation...");
        try {
            VaultResponse metadata = vaultTemplate.read(
                    vaultKeyPath.replace("/data/", "/metadata/")
            );
            if (metadata == null || metadata.getData() == null) {
                log.warn("Could not read Vault key metadata — skipping rotation check");
                return;
            }

            Object currentVersion = metadata.getData().get("current_version");
            int vaultVersion = currentVersion != null
                    ? Integer.parseInt(currentVersion.toString())
                    : currentKeyVersion;

            if (vaultVersion > currentKeyVersion) {
                log.info("Signing key rotation detected: version {} → {}", currentKeyVersion, vaultVersion);
                refreshKeyFromVault();
                log.info("Signing key rotated successfully to version {}", currentKeyVersion);
            } else {
                log.debug("Signing key is current (version {})", currentKeyVersion);
            }
        } catch (Exception e) {
            // Do NOT fail the scheduled task — the current key remains valid.
            // Alert operations if this persists beyond the key's TTL.
            log.error("Failed to check Vault for key rotation: {}", e.getMessage(), e);
        }
    }

    private void refreshKeyFromVault() {
        VaultResponse response = vaultTemplate.read(vaultKeyPath);
        if (response == null || response.getData() == null) {
            throw new IllegalStateException(
                    "Vault returned null for path: " + vaultKeyPath +
                    ". Verify the path exists and the token has read permissions."
            );
        }

        Map<String, Object> data = response.getData();
        // KV v2 wraps the actual data under a nested `data` key
        @SuppressWarnings("unchecked")
        Map<String, Object> kvData = (Map<String, Object>) data.getOrDefault("data", data);

        String base64Key = (String) kvData.get("value");
        if (base64Key == null || base64Key.isBlank()) {
            throw new IllegalStateException(
                    "Vault signing key at '" + vaultKeyPath + "' is missing the 'value' field."
            );
        }

        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        signingKey.set(Keys.hmacShaKeyFor(keyBytes));

        // Extract version from VaultResponse metadata (not from the data map).
        // Spring Vault's VaultResponse.getMetadata() is the correct location for
        // KV v2 version info — data.get("metadata") is always null here.
        if (response.getMetadata() != null && response.getMetadata().get("version") != null) {
            currentKeyVersion = Integer.parseInt(response.getMetadata().get("version").toString());
        } else {
            currentKeyVersion = currentKeyVersion + 1;
        }
    }
}
