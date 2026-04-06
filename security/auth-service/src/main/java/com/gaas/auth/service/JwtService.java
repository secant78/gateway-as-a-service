package com.gaas.auth.service;

// JJWT (Java JWT) library — fluent builder API for creating compact JWT strings.
// Jwts.builder() is the entry point to construct and sign a token.
import io.jsonwebtoken.Jwts;

// Keys.hmacShaKeyFor() converts raw bytes into a type-safe SecretKey object
// for HMAC-SHA algorithms (HS256, HS384, HS512).
import io.jsonwebtoken.security.Keys;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// @Value injects a value from application.properties into a field.
// Example: @Value("${gaas.jwt.issuer}") injects "https://gaas.internal"
import org.springframework.beans.factory.annotation.Value;

// @Scheduled marks a method to be called on a fixed schedule.
// Requires @EnableScheduling on the application class to activate.
import org.springframework.scheduling.annotation.Scheduled;

// @Service marks this class as a Spring service bean — it will be
// auto-detected by @ComponentScan and registered in the IoC container.
// It is functionally equivalent to @Component but communicates intent.
import org.springframework.stereotype.Service;

// VaultTemplate is Spring Vault's main class for interacting with HashiCorp Vault.
// It handles HTTP communication, authentication, and response parsing.
import org.springframework.vault.core.VaultTemplate;

// VaultResponse wraps a raw Vault API response, providing access to
// the data map, metadata (version, created_time), and lease information.
import org.springframework.vault.support.VaultResponse;

// @PostConstruct marks a method to be called after Spring has injected all
// dependencies but before the bean is made available to other beans.
// Used here to load the Vault signing key before the first token request arrives.
import jakarta.annotation.PostConstruct;

// SecretKey is the JCA (Java Cryptography Architecture) interface for symmetric keys.
// Storing the signing key as a SecretKey (not raw bytes) prevents accidental
// serialization, logging, or string conversion of key material.
import javax.crypto.SecretKey;

import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

// AtomicReference provides thread-safe reference updates without locking.
// When the key is rotated, the reference is atomically swapped to the new key —
// in-flight token requests using the old key are not interrupted.
import java.util.concurrent.atomic.AtomicReference;

/**
 * ============================================================
 * JWT Issuance and Vault Key Management Service
 * ============================================================
 *
 * PURPOSE:
 *   This service does two things:
 *     1. Issues signed JWTs (called by TokenController)
 *     2. Manages the HMAC signing key lifecycle via HashiCorp Vault
 *
 * SIGNING KEY LIFECYCLE:
 *
 *   Startup (@PostConstruct):
 *     JwtService contacts Vault at the configured path and reads the base64-
 *     encoded HMAC-SHA256 key. If Vault is unavailable or the key is missing,
 *     the application fails to start (fail-fast: better to crash early than
 *     to silently issue unsigned or incorrectly signed tokens).
 *
 *   Every 30 Minutes (@Scheduled):
 *     JwtService reads the metadata-only endpoint of Vault KV v2 to check
 *     the current key version number. If the version has increased (meaning
 *     the CI pipeline rotated the key), it fetches the new key and atomically
 *     swaps the AtomicReference. No tokens are interrupted during rotation.
 *
 *   CI Pipeline (external rotation trigger):
 *     The GitHub Actions pipeline runs:
 *       vault kv put secret/gaas/jwt-signing-key value=<new-base64-key>
 *     This increments the Vault KV version. The next scheduled check picks it up.
 *
 * JWT STRUCTURE (each issued token contains):
 *   Header:  {"alg": "HS256", "typ": "JWT"}
 *   Payload: {
 *     "jti": "<uuid>",         — unique token ID, prevents replay attacks
 *     "iss": "https://gaas.internal",  — identifies this service as the issuer
 *     "sub": "<client_id>",    — the authenticated machine client
 *     "aud": "gaas-api-gateway", — intended audience (APISIX gateway)
 *     "iat": <unix timestamp>, — issued at
 *     "exp": <unix timestamp>, — expiry (iat + 3600 seconds)
 *     "scope": "gateway:read", — granted OAuth scopes
 *     "grant_type": "client_credentials"
 *   }
 *   Signature: HMAC-SHA256(base64(header) + "." + base64(payload), signingKey)
 *
 * THREAD SAFETY:
 *   Multiple threads can call issueToken() simultaneously (Tomcat thread pool).
 *   The signing key is stored in an AtomicReference<SecretKey>:
 *     - Reads (issueToken) are lock-free and always see a consistent key
 *     - Writes (rotation) atomically swap the reference — no partial updates
 *   The currentKeyVersion field is volatile so the scheduler's write is
 *   immediately visible to all threads reading it.
 *
 * ACCOUNTABILITY NOTE (AI-generated code review):
 *   - AtomicReference: AI generated a regular field + synchronized block.
 *     Replaced with AtomicReference for lock-free reads — better for throughput.
 *   - Key stored as SecretKey: AI stored raw byte[]. Replaced with SecretKey
 *     to prevent accidental logging of key material (SecretKey.toString() = "...").
 *   - Vault version tracking: AI read version from wrong map key. Fixed to use
 *     response.getMetadata().get("version") which is the correct Spring Vault API.
 */
@Service
public class JwtService {

    private static final Logger log = LoggerFactory.getLogger(JwtService.class);

    // VaultTemplate injected by Spring via constructor injection.
    // Spring Vault auto-configures this bean from spring.cloud.vault.* properties.
    private final VaultTemplate vaultTemplate;

    // These four fields are injected from application.properties at startup.
    // @Value expressions resolve property placeholders like ${gaas.jwt.issuer}.

    @Value("${gaas.jwt.issuer}")
    private String issuer;          // e.g. "https://gaas.internal" — goes into JWT `iss` claim

    @Value("${gaas.jwt.expiry-seconds}")
    private long expirySeconds;     // e.g. 3600 — how long the issued token is valid

    @Value("${gaas.jwt.audience}")
    private String audience;        // e.g. "gaas-api-gateway" — the `aud` claim in the JWT

    @Value("${gaas.jwt.signing-key-vault-path}")
    private String vaultKeyPath;    // e.g. "secret/data/gaas/jwt-signing-key"
                                    // Must match the path in vault-policy.hcl exactly

    /**
     * The current HMAC-SHA256 signing key loaded from Vault.
     *
     * AtomicReference is used instead of a regular field + synchronized block because:
     *   - Token issuance (reads) are lock-free — no thread ever blocks waiting for the lock
     *   - Key rotation (write) is a single atomic reference swap
     *   - Java's memory model guarantees that after the swap, all subsequent reads of
     *     signingKey.get() see the new key — no stale cache issues
     */
    private final AtomicReference<SecretKey> signingKey = new AtomicReference<>();

    /**
     * The Vault KV v2 version number of the currently loaded signing key.
     *
     * volatile ensures that when the scheduler thread updates this value after
     * rotation, the updated value is immediately visible to other threads reading
     * it during the next rotation check. Without volatile, the JVM may cache the
     * old value in a CPU register and never see the update.
     *
     * Starts at -1 so any valid Vault version (which starts at 1) is always > -1,
     * causing the first rotation check to correctly compare against the loaded version.
     */
    private volatile int currentKeyVersion = -1;

    public JwtService(VaultTemplate vaultTemplate) {
        this.vaultTemplate = vaultTemplate;
    }

    /**
     * Loads the JWT signing key from Vault on application startup.
     *
     * @PostConstruct ensures this runs after all @Value fields are injected
     * but before the bean is available to TokenController. This means the server
     * will not accept any token requests until the signing key is ready.
     *
     * If Vault is unreachable or the key path doesn't exist, this throws an
     * IllegalStateException, which causes Spring Boot to abort startup and exit
     * with a non-zero code — a deliberate fail-fast behavior.
     */
    @PostConstruct
    public void loadSigningKey() {
        log.info("Loading JWT signing key from Vault path: {}", vaultKeyPath);
        refreshKeyFromVault();
        log.info("JWT signing key loaded successfully (version {})", currentKeyVersion);
    }

    /**
     * Builds and signs a JWT for a successfully authenticated client.
     *
     * This method is called by TokenController after all credential and scope
     * checks have passed. It is intentionally thin — it only assembles JWT
     * claims and delegates signing to the JJWT library.
     *
     * CLAIM DECISIONS:
     *   jti (JWT ID): A random UUID prevents token replay attacks. An attacker who
     *       intercepts a token cannot reuse it after expiry if the receiving service
     *       maintains a short-lived jti cache (APISIX can be configured to do this).
     *   sub (subject): The client_id identifies which machine client owns this token.
     *   aud (audience): "gaas-api-gateway" restricts the token to the APISIX gateway.
     *       A token presented to any other service should be rejected if the receiver
     *       validates the aud claim.
     *   exp (expiry): Set to iat + expirySeconds (default 3600 = 1 hour). Short-lived
     *       tokens limit the damage window if a token is compromised.
     *
     * @param clientId  The authenticated client's ID — becomes the JWT `sub` claim
     * @param scopes    The list of OAuth scopes granted — space-joined into `scope` claim
     * @return          A compact, URL-safe JWT string: base64(header).base64(payload).signature
     */
    public String issueToken(String clientId, List<String> scopes) {
        Instant now = Instant.now();
        Instant expiry = now.plusSeconds(expirySeconds);

        return Jwts.builder()
                .id(UUID.randomUUID().toString())       // jti: unique token ID, prevents replay
                .issuer(issuer)                          // iss: "https://gaas.internal"
                .subject(clientId)                       // sub: e.g. "gaas-gateway"
                .audience().add(audience).and()          // aud: "gaas-api-gateway"
                .issuedAt(Date.from(now))                // iat: current timestamp
                .expiration(Date.from(expiry))           // exp: now + 3600 seconds
                .claim("scope", String.join(" ", scopes))        // space-delimited scope list
                .claim("grant_type", "client_credentials")       // informational — grant type used
                .signWith(signingKey.get())              // HMAC-SHA256 with the Vault-managed key
                .compact();                              // serializes to "xxxxx.yyyyy.zzzzz"
    }

    /**
     * Issues a GaaS JWT enriched with Identity Provider claims.
     *
     * This method is called by BOTH TokenController (M2M Client Credentials) and
     * AuthorizationController (U2M Authorization Code). The resulting JWT is the
     * single unified token format that APISIX's jwt-auth plugin validates.
     *
     * DIFFERENCE vs issueToken():
     *   issueToken() was the original method for the mock auth service — it had no IdP.
     *   issueFromIdpClaims() is the production method that enriches the JWT with:
     *     - idp_sub:    The IdP's stable subject identifier (for audit correlation)
     *     - mfa:        Whether MFA was completed (true for U2M after OTP, false for M2M)
     *     - auth_flow:  Which OAuth grant was used ("client_credentials" or "authorization_code")
     *     - email:      User's email (U2M only; null for M2M machine clients)
     *
     * TOKEN CLAIMS EXPLAINED:
     *   jti         → UUID — prevents token replay. Each token has a unique ID.
     *                 If APISIX is configured with a jti cache, replayed tokens are rejected.
     *   iss         → issuer (from gaas.jwt.issuer) — identifies THIS auth service.
     *   sub         → subjectId (clientId for M2M, preferredUsername for U2M)
     *   aud         → audience ("gaas-api-gateway") — token is only valid at APISIX.
     *   iat         → issued at (current time)
     *   exp         → expiry (current time + gaas.jwt.expiry-seconds, typically 3600s)
     *   scope       → space-joined granted scopes ("gateway:read gateway:admin")
     *   grant_type  → "client_credentials" or "authorization_code"
     *   idp_sub     → Keycloak's `sub` claim — stable even if username changes
     *   mfa         → boolean — whether MFA was completed. Downstream services can
     *                 enforce MFA for specific operations by checking this claim.
     *   email       → user's email (U2M only). Useful for logging and user identification
     *                 in tenant applications without requiring a userinfo lookup.
     *
     * THREAD SAFETY:
     *   This method reads signingKey.get() which is an AtomicReference — lock-free read.
     *   Multiple threads can call this simultaneously without blocking.
     *
     * @param subjectId     JWT sub claim — clientId (M2M) or preferredUsername (U2M)
     * @param scopes        Granted OAuth scopes from Keycloak
     * @param authFlow      OAuth grant type: "client_credentials" or "authorization_code"
     * @param idpSubject    Keycloak's stable subject ID — embedded as `idp_sub` claim
     * @param mfaCompleted  true if user completed OTP/WebAuthn MFA; false for M2M
     * @param email         User's email address; null for M2M machine clients
     * @return              Compact GaaS JWT string (header.payload.signature)
     */
    public String issueFromIdpClaims(
            String subjectId,
            List<String> scopes,
            String authFlow,
            String idpSubject,
            boolean mfaCompleted,
            String email) {

        Instant now    = Instant.now();
        Instant expiry = now.plusSeconds(expirySeconds);

        return Jwts.builder()
            .id(UUID.randomUUID().toString())           // jti: unique token ID, prevents replay
            .issuer(issuer)                              // iss: "https://gaas.internal"
            .subject(subjectId)                          // sub: clientId or preferredUsername
            .audience().add(audience).and()              // aud: "gaas-api-gateway"
            .issuedAt(Date.from(now))                    // iat: current timestamp
            .expiration(Date.from(expiry))               // exp: now + expirySeconds
            .claim("scope", String.join(" ", scopes))    // space-delimited granted scopes
            .claim("grant_type", authFlow)               // which OAuth flow was used
            .claim("idp_sub", idpSubject)                // Keycloak's stable subject ID
            .claim("mfa", mfaCompleted)                  // was MFA completed? boolean
            // Email: include if present, otherwise omit the claim entirely.
            // An empty string in the `email` claim is misleading — null means "not applicable".
            .claim("email", email != null && !email.isBlank() ? email : null)
            .signWith(signingKey.get())                  // HMAC-SHA256 with the Vault-managed key
            .compact();                                  // "xxxxx.yyyyy.zzzzz"
    }

    /**
     * Polls Vault every 30 minutes to detect signing key rotation.
     *
     * HOW IT WORKS:
     *   1. Reads the KV v2 METADATA path (not the data path) — metadata contains the
     *      current_version number without fetching the actual key value. This is more
     *      efficient and avoids unnecessary key material transmission.
     *   2. Compares current_version from Vault against our locally tracked currentKeyVersion.
     *   3. If Vault's version is higher, calls refreshKeyFromVault() to load the new key.
     *
     * fixedDelay = 1800000ms (30 minutes):
     *   The delay starts AFTER the previous execution finishes. If Vault is slow (e.g., 5s),
     *   the next check starts 30 minutes after that, not 30 minutes from the start.
     *   This avoids overlapping executions piling up if Vault becomes unresponsive.
     *
     * ERROR HANDLING:
     *   Exceptions are caught and logged but do NOT fail the scheduled task.
     *   The current signing key remains in use. This is intentional — a brief Vault
     *   outage should not prevent token issuance. Operations should alert on repeated
     *   failures (the key may expire while Vault is unreachable).
     */
    @Scheduled(fixedDelay = 1800000)  // 30 minutes in milliseconds
    public void scheduledKeyRotationCheck() {
        log.debug("Checking Vault for signing key rotation...");
        try {
            // Read the metadata path to get version info without fetching the key itself.
            // KV v2 metadata path is the data path with "/data/" replaced by "/metadata/":
            //   secret/data/gaas/jwt-signing-key → secret/metadata/gaas/jwt-signing-key
            VaultResponse metadata = vaultTemplate.read(
                    vaultKeyPath.replace("/data/", "/metadata/")
            );
            if (metadata == null || metadata.getData() == null) {
                log.warn("Could not read Vault key metadata — skipping rotation check");
                return;
            }

            // The KV v2 metadata response includes "current_version" at the top level
            // of the data map (not nested under "data" like the actual secret value is).
            Object currentVersion = metadata.getData().get("current_version");
            int vaultVersion = currentVersion != null
                    ? Integer.parseInt(currentVersion.toString())
                    : currentKeyVersion;  // if missing, assume no change

            if (vaultVersion > currentKeyVersion) {
                // A newer key version exists in Vault — rotate immediately
                log.info("Signing key rotation detected: version {} → {}", currentKeyVersion, vaultVersion);
                refreshKeyFromVault();
                log.info("Signing key rotated successfully to version {}", currentKeyVersion);
            } else {
                log.debug("Signing key is current (version {})", currentKeyVersion);
            }
        } catch (Exception e) {
            // Log the error but keep the current key — a Vault hiccup should not
            // cause this service to stop issuing tokens. Alert if this persists.
            log.error("Failed to check Vault for key rotation: {}", e.getMessage(), e);
        }
    }

    /**
     * Fetches the signing key from Vault and atomically replaces the current key.
     *
     * VAULT KV v2 RESPONSE STRUCTURE:
     *   When you call vault kv put secret/gaas/jwt-signing-key value=<base64>
     *   and then read it back, the raw API response looks like:
     *     {
     *       "data": {
     *         "data": { "value": "<base64-encoded-key>" },   ← the actual secret
     *         "metadata": { "version": 2, "created_time": "..." }
     *       }
     *     }
     *
     *   Spring Vault's VaultResponse.getData() returns the outer "data" map.
     *   The actual secret is nested under getData().get("data").
     *   The version is in getData().get("metadata") OR in response.getMetadata().
     *
     * ATOMIC KEY SWAP:
     *   signingKey.set(newKey) atomically replaces the reference. Any thread
     *   currently calling signingKey.get() in issueToken() sees either the old
     *   key (if it called get() before set()) or the new key (if after).
     *   There is no window where signingKey.get() returns null.
     *
     * @throws IllegalStateException if Vault is unreachable or the key field is missing
     */
    private void refreshKeyFromVault() {
        // Read the KV v2 data path — this fetches the actual secret value
        VaultResponse response = vaultTemplate.read(vaultKeyPath);
        if (response == null || response.getData() == null) {
            throw new IllegalStateException(
                    "Vault returned null for path: " + vaultKeyPath +
                    ". Verify the path exists and the token has read permissions per vault-policy.hcl."
            );
        }

        Map<String, Object> data = response.getData();

        // KV v2 wraps the secret value under a nested "data" key within the outer data map.
        // If the nested "data" key is absent (KV v1 or malformed response), fall back to
        // treating the top-level map as the data — this handles both KV v1 and v2.
        @SuppressWarnings("unchecked")
        Map<String, Object> kvData = (Map<String, Object>) data.getOrDefault("data", data);

        // The signing key is stored as a base64-encoded string under the "value" field.
        // The CI pipeline writes it as: vault kv put secret/gaas/jwt-signing-key value=<base64>
        String base64Key = (String) kvData.get("value");
        if (base64Key == null || base64Key.isBlank()) {
            throw new IllegalStateException(
                    "Vault signing key at '" + vaultKeyPath + "' is missing the 'value' field. " +
                    "Run: vault kv put secret/gaas/jwt-signing-key value=<base64-encoded-256bit-key>"
            );
        }

        // Decode the base64 string back to raw bytes, then wrap in a SecretKey object.
        // Keys.hmacShaKeyFor() validates that the key is at least 256 bits (32 bytes) for HS256.
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        signingKey.set(Keys.hmacShaKeyFor(keyBytes));

        // Track which Vault version we loaded so the scheduler can detect future rotations.
        // Spring Vault's VaultResponse.getMetadata() is the correct location for KV v2
        // version info — it maps to the "metadata" sub-object in the raw Vault response.
        if (response.getMetadata() != null && response.getMetadata().get("version") != null) {
            currentKeyVersion = Integer.parseInt(response.getMetadata().get("version").toString());
        } else {
            // If metadata is unavailable (Vault v1 or stripped response), just increment.
            // The scheduler will still detect rotation on the next check via Vault metadata.
            currentKeyVersion = currentKeyVersion + 1;
        }
    }
}
