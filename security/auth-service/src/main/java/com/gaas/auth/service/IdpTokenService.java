package com.gaas.auth.service;

// Jackson: deserializes JSON responses from Keycloak into Java maps.
// TypeReference allows deserializing into generic types like Map<String, Object>.
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

// IdpProperties: the @ConfigurationProperties record that holds all gaas.idp.* settings.
// Injected via constructor — provides Keycloak URLs, client credentials, and MFA config.
import com.gaas.auth.config.IdpProperties;

// IdpTokenResponse: typed record that Jackson deserializes Keycloak token responses into.
import com.gaas.auth.model.IdpTokenResponse;

// Thrown when a U2M token has insufficient authentication strength for high-privilege scopes.
import com.gaas.auth.model.MfaValidationException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// Spring HTTP infrastructure:
// HttpEntity wraps headers + body for RestTemplate exchange calls.
// HttpHeaders sets Content-Type, Authorization headers.
// HttpMethod selects POST/GET for the exchange call.
// MediaType.APPLICATION_FORM_URLENCODED is required by OAuth 2.0 token endpoints (RFC 6749 §4.1.3).
// ResponseEntity wraps the HTTP response including status code, headers, and body.
import org.springframework.http.*;

// @Service marks this class as a Spring-managed service bean.
// Spring detects it via @ComponentScan and makes it injectable into controllers.
import org.springframework.stereotype.Service;

// MultiValueMap / LinkedMultiValueMap: Spring's form-encoded parameter holder.
// OAuth 2.0 token requests use application/x-www-form-urlencoded body (not JSON).
// LinkedMultiValueMap allows the same key to have multiple values (standard for form encoding).
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

// RestTemplate: Spring's synchronous HTTP client.
// Used for calling Keycloak's token and introspection endpoints.
// HttpClientErrorException is thrown for 4xx responses (invalid_client, etc.).
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

// UriComponentsBuilder: a fluent builder for constructing URLs with query parameters.
// Used to build the Keycloak authorization URL with PKCE and state parameters.
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

/**
 * ============================================================
 * Identity Provider Token Service
 * ============================================================
 *
 * PURPOSE:
 *   This service is the integration layer between the GaaS Auth Service
 *   and the Keycloak Identity Provider. It handles all HTTP communication
 *   with Keycloak and encapsulates the OAuth 2.0 / OIDC protocol details.
 *
 * RESPONSIBILITIES:
 *   1. M2M Authentication: performs Client Credentials grant at Keycloak to
 *      validate machine client_id + client_secret pairs.
 *
 *   2. U2M Code Exchange: exchanges authorization codes for tokens during
 *      the Authorization Code + PKCE flow.
 *
 *   3. JWT Claim Parsing: decodes and extracts claims from IdP-issued JWTs
 *      (without signature verification — tokens come directly from Keycloak).
 *
 *   4. MFA Validation: checks the `amr` (Authentication Methods References)
 *      claim to ensure MFA was completed for high-privilege scope requests.
 *
 *   5. PKCE Utilities: generates cryptographically secure code_verifier and
 *      derives code_challenge (SHA-256) per RFC 7636.
 *
 *   6. Authorization URL Construction: builds the Keycloak login URL with all
 *      required OAuth 2.0 / PKCE / OIDC parameters.
 *
 * FLOW DIAGRAMS:
 *
 *   M2M (Client Credentials):
 *     Client → TokenController → IdpTokenService.performClientCredentials()
 *                                       ↓ POST /token (client_id, client_secret)
 *                               [Keycloak validates]
 *                                       ↓ IdpTokenResponse
 *                               TokenController → JwtService.issueFromIdpClaims()
 *                                       ↓ GaaS JWT
 *                               Client ← HTTP 200 {"access_token": "..."}
 *
 *   U2M (Authorization Code + PKCE):
 *     User → AuthorizationController.initiateAuthFlow()
 *                   ↓ buildAuthorizationUrl() + generateCodeVerifier()
 *             [Redirect to Keycloak login + MFA]
 *                   ↓ callback with code + state
 *     User → AuthorizationController.handleCallback()
 *                   ↓ IdpTokenService.exchangeAuthorizationCode()
 *             [Keycloak validates code + PKCE]
 *                   ↓ IdpTokenResponse (with id_token)
 *             validateMfaForHighPrivilegeScopes() → checks amr claim
 *                   ↓ JwtService.issueFromIdpClaims()
 *             User ← HTTP 200 {"access_token": "<GaaS JWT>"}
 *
 * SECURITY DESIGN:
 *   - RestTemplate is used synchronously (blocking) for simplicity.
 *     Switch to WebClient (non-blocking) for higher concurrency requirements.
 *   - JWT claims are parsed WITHOUT signature verification because tokens are
 *     received directly from Keycloak's token endpoint over in-cluster mTLS.
 *     Parsing the trusted source's response is safe without re-verifying signatures.
 *   - PKCE code_verifier uses SecureRandom (CSPRNG) — never use Math.random().
 *   - SHA-256 for code_challenge is per RFC 7636 §4.2 (plain method is insecure).
 */
@Service
public class IdpTokenService {

    private static final Logger log = LoggerFactory.getLogger(IdpTokenService.class);

    // SecureRandom: Cryptographically Secure Pseudo-Random Number Generator (CSPRNG).
    // Used for generating PKCE code_verifiers and nonces.
    // Static final: SecureRandom is thread-safe and expensive to instantiate.
    // One instance per JVM is sufficient — the JVM seeds it from the OS entropy pool.
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    // IdpProperties: all Keycloak connection settings (URLs, client credentials, MFA config).
    // Injected via constructor — immutable configuration record.
    private final IdpProperties idpProperties;

    // RestTemplate: Spring's HTTP client for synchronous REST calls.
    // A single instance is reused across all requests — RestTemplate is thread-safe.
    // For production, configure with connection pooling, timeouts, and retry logic:
    //   HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory();
    //   factory.setConnectTimeout(5000); factory.setReadTimeout(10000);
    //   new RestTemplate(factory);
    private final RestTemplate restTemplate;

    // Jackson ObjectMapper: deserializes JSON responses into Java maps/objects.
    // Injected by Spring (Spring Boot auto-configures an ObjectMapper bean with correct settings).
    // Do not create new ObjectMapper() instances — use the shared bean for correct date/null handling.
    private final ObjectMapper objectMapper;

    public IdpTokenService(IdpProperties idpProperties, ObjectMapper objectMapper) {
        this.idpProperties = idpProperties;
        this.objectMapper = objectMapper;
        // Default RestTemplate has no timeouts — in production, configure timeouts explicitly.
        // All communication uses in-cluster mTLS (Istio) so no explicit TLS config needed.
        this.restTemplate = new RestTemplate();
    }

    // ============================================================
    // M2M: Client Credentials Grant
    // ============================================================

    /**
     * Authenticates an M2M (machine-to-machine) client against Keycloak using
     * the OAuth 2.0 Client Credentials Grant (RFC 6749 §4.4).
     *
     * HOW IT WORKS:
     *   The auth-service passes the client's client_id and client_secret directly
     *   to Keycloak's token endpoint. Keycloak validates them against its client registry
     *   and returns an access token if valid.
     *
     * KEYCLOAK CLIENT SETUP (from keycloak-setup.sh):
     *   The client must have "Service Accounts Enabled" = true in Keycloak.
     *   This allows the Client Credentials grant (no user login involved).
     *
     * @param clientId     The M2M client's client_id (e.g., "gaas-gateway")
     * @param clientSecret The M2M client's secret (validated by Keycloak)
     * @param scopes       Requested OAuth scopes (e.g., ["gateway:read", "gateway:admin"])
     * @return             IdpTokenResponse containing the Keycloak access_token
     * @throws SecurityException if Keycloak rejects the credentials (401/400)
     */
    public IdpTokenResponse performClientCredentials(
            String clientId, String clientSecret, List<String> scopes) {

        // Build the OAuth 2.0 token request as application/x-www-form-urlencoded.
        // RFC 6749 §4.4.2 specifies form encoding (NOT JSON) for token requests.
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "client_credentials");
        params.add("client_id", clientId);
        params.add("client_secret", clientSecret);
        // Scopes are optional in Client Credentials — if omitted, Keycloak grants
        // all scopes the client is configured for. If provided, Keycloak validates
        // that the client is allowed to request them.
        if (!scopes.isEmpty()) {
            params.add("scope", String.join(" ", scopes));
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        log.debug("Performing Client Credentials for client_id='{}' scopes={}",
            clientId, scopes);

        try {
            ResponseEntity<IdpTokenResponse> response = restTemplate.exchange(
                idpProperties.tokenEndpoint(),
                HttpMethod.POST,
                new HttpEntity<>(params, headers),
                IdpTokenResponse.class
            );

            IdpTokenResponse tokenResponse = response.getBody();
            if (tokenResponse == null || tokenResponse.accessToken() == null) {
                throw new SecurityException("Keycloak returned empty token response for client: " + clientId);
            }

            log.debug("Keycloak issued token for client_id='{}' granted_scope='{}'",
                clientId, tokenResponse.scope());
            return tokenResponse;

        } catch (HttpClientErrorException.Unauthorized | HttpClientErrorException.BadRequest e) {
            // Keycloak returns 401 for invalid client_id or wrong secret.
            // Keycloak returns 400 for malformed requests (unsupported grant type, etc.).
            // We log at WARN (not ERROR) because this is expected for credential attacks.
            log.warn("Keycloak rejected Client Credentials for client_id='{}': HTTP {} - {}",
                clientId, e.getStatusCode(), e.getResponseBodyAsString());
            throw new SecurityException(
                "IdP rejected client credentials for client '" + clientId + "': " + e.getStatusCode());
        }
    }

    // ============================================================
    // U2M: Authorization Code Exchange
    // ============================================================

    /**
     * Exchanges an OAuth 2.0 authorization code for tokens (Authorization Code Grant,
     * RFC 6749 §4.1.3) with PKCE verification (RFC 7636 §4.5).
     *
     * HOW IT WORKS:
     *   After the user logs in at Keycloak (and completes MFA if required), Keycloak
     *   redirects to /auth/callback with a short-lived authorization code. This method
     *   exchanges that code for actual tokens by calling Keycloak's token endpoint.
     *
     * PKCE VERIFICATION:
     *   The auth-service sends the code_verifier (the original random secret generated
     *   in /auth/authorize). Keycloak verifies: SHA-256(code_verifier) == code_challenge
     *   (the challenge that was sent in the authorization request). This proves that the
     *   entity exchanging the code is the same one that initiated the authorization flow,
     *   preventing authorization code interception attacks.
     *
     * @param code         The authorization code from Keycloak's callback redirect
     * @param redirectUri  Must exactly match the redirect_uri used in the authorization request
     * @param codeVerifier The PKCE code_verifier stored during /auth/authorize
     * @return             IdpTokenResponse containing access_token, id_token, and refresh_token
     * @throws SecurityException if Keycloak rejects the code (expired, already used, etc.)
     */
    public IdpTokenResponse exchangeAuthorizationCode(
            String code, String redirectUri, String codeVerifier) {

        // The auth-service uses its OWN client_id and client_secret when exchanging codes.
        // This identifies the auth-service as the "relying party" doing the exchange.
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("code", code);
        params.add("redirect_uri", redirectUri);
        params.add("client_id", idpProperties.clientId());         // auth-service's own client_id
        params.add("client_secret", idpProperties.clientSecret()); // auth-service's own client_secret
        params.add("code_verifier", codeVerifier);                 // PKCE: Keycloak verifies SHA-256(verifier)==challenge

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        log.debug("Exchanging authorization code at Keycloak token endpoint");

        try {
            ResponseEntity<IdpTokenResponse> response = restTemplate.exchange(
                idpProperties.tokenEndpoint(),
                HttpMethod.POST,
                new HttpEntity<>(params, headers),
                IdpTokenResponse.class
            );

            IdpTokenResponse tokenResponse = response.getBody();
            if (tokenResponse == null || tokenResponse.accessToken() == null) {
                throw new SecurityException("Keycloak returned empty token response during code exchange");
            }

            log.debug("Authorization code exchange successful. ID token present: {}",
                tokenResponse.idToken() != null);
            return tokenResponse;

        } catch (HttpClientErrorException e) {
            // Keycloak returns 400 for expired codes, already-used codes, PKCE failures.
            log.warn("Authorization code exchange failed: HTTP {} - {}",
                e.getStatusCode(), e.getResponseBodyAsString());
            throw new SecurityException(
                "Authorization code exchange failed: " + e.getStatusCode());
        }
    }

    // ============================================================
    // JWT Claim Parsing (without signature verification)
    // ============================================================

    /**
     * Parses claims from a JWT's payload section WITHOUT verifying the signature.
     *
     * WHY NO SIGNATURE VERIFICATION?
     *   This method is only called for tokens received directly from Keycloak's token
     *   endpoint over in-cluster mTLS (Istio-protected). Since the transport is secure
     *   and the source is trusted (we just received it from Keycloak), re-verifying
     *   the HMAC/RSA signature would add latency without security benefit.
     *
     *   Contrast with APISIX's openid-connect plugin, which DOES verify signatures
     *   because it receives tokens from untrusted clients (end users/applications).
     *
     * JWT STRUCTURE:
     *   A compact JWT has three base64url-encoded sections separated by dots:
     *   <header>.<payload>.<signature>
     *   This method decodes only the <payload> section (index 1).
     *
     * @param jwt A compact JWT string (header.payload.signature)
     * @return    Map of claim names to values (String, Number, List, Map)
     * @throws IllegalArgumentException if the JWT is malformed
     */
    public Map<String, Object> parseJwtClaims(String jwt) {
        // Split on "." to get the three JWT sections: header, payload, signature
        String[] parts = jwt.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException(
                "Malformed JWT: expected at least 2 sections (header.payload), got " + parts.length);
        }

        try {
            // JWT uses base64url encoding WITHOUT padding (RFC 7515 §2).
            // Java's Base64.getUrlDecoder() requires padding — add it back.
            String base64Payload = parts[1];
            int paddingNeeded = (4 - base64Payload.length() % 4) % 4;
            base64Payload += "=".repeat(paddingNeeded);

            // Decode base64url → raw UTF-8 JSON bytes
            byte[] payloadBytes = Base64.getUrlDecoder().decode(base64Payload);

            // Parse the JSON into a Map. Jackson maps JSON types to Java types:
            //   JSON string → String
            //   JSON number → Integer or Long or Double
            //   JSON array  → List<Object>
            //   JSON object → Map<String, Object>
            return objectMapper.readValue(payloadBytes,
                new TypeReference<Map<String, Object>>() {});

        } catch (Exception e) {
            throw new IllegalArgumentException(
                "Failed to parse JWT payload: " + e.getMessage(), e);
        }
    }

    // ============================================================
    // MFA Validation
    // ============================================================

    /**
     * Validates that Multi-Factor Authentication (MFA) was completed when
     * high-privilege OAuth scopes are requested.
     *
     * HOW MFA IS DETECTED:
     *   The OpenID Connect specification defines the `amr` (Authentication Methods
     *   References) claim (RFC 8176) as a list of authentication methods used.
     *   Common values in Keycloak:
     *     "pwd"  — Password authentication only (no MFA)
     *     "otp"  — One-Time Password (TOTP via Google Authenticator, Authy)
     *     "totp" — Explicit TOTP label (some Keycloak versions use this)
     *     "mfa"  — Generic MFA completed
     *     "hwk"  — Hardware key (WebAuthn/FIDO2 security key like YubiKey)
     *     "face" — Biometric face recognition (WebAuthn platform authenticator)
     *
     * HIGH-PRIVILEGE SCOPES (from gaas.idp.high-privilege-scopes):
     *   Default: ["gateway:admin", "api:write"]
     *   These scopes grant write access or administrative capabilities.
     *   Reading is low-risk; writing/administrating is high-risk.
     *
     * M2M vs U2M:
     *   M2M (isUserFlow=false): MFA doesn't apply to machine clients. High-privilege
     *   M2M access is controlled by Keycloak's client configuration — only clients
     *   explicitly granted those scopes can request them. We log it for audit trail.
     *
     *   U2M (isUserFlow=true): The user's `amr` claim MUST include a MFA factor.
     *   If it doesn't, MfaValidationException is thrown → HTTP 403 mfa_required.
     *
     * @param idpClaims       Parsed claims from the IdP access token
     * @param requestedScopes The scopes the client is requesting
     * @param isUserFlow      true for Authorization Code (human user), false for M2M
     * @throws MfaValidationException if MFA is required but not completed
     */
    public void validateMfaForHighPrivilegeScopes(
            Map<String, Object> idpClaims,
            List<String> requestedScopes,
            boolean isUserFlow) {

        // Check if any requested scope is in the high-privilege set
        List<String> highPrivilegeScopes = idpProperties.highPrivilegeScopes();
        boolean needsHighPrivilege = requestedScopes.stream()
            .anyMatch(highPrivilegeScopes::contains);

        if (!needsHighPrivilege) {
            // No high-privilege scopes requested — MFA not required for this request
            return;
        }

        if (!isUserFlow) {
            // M2M: Keycloak already enforced that this client can request these scopes.
            // Log for audit trail — M2M high-privilege access should be monitored.
            String clientSub = (String) idpClaims.getOrDefault("sub", "unknown");
            log.info("M2M high-privilege scope access granted for client sub='{}' scopes={}",
                clientSub, requestedScopes);
            return;
        }

        // U2M: Extract the AMR claim from the token.
        // The AMR claim is a JSON array → deserialized as List<Object> by Jackson.
        // We need to handle both List<String> and List<Object> defensively.
        @SuppressWarnings("unchecked")
        List<Object> rawAmr = (List<Object>) idpClaims.getOrDefault("amr", Collections.emptyList());
        List<String> amr = rawAmr.stream()
            .map(Object::toString)
            .toList();

        // Check if the AMR list contains any recognized MFA factor
        boolean mfaCompleted = amr.stream().anyMatch(method ->
            method.equalsIgnoreCase("otp")   ||  // TOTP (Keycloak default label)
            method.equalsIgnoreCase("totp")  ||  // Explicit TOTP label
            method.equalsIgnoreCase("mfa")   ||  // Generic MFA (some IdPs)
            method.equalsIgnoreCase("hwk")   ||  // Hardware WebAuthn key (YubiKey)
            method.equalsIgnoreCase("face")  ||  // Biometric (TouchID/FaceID WebAuthn)
            method.equalsIgnoreCase("swk")       // Software WebAuthn key
        );

        if (!mfaCompleted) {
            // Identify which high-privilege scope triggered this check
            String triggerScope = requestedScopes.stream()
                .filter(highPrivilegeScopes::contains)
                .findFirst()
                .orElse("unknown");

            String userSub = (String) idpClaims.getOrDefault("sub", "unknown");
            log.warn("MFA required for scope '{}' requested by user sub='{}'. " +
                "AMR=[{}] contains no MFA factor. High-privilege scopes require OTP/WebAuthn.",
                triggerScope, userSub, String.join(",", amr));

            throw new MfaValidationException(
                "MFA required for high-privilege scope: " + triggerScope + ". " +
                "Please authenticate with an OTP or hardware key.", triggerScope);
        }

        // MFA verified — log for audit trail
        String userSub = (String) idpClaims.getOrDefault("sub", "unknown");
        log.info("MFA validated for user sub='{}' via method=[{}] for high-privilege scopes {}",
            userSub, String.join(",", amr), requestedScopes);
    }

    // ============================================================
    // Authorization URL Construction (for PKCE flow initiation)
    // ============================================================

    /**
     * Constructs the Keycloak authorization URL that the user's browser is redirected to.
     *
     * The resulting URL includes all required OAuth 2.0 + OIDC + PKCE parameters:
     *   response_type=code             — Authorization Code flow (not Implicit)
     *   client_id                      — The auth-service's Keycloak client ID
     *   redirect_uri                   — Where Keycloak sends the code after login
     *   scope=openid <requested-scopes>— "openid" gets us the ID token with user claims
     *   state                          — Random CSRF token (verified in /auth/callback)
     *   nonce                          — Random ID token replay prevention token
     *   code_challenge                 — SHA-256(code_verifier), proves PKCE was used
     *   code_challenge_method=S256     — Specifies SHA-256 method (plain is insecure)
     *
     * @param state                Opaque CSRF prevention value (UUID generated by controller)
     * @param redirectUri          Where Keycloak redirects after login (auth-service /auth/callback)
     * @param scopes               Requested OAuth scopes (NOT including "openid" — added here)
     * @param codeChallenge        SHA-256 hash of code_verifier, base64url-encoded
     * @param codeChallengeMethod  Always "S256" — do not use "plain" (vulnerable to interception)
     * @param nonce                Random value embedded in ID token (validated in /auth/callback)
     * @return                     Complete Keycloak authorization URL for browser redirect
     */
    public String buildAuthorizationUrl(
            String state, String redirectUri, List<String> scopes,
            String codeChallenge, String codeChallengeMethod, String nonce) {

        // "openid" scope is required to receive an ID token from Keycloak.
        // The ID token contains user identity claims (sub, email, preferred_username)
        // and critically the `amr` claim that we use for MFA validation.
        // We add "openid" here if it's not already in the requested scopes.
        List<String> fullScopes = new ArrayList<>(scopes);
        if (!fullScopes.contains("openid")) {
            fullScopes.add(0, "openid");  // openid must be first (OIDC convention)
        }

        return UriComponentsBuilder
            .fromHttpUrl(idpProperties.authorizationEndpoint())
            .queryParam("response_type", "code")
            .queryParam("client_id", idpProperties.clientId())
            .queryParam("redirect_uri", redirectUri)
            .queryParam("scope", String.join(" ", fullScopes))
            .queryParam("state", state)
            .queryParam("nonce", nonce)
            .queryParam("code_challenge", codeChallenge)
            .queryParam("code_challenge_method", codeChallengeMethod)
            .build(false)  // false: don't encode values again (already correctly formatted)
            .toUriString();
    }

    // ============================================================
    // PKCE Utilities (RFC 7636)
    // ============================================================

    /**
     * Generates a cryptographically secure PKCE code_verifier.
     *
     * RFC 7636 §4.1 specifies:
     *   code_verifier = high-entropy cryptographic random string using [A-Z a-z 0-9 - . _ ~]
     *   Length: 43-128 characters
     *
     * Implementation:
     *   - 48 random bytes from SecureRandom (CSPRNG backed by /dev/urandom on Linux)
     *   - Base64url-encoded WITHOUT padding → 64 characters (within 43-128 limit)
     *   - Base64url alphabet [A-Za-z0-9-_] is a subset of the allowed RFC 7636 characters
     *
     * WHY SecureRandom?
     *   Math.random() and new Random() are NOT cryptographically secure.
     *   An attacker who observes several values can predict future values.
     *   SecureRandom uses OS entropy sources and cannot be predicted.
     *
     * @return 64-character base64url-encoded code_verifier string
     */
    public String generateCodeVerifier() {
        // 48 bytes of cryptographic randomness = 384 bits of entropy.
        // Base64url encoding: every 3 bytes → 4 characters = 48 bytes → 64 characters.
        byte[] bytes = new byte[48];
        SECURE_RANDOM.nextBytes(bytes);
        // withoutPadding(): RFC 7636 requires no padding characters ('=') in the verifier
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Derives the PKCE code_challenge from the code_verifier using S256 method.
     *
     * RFC 7636 §4.2 (S256 method):
     *   code_challenge = BASE64URL(SHA-256(ASCII(code_verifier)))
     *
     * The code_challenge is sent to Keycloak in the authorization request.
     * The code_verifier is sent later in the token exchange request.
     * Keycloak verifies: SHA-256(code_verifier) == code_challenge (stored from auth request).
     *
     * WHY S256 and not "plain"?
     *   The "plain" method sends the code_verifier directly as the code_challenge.
     *   If an attacker intercepts the authorization URL (in a public Wi-Fi network or
     *   via browser history), they learn the code_challenge = code_verifier and can
     *   exchange the code themselves. S256 prevents this because even if the challenge
     *   is intercepted, SHA-256 is one-way — the attacker cannot derive the verifier.
     *
     * @param codeVerifier The random verifier generated by generateCodeVerifier()
     * @return             Base64url-encoded SHA-256 hash of the verifier (no padding)
     */
    public String deriveCodeChallenge(String codeVerifier) {
        try {
            // SHA-256 is specified by RFC 7636. The JDK always provides it — no need
            // to handle the NoSuchAlgorithmException in practice, but the API requires it.
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            // RFC 7636 specifies ASCII encoding of the code_verifier before hashing.
            // Base64url characters are all ASCII, so StandardCharsets.US_ASCII is correct.
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            // Base64url without padding — same convention as the code_verifier itself
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            // This should never happen — every Java SE implementation must include SHA-256
            // (required by the Java Security Standard Algorithm Names spec).
            throw new IllegalStateException(
                "SHA-256 algorithm not available — this should never happen in a standard JRE", e);
        }
    }
}
