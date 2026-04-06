package com.gaas.auth.controller;

// IdpProperties: configuration record with Keycloak URLs and callback base URL.
import com.gaas.auth.config.IdpProperties;

// IdpTokenResponse: typed model for Keycloak's token endpoint response.
import com.gaas.auth.model.IdpTokenResponse;

// Thrown when MFA is required but the IdP token's AMR claim lacks an MFA factor.
import com.gaas.auth.model.MfaValidationException;

// IdpTokenService: handles all Keycloak HTTP calls and PKCE utilities.
import com.gaas.auth.service.IdpTokenService;

// JwtService: issues the GaaS-specific JWT (signed with Vault key) after IdP validation.
import com.gaas.auth.service.JwtService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

// @GetMapping maps GET requests to controller methods.
import org.springframework.web.bind.annotation.*;

// RedirectView: returns an HTTP 302 redirect response pointing the browser to a new URL.
// Used to redirect the user's browser to Keycloak's login page.
import org.springframework.web.servlet.view.RedirectView;

import java.time.Instant;
import java.util.*;
// ConcurrentHashMap: thread-safe Map for storing pending auth flow contexts.
// Multiple requests may arrive concurrently (different users starting auth flows simultaneously).
import java.util.concurrent.ConcurrentHashMap;

/**
 * ============================================================
 * Authorization Code + PKCE Controller
 * ============================================================
 *
 * PURPOSE:
 *   Implements the U2M (User-to-Machine) OAuth 2.0 Authorization Code + PKCE flow.
 *   This enables HUMAN users (not machines) to authenticate via the Keycloak IdP
 *   — including Multi-Factor Authentication — and receive a GaaS JWT.
 *
 * WHY AUTHORIZATION CODE + PKCE (not Implicit or Client Credentials)?
 *   - Authorization Code: The actual token is never exposed in the browser URL.
 *     The short-lived "code" in the redirect is exchanged server-side for the real token.
 *   - PKCE (Proof Key for Code Exchange, RFC 7636): Prevents authorization code
 *     interception. Even if an attacker captures the redirect URL, they cannot
 *     exchange the code without knowing the code_verifier (stored server-side).
 *   - Implicit flow: DEPRECATED (RFC 9700). Tokens in URL fragments are logged and cached.
 *   - Password grant: DEPRECATED. Requires the client to handle the user's password.
 *
 * FLOW OVERVIEW:
 *   1. GET /auth/authorize?scope=api:read gateway:admin&redirect_uri=<client-app>
 *      → Auth service generates PKCE code_verifier/challenge
 *      → Auth service generates random state (CSRF prevention)
 *      → Auth service stores {state → AuthFlowContext} in memory (10 min TTL)
 *      → Auth service redirects browser to Keycloak login URL
 *
 *   2. User logs in at Keycloak (username + password + OTP if high-privilege scope)
 *
 *   3. Keycloak redirects browser to: /auth/callback?code=XXXX&state=YYYY
 *
 *   4. GET /auth/callback?code=XXXX&state=YYYY
 *      → Auth service validates state (CSRF check)
 *      → Auth service exchanges code + code_verifier for tokens at Keycloak
 *      → Auth service validates nonce (ID token replay prevention)
 *      → Auth service checks AMR claim (MFA validation for high-privilege scopes)
 *      → Auth service issues GaaS JWT (Vault-signed) with user identity embedded
 *      → Returns 200 {"access_token": "<GaaS JWT>", "token_type": "Bearer", ...}
 *
 * MFA ENFORCEMENT:
 *   If the user requests a high-privilege scope (gateway:admin, api:write) but
 *   Keycloak's token shows only password authentication (amr=["pwd"]), this
 *   controller returns HTTP 403 mfa_required. The client must restart the flow
 *   and the user must complete OTP at Keycloak before receiving the token.
 *
 * MULTI-INSTANCE NOTE:
 *   The pendingFlows map is in-memory — for multiple auth-service replicas, use
 *   Redis or another distributed cache so any replica can handle the callback
 *   regardless of which replica initiated the flow.
 *
 * SECURITY PROPERTIES:
 *   - State parameter prevents CSRF (forged callback attacks)
 *   - Nonce prevents ID token replay attacks
 *   - PKCE prevents authorization code interception
 *   - 10-minute flow TTL limits the window for expired code usage
 *   - All secrets (code_verifier, nonce) are generated with SecureRandom
 */
@RestController
@RequestMapping("/auth")
public class AuthorizationController {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationController.class);

    // ============================================================
    // Pending flow state store (in-memory, single-instance)
    // ============================================================
    // Maps: state (UUID) → AuthFlowContext (code_verifier, nonce, scopes, etc.)
    //
    // WHY ConcurrentHashMap?
    //   Multiple requests arrive concurrently. Multiple users may be in the middle
    //   of a login flow simultaneously. ConcurrentHashMap is thread-safe and lock-free
    //   for reads (similar to AtomicReference in JwtService for the signing key).
    //   Regular HashMap would cause data corruption under concurrent access.
    //
    // TTL: flows expire after FLOW_TTL_SECONDS to prevent memory growth.
    //   purgeExpiredFlows() is called at each /auth/authorize request to clean up.
    //   The callback also checks the TTL after the remove() call.
    private final Map<String, AuthFlowContext> pendingFlows = new ConcurrentHashMap<>();

    // 10 minutes: the authorization code itself expires after 60 seconds (Keycloak default),
    // so the 10-minute window is generous. Any unexpired context after 10 min is abandoned.
    private static final long FLOW_TTL_SECONDS = 600;

    private final IdpTokenService idpTokenService;
    private final JwtService jwtService;
    private final IdpProperties idpProperties;

    public AuthorizationController(
            IdpTokenService idpTokenService,
            JwtService jwtService,
            IdpProperties idpProperties) {
        this.idpTokenService = idpTokenService;
        this.jwtService = jwtService;
        this.idpProperties = idpProperties;
    }

    // ============================================================
    // Step 1: Initiate the Authorization Flow
    // ============================================================

    /**
     * GET /auth/authorize
     *
     * Starts the Authorization Code + PKCE flow for a human user.
     *
     * SECURITY PROPERTIES SET UP HERE:
     *   state:          Random UUID stored server-side, echoed back by Keycloak in callback.
     *                   Verified in /auth/callback to prevent CSRF attacks where an attacker
     *                   tricks the user's browser into submitting a forged callback request.
     *
     *   nonce:          Random UUID embedded in the authorization request.
     *                   Keycloak includes it in the ID token's `nonce` claim.
     *                   Verified in /auth/callback to prevent ID token replay attacks.
     *
     *   code_verifier:  Random 64-char string (48 bytes of SecureRandom). Stored server-side.
     *                   Sent to Keycloak during code exchange to prove the same entity
     *                   that initiated the flow is exchanging the code.
     *
     *   code_challenge: SHA-256(code_verifier), sent in the authorization request.
     *                   Keycloak stores this and verifies it matches the verifier on exchange.
     *
     * @param scope      Space-delimited OAuth scopes to request (e.g., "api:read gateway:admin")
     * @param redirectUri Where to send the final GaaS JWT response (the calling application)
     *                    Note: Keycloak ALWAYS redirects to /auth/callback — this redirectUri
     *                    is where the GaaS JWT is eventually sent by the application layer.
     * @return            HTTP 302 redirect to Keycloak login page
     */
    @GetMapping("/authorize")
    public RedirectView initiateAuthFlow(
            @RequestParam("scope") String scope,
            @RequestParam(value = "redirect_uri", required = false, defaultValue = "") String redirectUri) {

        // Clean up abandoned flows before adding a new one (prevents memory growth)
        purgeExpiredFlows();

        // ---- Generate PKCE parameters ----
        String codeVerifier  = idpTokenService.generateCodeVerifier();   // 64-char random string
        String codeChallenge = idpTokenService.deriveCodeChallenge(codeVerifier); // SHA-256(verifier)

        // ---- Generate anti-CSRF state and nonce ----
        // UUID.randomUUID() uses SecureRandom internally — cryptographically secure.
        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();

        // ---- Parse requested scopes ----
        // Split on whitespace (RFC 6749 scope format: space-separated strings).
        // filter(not blank): handles multiple consecutive spaces gracefully.
        List<String> scopes = Arrays.stream(scope.split("\\s+"))
            .filter(s -> !s.isBlank())
            .toList();

        // ---- Store PKCE context keyed by state ----
        // The callback handler (below) looks up the context by state to retrieve
        // code_verifier, nonce, and requested scopes.
        pendingFlows.put(state, new AuthFlowContext(
            codeVerifier, nonce, redirectUri, scopes, Instant.now()
        ));

        // ---- Build the Keycloak authorization URL ----
        // The user's browser is redirected to this URL to start the Keycloak login flow.
        // Keycloak will prompt for username, password, and OTP (if required for the scopes).
        String callbackUri = idpProperties.callbackBaseUrl() + "/auth/callback";
        String authUrl = idpTokenService.buildAuthorizationUrl(
            state, callbackUri, scopes, codeChallenge, "S256", nonce);

        log.info("Authorization flow initiated: state={}, scopes={}", state, scopes);

        // HTTP 302 redirect: tells the browser to navigate to Keycloak's login page
        return new RedirectView(authUrl);
    }

    // ============================================================
    // Step 2: Handle the Callback from Keycloak
    // ============================================================

    /**
     * GET /auth/callback?code=...&state=...
     *
     * Keycloak redirects the user's browser here after successful authentication.
     * This endpoint completes the Authorization Code + PKCE flow by:
     *   1. Validating the state parameter (CSRF check)
     *   2. Exchanging the code for IdP tokens at Keycloak (with PKCE verification)
     *   3. Validating the nonce (ID token replay prevention)
     *   4. Checking AMR for MFA completion (for high-privilege scopes)
     *   5. Issuing a GaaS JWT (signed with Vault key) containing user identity
     *   6. Returning the GaaS JWT as a standard OAuth 2.0 token response
     *
     * KEYCLOAK ERROR CALLBACKS:
     *   If the user denies consent or login fails, Keycloak redirects with:
     *   /auth/callback?error=access_denied&error_description=...
     *   The error and error_description parameters handle this case.
     *
     * @param code             Authorization code from Keycloak (short-lived, one-use)
     * @param state            CSRF token echoed back from the authorization request
     * @param error            Optional error code if Keycloak reports a failure
     * @param errorDescription Optional human-readable error description from Keycloak
     * @return HTTP 200 with GaaS JWT token response, or 400/401/403 on failure
     */
    @GetMapping("/callback")
    public ResponseEntity<Map<String, Object>> handleCallback(
            @RequestParam(value = "code", required = false) String code,
            @RequestParam("state") String state,
            @RequestParam(value = "error", required = false) String error,
            @RequestParam(value = "error_description", required = false) String errorDescription) {

        // ---- Handle IdP-reported errors (user denied, session expired, etc.) ----
        if (error != null) {
            log.warn("IdP returned error in auth callback: error='{}' description='{}'",
                error, errorDescription);
            return ResponseEntity.badRequest().body(Map.of(
                "error", error,
                "error_description", errorDescription != null
                    ? errorDescription
                    : "Authentication failed at identity provider"
            ));
        }

        // ---- Validate the code is present ----
        if (code == null || code.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "invalid_request",
                "error_description", "Authorization code is missing from callback"
            ));
        }

        // ---- Validate state (CSRF check) ----
        // pendingFlows.remove() atomically retrieves AND removes the context.
        // If state is not found: either CSRF attack, state expired, or replay attempt.
        AuthFlowContext context = pendingFlows.remove(state);
        if (context == null) {
            log.warn("Unknown or expired state '{}' in callback — possible CSRF or replay attack", state);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                "error", "invalid_state",
                "error_description",
                    "State parameter is invalid or the authorization flow has expired (10-min TTL). " +
                    "Please restart the authorization flow."
            ));
        }

        // ---- Check flow TTL ----
        // Extra guard: even after the remove() above, verify the context isn't stale.
        // This is defense-in-depth — purgeExpiredFlows() may not have run yet.
        if (Instant.now().isAfter(context.createdAt().plusSeconds(FLOW_TTL_SECONDS))) {
            log.warn("Expired auth flow context for state '{}' — flow started at {}",
                state, context.createdAt());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                "error", "expired_flow",
                "error_description",
                    "Authorization flow has expired (10-minute limit). Please start over."
            ));
        }

        try {
            // ---- Exchange authorization code for IdP tokens ----
            // The auth-service presents: code, client_id, client_secret, redirect_uri, code_verifier.
            // Keycloak verifies: SHA-256(code_verifier) == code_challenge (from step 1) → PKCE validated.
            String callbackUri = idpProperties.callbackBaseUrl() + "/auth/callback";
            IdpTokenResponse idpTokens = idpTokenService.exchangeAuthorizationCode(
                code, callbackUri, context.codeVerifier());

            // ---- Parse access token claims ----
            // Contains: sub, scope, amr, acr, etc. Used for MFA validation.
            Map<String, Object> accessTokenClaims = idpTokenService.parseJwtClaims(
                idpTokens.accessToken());

            // ---- Parse ID token claims ----
            // Contains: sub, email, preferred_username, nonce, amr.
            // Fall back to access token claims if no ID token (e.g., "openid" scope not granted).
            Map<String, Object> idTokenClaims = idpTokens.idToken() != null
                ? idpTokenService.parseJwtClaims(idpTokens.idToken())
                : accessTokenClaims;

            // ---- Validate nonce (ID token replay prevention) ----
            // The nonce was generated in /auth/authorize and stored in the AuthFlowContext.
            // Keycloak embedded it in the ID token. If they match, this is the correct token
            // for this specific flow initiation — not a replayed token from another flow.
            String receivedNonce = (String) idTokenClaims.get("nonce");
            if (receivedNonce == null || !context.nonce().equals(receivedNonce)) {
                log.warn("Nonce mismatch in callback for state '{}' — possible token replay. " +
                    "Expected={}, Received={}",
                    state, context.nonce(), receivedNonce);
                return ResponseEntity.badRequest().body(Map.of(
                    "error", "invalid_nonce",
                    "error_description", "ID token nonce validation failed — possible replay attack"
                ));
            }

            // ---- MFA validation for high-privilege scopes ----
            // If the user requested gateway:admin or api:write, the `amr` claim in the
            // access token MUST include "otp", "mfa", "hwk", or similar MFA factor.
            // If not, MfaValidationException is thrown (caught below → HTTP 403).
            idpTokenService.validateMfaForHighPrivilegeScopes(
                accessTokenClaims, context.scopes(), true /* isUserFlow */);

            // ---- Extract user identity from ID token ----
            // preferred_username: human-readable name (email prefix or custom username)
            // sub: stable, opaque subject identifier (never changes, even if username changes)
            // email: for embedding in the GaaS JWT as an informational claim
            String idpSubject        = (String) idTokenClaims.getOrDefault("sub", "unknown");
            String preferredUsername = (String) idTokenClaims.getOrDefault(
                "preferred_username", idpSubject);
            String email             = (String) idTokenClaims.getOrDefault("email", "");

            // ---- Issue the GaaS JWT ----
            // This is the token the client actually uses. It's signed with the Vault-managed
            // HMAC key (not Keycloak's RSA key). It contains:
            //   sub: preferredUsername (human-readable subject)
            //   idp_sub: Keycloak's stable sub (for audit trail and logout)
            //   scope: granted scopes
            //   mfa: true (MFA was completed for this flow — validated above)
            //   grant_type: "authorization_code" (informational)
            String gaasToken = jwtService.issueFromIdpClaims(
                preferredUsername,
                context.scopes(),
                "authorization_code",
                idpSubject,
                true,  /* mfaCompleted — validated above by validateMfaForHighPrivilegeScopes */
                email
            );

            log.info("GaaS JWT issued for user '{}' (idp_sub='{}') scopes={} mfa=true",
                preferredUsername, idpSubject, context.scopes());

            // ---- Return the GaaS JWT in standard OAuth 2.0 token response format ----
            return ResponseEntity.ok(Map.of(
                "access_token",  gaasToken,
                "token_type",    "Bearer",
                "expires_in",    3600,
                "scope",         String.join(" ", context.scopes()),
                "idp_subject",   idpSubject   // informational — stable user ID for client apps
            ));

        } catch (MfaValidationException e) {
            // MFA was required (high-privilege scope) but the user only did password auth.
            // The client should restart the flow. Keycloak's Conditional OTP flow should
            // detect this on the next attempt and prompt for OTP.
            log.warn("MFA required for scope '{}' but not completed by user", e.getRequiredScope());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                "error",             "mfa_required",
                "error_description", "Multi-factor authentication is required for the requested scope: "
                    + e.getRequiredScope() + ". Please restart the authorization flow and complete OTP.",
                "mfa_scope",         e.getRequiredScope()
            ));

        } catch (SecurityException e) {
            // Authorization code exchange failed (expired code, invalid PKCE, etc.)
            log.warn("Authorization code exchange failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                "error",             "invalid_grant",
                "error_description", "Authorization code exchange failed. " +
                    "The code may have expired or already been used."
            ));
        }
    }

    // ============================================================
    // Pending flow cleanup
    // ============================================================

    /**
     * Removes auth flow contexts older than FLOW_TTL_SECONDS.
     *
     * Called at the beginning of each /auth/authorize request to prevent
     * unbounded memory growth if users start flows but never complete them.
     *
     * ConcurrentHashMap.entrySet().removeIf() is thread-safe — it does not require
     * external synchronization and will not throw ConcurrentModificationException.
     */
    private void purgeExpiredFlows() {
        Instant cutoff = Instant.now().minusSeconds(FLOW_TTL_SECONDS);
        int sizeBefore = pendingFlows.size();
        pendingFlows.entrySet().removeIf(entry ->
            entry.getValue().createdAt().isBefore(cutoff));
        int removed = sizeBefore - pendingFlows.size();
        if (removed > 0) {
            log.debug("Purged {} expired authorization flow(s) from memory", removed);
        }
    }

    // ============================================================
    // AuthFlowContext record
    // ============================================================

    /**
     * Holds all state for a pending authorization flow.
     *
     * Stored in pendingFlows keyed by state parameter.
     * Retrieved in /auth/callback to:
     *   - Provide code_verifier for PKCE exchange
     *   - Validate nonce against the ID token
     *   - Know which scopes were originally requested
     *   - Enforce the 10-minute TTL via createdAt
     *
     * Java records are immutable — once created, no fields can be changed.
     * This is the correct semantic for flow context: created once, read once.
     */
    private record AuthFlowContext(
        String codeVerifier,   // PKCE: sent to Keycloak during code exchange to prove identity
        String nonce,          // ID token replay prevention: validated against id_token.nonce
        String clientRedirect, // The calling application's final redirect (NOT Keycloak's redirect)
        List<String> scopes,   // Scopes requested in /auth/authorize — used when issuing GaaS JWT
        Instant createdAt      // Timestamp for TTL enforcement in purgeExpiredFlows()
    ) {}
}
