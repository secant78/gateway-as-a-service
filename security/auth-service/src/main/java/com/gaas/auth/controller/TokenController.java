package com.gaas.auth.controller;

// IdpTokenService: delegates M2M credential validation to Keycloak.
// Replaced the previous in-memory CLIENT_REGISTRY with real IdP validation.
import com.gaas.auth.service.IdpTokenService;

// IdpTokenResponse: typed response from Keycloak's token endpoint.
// Contains the access_token (from Keycloak), scope, and expiry.
import com.gaas.auth.model.IdpTokenResponse;

// MfaValidationException: thrown by IdpTokenService when high-privilege scopes
// are requested but the IdP token lacks an MFA factor in the `amr` claim.
// For M2M, this exception is not thrown (MFA is not applicable to machines).
import com.gaas.auth.model.MfaValidationException;

// JwtService: issues the GaaS-specific JWT signed with the Vault HMAC key.
// After IdP validation, we re-issue a GaaS JWT so all downstream services
// use a uniformly-formatted, Vault-key-signed token regardless of grant type.
import com.gaas.auth.service.JwtService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * ============================================================
 * OAuth 2.0 Token Endpoint — M2M Client Credentials Grant (RFC 6749 §4.4)
 * ============================================================
 *
 * PURPOSE:
 *   Provides the POST /oauth2/token endpoint for Machine-to-Machine (M2M) token issuance.
 *   Machine clients (APISIX gateway, tenant apps, CI pipeline) authenticate here
 *   using client_id + client_secret to receive a signed JWT.
 *
 * ARCHITECTURE (before vs. after IdP integration):
 *
 *   BEFORE (mock auth service):
 *     Client → POST /oauth2/token
 *     TokenController validates against in-memory CLIENT_REGISTRY (HashMap)
 *     TokenController → JwtService.issueToken() → GaaS JWT
 *
 *   AFTER (IdP-integrated):
 *     Client → POST /oauth2/token
 *     TokenController → IdpTokenService.performClientCredentials()
 *                              ↓ POST to Keycloak token endpoint
 *                     [Keycloak validates client_id + client_secret]
 *                              ↓ IdP access token (if valid)
 *     TokenController → check AMR for high-privilege scopes (M2M: always passes)
 *     TokenController → JwtService.issueFromIdpClaims() → GaaS JWT
 *     Client ← HTTP 200 {"access_token": "<GaaS JWT>"}
 *
 * WHY RE-ISSUE A GAAS JWT INSTEAD OF USING THE KEYCLOAK TOKEN DIRECTLY?
 *   1. Vendor independence: APISIX's jwt-auth plugin uses the Vault-signed HMAC key.
 *      If we switched IdPs, no APISIX configuration would need to change.
 *   2. Claim enrichment: The GaaS JWT can carry GaaS-specific claims (idp_sub, mfa,
 *      grant_type) that Keycloak tokens don't have.
 *   3. Uniform validation: All tokens — regardless of grant type — are validated by
 *      APISIX using the same jwt-auth plugin and ApisixConsumer config.
 *   4. Key rotation: The Vault key is rotated independently of Keycloak's RSA keys.
 *      Auth service picks up the new key every 30 minutes.
 *
 * U2M FLOW:
 *   The Authorization Code + PKCE flow is handled by AuthorizationController.java.
 *   This controller handles ONLY the Client Credentials grant (machine-to-machine).
 *
 * REQUEST FORMAT (application/x-www-form-urlencoded per RFC 6749 §4.4.2):
 *   grant_type=client_credentials
 *   &client_id=gaas-gateway
 *   &client_secret=gateway-secret-change-me
 *   &scope=gateway:read gateway:admin    ← optional
 *
 * SUCCESS RESPONSE (200 OK):
 *   {
 *     "access_token": "<GaaS JWT — Vault HMAC signed>",
 *     "token_type": "Bearer",
 *     "expires_in": 3600,
 *     "scope": "gateway:read gateway:admin"
 *   }
 *
 * ERROR RESPONSES (RFC 6749 §5.2):
 *   400 unsupported_grant_type — grant_type != client_credentials
 *   401 invalid_client         — Keycloak rejected the client credentials
 *   403 mfa_required           — high-privilege scope requested without MFA (M2M: won't happen)
 *   503 idp_unavailable        — Keycloak is unreachable
 */
@RestController
public class TokenController {

    private static final Logger log = LoggerFactory.getLogger(TokenController.class);

    // IdpTokenService: the new integration point with Keycloak.
    // Replaces the in-memory CLIENT_REGISTRY from the mock auth service.
    // All credential validation now happens at the IdP level.
    private final IdpTokenService idpTokenService;

    // JwtService: issues the final GaaS JWT after IdP validation.
    // The JWT is signed with the Vault-managed HMAC-SHA256 key.
    private final JwtService jwtService;

    // Constructor injection: both dependencies are required.
    // Spring detects @RestController and injects these via the constructor.
    public TokenController(IdpTokenService idpTokenService, JwtService jwtService) {
        this.idpTokenService = idpTokenService;
        this.jwtService = jwtService;
    }

    /**
     * POST /oauth2/token — issues a GaaS JWT for a validated M2M client.
     *
     * This endpoint:
     *   1. Validates grant_type is "client_credentials"
     *   2. Delegates credential validation to Keycloak via IdpTokenService
     *   3. Parses the IdP token to extract granted scopes and subject
     *   4. (For M2M: MFA check always passes — machines can't do OTP)
     *   5. Re-issues a GaaS JWT (Vault-signed) with enriched claims
     *
     * @param grantType    Must be "client_credentials" — only supported grant for M2M
     * @param clientId     The machine client's ID (e.g., "gaas-gateway")
     * @param clientSecret The machine client's secret (validated by Keycloak)
     * @param scopeParam   Optional space-delimited requested scopes; Keycloak enforces
     *                     that the client can only request scopes it was granted
     * @return ResponseEntity with GaaS JWT on success, or RFC 6749 error on failure
     */
    @PostMapping(
            value = "/oauth2/token",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<Map<String, Object>> issueToken(
            @RequestParam("grant_type")  String grantType,
            @RequestParam("client_id")   String clientId,
            @RequestParam("client_secret") String clientSecret,
            // scope is optional per RFC 6749; if absent, Keycloak grants
            // the client's configured default scopes
            @RequestParam(value = "scope", required = false, defaultValue = "") String scopeParam
    ) {
        // ---- Validate grant type ----
        // RFC 6749 §5.2: unsupported_grant_type → 400 Bad Request.
        // This endpoint handles ONLY client_credentials.
        // Authorization Code is handled by AuthorizationController (/auth/authorize, /auth/callback).
        if (!"client_credentials".equals(grantType)) {
            log.warn("Unsupported grant_type='{}' from client_id='{}'", grantType, clientId);
            return ResponseEntity.badRequest().body(Map.of(
                "error", "unsupported_grant_type",
                "error_description",
                    "Only client_credentials grant is supported on this endpoint. " +
                    "For user login, use GET /auth/authorize (Authorization Code + PKCE)."
            ));
        }

        // ---- Parse requested scopes ----
        // RFC 6749: scope is space-delimited. An empty scopeParam means "use client defaults".
        // Keycloak will grant the intersection of requested scopes and the client's allowed scopes.
        List<String> requestedScopes = scopeParam.isBlank()
            ? List.of()   // Empty list → Keycloak grants default scopes for this client
            : Arrays.stream(scopeParam.split("\\s+"))
                  .filter(s -> !s.isBlank())
                  .toList();

        try {
            // ---- Delegate credential validation to Keycloak ----
            // IdpTokenService calls POST <keycloak-token-endpoint> with:
            //   grant_type=client_credentials, client_id=..., client_secret=..., scope=...
            // If Keycloak rejects the credentials (wrong secret, unknown client, unauthorized
            // scope), it returns 401 or 400, which IdpTokenService converts to SecurityException.
            log.debug("Authenticating M2M client '{}' via IdP", clientId);
            IdpTokenResponse idpResponse = idpTokenService.performClientCredentials(
                clientId, clientSecret, requestedScopes);

            // ---- Parse IdP token claims ----
            // The IdP access token is trusted (received directly from Keycloak over mTLS).
            // We parse it without signature verification to extract: sub, scope, exp.
            Map<String, Object> idpClaims = idpTokenService.parseJwtClaims(
                idpResponse.accessToken());

            // ---- Extract the ACTUAL granted scopes from Keycloak's token ----
            // Keycloak may grant fewer scopes than requested (if client config restricts them).
            // We use the scopes in the Keycloak token — not the requested scopes — to ensure
            // the GaaS JWT doesn't claim more than what Keycloak authorized.
            String scopeFromIdp = (String) idpClaims.getOrDefault("scope", "");
            List<String> grantedScopes = scopeFromIdp.isBlank()
                ? requestedScopes  // fallback: use requested if Keycloak didn't include scope
                : Arrays.stream(scopeFromIdp.split("\\s+"))
                      .filter(s -> !s.isBlank())
                      .toList();

            // ---- MFA validation (M2M: always passes) ----
            // For M2M clients, MFA (OTP/WebAuthn) is not applicable.
            // IdpTokenService.validateMfaForHighPrivilegeScopes() recognizes isUserFlow=false
            // and logs the high-privilege access for audit purposes without throwing.
            // Defense-in-depth: Keycloak already controls which clients can request which scopes.
            idpTokenService.validateMfaForHighPrivilegeScopes(idpClaims, grantedScopes, false);

            // ---- Extract IdP subject ----
            // For Client Credentials, the `sub` claim in Keycloak's token is typically
            // the service account ID (UUID). We store this as `idp_sub` in the GaaS JWT
            // for audit trail correlation (e.g., linking GaaS JWT to Keycloak audit logs).
            String idpSubject = (String) idpClaims.getOrDefault("sub", clientId);

            // ---- Issue GaaS JWT ----
            // The GaaS JWT is signed with the Vault HMAC-SHA256 key (not Keycloak's RSA key).
            // It carries:
            //   sub:        clientId (human-readable machine client identity)
            //   idp_sub:    Keycloak's stable subject ID (for audit logs)
            //   scope:      the scopes Keycloak actually granted (not just requested)
            //   grant_type: "client_credentials" (informational)
            //   mfa:        false (M2M — MFA not applicable)
            //   email:      null (M2M clients don't have email addresses)
            String gaasToken = jwtService.issueFromIdpClaims(
                clientId,
                grantedScopes,
                "client_credentials",
                idpSubject,
                false,   /* mfaCompleted: false for M2M */
                null     /* email: null for machine clients */
            );

            log.info("GaaS JWT issued for M2M client '{}' (idp_sub='{}') scopes={}",
                clientId, idpSubject, grantedScopes);

            // ---- RFC 6749 §5.1 success response ----
            return ResponseEntity.ok(Map.of(
                "access_token", gaasToken,
                "token_type",   "Bearer",
                "expires_in",   3600,
                "scope",        String.join(" ", grantedScopes)
            ));

        } catch (SecurityException e) {
            // Keycloak rejected the client credentials (wrong secret, unknown client,
            // unauthorized scope, or Keycloak is misconfigured for this client).
            // RFC 6749 §5.2: invalid_client → 401 Unauthorized.
            // WWW-Authenticate header is required by RFC 6749 when returning 401.
            log.warn("IdP rejected M2M credentials for client_id='{}': {}", clientId, e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .header("WWW-Authenticate", "Bearer realm=\"gaas\"")
                .body(Map.of(
                    "error", "invalid_client",
                    "error_description",
                        "Client authentication failed at identity provider. " +
                        "Check client_id, client_secret, and scope configuration in Keycloak."
                ));

        } catch (MfaValidationException e) {
            // This path should not be reached for M2M (MFA check always passes for machines).
            // Included as a defensive catch in case IdpTokenService behavior changes.
            log.error("Unexpected MFA validation failure for M2M client '{}': {}",
                clientId, e.getMessage());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                "error", "mfa_required",
                "error_description", "Unexpected MFA requirement for M2M client: " + e.getMessage()
            ));

        } catch (Exception e) {
            // Catch-all for unexpected failures (Keycloak unreachable, JSON parse errors, etc.)
            // Log at ERROR level because this is unexpected — not a normal auth failure.
            log.error("Unexpected error during M2M token issuance for client '{}': {}",
                clientId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of(
                "error", "idp_unavailable",
                "error_description",
                    "The identity provider is temporarily unavailable. Please retry in a moment."
            ));
        }
    }
}
