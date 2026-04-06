package com.gaas.auth.model;

// Jackson annotation: maps JSON field names (snake_case) to Java field names (camelCase).
// Without this, Jackson would try to map "access_token" to "accessToken" only if
// DeserializationFeature.ALLOW_CAMELCASE_TO_UNDERSCORE is enabled. @JsonProperty is explicit.
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * ============================================================
 * IdP Token Response Model
 * ============================================================
 *
 * PURPOSE:
 *   Deserializes the JSON response from Keycloak's token endpoint into a typed Java record.
 *   Used by IdpTokenService when performing:
 *     1. Client Credentials grant (M2M) — POST /realms/gaas/protocol/openid-connect/token
 *     2. Authorization Code exchange (U2M) — same endpoint with grant_type=authorization_code
 *
 * KEYCLOAK TOKEN RESPONSE FORMAT (RFC 6749 §5.1):
 *   {
 *     "access_token":  "eyJhbGciOiJS...",  ← JWT for accessing protected resources
 *     "token_type":    "Bearer",            ← always "Bearer" for JWT-based tokens
 *     "expires_in":    3600,                ← seconds until access_token expires
 *     "refresh_token": "eyJhbGci...",       ← longer-lived token to get new access tokens
 *     "id_token":      "eyJhbGci...",       ← OIDC ID token (only present with "openid" scope)
 *     "scope":         "openid api:read",   ← space-separated granted scopes
 *     "session_state": "abc-123"            ← Keycloak session ID (for logout)
 *   }
 *
 * WHY A RECORD?
 *   Records are immutable — the IdP token response should never be modified after
 *   deserialization. Using a record makes this intent explicit and prevents accidental
 *   mutation of token material.
 *
 * USAGE IN IdpTokenService:
 *   IdpTokenResponse response = restTemplate.exchange(
 *       tokenEndpoint, POST, entity, IdpTokenResponse.class).getBody();
 *
 *   String accessToken = response.accessToken();  // Use for M2M: parse claims
 *   String idToken     = response.idToken();      // Use for U2M: validate nonce, get AMR
 *
 * SECURITY NOTE:
 *   The access_token and id_token are trusted ONLY because they come directly from
 *   Keycloak's token endpoint over mTLS (in-cluster). The auth-service parses their
 *   claims without signature verification (trusted source) in IdpTokenService.parseJwtClaims().
 *   APISIX validates signature for user-facing tokens via Keycloak's JWKS endpoint.
 */
public record IdpTokenResponse(

    /**
     * The JWT access token issued by Keycloak.
     * For M2M: contains client identity (sub), scopes, and expiry.
     * For U2M: contains user identity, roles, scopes, and AMR (authentication methods).
     * The auth-service parses claims from this to extract scope and AMR, then re-issues
     * a GaaS-specific JWT signed with the Vault key.
     */
    @JsonProperty("access_token")
    String accessToken,

    /**
     * Always "Bearer" for JWTs. The client presents this as:
     *   Authorization: Bearer <accessToken>
     */
    @JsonProperty("token_type")
    String tokenType,

    /**
     * Seconds until the access_token expires.
     * The auth-service uses this to set the exp claim in the re-issued GaaS JWT.
     * Typically 300-3600 seconds in Keycloak (matches gaas.jwt.expiry-seconds=3600).
     */
    @JsonProperty("expires_in")
    int expiresIn,

    /**
     * Refresh token — longer-lived (hours to days) token that can be exchanged for
     * a new access_token when it expires, without requiring re-authentication.
     * The auth-service currently does NOT issue refresh tokens to clients (stateless design).
     * This field is captured but not propagated.
     */
    @JsonProperty("refresh_token")
    String refreshToken,

    /**
     * OIDC ID Token — present only when the "openid" scope is included in the request.
     * Contains user identity claims:
     *   sub:                 User's stable subject identifier
     *   email:               User's email address
     *   preferred_username:  User's username
     *   nonce:               Anti-replay value (must match what we sent in the auth request)
     *   amr:                 Authentication Methods References (e.g., ["pwd", "otp"])
     *   acr:                 Authentication Context Class Reference (assurance level)
     *
     * For U2M flows, the auth-service MUST verify:
     *   1. nonce matches the one stored during /auth/authorize (replay prevention)
     *   2. amr contains "otp" or "mfa" when high-privilege scopes are requested
     */
    @JsonProperty("id_token")
    String idToken,

    /**
     * Space-separated list of scopes that Keycloak actually granted.
     * May be fewer than requested if the client isn't authorized for all requested scopes.
     * The auth-service embeds this as the `scope` claim in the re-issued GaaS JWT.
     */
    String scope,

    /**
     * Keycloak's internal session state identifier.
     * Can be used to construct logout URLs (front-channel logout) so that logging
     * out of Keycloak also invalidates this session.
     * Not currently used by the auth-service but captured for future logout support.
     */
    @JsonProperty("session_state")
    String sessionState

) {}
