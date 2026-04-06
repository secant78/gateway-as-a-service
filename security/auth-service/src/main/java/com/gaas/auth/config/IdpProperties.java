package com.gaas.auth.config;

// @ConfigurationProperties binds all application.properties keys under the given prefix
// into this record's fields automatically. No @Value annotations needed per field.
// Spring Boot reads these at startup and validates required fields are present.
import org.springframework.boot.context.properties.ConfigurationProperties;

// @EnableConfigurationProperties activates this binding (added to AuthServiceApplication.java).
// Alternatively, annotating this class with @Component also works but @EnableConfigurationProperties
// is more explicit and works better with Spring Boot's auto-configuration.

// DefaultValue supplies a fallback when the property is not set in application.properties.
// Useful for optional properties like highPrivilegeScopes where we have sensible defaults.
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.util.List;

/**
 * ============================================================
 * Identity Provider (IdP) Configuration Properties
 * ============================================================
 *
 * PURPOSE:
 *   Type-safe binding for all gaas.idp.* properties in application.properties.
 *   Spring Boot reads these properties at startup and populates this record.
 *   If a required property is missing, Spring Boot fails fast with a clear error.
 *
 * WHY A RECORD?
 *   Java records (Java 16+) are immutable data carriers with auto-generated:
 *   - Compact constructor
 *   - Accessor methods (issuerUri(), clientId(), etc.)
 *   - equals(), hashCode(), toString()
 *   Properties are injected once at startup and never change — immutability
 *   is the correct semantic for configuration objects.
 *
 * CONFIGURATION PROPERTIES vs @Value:
 *   @ConfigurationProperties:
 *   + Groups all related properties in one place
 *   + Type-safe (Spring converts strings to List, Integer, etc.)
 *   + Validated by @Validated + Bean Validation annotations
 *   + IDE autocomplete support via spring-configuration-metadata-json
 *
 *   @Value:
 *   - Per-field injection, scattered across classes
 *   - No group-level type safety
 *   - Harder to test (requires Spring context)
 *
 * PROPERTIES (all under prefix "gaas.idp"):
 *   issuerUri                Keycloak realm URL. Forms the base for OIDC discovery.
 *                            Example: http://keycloak-svc.gaas-idp.svc.cluster.local:8080/realms/gaas
 *
 *   clientId                 The auth-service's own client ID in Keycloak.
 *                            Used when exchanging authorization codes (U2M flow).
 *
 *   clientSecret             The auth-service's client secret. Inject from Vault at runtime.
 *                            Never hardcode in application.properties in production.
 *
 *   tokenEndpoint            Full URL of Keycloak's token endpoint.
 *                            Used for Client Credentials and code exchange calls.
 *
 *   introspectEndpoint       Token introspection endpoint. Used to validate opaque tokens.
 *
 *   jwksUri                  URL serving Keycloak's public signing keys (JSON Web Key Set).
 *                            APISIX's openid-connect plugin fetches these to validate user JWTs.
 *
 *   authorizationEndpoint    URL of Keycloak's authorization endpoint.
 *                            The auth-service redirects users here to start the login flow.
 *
 *   callbackBaseUrl          The public base URL of THIS auth-service.
 *                            Keycloak redirects back to callbackBaseUrl + "/auth/callback"
 *                            after a successful login. Must match Keycloak's allowed redirect URIs.
 *
 *   highPrivilegeScopes      Scopes that require MFA (Multi-Factor Authentication).
 *                            If a user requests any of these scopes, the AMR claim in
 *                            the IdP token MUST contain "otp", "mfa", "totp", or "hwk".
 *                            Default: gateway:admin and api:write.
 */
@ConfigurationProperties(prefix = "gaas.idp")
public record IdpProperties(

    // ---- IdP identity ----

    /**
     * Keycloak realm issuer URI.
     * All tokens issued by this realm will have this value as the `iss` (issuer) claim.
     * OIDC Discovery: appending /.well-known/openid-configuration gives the full metadata.
     * Format: <keycloak-url>/realms/<realm-name>
     */
    String issuerUri,

    // ---- Auth service's own Keycloak identity ----

    /**
     * The auth-service's client_id in Keycloak.
     * This is the client that the auth-service uses when it exchanges authorization codes
     * (the auth-service presents itself as this client to Keycloak's token endpoint).
     */
    String clientId,

    /**
     * The auth-service's client_secret in Keycloak.
     * Inject at runtime via: GAAS_IDP_CLIENT_SECRET environment variable
     * or from Vault: gaas.idp.client-secret=${KEYCLOAK_AUTH_SERVICE_SECRET}
     * NEVER hardcode in application.properties or commit to git.
     */
    String clientSecret,

    // ---- Keycloak endpoints ----

    /**
     * Full URL of Keycloak's token endpoint.
     * Used to:
     *   1. Validate M2M client credentials (Client Credentials grant)
     *   2. Exchange authorization codes for tokens (Authorization Code grant)
     * Format: <issuerUri>/protocol/openid-connect/token
     */
    String tokenEndpoint,

    /**
     * Token introspection endpoint.
     * Used to check if an opaque or JWT token is still valid (not revoked, not expired).
     * Returns the token's claims if valid, or {"active": false} if not.
     * Format: <issuerUri>/protocol/openid-connect/token/introspect
     */
    String introspectEndpoint,

    /**
     * JSON Web Key Set URI — Keycloak's public signing keys.
     * APISIX's openid-connect plugin fetches this URL to get the RSA/EC public keys
     * it uses to verify the signature of user-flow JWTs issued by Keycloak.
     * Format: <issuerUri>/protocol/openid-connect/certs
     */
    String jwksUri,

    /**
     * Keycloak's authorization endpoint — where users are redirected to log in.
     * The auth-service redirects users here with: response_type=code, PKCE params,
     * state (CSRF token), nonce (replay prevention), and requested scopes.
     * Format: <issuerUri>/protocol/openid-connect/auth
     */
    String authorizationEndpoint,

    /**
     * The public base URL of this auth-service (for constructing the callback URL).
     * Keycloak redirects back to: callbackBaseUrl + "/auth/callback"
     * MUST be listed in Keycloak's client "Valid Redirect URIs" for auth-service.
     * Example: https://auth.gaas.internal (production) or http://localhost:8081 (local dev)
     */
    String callbackBaseUrl,

    // ---- MFA enforcement ----

    /**
     * OAuth scopes that require MFA (Multi-Factor Authentication) before issuance.
     * When a user requests any of these scopes via the Authorization Code flow,
     * the auth-service checks the `amr` claim in the IdP token to verify MFA was done.
     *
     * For M2M (Client Credentials): MFA is not applicable (machines can't do OTP).
     * High-privilege M2M access is controlled at the Keycloak client level —
     * only clients explicitly configured with these scopes can request them.
     *
     * @DefaultValue: if gaas.idp.high-privilege-scopes is not set in application.properties,
     * defaults to ["gateway:admin", "api:write"]. The comma-separated string is automatically
     * split into a List<String> by Spring Boot's configuration binding.
     */
    @DefaultValue("gateway:admin,api:write")
    List<String> highPrivilegeScopes

) {}
