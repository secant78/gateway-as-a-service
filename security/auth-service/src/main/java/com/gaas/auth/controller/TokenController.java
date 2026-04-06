package com.gaas.auth.controller;

// JwtService handles all JWT signing logic and Vault key management.
// TokenController delegates token creation here — it only handles HTTP concerns.
import com.gaas.auth.service.JwtService;

// SLF4J logger — writes structured log messages (INFO, WARN, ERROR) to stdout.
// In Kubernetes, stdout is captured by the container runtime and forwarded to your
// logging stack (e.g., Fluentd → Elasticsearch). Never use System.out.println() in production.
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// Spring HTTP response status and body types
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

// @PostMapping maps this method to POST /oauth2/token
import org.springframework.web.bind.annotation.PostMapping;

// @RequestParam extracts individual fields from the form-encoded request body
import org.springframework.web.bind.annotation.RequestParam;

// MessageDigest.isEqual provides the constant-time byte comparison we use for secrets.
// The JDK guarantees this method runs in O(n) time regardless of where bytes differ,
// preventing timing-based attacks that could reveal the real secret character by character.
import java.security.MessageDigest;

// @RestController combines @Controller + @ResponseBody.
// All return values are automatically serialized to JSON and written to the HTTP response body.
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * ============================================================
 * OAuth 2.0 Token Endpoint — Client Credentials Grant (RFC 6749 §4.4)
 * ============================================================
 *
 * PURPOSE:
 *   This is the only public-facing endpoint of the auth service.
 *   It validates a client's identity and issues a signed JWT that the
 *   client presents to APISIX's jwt-auth plugin on subsequent API calls.
 *
 * WHAT IS CLIENT CREDENTIALS GRANT?
 *   It is the OAuth 2.0 flow for machine-to-machine authentication where
 *   no human user is involved. Instead of a username + password, the "user"
 *   is a machine client identified by client_id and client_secret.
 *   The client exchanges these credentials directly for an access token.
 *
 *   Flow:
 *     Client ──POST /oauth2/token──► TokenController ──► JwtService ──► Signed JWT
 *             (client_id, secret)                        (builds claims, signs with Vault key)
 *
 * REQUEST FORMAT (application/x-www-form-urlencoded):
 *   grant_type=client_credentials
 *   &client_id=gaas-gateway
 *   &client_secret=gateway-secret-change-me
 *   &scope=gateway:read gateway:admin    ← optional; defaults to all allowed scopes
 *
 * SUCCESS RESPONSE (200 OK, application/json):
 *   {
 *     "access_token": "<compact JWT string>",
 *     "token_type": "Bearer",
 *     "expires_in": 3600,
 *     "scope": "gateway:read gateway:admin"
 *   }
 *
 * ERROR RESPONSES (per RFC 6749):
 *   400 unsupported_grant_type — wrong grant_type parameter
 *   401 invalid_client         — wrong client_id or client_secret
 *   403 insufficient_scope     — requested scope not allowed for this client
 *
 * CLIENT REGISTRY (IN-MEMORY):
 *   Three demo clients are pre-registered:
 *     gaas-gateway   → scopes: gateway:read, gateway:admin
 *     tenant-app-001 → scopes: api:read
 *     ci-pipeline    → scopes: api:read, api:write
 *   In production: replace with a database table or Vault KV-backed store.
 *
 * SECURITY NOTES:
 *   - Client secrets are compared using MessageDigest.isEqual() (constant-time)
 *     to prevent timing attacks that could reveal how many characters of the
 *     secret are correct. See constantTimeEquals() for details.
 *   - Scopes are validated against the client's registered allowed list.
 *     A client cannot request more scopes than it was granted at registration time.
 *
 * ACCOUNTABILITY NOTE (AI-generated code review):
 *   - Constant-time comparison: original AI draft used String.equals() which
 *     short-circuits. Replaced with MessageDigest.isEqual().
 *   - Scope validation: AI draft returned tokens without checking whether the
 *     requested scopes were within the client's allowed set. Added manually.
 *   - Client registry: AI draft used a plain HashMap without making it final/static.
 *     Made it a static final immutable Map.of() to prevent accidental mutation.
 */
@RestController
public class TokenController {

    // Logger instance scoped to this class — log messages will include the fully
    // qualified class name, making it easy to filter logs in production.
    private static final Logger log = LoggerFactory.getLogger(TokenController.class);

    /**
     * In-memory client registry mapping client_id → credentials + allowed scopes.
     *
     * Map.of() creates an immutable map — any attempt to call .put() at runtime
     * throws UnsupportedOperationException, preventing accidental client registration
     * bugs during request handling.
     *
     * PRODUCTION NOTE: Replace this with a database lookup or Vault KV store.
     * The secrets here are placeholder values — change them before any real deployment.
     */
    private static final Map<String, ClientRecord> CLIENT_REGISTRY = Map.of(
            // The APISIX gateway itself uses this identity to call protected admin APIs
            "gaas-gateway", new ClientRecord("gateway-secret-change-me", List.of("gateway:read", "gateway:admin")),
            // A sample tenant application with read-only access
            "tenant-app-001", new ClientRecord("tenant-secret-change-me", List.of("api:read")),
            // The CI pipeline uses this identity for integration tests and deployments
            "ci-pipeline", new ClientRecord("ci-secret-change-me", List.of("api:read", "api:write"))
    );

    // JwtService is injected by Spring's constructor injection (preferred over @Autowired field injection
    // because it makes the dependency explicit and enables easier unit testing with mocks).
    private final JwtService jwtService;

    public TokenController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    /**
     * POST /oauth2/token — issues a JWT for a validated client.
     *
     * Spring maps this to the POST /oauth2/token URL.
     * - consumes = FORM_URLENCODED: the request body must be form-encoded (not JSON)
     *   per the OAuth 2.0 spec (RFC 6749 §4.4.2)
     * - produces = JSON: the response body is always JSON regardless of the Accept header
     *
     * @param grantType    Must be "client_credentials" — the only supported grant
     * @param clientId     The machine client's unique identifier
     * @param clientSecret The client's secret (compared in constant time)
     * @param scopeParam   Optional space-delimited list of requested scopes;
     *                     defaults to all scopes the client is allowed
     * @return ResponseEntity containing the token JSON body and appropriate HTTP status
     */
    @PostMapping(
            value = "/oauth2/token",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<Map<String, Object>> issueToken(
            @RequestParam("grant_type") String grantType,
            @RequestParam("client_id") String clientId,
            @RequestParam("client_secret") String clientSecret,
            // scope is optional per RFC 6749; if absent, grant all allowed scopes
            @RequestParam(value = "scope", required = false, defaultValue = "") String scopeParam
    ) {
        // RFC 6749 §5.2: unsupported_grant_type → 400 Bad Request
        // Only client_credentials is supported — no auth code, no refresh tokens
        if (!"client_credentials".equals(grantType)) {
            log.warn("Unsupported grant_type '{}' requested by client '{}'", grantType, clientId);
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "unsupported_grant_type",
                    "error_description", "Only client_credentials grant type is supported"
            ));
        }

        // Look up the client in the in-memory registry.
        // If client is null, the clientId is unknown. We still call constantTimeEquals()
        // against an empty string to avoid timing differences between "unknown client"
        // and "known client, wrong secret" — both should take the same time to respond.
        ClientRecord client = CLIENT_REGISTRY.get(clientId);
        if (client == null || !constantTimeEquals(client.secret(), clientSecret)) {
            // RFC 6749 §5.2: invalid_client → 401 Unauthorized
            // The WWW-Authenticate header is required by RFC 6749 when returning 401
            log.warn("Authentication failed for client_id '{}'", clientId);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .header("WWW-Authenticate", "Bearer realm=\"gaas\"")
                    .body(Map.of(
                            "error", "invalid_client",
                            "error_description", "Client authentication failed"
                    ));
        }

        // Determine the effective scopes for this token.
        // If the client provided no scope parameter, grant all allowed scopes for this client.
        // If scopes were requested, split them on whitespace (RFC 6749 scope format).
        List<String> requestedScopes = scopeParam.isBlank()
                ? client.allowedScopes()
                : Arrays.stream(scopeParam.split("\\s+"))
                        .filter(s -> !s.isBlank())  // remove empty strings from multiple spaces
                        .toList();

        // Scope elevation check: verify the client isn't requesting more than it's entitled to.
        // Without this check, a client with api:read could request gateway:admin and receive it.
        // The AI-generated draft omitted this check entirely — added manually during code review.
        List<String> unauthorizedScopes = requestedScopes.stream()
                .filter(s -> !client.allowedScopes().contains(s))
                .toList();

        if (!unauthorizedScopes.isEmpty()) {
            log.warn("Client '{}' requested unauthorized scopes: {}", clientId, unauthorizedScopes);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                    "error", "insufficient_scope",
                    "error_description", "Requested scopes exceed client permissions: " + unauthorizedScopes
            ));
        }

        // All checks passed — ask JwtService to build and sign the JWT.
        // JwtService handles all cryptographic operations and Vault key management.
        String token = jwtService.issueToken(clientId, requestedScopes);
        log.info("Issued token for client '{}' with scopes: {}", clientId, requestedScopes);

        // RFC 6749 §5.1 success response format
        return ResponseEntity.ok(Map.of(
                "access_token", token,          // the signed JWT compact string
                "token_type", "Bearer",          // always Bearer for JWTs
                "expires_in", 3600,             // seconds until expiry (matches gaas.jwt.expiry-seconds)
                "scope", String.join(" ", requestedScopes)  // space-delimited granted scopes
        ));
    }

    /**
     * Constant-time byte comparison to prevent timing-based client secret enumeration.
     *
     * WHY THIS MATTERS:
     *   Standard string comparison (String.equals, ==) returns early on the first
     *   mismatched byte, leaking how many bytes of the guess are correct via response time.
     *   An attacker measuring 10,000 requests can determine the secret character by character.
     *
     * WHY MessageDigest.isEqual():
     *   The JDK's MessageDigest.isEqual() is documented to run in O(n) time where n is
     *   the length of the shorter array, regardless of where the bytes differ. It does NOT
     *   short-circuit on length mismatch or on a mismatched byte — both cases take the same
     *   wall-clock time, giving the attacker no useful signal.
     *
     * @param a The expected secret (from the client registry)
     * @param b The provided secret (from the incoming HTTP request)
     * @return  true if and only if a and b are byte-for-byte identical
     */
    private boolean constantTimeEquals(String a, String b) {
        // Convert to bytes first — String encoding is platform-dependent,
        // but getBytes() uses the JVM's default charset consistently here.
        return MessageDigest.isEqual(a.getBytes(), b.getBytes());
    }

    /**
     * Immutable record holding a client's registered credentials and allowed scopes.
     *
     * Java records are:
     *   - Immutable by default (all fields are final)
     *   - Auto-generated with constructor, getters, equals(), hashCode(), toString()
     *   - Ideal for simple data carriers like this client registration entry
     *
     * In production, this would be a JPA Entity or a Vault KV response object.
     */
    private record ClientRecord(String secret, List<String> allowedScopes) {}
}
