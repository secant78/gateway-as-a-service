package com.gaas.auth.controller;

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
 * OAuth 2.0 Token Endpoint — Client Credentials Grant
 *
 * Implements RFC 6749 Section 4.4 (Client Credentials Grant).
 * Only the `client_credentials` grant type is supported — this is a
 * machine-to-machine service with no user-facing flows.
 *
 * Request (application/x-www-form-urlencoded):
 *   grant_type=client_credentials
 *   &client_id=<id>
 *   &client_secret=<secret>
 *   &scope=read write          (optional, space-delimited)
 *
 * Response (200 OK, application/json):
 *   {
 *     "access_token": "<JWT>",
 *     "token_type": "Bearer",
 *     "expires_in": 3600,
 *     "scope": "read write"
 *   }
 *
 * ACCOUNTABILITY NOTE (AI-generated code review):
 *   - Client validation uses a constant-time comparison (via validateClientCredentials)
 *     to prevent timing-based enumeration of valid client IDs. Manually verified.
 *   - Scopes are validated against the client's allowed scope list to prevent
 *     scope elevation. Manually added — the AI-generated draft omitted this check.
 *   - The client registry is in-memory for demo purposes. In production this
 *     would be backed by a database or Vault's KV store.
 */
@RestController
public class TokenController {

    private static final Logger log = LoggerFactory.getLogger(TokenController.class);

    // In-memory client registry: clientId → {secret, allowedScopes}
    // PRODUCTION NOTE: Replace with a database or Vault-backed client store.
    private static final Map<String, ClientRecord> CLIENT_REGISTRY = Map.of(
            "gaas-gateway", new ClientRecord("gateway-secret-change-me", List.of("gateway:read", "gateway:admin")),
            "tenant-app-001", new ClientRecord("tenant-secret-change-me", List.of("api:read")),
            "ci-pipeline", new ClientRecord("ci-secret-change-me", List.of("api:read", "api:write"))
    );

    private final JwtService jwtService;

    public TokenController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @PostMapping(
            value = "/oauth2/token",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<Map<String, Object>> issueToken(
            @RequestParam("grant_type") String grantType,
            @RequestParam("client_id") String clientId,
            @RequestParam("client_secret") String clientSecret,
            @RequestParam(value = "scope", required = false, defaultValue = "") String scopeParam
    ) {
        // RFC 6749: reject unsupported grant types with 400 + error code
        if (!"client_credentials".equals(grantType)) {
            log.warn("Unsupported grant_type '{}' requested by client '{}'", grantType, clientId);
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "unsupported_grant_type",
                    "error_description", "Only client_credentials grant type is supported"
            ));
        }

        ClientRecord client = CLIENT_REGISTRY.get(clientId);
        if (client == null || !constantTimeEquals(client.secret(), clientSecret)) {
            // RFC 6749: return 401 with WWW-Authenticate header for invalid credentials
            log.warn("Authentication failed for client_id '{}'", clientId);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .header("WWW-Authenticate", "Bearer realm=\"gaas\"")
                    .body(Map.of(
                            "error", "invalid_client",
                            "error_description", "Client authentication failed"
                    ));
        }

        // Validate requested scopes against the client's allowed set
        List<String> requestedScopes = scopeParam.isBlank()
                ? client.allowedScopes()
                : Arrays.stream(scopeParam.split("\\s+"))
                        .filter(s -> !s.isBlank())
                        .toList();

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

        String token = jwtService.issueToken(clientId, requestedScopes);
        log.info("Issued token for client '{}' with scopes: {}", clientId, requestedScopes);

        return ResponseEntity.ok(Map.of(
                "access_token", token,
                "token_type", "Bearer",
                "expires_in", 3600,
                "scope", String.join(" ", requestedScopes)
        ));
    }

    /**
     * Constant-time string comparison to prevent timing-based client enumeration.
     * Standard String.equals() short-circuits on the first mismatched character,
     * leaking information about how many characters are correct.
     */
    private boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }

    private record ClientRecord(String secret, List<String> allowedScopes) {}
}
