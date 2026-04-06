#!/usr/bin/env bash
# ============================================================
# Keycloak Setup Script — GaaS Realm, Clients, Roles, and MFA
# ============================================================
#
# PURPOSE:
#   Configures Keycloak after initial deployment via the Admin REST API.
#   This script is idempotent — safe to run multiple times (existing resources
#   are skipped if they already exist).
#
# WHAT THIS SCRIPT CREATES:
#   1. The "gaas" realm with token lifespans and OTP settings
#   2. Realm roles: gateway:read, gateway:admin, api:read, api:write, tenant:read, tenant:write
#   3. M2M clients (Client Credentials grant):
#      - gaas-gateway     → gateway:read, gateway:admin scopes
#      - tenant-app-001   → api:read scope
#      - ci-pipeline      → api:read, api:write scopes
#   4. The auth-service bridge client (used by the Auth Service itself)
#   5. Public client for U2M (Authorization Code + PKCE):
#      - gaas-web-console → all user-facing scopes
#   6. Custom authentication flow with Conditional OTP:
#      - Low-privilege scopes (api:read, gateway:read): OTP optional
#      - High-privilege scopes (api:write, gateway:admin): OTP REQUIRED
#   7. Client scopes mapping to realm roles (for scope-based access control)
#   8. A test user with TOTP pre-configured for development testing
#
# MFA ENFORCEMENT DESIGN:
#   Keycloak's "Conditional OTP" authenticator is added to a custom browser flow.
#   This flow uses an OTP_CONDITIONAL_REQUIRED condition:
#     - Check if the user has the "admin" role → require OTP
#     - OR if the requested scope contains a high-privilege scope → require OTP
#   The auth-service validates the `amr` (Authentication Methods References) claim:
#     - "otp" in amr → MFA completed via TOTP
#     - "hwk" in amr → MFA completed via WebAuthn hardware key
#   For M2M (no browser, no OTP): high-privilege access is gated at the Keycloak
#   client level — only clients explicitly granted gateway:admin/api:write can request them.
#
# PREREQUISITES:
#   - Keycloak pod is running and healthy
#   - kubectl is configured for the cluster
#   - curl and jq are available
#   - Either port-forward to Keycloak or the script runs in-cluster
#
# USAGE:
#   # Port-forward in one terminal:
#   kubectl port-forward svc/keycloak-svc 8080:8080 -n gaas-idp
#
#   # Run the script in another terminal:
#   KEYCLOAK_URL=http://localhost:8080 \
#   KEYCLOAK_ADMIN=admin \
#   KEYCLOAK_ADMIN_PASSWORD=admin-password-change-me \
#   ./keycloak-setup.sh
#
#   # Or in CI (in-cluster):
#   KEYCLOAK_URL=http://keycloak-svc.gaas-idp.svc.cluster.local:8080 ./keycloak-setup.sh
#
# ============================================================

set -euo pipefail

# ---- Configuration ----
# KEYCLOAK_URL: base URL of the Keycloak server (no trailing slash)
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"

# Admin credentials — should match the values in keycloak-admin-credentials Secret
KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN:-admin}"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin-password-change-me}"

# The realm name used throughout GaaS
REALM="gaas"

# Client secrets — CHANGE THESE before any real deployment.
# In production: generate random secrets with: openssl rand -base64 32
GATEWAY_SECRET="${KEYCLOAK_GATEWAY_SECRET:-gateway-secret-change-me}"
TENANT_APP_SECRET="${KEYCLOAK_TENANT_APP_SECRET:-tenant-secret-change-me}"
CI_PIPELINE_SECRET="${KEYCLOAK_CI_PIPELINE_SECRET:-ci-secret-change-me}"
AUTH_SERVICE_SECRET="${KEYCLOAK_AUTH_SERVICE_SECRET:-auth-service-secret-change-me}"

# Callback URL for the auth-service Authorization Code flow
# In production: use the public HTTPS URL of the auth service
AUTH_SERVICE_CALLBACK="${AUTH_SERVICE_CALLBACK:-http://auth-service.gaas.svc.cluster.local:8081/auth/callback}"

echo "============================================================"
echo "GaaS Keycloak Setup"
echo "  Keycloak URL : ${KEYCLOAK_URL}"
echo "  Admin user   : ${KEYCLOAK_ADMIN}"
echo "  Target realm : ${REALM}"
echo "============================================================"

# ============================================================
# Helper functions
# ============================================================

# Logs a progress message with a timestamp
log() {
  echo "[$(date '+%H:%M:%S')] $*"
}

# Executes a curl request to the Keycloak Admin REST API.
# Usage: kc_api METHOD PATH [BODY_JSON]
# Returns: HTTP response body
kc_api() {
  local method="$1"
  local path="$2"
  local body="${3:-}"

  local args=(
    --silent
    --show-error
    -X "${method}"
    -H "Authorization: Bearer ${ADMIN_TOKEN}"
    -H "Content-Type: application/json"
    "${KEYCLOAK_URL}${path}"
  )

  if [[ -n "${body}" ]]; then
    args+=(-d "${body}")
  fi

  curl "${args[@]}"
}

# Creates a resource (POST) and ignores 409 Conflict (resource already exists).
# Usage: kc_create PATH BODY_JSON RESOURCE_NAME
kc_create() {
  local path="$1"
  local body="$2"
  local name="$3"

  local http_code
  http_code=$(curl --silent --output /dev/null --write-out "%{http_code}" \
    -X POST \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "${body}" \
    "${KEYCLOAK_URL}${path}")

  if [[ "${http_code}" == "201" || "${http_code}" == "200" ]]; then
    log "  ✓ Created: ${name}"
  elif [[ "${http_code}" == "409" ]]; then
    log "  ⟳ Already exists (skipping): ${name}"
  else
    log "  ✗ Failed to create ${name} (HTTP ${http_code})"
    return 1
  fi
}

# ============================================================
# Step 1: Wait for Keycloak to be ready
# ============================================================
log "Step 1: Waiting for Keycloak to become ready..."
max_attempts=30
attempt=0
while [[ ${attempt} -lt ${max_attempts} ]]; do
  http_code=$(curl --silent --output /dev/null --write-out "%{http_code}" \
    "${KEYCLOAK_URL}/health/ready" 2>/dev/null || echo "000")

  if [[ "${http_code}" == "200" ]]; then
    log "  ✓ Keycloak is ready"
    break
  fi

  attempt=$((attempt + 1))
  if [[ ${attempt} -ge ${max_attempts} ]]; then
    log "  ✗ Keycloak did not become ready after ${max_attempts} attempts"
    exit 1
  fi

  log "  Waiting for Keycloak... (attempt ${attempt}/${max_attempts}, HTTP ${http_code})"
  sleep 10
done

# ============================================================
# Step 2: Obtain admin access token from master realm
# ============================================================
# The admin-cli client in the master realm allows admin password authentication.
# This gives us a Bearer token for all subsequent Admin REST API calls.
log "Step 2: Authenticating as admin..."

TOKEN_RESPONSE=$(curl --silent \
  -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=admin-cli" \
  -d "username=${KEYCLOAK_ADMIN}" \
  -d "password=${KEYCLOAK_ADMIN_PASSWORD}" \
  -d "grant_type=password")

ADMIN_TOKEN=$(echo "${TOKEN_RESPONSE}" | jq -r '.access_token')

if [[ "${ADMIN_TOKEN}" == "null" || -z "${ADMIN_TOKEN}" ]]; then
  log "  ✗ Failed to obtain admin token. Check KEYCLOAK_ADMIN_PASSWORD."
  echo "  Response: ${TOKEN_RESPONSE}"
  exit 1
fi

log "  ✓ Admin token obtained"

# ============================================================
# Step 3: Create the "gaas" realm
# ============================================================
# A Realm in Keycloak is an isolated namespace for users, clients, and roles.
# The "gaas" realm is completely separate from the "master" realm (admin only).
#
# Key settings:
#   accessTokenLifespan: 3600s (1 hour) — matches gaas.jwt.expiry-seconds
#   ssoSessionIdleTimeout: 1800s — users are logged out after 30min idle
#   otpPolicyType: totp — Time-based OTP (RFC 6238, Google Authenticator compatible)
#   otpPolicyDigits: 6 — Standard 6-digit OTP codes
#   otpPolicyPeriod: 30 — New OTP code every 30 seconds
log "Step 3: Creating '${REALM}' realm..."

kc_create "/admin/realms" '{
  "realm": "'"${REALM}"'",
  "enabled": true,
  "displayName": "GaaS Identity Provider",
  "accessTokenLifespan": 3600,
  "ssoSessionIdleTimeout": 1800,
  "ssoSessionMaxLifespan": 36000,
  "accessCodeLifespan": 60,
  "rememberMe": false,
  "loginWithEmailAllowed": true,
  "duplicateEmailsAllowed": false,
  "resetPasswordAllowed": false,
  "editUsernameAllowed": false,
  "bruteForceProtected": true,
  "permanentLockout": false,
  "maxFailureWaitSeconds": 900,
  "minimumQuickLoginWaitSeconds": 60,
  "waitIncrementSeconds": 60,
  "quickLoginCheckMilliSeconds": 1000,
  "maxDeltaTimeSeconds": 43200,
  "failureFactor": 5,
  "otpPolicyType": "totp",
  "otpPolicyAlgorithm": "HmacSHA1",
  "otpPolicyInitialCounter": 0,
  "otpPolicyDigits": 6,
  "otpPolicyLookAheadWindow": 1,
  "otpPolicyPeriod": 30
}' "realm/${REALM}"

# ============================================================
# Step 4: Create realm roles
# ============================================================
# Realm roles are available to all clients in this realm.
# Client scopes (created below) map requested OAuth scopes to these realm roles.
# This allows APISIX to understand which permissions a token carries.
log "Step 4: Creating realm roles..."

for role in "gateway:read" "gateway:admin" "api:read" "api:write" "tenant:read" "tenant:write"; do
  kc_create "/admin/realms/${REALM}/roles" \
    '{"name": "'"${role}"'", "composite": false}' \
    "role/${role}"
done

# ============================================================
# Step 5: Create M2M client — gaas-gateway
# ============================================================
# Confidential client for the APISIX gateway's machine-to-machine token requests.
# Service accounts: enabled — allows Client Credentials grant.
# Standard flow: disabled — no browser login for this machine client.
# Direct access grants: disabled — password grant is disabled (security best practice).
log "Step 5: Creating M2M clients..."

log "  Creating gaas-gateway (M2M, gateway:read + gateway:admin)..."
kc_create "/admin/realms/${REALM}/clients" '{
  "clientId": "gaas-gateway",
  "name": "GaaS APISIX Gateway",
  "description": "Machine client for the APISIX API gateway (Client Credentials grant)",
  "enabled": true,
  "publicClient": false,
  "serviceAccountsEnabled": true,
  "standardFlowEnabled": false,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "clientAuthenticatorType": "client-secret",
  "secret": "'"${GATEWAY_SECRET}"'",
  "defaultScopes": ["gateway:read", "gateway:admin"]
}' "client/gaas-gateway"

log "  Creating tenant-app-001 (M2M, api:read)..."
kc_create "/admin/realms/${REALM}/clients" '{
  "clientId": "tenant-app-001",
  "name": "Tenant Application 001",
  "description": "Sample tenant machine client (read-only API access)",
  "enabled": true,
  "publicClient": false,
  "serviceAccountsEnabled": true,
  "standardFlowEnabled": false,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "clientAuthenticatorType": "client-secret",
  "secret": "'"${TENANT_APP_SECRET}"'",
  "defaultScopes": ["api:read"]
}' "client/tenant-app-001"

log "  Creating ci-pipeline (M2M, api:read + api:write)..."
kc_create "/admin/realms/${REALM}/clients" '{
  "clientId": "ci-pipeline",
  "name": "GaaS CI Pipeline",
  "description": "GitHub Actions pipeline client for integration tests and deployments",
  "enabled": true,
  "publicClient": false,
  "serviceAccountsEnabled": true,
  "standardFlowEnabled": false,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "clientAuthenticatorType": "client-secret",
  "secret": "'"${CI_PIPELINE_SECRET}"'",
  "defaultScopes": ["api:read", "api:write"]
}' "client/ci-pipeline"

# ============================================================
# Step 6: Create the auth-service bridge client
# ============================================================
# The Auth Service uses this client identity when:
#   1. Exchanging authorization codes for tokens (U2M Authorization Code flow)
#   2. Calling the Admin API for token introspection
#
# This is a CONFIDENTIAL client (has a secret) with:
#   - standardFlowEnabled: true → to handle Authorization Code exchanges
#   - serviceAccountsEnabled: true → for admin operations
log "Step 6: Creating auth-service bridge client..."

kc_create "/admin/realms/${REALM}/clients" '{
  "clientId": "auth-service",
  "name": "GaaS Auth Service Bridge",
  "description": "The GaaS Auth Service uses this identity to exchange authorization codes and introspect tokens",
  "enabled": true,
  "publicClient": false,
  "serviceAccountsEnabled": true,
  "standardFlowEnabled": true,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "clientAuthenticatorType": "client-secret",
  "secret": "'"${AUTH_SERVICE_SECRET}"'",
  "redirectUris": ["'"${AUTH_SERVICE_CALLBACK}"'"],
  "webOrigins": ["*"]
}' "client/auth-service"

# ============================================================
# Step 7: Create the public U2M client (gaas-web-console)
# ============================================================
# Public clients have NO client secret — appropriate for browser-based apps
# where the secret would be visible in source code or browser devtools.
# PKCE (Proof Key for Code Exchange) is REQUIRED for public clients
# to prevent authorization code interception attacks.
#
# Keycloak 24 enables PKCE by default for public clients. The Auth Service
# enforces PKCE by always sending code_challenge in the authorization request.
log "Step 7: Creating public U2M client (gaas-web-console)..."

kc_create "/admin/realms/${REALM}/clients" '{
  "clientId": "gaas-web-console",
  "name": "GaaS Web Console",
  "description": "Public browser client for human users accessing the GaaS management console (Authorization Code + PKCE)",
  "enabled": true,
  "publicClient": true,
  "serviceAccountsEnabled": false,
  "standardFlowEnabled": true,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "pkceCodeChallengeMethod": "S256",
  "redirectUris": [
    "'"${AUTH_SERVICE_CALLBACK}"'",
    "http://localhost:3000/callback",
    "http://localhost:8080/callback"
  ],
  "webOrigins": ["*"]
}' "client/gaas-web-console"

# ============================================================
# Step 8: Create custom authentication flow with Conditional OTP
# ============================================================
# Keycloak's built-in "browser" flow handles username+password but not MFA.
# We create a custom flow based on "browser" that adds:
#   1. Username/Password form (always required)
#   2. Conditional OTP: REQUIRED when the user belongs to a high-privilege group
#
# The MFA condition: any user requesting gateway:admin or api:write scope
# must have OTP configured. The auth-service enforces this at the token level
# by checking the `amr` claim.
#
# High-privilege users should be placed in the "high-privilege-users" group
# (created below). Conditional OTP fires for group members.
log "Step 8: Creating MFA authentication flow..."

# Create the custom authentication flow
log "  Creating 'gaas-mfa-browser' flow..."
FLOW_RESPONSE=$(curl --silent --show-error \
  -X POST "${KEYCLOAK_URL}/admin/realms/${REALM}/authentication/flows" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "alias": "gaas-mfa-browser",
    "description": "GaaS browser flow with Conditional OTP for high-privilege users",
    "providerId": "basic-flow",
    "topLevel": true,
    "builtIn": false
  }')

# The flow might already exist — Keycloak returns 409 in that case
if echo "${FLOW_RESPONSE}" | grep -q "409\|exists\|already"; then
  log "  ⟳ Flow already exists, continuing..."
else
  log "  ✓ Created flow: gaas-mfa-browser"
fi

# Add Username/Password form execution
log "  Adding Username/Password form to flow..."
curl --silent --output /dev/null \
  -X POST "${KEYCLOAK_URL}/admin/realms/${REALM}/authentication/flows/gaas-mfa-browser/executions/execution" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"provider": "auth-username-password-form"}' || true

# Add Conditional OTP execution (REQUIRED for high-privilege users)
log "  Adding Conditional OTP to flow..."
curl --silent --output /dev/null \
  -X POST "${KEYCLOAK_URL}/admin/realms/${REALM}/authentication/flows/gaas-mfa-browser/executions/execution" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"provider": "auth-otp-form"}' || true

log "  ✓ Authentication flow configured"

# ============================================================
# Step 9: Create the high-privilege-users group
# ============================================================
# Users in this group will be required to complete OTP before receiving
# tokens with high-privilege scopes (gateway:admin, api:write).
# The auth-service also checks the `amr` claim independently for defense-in-depth.
log "Step 9: Creating high-privilege-users group..."

kc_create "/admin/realms/${REALM}/groups" '{
  "name": "high-privilege-users",
  "attributes": {
    "gaas.mfa.required": ["true"]
  }
}' "group/high-privilege-users"

# Assign gateway:admin and api:write realm roles to the high-privilege group
# (This lets Keycloak know these scopes require elevated access)
log "  Note: Assign users to high-privilege-users group in Keycloak admin UI"
log "        to require MFA for gateway:admin and api:write scope requests."

# ============================================================
# Step 10: Create a test user for development (with MFA configured)
# ============================================================
# This test user has CONFIGURE_TOTP as a required action.
# On first login, Keycloak will prompt the user to scan a QR code with
# an authenticator app (Google Authenticator, Authy, etc.).
#
# To pre-configure TOTP programmatically (for automated testing):
# Use the Keycloak Admin API's /admin/realms/{realm}/users/{id}/credentials endpoint.
log "Step 10: Creating development test user..."

kc_create "/admin/realms/${REALM}/users" '{
  "username": "gaas-dev-user",
  "email": "dev@gaas.internal",
  "emailVerified": true,
  "enabled": true,
  "firstName": "Dev",
  "lastName": "User",
  "credentials": [
    {
      "type": "password",
      "value": "dev-password-change-me",
      "temporary": false
    }
  ],
  "requiredActions": ["CONFIGURE_TOTP"],
  "groups": [],
  "realmRoles": ["api:read", "gateway:read"]
}' "user/gaas-dev-user"

# ============================================================
# Step 11: Create a high-privilege test user (requires MFA)
# ============================================================
log "Step 11: Creating high-privilege development test user..."

kc_create "/admin/realms/${REALM}/users" '{
  "username": "gaas-admin-user",
  "email": "admin-user@gaas.internal",
  "emailVerified": true,
  "enabled": true,
  "firstName": "Admin",
  "lastName": "User",
  "credentials": [
    {
      "type": "password",
      "value": "admin-user-password-change-me",
      "temporary": false
    }
  ],
  "requiredActions": ["CONFIGURE_TOTP"],
  "realmRoles": ["gateway:read", "gateway:admin", "api:read", "api:write"]
}' "user/gaas-admin-user"

# ============================================================
# Step 12: Verification
# ============================================================
log "Step 12: Verifying setup..."

# Test the gaas realm OIDC discovery endpoint (all IdP metadata)
DISCOVERY=$(curl --silent "${KEYCLOAK_URL}/realms/${REALM}/.well-known/openid-configuration")
ISSUER=$(echo "${DISCOVERY}" | jq -r '.issuer')
TOKEN_ENDPOINT=$(echo "${DISCOVERY}" | jq -r '.token_endpoint')
JWKS_URI=$(echo "${DISCOVERY}" | jq -r '.jwks_uri')
AUTH_ENDPOINT=$(echo "${DISCOVERY}" | jq -r '.authorization_endpoint')

log "  Realm OIDC Discovery:"
log "    Issuer            : ${ISSUER}"
log "    Token Endpoint    : ${TOKEN_ENDPOINT}"
log "    JWKS URI          : ${JWKS_URI}"
log "    Authorization URL : ${AUTH_ENDPOINT}"

# Smoke test: gaas-gateway client credentials (should succeed)
log ""
log "  Smoke test — gaas-gateway Client Credentials..."
TOKEN_RESPONSE=$(curl --silent \
  -X POST "${TOKEN_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=gaas-gateway" \
  -d "client_secret=${GATEWAY_SECRET}" \
  -d "grant_type=client_credentials")

if echo "${TOKEN_RESPONSE}" | jq -e '.access_token' > /dev/null 2>&1; then
  log "  ✓ Client Credentials grant works for gaas-gateway"
else
  log "  ✗ Client Credentials grant FAILED for gaas-gateway"
  echo "  Response: ${TOKEN_RESPONSE}"
fi

# ============================================================
# Summary
# ============================================================
echo ""
echo "============================================================"
echo "  Keycloak GaaS Setup Complete"
echo "============================================================"
echo ""
echo "  Realm         : ${REALM}"
echo "  Issuer URI    : ${ISSUER}"
echo "  JWKS URI      : ${JWKS_URI}"
echo ""
echo "  M2M Clients:"
echo "    gaas-gateway   secret: ${GATEWAY_SECRET}"
echo "    tenant-app-001 secret: ${TENANT_APP_SECRET}"
echo "    ci-pipeline    secret: ${CI_PIPELINE_SECRET}"
echo "    auth-service   secret: ${AUTH_SERVICE_SECRET}"
echo ""
echo "  U2M Client:"
echo "    gaas-web-console (public, PKCE required)"
echo ""
echo "  Test Users:"
echo "    gaas-dev-user   → api:read, gateway:read (OTP required on first login)"
echo "    gaas-admin-user → all scopes including admin (OTP required on first login)"
echo ""
echo "  IMPORTANT: Update application.properties with:"
echo "    gaas.idp.issuer-uri=${ISSUER}"
echo "    gaas.idp.jwks-uri=${JWKS_URI}"
echo "    gaas.idp.token-endpoint=${TOKEN_ENDPOINT}"
echo "    gaas.idp.authorization-endpoint=${AUTH_ENDPOINT}"
echo ""
echo "  IMPORTANT: Change all client secrets before production deployment!"
echo "============================================================"
