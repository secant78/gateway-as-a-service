# ============================================================
# GaaS Auth Service Vault Policy
# ============================================================
# This policy grants the minimum required permissions to the
# gaas-auth-service workload identity.
#
# Apply this policy:
#   vault policy write gaas-auth vault-policy.hcl
#
# Bind it to the auth-service Kubernetes ServiceAccount:
#   vault write auth/kubernetes/role/gaas-auth \
#     bound_service_account_names=auth-service \
#     bound_service_account_namespaces=gaas \
#     policies=gaas-auth \
#     ttl=1h
# ============================================================

# Allow the auth-service to READ the JWT signing key.
# The auth-service reads this at startup and on rotation events.
# It does NOT have permission to update or delete the key — that is
# restricted to the CI pipeline identity (gaas-ci policy below).
path "secret/data/gaas/jwt-signing-key" {
  capabilities = ["read"]
}

# Allow reading the metadata to detect key version changes.
# The auth-service uses this to know when to refresh its cached key
# without polling the data path on every token issuance request.
path "secret/metadata/gaas/jwt-signing-key" {
  capabilities = ["read", "list"]
}

# Allow the auth-service to look up its own token's capabilities.
# Required for the /v1/auth/token/lookup-self call made on startup
# to validate that the Vault connection and permissions are working.
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# ============================================================
# GaaS CI Pipeline Policy (separate policy, applied to CI identity)
# ============================================================
# The CI pipeline rotates the signing key. It needs create/update
# but NOT delete — we keep prior versions for token validation
# during the rotation window (old tokens signed with the prior key
# must remain verifiable until they expire).
#
# Apply: vault policy write gaas-ci vault-policy.hcl
# (In production, split this into a separate gaas-ci-policy.hcl file)

path "secret/data/gaas/jwt-signing-key" {
  capabilities = ["create", "update", "read"]
}

path "secret/metadata/gaas/jwt-signing-key" {
  capabilities = ["list", "read"]
}

# Allow the CI pipeline to enable/configure the KV secrets engine
# and the Kubernetes auth method during bootstrapping.
path "sys/mounts/secret" {
  capabilities = ["read"]
}

path "auth/kubernetes/role/gaas-auth" {
  capabilities = ["create", "update", "read"]
}
