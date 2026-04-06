# ============================================================
# GaaS HashiCorp Vault Policies
# ============================================================
#
# PURPOSE:
#   Vault policies define WHO can do WHAT to WHICH secrets.
#   This file defines two policies used in the GaaS project:
#
#     gaas-auth  → minimum permissions for the auth-service at runtime
#     gaas-ci    → permissions for the CI pipeline to bootstrap/rotate keys
#
# HOW VAULT POLICIES WORK:
#   Every Vault token is associated with one or more policies.
#   Policies use path-based rules to grant capabilities:
#     path "secret/data/foo" { capabilities = ["read"] }
#   means: any token with this policy can call GET /v1/secret/data/foo
#
#   Capabilities map to Vault HTTP methods:
#     "create"  → PUT (only on new paths, no overwrite)
#     "read"    → GET
#     "update"  → POST (update existing)
#     "delete"  → DELETE
#     "list"    → LIST (enumerate keys)
#
# HOW TO APPLY THESE POLICIES:
#   vault policy write gaas-auth  vault-policy.hcl   (for auth-service identity)
#   vault policy write gaas-ci    vault-policy.hcl   (for CI pipeline identity)
#
# HOW TO BIND THE AUTH-SERVICE TO THE gaas-auth POLICY:
#   Using Vault's Kubernetes auth method (production approach):
#     vault write auth/kubernetes/role/gaas-auth \
#       bound_service_account_names=auth-service \
#       bound_service_account_namespaces=gaas \
#       policies=gaas-auth \
#       ttl=1h
#   This means: any pod running as the "auth-service" ServiceAccount in the
#   "gaas" namespace can exchange its K8s token for a Vault token with the
#   gaas-auth policy attached. The Vault token is refreshed automatically.
#
# LEAST PRIVILEGE PRINCIPLE:
#   Each identity gets ONLY the capabilities it needs. The auth-service
#   has NO create/update/delete — it can only read. The CI pipeline has
#   create/update but NOT delete, ensuring old key versions are retained
#   for token validation during the rotation window.
# ============================================================

# ============================================================
# POLICY: gaas-auth (for the auth-service workload)
# ============================================================

# READ the JWT signing key value.
# The auth-service calls this path at startup and after detecting a rotation.
# Returns: { "data": { "value": "<base64-key>" }, "metadata": { "version": N } }
#
# KV v2 data path format: secret/data/<your-path>
# The "/data/" segment is required by the KV v2 API to distinguish data reads
# from metadata reads (which use "/metadata/" instead).
path "secret/data/gaas/jwt-signing-key" {
  capabilities = ["read"]
  # Explicitly NOT granting: create, update, delete
  # The auth-service should never be able to change the signing key
}

# READ the metadata for the JWT signing key.
# Metadata contains the version number, creation time, and deletion time.
# The auth-service's scheduled rotation check reads ONLY metadata (not the key value)
# to detect when the version number has increased, then fetches the actual key separately.
# This is more efficient — avoids transmitting the key value on every 30-minute check.
path "secret/metadata/gaas/jwt-signing-key" {
  capabilities = ["read", "list"]
  # "list" allows enumerating version history (useful for audit, not strictly required)
}

# LOOK UP the auth-service's own token capabilities.
# Spring Vault calls this at startup (/v1/auth/token/lookup-self) to verify
# that the Vault connection works and the token has not expired.
# This is a self-referential call — the token is only checking its own metadata.
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# ============================================================
# POLICY: gaas-ci (for the GitHub Actions CI pipeline)
# ============================================================
# The CI pipeline is responsible for:
#   1. Writing the initial signing key at cluster bootstrap time
#   2. Rotating the signing key on a schedule (create a new version)
#
# The CI pipeline should NEVER delete key versions, because:
#   - Old key versions may still have valid tokens signed with them
#   - Tokens have a 1-hour TTL (gaas.jwt.expiry-seconds=3600)
#   - During the rotation window, APISIX may hold tokens signed with the old key
#   - Deleting the old version would make those tokens unverifiable
#   - Let Vault's version history handle retention; don't delete manually

# CREATE or UPDATE the JWT signing key (rotation).
# "create" allows writing to a new path; "update" allows overwriting an existing version.
# Both are needed because:
#   - First bootstrap: path doesn't exist yet → needs "create"
#   - Key rotation: path already exists → needs "update" (creates a new version in KV v2)
path "secret/data/gaas/jwt-signing-key" {
  capabilities = ["create", "update", "read"]
  # NOT granting "delete" — see explanation above
}

# READ metadata (same as auth-service, but CI also needs it for bootstrapping checks)
path "secret/metadata/gaas/jwt-signing-key" {
  capabilities = ["list", "read"]
}

# CHECK that the KV v2 secrets engine is enabled at the "secret" mount.
# The CI pipeline runs: vault secrets enable -path=secret kv-v2
# Before enabling, it reads sys/mounts/secret to check if it already exists.
# Without this, the CI job would fail trying to re-enable an already-enabled mount.
path "sys/mounts/secret" {
  capabilities = ["read"]
}

# CONFIGURE the Kubernetes auth role that binds the auth-service ServiceAccount
# to the gaas-auth policy. The CI pipeline runs this at bootstrap time:
#   vault write auth/kubernetes/role/gaas-auth ...
# Without this permission, the CI pipeline cannot bind the auth-service identity to Vault.
path "auth/kubernetes/role/gaas-auth" {
  capabilities = ["create", "update", "read"]
}
