# Enterprise Gateway-as-a-Service (GaaS)

A production-grade reference architecture demonstrating a multi-tenant API gateway platform with Zero Trust security, automated CI/CD, and operational tooling.

---

## Architecture Overview

```
Internet
    │
    ▼
┌─────────────────────────┐
│  AWS ALB (Terraform)    │  ← TLS termination, HTTP→HTTPS redirect
└──────────┬──────────────┘
           │ HTTPS → NodePort 30080
           ▼
┌──────────────────────────────────────────────────────────┐
│  Kubernetes Cluster (Minikube / EKS)                     │
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Istio Service Mesh (STRICT mTLS everywhere)     │    │
│  │                                                  │    │
│  │  ┌──────────────┐    ┌──────────────────────┐   │    │
│  │  │   APISIX     │───▶│  Tenant App (Helm)   │   │    │
│  │  │  Gateway     │    │  + RBAC + Quota       │   │    │
│  │  └──────┬───────┘    └──────────────────────┘   │    │
│  │         │ JWT validation                         │    │
│  │         ▼                                        │    │
│  │  ┌──────────────┐    ┌──────────────────────┐   │    │
│  │  │  Auth Service│◀───│  HashiCorp Vault      │   │    │
│  │  │  (Spring     │    │  (JWT signing keys)   │   │    │
│  │  │   Boot/JWT)  │    └──────────────────────┘   │    │
│  │  └──────────────┘                                │    │
│  └─────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────┘

CI/CD: GitHub Actions (05-gaas-pipeline.yml)
  security-scan → build → lint → terraform-plan → deploy-staging
  → canary-deploy (Istio traffic shifting) → terraform-apply
```

---

## Project Structure

```
gaas/
├── infrastructure/
│   ├── namespace.yaml              # gaas + gaas-vault namespaces with istio-injection label
│   ├── peer-authentication.yaml    # STRICT mTLS for both namespaces (Zero Trust)
│   └── istio-install.sh           # Minikube bootstrap script
│
├── gateway/
│   ├── apisix-values.yaml          # APISIX Helm values (NodePort, resource limits)
│   ├── apisix-dashboard-config.yaml # Dashboard deployment + ConfigMap
│   └── charts/
│       └── tenant-app/             # Standardized tenant Helm chart
│           ├── Chart.yaml
│           ├── values.yaml
│           └── templates/
│               ├── deployment.yaml
│               ├── service.yaml    # ClusterIP + ApisixRoute (JWT auth plugin)
│               ├── serviceaccount.yaml
│               ├── role.yaml       # Namespace-scoped only — no ClusterRole
│               ├── rolebinding.yaml
│               └── resourcequota.yaml
│
├── security/
│   ├── auth-service/               # Spring Boot OAuth 2.0 mock token server
│   │   ├── Dockerfile              # Multi-stage, non-root runtime
│   │   ├── pom.xml                 # Spring Boot 3.2 + JJWT 0.12 + Spring Vault
│   │   └── src/main/java/com/gaas/auth/
│   │       ├── AuthServiceApplication.java
│   │       ├── controller/TokenController.java  # POST /oauth2/token
│   │       ├── service/JwtService.java          # Vault-backed key rotation
│   │       └── config/SecurityConfig.java
│   └── vault/
│       ├── vault-deployment.yaml   # Vault dev-mode K8s Deployment + Service
│       └── vault-policy.hcl        # Least-privilege policy for auth-service + CI
│
├── terraform/
│   ├── main.tf                     # ALB + Target Group + Security Group
│   ├── variables.tf
│   └── outputs.tf
│
└── ops/
    └── rbac_audit.py               # RBAC "broken links" audit script
```

---

## Component Details

### 1. Infrastructure Layer — Zero Trust with Istio mTLS

**Namespaces** (`infrastructure/namespace.yaml`)
- `gaas`: all gateway workloads, auth service, tenant apps
- `gaas-vault`: Vault, isolated for blast-radius containment

Both namespaces carry `istio-injection: enabled` — the Envoy sidecar is injected into every Pod automatically at admission time.

**PeerAuthentication** (`infrastructure/peer-authentication.yaml`)
- `mode: STRICT` on both namespaces
- Any pod without a valid SPIFFE X.509 certificate is rejected
- Eliminates the need for network-layer firewall rules between services

**Local Bootstrap** (`infrastructure/istio-install.sh`)
```bash
./gaas/infrastructure/istio-install.sh
```
Provisions Minikube (4 CPU, 8 GB) + Istio `demo` profile in one command.

---

### 2. Gateway Layer — APISIX Gen 2 Migration

**APISIX** (`gateway/apisix-values.yaml`)
- Deployed via Helm with `NodePort: 30080` (Minikube) or `LoadBalancer` (cloud)
- Istio sidecar injection on APISIX pods for mTLS coverage
- Admin API restricted to cluster-internal CIDRs

**APISIX Dashboard** (`gateway/apisix-dashboard-config.yaml`)
- Deployed separately from APISIX for independent access control
- Port 9000, ClusterIP — not exposed externally
- Admin password injected via Kubernetes Secret (not committed to git)

**Tenant App Helm Chart** (`gateway/charts/tenant-app/`)

Deploy a tenant:
```bash
helm install acme-corp gaas/gateway/charts/tenant-app \
  --namespace tenant-acme \
  --create-namespace \
  --set tenantId=acme-corp \
  --set image.repository=gcr.io/acme/api \
  --set apisixRoute.pathPrefix=/tenants/acme
```

Every release creates:
| Resource | Purpose |
|---|---|
| `Deployment` | Tenant app pods with non-root securityContext |
| `ServiceAccount` | Dedicated identity for the tenant's workload |
| `Role` | Namespace-scoped read-only access (pods, services, configmaps) |
| `RoleBinding` | Binds Role to ServiceAccount |
| `ResourceQuota` | Enforces CPU/memory limits at namespace level |
| `ApisixRoute` | APISIX JWT-auth plugin routes traffic to tenant service |

---

### 3. Security & Identity — Mock Token Server

**Auth Service** (`security/auth-service/`)

Spring Boot 3.2 application issuing JWTs via OAuth 2.0 Client Credentials Grant:

```bash
curl -X POST http://localhost:8081/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=gaas-gateway&client_secret=gateway-secret-change-me"
```

Response:
```json
{
  "access_token": "<signed-JWT>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "gateway:read gateway:admin"
}
```

JWT claims: `iss`, `sub`, `aud`, `iat`, `exp`, `jti`, `scope`, `grant_type`

**HashiCorp Vault** (`security/vault/`)
- Dev mode for CI/Minikube (no unseal, root token known)
- Signing key stored at `secret/data/gaas/jwt-signing-key`
- `JwtService` checks for key rotation every 30 minutes via `@Scheduled`
- Vault policy limits auth-service to `read` only; CI pipeline has `create`/`update`

**Key Rotation Flow:**
```
CI pipeline → vault kv put secret/gaas/jwt-signing-key value=<new-base64-key>
                                    ↓ (within 30 min)
                         JwtService.scheduledKeyRotationCheck()
                                    ↓
                         Vault metadata version incremented
                                    ↓
                         refreshKeyFromVault() → AtomicReference<SecretKey> updated
                                    ↓
                         New tokens signed with new key (old tokens still valid until exp)
```

---

### 4. CI/CD Pipeline — Confidence Engine

**Workflow:** `.github/workflows/05-gaas-pipeline.yml`

Triggers on any push to `main` or `feature/**` that touches `gaas/**`.

| Job | What it does |
|---|---|
| `security-scan` | Trivy IaC misconfiguration scan + Maven CVE scan. Fails pipeline on HIGH/CRITICAL. |
| `build-auth-service` | Maven build + unit tests + Docker image push to GHCR |
| `lint-and-validate` | Flake8 (120-char), YAML validation, Helm lint + template dry-run |
| `terraform-plan` | `terraform plan` with OIDC AWS auth |
| `deploy-staging` | Full Minikube cluster: Istio + Vault + APISIX + auth-service + RBAC audit smoke test |
| `canary-deploy` | Istio traffic shifting: 10% → 50% → 100% canary with rollback on failure |
| `terraform-apply` | `terraform apply` (main branch only, after canary succeeds) |

**Canary Traffic Shifting:**
```
Phase 1: 90% stable / 10% canary  (60s observation)
Phase 2: 50% stable / 50% canary  (60s observation)
Phase 3: 0%  stable / 100% canary (full promotion)

On any failure: auto-rollback to 100% stable
```

---

### 5. Operational Tooling — RBAC Audit

**Script:** `ops/rbac_audit.py`

```bash
# Install dependency
pip install kubernetes

# Audit gaas namespace (CI gate mode)
python gaas/ops/rbac_audit.py --namespace gaas --fail-on-findings

# Audit entire cluster, output JSON
python gaas/ops/rbac_audit.py --json

# Run inside a Pod
python gaas/ops/rbac_audit.py --in-cluster --fail-on-findings
```

Detects:
- `RoleBinding` referencing a `Role` that doesn't exist → **HIGH**
- `RoleBinding` referencing a non-existent `ServiceAccount` → **MEDIUM**
- `ClusterRoleBinding` pointing to a non-existent `ClusterRole` → **HIGH**
- `ClusterRoleBinding` granting cluster-wide access to a GaaS tenant `ServiceAccount` → **HIGH** (tenant isolation violation)

Exit code `1` with `--fail-on-findings` makes it usable as a CI gate (runs in `deploy-staging` job after all workloads are applied).

---

## AI Accountability Documentation

### What was AI-generated
GitHub Copilot was used to generate initial drafts of:
- The Spring Boot Maven dependency structure in `pom.xml`
- The `SecurityFilterChain` bean pattern in `SecurityConfig.java`
- The Istio `VirtualService` weight syntax in the canary job
- The Vault HCL policy path syntax

### Quality checks performed on AI-generated code

| File | AI Issue Detected | Manual Fix Applied |
|---|---|---|
| `SecurityConfig.java` | Used deprecated `WebSecurityConfigurerAdapter` (removed in Spring Boot 3.x) | Rewrote using `SecurityFilterChain` bean |
| `SecurityConfig.java` | Protected `/actuator/health` endpoint, breaking K8s readiness probes | Opened health/info endpoints explicitly |
| `TokenController.java` | Used `String.equals()` for secret comparison (timing attack vector) | Replaced with constant-time comparison loop |
| `TokenController.java` | Did not validate requested scopes against allowed client scopes | Added scope elevation check |
| `JwtService.java` | Stored raw key bytes in a field (risk of accidental serialization/logging) | Changed to `SecretKey` object in `AtomicReference` |
| `vault-policy.hcl` | Granted `delete` capability to the CI pipeline identity | Removed — old key versions must be retained for token validation during rotation window |

### Accountability principle applied
Every AI-generated block was reviewed against: (1) security implications, (2) correctness for the specific Spring Boot 3.x / JJWT 0.12.x API version, and (3) whether the code matches the documented contract (e.g., port numbers, Vault paths, K8s resource names must all be internally consistent).

---

## Running Locally

### Prerequisites
- Docker Desktop (for Minikube)
- `minikube` >= 1.32, `kubectl` >= 1.28, `istioctl` >= 1.20, `helm` >= 3.12
- Java 21 + Maven 3.9 (for auth-service)
- Python 3.11 (for RBAC audit)

### Quick Start
```bash
# 1. Bootstrap cluster + Istio + namespaces
chmod +x gaas/infrastructure/istio-install.sh
./gaas/infrastructure/istio-install.sh

# 2. Deploy Vault and write signing key
kubectl apply -f gaas/security/vault/vault-deployment.yaml
kubectl port-forward svc/vault 8200:8200 -n gaas-vault &
export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=gaas-dev-root
vault secrets enable -path=secret kv-v2
vault kv put secret/gaas/jwt-signing-key \
  value=$(python3 -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())")
vault policy write gaas-auth gaas/security/vault/vault-policy.hcl

# 3. Install APISIX
helm repo add apisix https://charts.apiseven.com && helm repo update
helm install apisix apisix/apisix -n gaas -f gaas/gateway/apisix-values.yaml --wait

# 4. Build and run auth-service
cd gaas/security/auth-service
mvn spring-boot:run

# 5. Get a token
curl -X POST http://localhost:8081/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=gaas-gateway&client_secret=gateway-secret-change-me"

# 6. Run RBAC audit
pip install kubernetes
python gaas/ops/rbac_audit.py --namespace gaas
```

### Deploy a Tenant
```bash
helm install acme-corp gaas/gateway/charts/tenant-app \
  --namespace tenant-acme --create-namespace \
  --set tenantId=acme-corp \
  --set image.repository=nginx \
  --set apisixRoute.pathPrefix=/tenants/acme
```
