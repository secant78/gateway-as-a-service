#!/usr/bin/env python3
"""
GaaS RBAC Audit Tool
====================
PURPOSE:
  Audits Kubernetes RBAC configuration for "broken links" — bindings that
  reference resources that no longer exist. This is an operational health
  check for the identity chain that connects:
    ServiceAccount (who the pod is) → RoleBinding (the link) → Role (what it can do)

WHY BROKEN LINKS HAPPEN:
  Kubernetes does NOT enforce referential integrity in RBAC.
  If you delete a ServiceAccount but forget to delete its RoleBinding,
  the RoleBinding remains with a dangling reference — Kubernetes doesn't
  warn you. These "zombie" bindings:
    - Pollute audit logs with confusing entries
    - Can accidentally grant permissions if a new ServiceAccount is created
      with the same name (the old binding immediately activates)
    - Indicate poor lifecycle management that creates security debt

WHAT THIS SCRIPT CHECKS:
  1. For every RoleBinding in a namespace:
     a. Does the referenced Role (or ClusterRole) exist?
     b. Do all ServiceAccount subjects exist?

  2. For every ClusterRoleBinding cluster-wide:
     a. Does the referenced ClusterRole exist?
     b. Do all ServiceAccount subjects exist?
     c. HIGH SEVERITY: Does the binding grant cluster-wide access to a
        ServiceAccount in a GaaS tenant namespace (gaas, gaas-vault)?
        Tenant SAs should NEVER have cluster-wide access — this indicates
        a tenant isolation violation.

EXIT CODES:
  0 — no findings (clean RBAC state, safe to deploy)
  1 — findings present (use --fail-on-findings to enforce this in CI gates)
  2 — script error (missing dependency, permission denied, etc.)

USAGE EXAMPLES:
  # Audit all namespaces (broad check)
  python rbac_audit.py

  # Audit only the gaas namespace (fast, used in CI gate)
  python rbac_audit.py --namespace gaas

  # Output findings as JSON for downstream processing (SIEM, dashboards)
  python rbac_audit.py --json

  # Fail with exit code 1 if any findings exist (used as a CI gate in 05-gaas-pipeline.yml)
  python rbac_audit.py --fail-on-findings

  # Run inside a Pod (uses in-cluster Kubernetes config instead of ~/.kube/config)
  python rbac_audit.py --in-cluster

REQUIREMENTS:
  pip install kubernetes
"""

import argparse
import json
import sys
from dataclasses import dataclass, asdict  # dataclass = structured data container; asdict = serialize to dict
from typing import Optional

# Import the official Kubernetes Python client library.
# If not installed, print a helpful error and exit with code 2 (script error, not RBAC finding).
try:
    from kubernetes import client, config
    from kubernetes.client.exceptions import ApiException
except ImportError:
    print("ERROR: kubernetes package not installed. Run: pip install kubernetes", file=sys.stderr)
    sys.exit(2)


@dataclass
class Finding:
    """
    A single RBAC issue detected during the audit.

    dataclass automatically generates __init__, __repr__, and __eq__ methods.
    asdict(finding) converts this to a dict for JSON serialization.

    Fields:
      severity:         HIGH = immediate action needed, MEDIUM = fix soon, LOW = informational
      namespace:        The Kubernetes namespace where the issue was found
      binding_kind:     "RoleBinding" or "ClusterRoleBinding"
      binding_name:     The name of the broken binding resource
      subject_kind:     "ServiceAccount", "User", or "Group"
      subject_name:     The name of the missing/problematic subject
      subject_namespace: The namespace the subject should be in
      issue:            Human-readable description of the problem
      remediation:      Recommended fix action
    """
    severity: str           # HIGH, MEDIUM, LOW
    namespace: str
    binding_kind: str       # RoleBinding or ClusterRoleBinding
    binding_name: str
    subject_kind: str       # ServiceAccount, User, Group
    subject_name: str
    subject_namespace: str
    issue: str
    remediation: str


def load_k8s_config(in_cluster: bool) -> None:
    """
    Loads Kubernetes authentication configuration.

    Two modes:
      in_cluster=False (default): reads ~/.kube/config (local development, CI runners)
      in_cluster=True:           reads the ServiceAccount token mounted in the pod
                                  at /var/run/secrets/kubernetes.io/serviceaccount/
                                  Used when running this script INSIDE a Kubernetes pod.
    """
    if in_cluster:
        # Uses the pod's mounted ServiceAccount token and cluster CA certificate.
        # The pod must have RBAC permissions to list RoleBindings, ClusterRoleBindings,
        # ServiceAccounts, and ClusterRoles — configure this via a Role + RoleBinding.
        config.load_incluster_config()
    else:
        # Reads the kubeconfig file from the default location (~/.kube/config)
        # or from the KUBECONFIG environment variable.
        config.load_kube_config()


def get_existing_service_accounts(core_v1: client.CoreV1Api, namespace: str) -> set:
    """
    Returns a set of (namespace, name) tuples for all ServiceAccounts in one namespace.

    Returns a set for O(1) membership testing: (ns, name) in all_service_accounts
    is faster than iterating a list for each binding subject.

    Handles 403 Permission Denied gracefully — prints a warning and returns an empty set
    rather than crashing the script. This allows partial audits when the script doesn't
    have permission to list SAs in every namespace.
    """
    try:
        sa_list = core_v1.list_namespaced_service_account(namespace)
        # Build a set of (namespace, name) tuples for quick membership testing
        return {(namespace, sa.metadata.name) for sa in sa_list.items}
    except ApiException as e:
        if e.status == 403:
            # This namespace is off-limits — skip it rather than crashing
            print(f"  WARNING: No permission to list ServiceAccounts in namespace '{namespace}'", file=sys.stderr)
            return set()
        raise  # Re-raise unexpected errors (500, 404, etc.)


def get_all_service_accounts(core_v1: client.CoreV1Api) -> set:
    """
    Returns a set of (namespace, name) tuples for ALL ServiceAccounts cluster-wide.

    Used when no --namespace filter is specified. Fetches all SAs in one API call
    rather than making one call per namespace (much more efficient on large clusters).
    """
    try:
        # list_service_account_for_all_namespaces() fetches across all namespaces in one call
        sa_list = core_v1.list_service_account_for_all_namespaces()
        return {(sa.metadata.namespace, sa.metadata.name) for sa in sa_list.items}
    except ApiException as e:
        if e.status == 403:
            print("  WARNING: No permission to list ServiceAccounts cluster-wide", file=sys.stderr)
            return set()
        raise


def get_existing_roles(rbac_v1: client.RbacAuthorizationV1Api, namespace: str) -> set:
    """
    Returns a set of Role names for all Roles in a specific namespace.

    Used to check whether a RoleBinding's roleRef.name points to an existing Role.
    Returns a set of strings (not tuples) because Roles are namespace-scoped and
    we already know the namespace from the context.
    """
    try:
        role_list = rbac_v1.list_namespaced_role(namespace)
        return {r.metadata.name for r in role_list.items}
    except ApiException as e:
        if e.status == 403:
            return set()  # Can't list Roles here — skip silently
        raise


def get_existing_cluster_roles(rbac_v1: client.RbacAuthorizationV1Api) -> set:
    """
    Returns a set of ClusterRole names for all ClusterRoles in the cluster.

    ClusterRoles are cluster-scoped (not namespaced), so we fetch them all at once.
    This set is passed to both audit_role_bindings() and audit_cluster_role_bindings()
    to avoid redundant API calls.
    """
    try:
        cr_list = rbac_v1.list_cluster_role()
        return {cr.metadata.name for cr in cr_list.items}
    except ApiException as e:
        if e.status == 403:
            return set()
        raise


def audit_role_bindings(
    rbac_v1: client.RbacAuthorizationV1Api,
    core_v1: client.CoreV1Api,
    namespace: str,
    all_service_accounts: set,
    cluster_roles: set,
) -> list[Finding]:
    """
    Audits all RoleBindings in a single namespace for broken links.

    For each RoleBinding:
      Check 1: Does the roleRef (Role or ClusterRole) exist?
               If not → HIGH severity finding (binding grants permissions to nothing)
      Check 2: Do all ServiceAccount subjects exist?
               If not → MEDIUM severity finding (binding references a deleted/renamed SA)

    Returns a list of Finding objects (empty if no issues found).

    Parameters:
      rbac_v1:              RbacAuthorizationV1Api client
      core_v1:              CoreV1Api client (for ServiceAccount lookups)
      namespace:            The namespace to audit
      all_service_accounts: Pre-fetched set of (ns, name) tuples for all known SAs
      cluster_roles:        Pre-fetched set of all ClusterRole names
    """
    findings = []

    try:
        rb_list = rbac_v1.list_namespaced_role_binding(namespace)
    except ApiException as e:
        if e.status == 403:
            print(f"  WARNING: No permission to list RoleBindings in namespace '{namespace}'", file=sys.stderr)
            return []
        raise

    # Fetch the Roles in this specific namespace to validate roleRef.name
    roles_in_ns = get_existing_roles(rbac_v1, namespace)

    for rb in rb_list.items:
        rb_name = rb.metadata.name
        role_ref = rb.role_ref  # Contains: kind (Role/ClusterRole), name, apiGroup

        # ---- Check 1: Does the referenced Role/ClusterRole exist? ----
        # A RoleBinding can reference either a Role (namespace-scoped) or a ClusterRole
        # (cluster-scoped used in a namespaced context). Check the appropriate set.
        if role_ref.kind == "Role" and role_ref.name not in roles_in_ns:
            findings.append(Finding(
                severity="HIGH",
                namespace=namespace,
                binding_kind="RoleBinding",
                binding_name=rb_name,
                subject_kind="N/A",
                subject_name="N/A",
                subject_namespace="N/A",
                issue=f"RoleBinding references non-existent Role '{role_ref.name}' in namespace '{namespace}'",
                remediation=f"Delete the RoleBinding or create the Role '{role_ref.name}'"
            ))
        elif role_ref.kind == "ClusterRole" and role_ref.name not in cluster_roles:
            findings.append(Finding(
                severity="HIGH",
                namespace=namespace,
                binding_kind="RoleBinding",
                binding_name=rb_name,
                subject_kind="N/A",
                subject_name="N/A",
                subject_namespace="N/A",
                issue=f"RoleBinding references non-existent ClusterRole '{role_ref.name}'",
                remediation=f"Delete the RoleBinding or create the ClusterRole '{role_ref.name}'"
            ))

        # ---- Check 2: Do all ServiceAccount subjects exist? ----
        # Subjects is None if the binding has no subjects (malformed, but handle gracefully)
        if rb.subjects is None:
            continue
        for subject in rb.subjects:
            # Only check ServiceAccount subjects — Users and Groups are external identities
            # (e.g., LDAP) that we can't validate against the K8s API.
            if subject.kind != "ServiceAccount":
                continue
            # subject.namespace can be empty for SAs in the same namespace as the binding
            sa_ns = subject.namespace or namespace
            if (sa_ns, subject.name) not in all_service_accounts:
                findings.append(Finding(
                    severity="MEDIUM",
                    namespace=namespace,
                    binding_kind="RoleBinding",
                    binding_name=rb_name,
                    subject_kind="ServiceAccount",
                    subject_name=subject.name,
                    subject_namespace=sa_ns,
                    issue=f"RoleBinding subject ServiceAccount '{subject.name}' does not exist in namespace '{sa_ns}'",
                    remediation=f"Delete the RoleBinding or create ServiceAccount '{subject.name}' in namespace '{sa_ns}'"
                ))

    return findings


def audit_cluster_role_bindings(
    rbac_v1: client.RbacAuthorizationV1Api,
    all_service_accounts: set,
    cluster_roles: set,
    gaas_namespaces: set,
) -> list[Finding]:
    """
    Audits all ClusterRoleBindings cluster-wide for broken links and isolation violations.

    ClusterRoleBindings grant cluster-wide permissions — they are more dangerous
    than RoleBindings and warrant extra scrutiny, especially for GaaS tenant SAs.

    Three checks:
      Check 1: Does the referenced ClusterRole exist?
               → HIGH if not (same as RoleBinding audit)
      Check 2: Do all ServiceAccount subjects exist?
               → MEDIUM if not
      Check 3: TENANT ISOLATION VIOLATION — does this ClusterRoleBinding grant
               cluster-wide access to a SA in a GaaS tenant namespace?
               → HIGH severity — tenants must NEVER have cluster-wide access.
               The tenant-app Helm chart only creates namespace-scoped Roles.
               Any ClusterRoleBinding involving a gaas-namespace SA is unexpected.

    Parameters:
      gaas_namespaces: set of namespace names to check for isolation violations
                       Currently: {"gaas", "gaas-vault"}
    """
    findings = []

    try:
        crb_list = rbac_v1.list_cluster_role_binding()
    except ApiException as e:
        if e.status == 403:
            print("  WARNING: No permission to list ClusterRoleBindings", file=sys.stderr)
            return []
        raise

    for crb in crb_list.items:
        crb_name = crb.metadata.name
        role_ref = crb.role_ref

        # ---- Check 1: Does the referenced ClusterRole exist? ----
        if role_ref.kind == "ClusterRole" and role_ref.name not in cluster_roles:
            findings.append(Finding(
                severity="HIGH",
                namespace="cluster-wide",
                binding_kind="ClusterRoleBinding",
                binding_name=crb_name,
                subject_kind="N/A",
                subject_name="N/A",
                subject_namespace="N/A",
                issue=f"ClusterRoleBinding references non-existent ClusterRole '{role_ref.name}'",
                remediation=f"Delete the ClusterRoleBinding or create the ClusterRole '{role_ref.name}'"
            ))

        if crb.subjects is None:
            continue

        for subject in crb.subjects:
            if subject.kind == "ServiceAccount":
                # Determine the subject's namespace.
                # ClusterRoleBinding subjects may have an empty namespace field.
                # System accounts like "system:serviceaccount:kube-system:foo" encode
                # their namespace in their name — parse it out to avoid false positives.
                if subject.namespace:
                    # Explicit namespace field — most common case
                    sa_ns = subject.namespace
                elif subject.name.startswith("system:serviceaccount:"):
                    # System service account format: "system:serviceaccount:<namespace>:<name>"
                    # Split on ":" and extract the namespace (index 2, 0-based)
                    # Example: "system:serviceaccount:kube-system:coredns" → "kube-system"
                    parts = subject.name.split(":")
                    sa_ns = parts[2] if len(parts) >= 4 else "default"
                else:
                    # No namespace info available — assume default
                    sa_ns = "default"

                # ---- Check 2: Does the ServiceAccount exist? ----
                if (sa_ns, subject.name) not in all_service_accounts:
                    findings.append(Finding(
                        severity="MEDIUM",
                        namespace="cluster-wide",
                        binding_kind="ClusterRoleBinding",
                        binding_name=crb_name,
                        subject_kind="ServiceAccount",
                        subject_name=subject.name,
                        subject_namespace=sa_ns,
                        issue=f"ClusterRoleBinding subject ServiceAccount '{subject.name}' does not exist in namespace '{sa_ns}'",
                        remediation=f"Delete the ClusterRoleBinding or create ServiceAccount '{subject.name}' in namespace '{sa_ns}'"
                    ))

                # ---- Check 3: Tenant isolation violation ----
                # If this SA is in a GaaS namespace AND the binding is not a known
                # system binding (Istio, system:*), flag it as HIGH severity.
                # Tenant SAs should only appear in RoleBindings (namespace-scoped),
                # never in ClusterRoleBindings (cluster-wide access).
                if sa_ns in gaas_namespaces:
                    # Skip well-known system-managed ClusterRoleBindings:
                    # system:* — Kubernetes-managed bindings (node bootstrapping, etc.)
                    # istio-*  — Istio-managed bindings for the service mesh control plane
                    if not (crb_name.startswith("system:") or crb_name.startswith("istio-")):
                        findings.append(Finding(
                            severity="HIGH",
                            namespace=sa_ns,
                            binding_kind="ClusterRoleBinding",
                            binding_name=crb_name,
                            subject_kind="ServiceAccount",
                            subject_name=subject.name,
                            subject_namespace=sa_ns,
                            issue=(
                                f"TENANT ISOLATION VIOLATION: ClusterRoleBinding '{crb_name}' grants "
                                f"cluster-wide access to ServiceAccount '{subject.name}' in GaaS namespace '{sa_ns}'. "
                                f"Tenant SAs must only have namespace-scoped RoleBindings."
                            ),
                            remediation=(
                                f"Delete ClusterRoleBinding '{crb_name}' and create a namespace-scoped "
                                f"RoleBinding in namespace '{sa_ns}' instead."
                            )
                        ))

    return findings


def print_table(findings: list[Finding]) -> None:
    """
    Prints findings as a formatted human-readable table to stdout.

    Each finding shows:
      - Severity and binding kind/name
      - Namespace
      - Subject information (if applicable)
      - Issue description
      - Remediation step

    A summary line at the bottom counts HIGH and MEDIUM findings.
    """
    if not findings:
        # Happy path: clean RBAC state
        print("\n✓ No RBAC findings. Identity chain is clean.\n")
        return

    print(f"\n{'=' * 100}")
    print(f"  RBAC AUDIT FINDINGS — {len(findings)} issue(s) detected")
    print(f"{'=' * 100}")

    for i, f in enumerate(findings, 1):
        # Map severity to a fixed-width label for alignment
        severity_icon = {"HIGH": "[HIGH]", "MEDIUM": "[MED]", "LOW": "[LOW]"}.get(f.severity, f.severity)
        print(f"\n  [{i}] {severity_icon}  {f.binding_kind}: {f.binding_name}")
        print(f"       Namespace:   {f.namespace}")
        if f.subject_kind != "N/A":
            print(f"       Subject:     {f.subject_kind}/{f.subject_name} (ns: {f.subject_namespace})")
        print(f"       Issue:       {f.issue}")
        print(f"       Remediation: {f.remediation}")

    print(f"\n{'=' * 100}")
    high = sum(1 for f in findings if f.severity == "HIGH")
    med = sum(1 for f in findings if f.severity == "MEDIUM")
    print(f"  Summary: {high} HIGH, {med} MEDIUM")
    print(f"{'=' * 100}\n")


def main() -> int:
    """
    Main entry point — parses CLI arguments, runs the audit, outputs results.

    Returns the exit code (0 = clean, 1 = findings, 2 = error).
    """
    parser = argparse.ArgumentParser(
        description="Audit Kubernetes RBAC for broken links and GaaS tenant isolation violations"
    )
    # --namespace: scope the audit to one namespace (faster, used in CI for gaas namespace only)
    parser.add_argument("--namespace", help="Audit only this namespace (default: all namespaces)")
    # --in-cluster: use pod's mounted ServiceAccount token instead of ~/.kube/config
    parser.add_argument("--in-cluster", action="store_true", help="Use in-cluster Kubernetes config (for Pod execution)")
    # --json: machine-readable output for SIEM, dashboards, or downstream CI steps
    parser.add_argument("--json", action="store_true", dest="output_json", help="Output findings as JSON")
    # --fail-on-findings: exit with code 1 if any findings exist — makes this a CI gate
    parser.add_argument("--fail-on-findings", action="store_true", help="Exit with code 1 if any findings exist (CI gate)")
    args = parser.parse_args()

    print("Loading Kubernetes configuration...")
    load_k8s_config(args.in_cluster)

    # Initialize the Kubernetes API clients.
    # CoreV1Api:              for ServiceAccount, Namespace, Pod listing
    # RbacAuthorizationV1Api: for Role, RoleBinding, ClusterRole, ClusterRoleBinding listing
    core_v1 = client.CoreV1Api()
    rbac_v1 = client.RbacAuthorizationV1Api()

    # Fetch ClusterRoles once and reuse — they're the same for all namespaces.
    print("Fetching cluster-wide resources...")
    cluster_roles = get_existing_cluster_roles(rbac_v1)
    print(f"  Found {len(cluster_roles)} ClusterRoles")

    all_findings: list[Finding] = []

    # GaaS-owned namespaces — any ClusterRoleBinding granting access to SAs here
    # is a potential tenant isolation violation (HIGH severity).
    gaas_namespaces = {"gaas", "gaas-vault"}

    # Determine scope: single namespace or cluster-wide.
    if args.namespace:
        # Single namespace mode: faster, used in CI for the gaas namespace gate.
        namespaces_to_audit = [args.namespace]
        print(f"  Fetching ServiceAccounts in namespace '{args.namespace}'...")
        all_service_accounts = get_existing_service_accounts(core_v1, args.namespace)
    else:
        # Cluster-wide mode: audits every namespace.
        print("  Fetching all ServiceAccounts cluster-wide...")
        all_service_accounts = get_all_service_accounts(core_v1)

        print("  Fetching all namespaces...")
        ns_list = core_v1.list_namespace()
        namespaces_to_audit = [ns.metadata.name for ns in ns_list.items]

    print(f"  Found {len(all_service_accounts)} ServiceAccount(s)")

    # ---- Audit RoleBindings per namespace ----
    print(f"\nAuditing RoleBindings across {len(namespaces_to_audit)} namespace(s)...")
    for ns in namespaces_to_audit:
        ns_findings = audit_role_bindings(rbac_v1, core_v1, ns, all_service_accounts, cluster_roles)
        all_findings.extend(ns_findings)

    # ---- Audit ClusterRoleBindings (cluster-wide, only in full-scan mode) ----
    # Skip in single-namespace mode because ClusterRoleBindings span all namespaces —
    # auditing them for a single namespace would produce incomplete results.
    if not args.namespace:
        print("Auditing ClusterRoleBindings...")
        crb_findings = audit_cluster_role_bindings(rbac_v1, all_service_accounts, cluster_roles, gaas_namespaces)
        all_findings.extend(crb_findings)

    # ---- Output results ----
    if args.output_json:
        # JSON output: serialize all Finding dataclasses to a JSON array.
        # asdict() converts each dataclass to a plain dict for json.dumps().
        print(json.dumps([asdict(f) for f in all_findings], indent=2))
    else:
        # Human-readable table output
        print_table(all_findings)

    # ---- Exit code ----
    # If --fail-on-findings is set AND there are findings, return 1 (failure).
    # In the CI pipeline (05-gaas-pipeline.yml), this causes the deploy-staging job to fail.
    if args.fail_on_findings and all_findings:
        return 1
    return 0  # Clean exit — no findings, or findings present but --fail-on-findings not set


if __name__ == "__main__":
    # sys.exit() converts the integer return value of main() into the process exit code.
    # GitHub Actions and other CI tools read this exit code to determine pass/fail.
    sys.exit(main())
