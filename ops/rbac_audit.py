#!/usr/bin/env python3
"""
GaaS RBAC Audit Tool
====================
Audits Kubernetes RBAC configuration for "broken links" — bindings that
reference non-existent ServiceAccounts, Roles, or ClusterRoles.

This is the operational tooling component of the Enterprise GaaS project.
It mimics the kind of RBAC/identity-chain verification you would run
periodically to ensure no "broken links" exist between:
  - RoleBindings and the Roles they reference
  - ClusterRoleBindings and the ClusterRoles they reference
  - Any binding and the ServiceAccounts listed as subjects

Additionally flags: ClusterRoleBindings that grant permissions to
ServiceAccounts in the `gaas` namespace (high-severity finding, since
tenant apps should never have cluster-wide access).

Exit codes:
  0 — no findings (clean RBAC state)
  1 — findings present (use --fail-on-findings to enforce this in CI)

Usage:
  # Audit all namespaces
  python rbac_audit.py

  # Audit only the gaas namespace
  python rbac_audit.py --namespace gaas

  # Output as JSON (for downstream processing)
  python rbac_audit.py --json

  # Fail with exit code 1 if any findings exist (CI gate)
  python rbac_audit.py --fail-on-findings

  # Run inside a Pod with in-cluster config
  python rbac_audit.py --in-cluster

Requirements:
  pip install kubernetes
"""

import argparse
import json
import sys
from dataclasses import dataclass, asdict
from typing import Optional

try:
    from kubernetes import client, config
    from kubernetes.client.exceptions import ApiException
except ImportError:
    print("ERROR: kubernetes package not installed. Run: pip install kubernetes", file=sys.stderr)
    sys.exit(2)


@dataclass
class Finding:
    severity: str          # HIGH, MEDIUM, LOW
    namespace: str
    binding_kind: str      # RoleBinding or ClusterRoleBinding
    binding_name: str
    subject_kind: str      # ServiceAccount, User, Group
    subject_name: str
    subject_namespace: str
    issue: str
    remediation: str


def load_k8s_config(in_cluster: bool) -> None:
    if in_cluster:
        config.load_incluster_config()
    else:
        config.load_kube_config()


def get_existing_service_accounts(core_v1: client.CoreV1Api, namespace: str) -> set:
    """Returns a set of (namespace, name) tuples for all ServiceAccounts in `namespace`."""
    try:
        sa_list = core_v1.list_namespaced_service_account(namespace)
        return {(namespace, sa.metadata.name) for sa in sa_list.items}
    except ApiException as e:
        if e.status == 403:
            print(f"  WARNING: No permission to list ServiceAccounts in namespace '{namespace}'", file=sys.stderr)
            return set()
        raise


def get_all_service_accounts(core_v1: client.CoreV1Api) -> set:
    """Returns a set of (namespace, name) tuples for all ServiceAccounts cluster-wide."""
    try:
        sa_list = core_v1.list_service_account_for_all_namespaces()
        return {(sa.metadata.namespace, sa.metadata.name) for sa in sa_list.items}
    except ApiException as e:
        if e.status == 403:
            print("  WARNING: No permission to list ServiceAccounts cluster-wide", file=sys.stderr)
            return set()
        raise


def get_existing_roles(rbac_v1: client.RbacAuthorizationV1Api, namespace: str) -> set:
    """Returns a set of role names for all Roles in `namespace`."""
    try:
        role_list = rbac_v1.list_namespaced_role(namespace)
        return {r.metadata.name for r in role_list.items}
    except ApiException as e:
        if e.status == 403:
            return set()
        raise


def get_existing_cluster_roles(rbac_v1: client.RbacAuthorizationV1Api) -> set:
    """Returns a set of names for all ClusterRoles."""
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
    findings = []

    try:
        rb_list = rbac_v1.list_namespaced_role_binding(namespace)
    except ApiException as e:
        if e.status == 403:
            print(f"  WARNING: No permission to list RoleBindings in namespace '{namespace}'", file=sys.stderr)
            return []
        raise

    roles_in_ns = get_existing_roles(rbac_v1, namespace)

    for rb in rb_list.items:
        rb_name = rb.metadata.name
        role_ref = rb.role_ref

        # Check 1: Does the referenced Role or ClusterRole exist?
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

        # Check 2: Do all ServiceAccount subjects exist?
        if rb.subjects is None:
            continue
        for subject in rb.subjects:
            if subject.kind != "ServiceAccount":
                continue
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

        # Check 1: Does the referenced ClusterRole exist?
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
            # Check 2: ServiceAccount subjects — do they exist?
            if subject.kind == "ServiceAccount":
                # Subjects in ClusterRoleBindings sometimes have no namespace field set.
                # For system accounts expressed as `system:serviceaccount:<ns>:<name>`,
                # the namespace is in the name — parse it rather than assuming "default".
                if subject.namespace:
                    sa_ns = subject.namespace
                elif subject.name.startswith("system:serviceaccount:"):
                    parts = subject.name.split(":")
                    sa_ns = parts[2] if len(parts) >= 4 else "default"
                else:
                    sa_ns = "default"
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

                # Check 3: HIGH SEVERITY — GaaS tenant ServiceAccount with cluster-wide access.
                # Tenants must only have namespace-scoped Role bindings (see tenant-app Helm chart).
                # A ClusterRoleBinding granting cluster-wide access to a tenant SA breaks
                # the GaaS multi-tenant isolation model.
                if sa_ns in gaas_namespaces:
                    # Skip system ClusterRoleBindings (e.g., istio-*, system:*)
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
    if not findings:
        print("\n✓ No RBAC findings. Identity chain is clean.\n")
        return

    print(f"\n{'=' * 100}")
    print(f"  RBAC AUDIT FINDINGS — {len(findings)} issue(s) detected")
    print(f"{'=' * 100}")

    for i, f in enumerate(findings, 1):
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
    parser = argparse.ArgumentParser(
        description="Audit Kubernetes RBAC for broken links and GaaS tenant isolation violations"
    )
    parser.add_argument("--namespace", help="Audit only this namespace (default: all namespaces)")
    parser.add_argument("--in-cluster", action="store_true", help="Use in-cluster Kubernetes config (for Pod execution)")
    parser.add_argument("--json", action="store_true", dest="output_json", help="Output findings as JSON")
    parser.add_argument("--fail-on-findings", action="store_true", help="Exit with code 1 if any findings exist (CI gate)")
    args = parser.parse_args()

    print("Loading Kubernetes configuration...")
    load_k8s_config(args.in_cluster)

    core_v1 = client.CoreV1Api()
    rbac_v1 = client.RbacAuthorizationV1Api()

    print("Fetching cluster-wide resources...")
    cluster_roles = get_existing_cluster_roles(rbac_v1)
    print(f"  Found {len(cluster_roles)} ClusterRoles")

    all_findings: list[Finding] = []

    # GaaS namespaces — ClusterRoleBindings granting access to SAs here are flagged HIGH
    gaas_namespaces = {"gaas", "gaas-vault"}

    # Determine which namespaces to audit
    if args.namespace:
        namespaces_to_audit = [args.namespace]
        print(f"  Fetching ServiceAccounts in namespace '{args.namespace}'...")
        all_service_accounts = get_existing_service_accounts(core_v1, args.namespace)
    else:
        print("  Fetching all ServiceAccounts cluster-wide...")
        all_service_accounts = get_all_service_accounts(core_v1)

        print("  Fetching all namespaces...")
        ns_list = core_v1.list_namespace()
        namespaces_to_audit = [ns.metadata.name for ns in ns_list.items]

    print(f"  Found {len(all_service_accounts)} ServiceAccount(s)")

    # Audit RoleBindings in each namespace
    print(f"\nAuditing RoleBindings across {len(namespaces_to_audit)} namespace(s)...")
    for ns in namespaces_to_audit:
        ns_findings = audit_role_bindings(rbac_v1, core_v1, ns, all_service_accounts, cluster_roles)
        all_findings.extend(ns_findings)

    # Audit ClusterRoleBindings (only once, cluster-wide)
    if not args.namespace:
        print("Auditing ClusterRoleBindings...")
        crb_findings = audit_cluster_role_bindings(rbac_v1, all_service_accounts, cluster_roles, gaas_namespaces)
        all_findings.extend(crb_findings)

    # Output results
    if args.output_json:
        print(json.dumps([asdict(f) for f in all_findings], indent=2))
    else:
        print_table(all_findings)

    if args.fail_on_findings and all_findings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
