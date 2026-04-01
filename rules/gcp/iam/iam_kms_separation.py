import uuid
from google.cloud import resourcemanager_v3
from google.iam.v1 import iam_policy_pb2
from collections import defaultdict


# Roles that grant KMS administrative capabilities
KMS_ADMIN_ROLES = {
    "roles/cloudkms.admin",
    "roles/owner",
    "roles/editor",
}

# Roles that grant KMS cryptographic (encrypt/decrypt) capabilities
KMS_CRYPTO_ROLES = {
    "roles/cloudkms.cryptoKeyEncrypterDecrypter",
    "roles/cloudkms.cryptoKeyEncrypter",
    "roles/cloudkms.cryptoKeyDecrypter",
    "roles/owner",
    "roles/editor",
}


def run_check(project_id: str):
    """
    Checks that no single IAM principal holds both KMS admin and KMS
    cryptographic (encrypter/decrypter) roles — enforcing KMS separation of duties.
    """
    findings = []
    violations = []

    try:
        client = resourcemanager_v3.ProjectsClient()
        request = iam_policy_pb2.GetIamPolicyRequest(
            resource=f"projects/{project_id}"
        )
        policy = client.get_iam_policy(request=request)

        # Map each member to the set of roles they hold
        member_roles = defaultdict(set)
        for binding in policy.bindings:
            for member in binding.members:
                member_roles[member].add(binding.role)

        for member, roles in member_roles.items():
            has_admin = bool(roles & KMS_ADMIN_ROLES)
            has_crypto = bool(roles & KMS_CRYPTO_ROLES)

            # Exclude if only reason is roles/owner or roles/editor (handled separately)
            admin_roles_held = roles & KMS_ADMIN_ROLES
            crypto_roles_held = roles & KMS_CRYPTO_ROLES

            if has_admin and has_crypto:
                violations.append({
                    "member": member,
                    "admin_roles": list(admin_roles_held),
                    "crypto_roles": list(crypto_roles_held)
                })

        status = "FAIL" if violations else "PASS"
        desc = (
            f"{len(violations)} principal(s) hold both KMS admin and cryptographic roles, "
            "violating KMS separation of duties."
            if violations
            else "KMS separation of duties is properly enforced — no principal holds both admin and crypto roles."
        )

        findings.append(create_finding(
            rule_id="GCP-IAM-08",
            check="KMS IAM Separation of Duties",
            severity="High",
            status=status,
            project_id=project_id,
            res_id=f"projects/{project_id}",
            desc=desc,
            rem=(
                "Ensure that the 'roles/cloudkms.admin' role and cryptographic roles "
                "(e.g., 'roles/cloudkms.cryptoKeyEncrypterDecrypter') are assigned to "
                "different identities. No single principal should be able to both manage "
                "keys and perform cryptographic operations."
            ),
            evidence={
                "violations": violations,
                "kms_admin_roles_checked": list(KMS_ADMIN_ROLES),
                "kms_crypto_roles_checked": list(KMS_CRYPTO_ROLES)
            }
        ))
    except Exception as e:
        findings.append(create_finding(
            rule_id="GCP-IAM-08",
            check="KMS IAM Separation of Duties",
            severity="High",
            status="ERROR",
            project_id=project_id,
            res_id=f"projects/{project_id}",
            desc=f"Error checking KMS separation of duties: {e}",
            rem="Ensure resourcemanager.googleapis.com and cloudkms.googleapis.com are enabled.",
            evidence={"error": str(e)}
        ))

    return findings


def create_finding(rule_id, check, severity, status, project_id, res_id, desc, rem, evidence):
    return {
        "finding_id": str(uuid.uuid4()),
        "rule_id": rule_id,
        "check": check,
        "severity": severity,
        "status": status,
        "cloud_provider": "gcp",
        "category": "IAM",
        "resource_type": "gcp_kms_iam_policy",
        "resource_id": res_id,
        "project_id": project_id,
        "region": "global",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://cloud.google.com/kms/docs/separation-of-duties",
            "https://cloud.google.com/iam/docs/understanding-roles#cloud-kms-roles"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
