import uuid
import os
import re
import json
import glob


def find_tf_files(search_dir="."):
    """Recursively find all .tf and .tf.json files under the given directory."""
    tf_files = glob.glob(os.path.join(search_dir, "**", "*.tf"), recursive=True)
    tf_json_files = glob.glob(os.path.join(search_dir, "**", "*.tf.json"), recursive=True)
    return tf_files + tf_json_files


def run_check(session, tf_path="."):
    """
    Static analysis rule: Detect IAM policies in Terraform that grant
    overly permissive '*' (wildcard) actions on '*' (all) resources.
    This violates the principle of least privilege.
    """
    findings = []
    tf_files = find_tf_files(tf_path)

    if not tf_files:
        findings.append(create_finding(
            "IAC-AWS-IAM-01", "Terraform IAM Star Policy", "Info",
            "PASS", "N/A",
            "No Terraform files found to scan.",
            "No action required.",
            {"scanned_files": 0}
        ))
        return findings

    all_content = ""
    for tf_file in tf_files:
        try:
            with open(tf_file, "r", encoding="utf-8", errors="ignore") as f:
                all_content += f"\n# FILE: {tf_file}\n" + f.read()
        except Exception:
            continue

    # 1. Check aws_iam_policy resources
    policy_pattern = re.compile(
        r'resource\s+"aws_iam_policy"\s+"(\w+)"\s*\{(.*?)\n\}',
        re.DOTALL
    )

    # 2. Check aws_iam_role_policy (inline policies)
    role_policy_pattern = re.compile(
        r'resource\s+"aws_iam_role_policy"\s+"(\w+)"\s*\{(.*?)\n\}',
        re.DOTALL
    )

    # 3. Check aws_iam_user_policy (inline user policies)
    user_policy_pattern = re.compile(
        r'resource\s+"aws_iam_user_policy"\s+"(\w+)"\s*\{(.*?)\n\}',
        re.DOTALL
    )

    # 4. Check aws_iam_group_policy (inline group policies)
    group_policy_pattern = re.compile(
        r'resource\s+"aws_iam_group_policy"\s+"(\w+)"\s*\{(.*?)\n\}',
        re.DOTALL
    )

    # 5. Check aws_iam_policy_document data sources
    policy_doc_pattern = re.compile(
        r'data\s+"aws_iam_policy_document"\s+"(\w+)"\s*\{(.*?)\n\}',
        re.DOTALL
    )

    all_policies = []

    for name, body in policy_pattern.findall(all_content):
        all_policies.append(("aws_iam_policy", name, body))
    for name, body in role_policy_pattern.findall(all_content):
        all_policies.append(("aws_iam_role_policy", name, body))
    for name, body in user_policy_pattern.findall(all_content):
        all_policies.append(("aws_iam_user_policy", name, body))
    for name, body in group_policy_pattern.findall(all_content):
        all_policies.append(("aws_iam_group_policy", name, body))

    for resource_type, policy_name, policy_body in all_policies:
        has_star_star = _check_policy_body_for_star_star(policy_body)

        if has_star_star:
            findings.append(create_finding(
                "IAC-AWS-IAM-01", "Terraform IAM Star Policy", "Critical",
                "FAIL", f"{resource_type}.{policy_name}",
                f"IAM policy '{policy_name}' ({resource_type}) grants Action: '*' on Resource: '*'. "
                "This is equivalent to full administrator access and violates the principle "
                "of least privilege.",
                "Restrict the policy to only the specific actions and resources required. "
                "Use separate policies for different access levels.",
                {"policy": policy_name, "resource_type": resource_type, "star_star": True}
            ))
        else:
            findings.append(create_finding(
                "IAC-AWS-IAM-01", "Terraform IAM Star Policy", "Low",
                "PASS", f"{resource_type}.{policy_name}",
                f"IAM policy '{policy_name}' does not grant full wildcard (*:*) access.",
                "No action required.",
                {"policy": policy_name, "resource_type": resource_type, "star_star": False}
            ))

    # Check policy document data sources
    for doc_name, doc_body in policy_doc_pattern.findall(all_content):
        has_star_star = _check_policy_document_for_star_star(doc_body)

        if has_star_star:
            findings.append(create_finding(
                "IAC-AWS-IAM-01", "Terraform IAM Policy Document Star", "Critical",
                "FAIL", f"data.aws_iam_policy_document.{doc_name}",
                f"IAM policy document '{doc_name}' contains a statement with Action: '*' "
                "and Resource: '*', granting full administrator access.",
                "Restrict actions and resources to only what is necessary.",
                {"policy_document": doc_name, "star_star": True}
            ))

    return findings


def _check_policy_body_for_star_star(body):
    """
    Check if a policy resource body contains a JSON policy with Action: * and Resource: *.
    Handles both heredoc and inline JSON policy definitions.
    """
    # Try to extract JSON policy from the body
    # Match heredoc: policy = <<EOF ... EOF or jsonencode patterns
    json_match = re.search(r'policy\s*=\s*<<-?\s*(\w+)\s*\n(.*?)\n\s*\1', body, re.DOTALL)
    if json_match:
        try:
            policy_json = json.loads(json_match.group(2))
            return _check_policy_json(policy_json)
        except (json.JSONDecodeError, ValueError):
            pass

    # Check for inline JSON string
    json_inline = re.search(r'policy\s*=\s*"(\{.*?\})"', body, re.DOTALL)
    if json_inline:
        try:
            policy_str = json_inline.group(1).replace('\\"', '"')
            policy_json = json.loads(policy_str)
            return _check_policy_json(policy_json)
        except (json.JSONDecodeError, ValueError):
            pass

    # Check for jsonencode() with inline HCL-style action/resource
    if re.search(r'actions\s*=\s*\[\s*"\*"\s*\]', body) and \
       re.search(r'resources\s*=\s*\[\s*"\*"\s*\]', body):
        effect_match = re.search(r'effect\s*=\s*"(\w+)"', body, re.IGNORECASE)
        if not effect_match or effect_match.group(1).lower() == "allow":
            return True

    return False


def _check_policy_document_for_star_star(body):
    """
    Check an aws_iam_policy_document data source for star-star statements.
    These use HCL syntax with statement blocks.
    """
    statement_blocks = re.findall(r'statement\s*\{(.*?)\}', body, re.DOTALL)

    for stmt in statement_blocks:
        effect_match = re.search(r'effect\s*=\s*"(\w+)"', stmt, re.IGNORECASE)
        effect = effect_match.group(1).lower() if effect_match else "allow"

        if effect != "allow":
            continue

        actions = re.search(r'actions\s*=\s*\[\s*"\*"\s*\]', stmt)
        resources = re.search(r'resources\s*=\s*\[\s*"\*"\s*\]', stmt)

        if actions and resources:
            return True

    return False


def _check_policy_json(policy):
    """Check a parsed JSON IAM policy for Action: * and Resource: *"""
    statements = policy.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect", "Allow") != "Allow":
            continue

        action = stmt.get("Action", "")
        resource = stmt.get("Resource", "")

        action_is_star = (action == "*") or (isinstance(action, list) and "*" in action)
        resource_is_star = (resource == "*") or (isinstance(resource, list) and "*" in resource)

        if action_is_star and resource_is_star:
            return True

    return False


def create_finding(rule_id, check, severity, status, res_id, desc, rem, evidence):
    """Helper to maintain Nebuloupe finding schema"""
    return {
        "finding_id": str(uuid.uuid4()),
        "rule_id": rule_id,
        "check": check,
        "severity": severity,
        "status": status,
        "cloud_provider": "aws",
        "category": "IaC IAM",
        "resource_type": "aws_iam_policy",
        "resource_id": res_id,
        "region": "N/A",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
