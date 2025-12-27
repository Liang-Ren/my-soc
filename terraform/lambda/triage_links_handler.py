import json
import os
from typing import Dict, Any
from urllib.parse import quote_plus

import boto3

sns = boto3.client("sns")

TRIAGE_SNS_TOPIC_ARN = os.environ.get("TRIAGE_SNS_TOPIC_ARN", "")
PROJECT_PREFIX = os.environ.get("PROJECT_PREFIX", "my-soc")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")


SCENARIO_CONFIG: Dict[str, Dict[str, str]] = {
    "cloudtrail_account_takeover": {
        "title": "Account Takeover (Console Login)",
        "detection_doc": "detections/cloudtrail_account_takeover.md",
        "playbook_doc": "playbooks/scenario1_account_takeover.md",
        "query_hint": (
            "CloudTrail / CloudWatch Logs Insights: filter ConsoleLogin events for this principal, "
            "look for many failures then a success, and review subsequent API calls."
        ),
    },
    "privilege_abuse": {
        "title": "Privilege Abuse (Over-Privileged IAM)",
        "detection_doc": "detections/privilege_abuse.md",
        "playbook_doc": "playbooks/scenario2_privilege_abuse.md",
        "query_hint": (
            "CloudTrail / Athena: search for IAM policy changes (Put*Policy, Attach*Policy, CreatePolicy) "
            "around the time of this finding, and see if new privileges were used."
        ),
        "approve_rollback_hint": "To approve rollback, click the Approve link in this email.",
    },
    "public_s3_bucket": {
        "title": "Public S3 Bucket Exposure",
        "detection_doc": "detections/public_s3_bucket.md",
        "playbook_doc": "playbooks/scenario3_public_s3.md",
        "query_hint": (
            "Config / CloudTrail / Athena: identify which bucket became public, who changed it, "
            "and whether it has already been accessed externally."
        ),
    },
    "guardduty_high_severity": {
        "title": "High-Severity GuardDuty Campaign",
        "detection_doc": "detections/guardduty_high_severity.md",
        "playbook_doc": "playbooks/scenario4_guardduty_critical.md",
        "query_hint": (
            "GuardDuty / Athena: group recent HIGH/CRITICAL GuardDuty findings by resource, principal, "
            "and time to see potential kill-chain patterns or campaigns."
        ),
    },
}


def _classify_scenario(finding: Dict[str, Any]) -> str:
    """Best-effort mapping of a Security Hub finding to one of the 4 scenarios.

    This is intentionally simple for lab/demo purposes.
    """

    product_name = (finding.get("ProductName") or "").lower()
    title = (finding.get("Title") or "").lower()
    description = (finding.get("Description") or "").lower()
    types = finding.get("Types") or []
    resource_types = [
        (r.get("Type") or "").lower() for r in finding.get("Resources") or []
    ]

    # Scenario 3: public S3 bucket
    if any("awss3bucket" in rt for rt in resource_types) or "s3" in title:
        return "public_s3_bucket"

    # Scenario 1: console login / account takeover
    if "consolelogin" in title or "consolelogin" in description:
        return "cloudtrail_account_takeover"
    if any("unauthorizedaccess:iamuser/consolelogin" in t.lower() for t in types):
        return "cloudtrail_account_takeover"

    # Scenario 2: privilege abuse / IAM changes
    if "privilege" in title or "privilege" in description:
        return "privilege_abuse"
    if any("privilegeescalation" in t.lower() for t in types):
        return "privilege_abuse"
    if "iam" in product_name and ("policy" in title or "policy" in description):
        return "privilege_abuse"

    # Fallback: treat as general high-severity GuardDuty / campaign
    return "guardduty_high_severity"


def _build_email_body(scenario_key: str, finding: Dict[str, Any], event_region: str) -> str:
    cfg = SCENARIO_CONFIG.get(scenario_key, SCENARIO_CONFIG["guardduty_high_severity"])

    finding_id = finding.get("Id", "<unknown-id>")
    finding_title = finding.get("Title", "<no-title>")
    severity_label = (
        (finding.get("Severity") or {}).get("Label")
        or finding.get("SeverityLabel")
        or "<unknown>"
    )

    # Determine which region to show (event region preferred, then Lambda env)
    region = event_region or AWS_REGION

    # Best-effort Security Hub console URL for this finding
    if finding_id != "<unknown-id>":
        encoded_id = quote_plus(finding_id)
        securityhub_url = (
            f"https://{region}.console.aws.amazon.com/securityhub/home?region={region}"
            f"#/findings?search=id%3D{encoded_id}"
        )
    else:
        securityhub_url = (
            f"https://{region}.console.aws.amazon.com/securityhub/home?region={region}#/findings"
        )

    # Optional approve-rollback link for privilege abuse scenario (Scenario 2)
    approve_link = None
    if scenario_key == "privilege_abuse":
        api_id = os.environ.get("IAM_ROLLBACK_API_ID", "")
        if api_id:
            approve_link = (
                f"https://{api_id}.execute-api.{region}.amazonaws.com/approve-iam-rollback"
            )

    # Keep finding JSON short-ish to avoid very large emails
    finding_json = json.dumps(finding, indent=2)[:6000]

    lines = [
        f"Project: {PROJECT_PREFIX}",
        f"Region: {region}",
        "",
        "=== Initial Alert (from Security Hub) ===",
        f"Severity: {severity_label}",
        f"Finding ID: {finding_id}",
        f"Finding Title: {finding_title}",
        f"Security Hub finding URL (best-effort): {securityhub_url}",
        "",
        "=== Suggested Triage Scenario ===",
        f"Scenario: {cfg['title']}",
        f"Detections doc: {cfg['detection_doc']}",
        f"Playbook doc: {cfg['playbook_doc']}",
        "",
    ]

    # Optional approval section for scenario 2 (privilege abuse)
    if scenario_key == "privilege_abuse":
        lines.append("How to approve response (if applicable):")
        if approve_link:
            lines.append(f"- To approve IAM privilege rollback, click: {approve_link}")
        else:
            lines.append("- IAM rollback approval URL is not configured in this environment.")

    lines.extend([
        "",
        "How to triage now:",
        f"- {cfg['query_hint']}",
        "- Open the detections doc in your repo and copy the sample queries into CloudWatch Logs Insights / Athena / OpenSearch.",
        "- Then follow the corresponding playbook for containment / eradication / recovery.",
        "",
        "=== Raw Finding (truncated for reference) ===",
        finding_json,
    ])

    return "\n".join(lines)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    if not TRIAGE_SNS_TOPIC_ARN:
        # Misconfiguration – nothing we can do usefully
        return {"statusCode": 500, "body": "TRIAGE_SNS_TOPIC_ARN not set"}

    detail = event.get("detail") or {}
    findings = detail.get("findings") or []

    if not findings:
        return {"statusCode": 200, "body": "No findings in event"}

    # For simplicity, only process the first finding in the batch
    finding = findings[0]

    scenario_key = _classify_scenario(finding)
    cfg = SCENARIO_CONFIG.get(scenario_key, SCENARIO_CONFIG["guardduty_high_severity"])

    subject = (
        f"[{PROJECT_PREFIX}] Triage helper - {cfg['title']} "
        f"(Security Hub {finding.get('Id', '')})"
    )[:100]  # SNS subject limit

    event_region = event.get("region") or ""

    body = _build_email_body(scenario_key, finding, event_region)

    sns.publish(TopicArn=TRIAGE_SNS_TOPIC_ARN, Subject=subject, Message=body)

    return {"statusCode": 200, "body": "Triage email published"}
