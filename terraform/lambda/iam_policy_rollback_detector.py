import datetime
import json
import logging
import os
import uuid
from typing import Any, Dict

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

securityhub = boto3.client("securityhub")


def _get_account_id(detail: Dict[str, Any], event: Dict[str, Any]) -> str:
    account_id = (
        detail.get("recipientAccountId")
        or detail.get("userIdentity", {}).get("accountId")
        or event.get("account")
    )
    if not account_id:
        return "000000000000"
    return str(account_id)


def _build_finding(detail: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
    region = detail.get("awsRegion") or os.environ.get("AWS_REGION", "us-east-1")

    account_id = _get_account_id(detail, event)

    request_params = detail.get("requestParameters", {}) or {}
    policy_arn = request_params.get("policyArn", "unknown-policy")
    version_id = request_params.get("versionId", "unknown-version")

    event_id = detail.get("eventID") or event.get("id") or str(uuid.uuid4())
    principal_arn = detail.get("userIdentity", {}).get("arn", "unknown-principal")
    source_ip = detail.get("sourceIPAddress", "unknown-ip")
    event_time = detail.get("eventTime")

    # Security Hub default product for the account
    product_arn = f"arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default"

    now_iso = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    created_at = event_time or now_iso

    finding_id = f"{account_id}/iam-policy-rollback/{event_id}"

    finding: Dict[str, Any] = {
        "SchemaVersion": "2018-10-08",
        "Id": finding_id,
        "ProductArn": product_arn,
        "GeneratorId": "my-soc/iam-policy-rollback-detector",
        "AwsAccountId": account_id,
        "Types": [
            "TTPs/PrivilegeEscalation",
            "Effects/PrivilegeEscalation",
        ],
        "CreatedAt": created_at,
        "UpdatedAt": created_at,
        "Severity": {"Label": "HIGH"},
        "Title": "IAM policy default version rolled back to privileged version",
        "Description": (
            f"Principal {principal_arn} called SetDefaultPolicyVersion on {policy_arn}, "
            f"setting version {version_id} as default from IP {source_ip}. "
            "This may indicate IAM privilege escalation by policy rollback."
        ),
        "Resources": [
            {
                "Type": "AwsIamPolicy",
                "Id": policy_arn,
                "Region": region,
                "Partition": "aws",
                "Details": {
                    "Other": {
                        "PolicyVersion": version_id,
                        "EventId": event_id,
                        "EventSource": detail.get("eventSource", "iam.amazonaws.com"),
                    }
                },
            }
        ],
        "RecordState": "ACTIVE",
        "Workflow": {"Status": "NEW"},
    }

    return finding


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    logger.info("Received event: %s", json.dumps(event))

    detail = event.get("detail") or {}
    event_name = detail.get("eventName")

    if event_name != "SetDefaultPolicyVersion":
        logger.info("Ignoring eventName=%s", event_name)
        return {"statusCode": 200, "body": "Ignored non-SetDefaultPolicyVersion event"}

    try:
        finding = _build_finding(detail, event)
        response = securityhub.batch_import_findings(Findings=[finding])
        logger.info("batch_import_findings response: %s", json.dumps(response, default=str))
        return {"statusCode": 200, "body": "Finding imported"}
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("Failed to import finding: %s", exc)
        return {"statusCode": 500, "body": str(exc)}
