import json
import logging
import os
from typing import Any, Dict

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2 = boto3.client("ec2")

QUARANTINE_SG_ID = os.environ.get("QUARANTINE_SG_ID", "")


def _extract_instance_id(finding: Dict[str, Any]) -> str | None:
    resources = finding.get("Resources") or []
    for r in resources:
        if (r.get("Type") or "").lower() == "awsec2instance":
            # For EC2, Id is usually the instance ARN; the instance ID is the last segment
            rid = r.get("Id") or ""
            if rid.startswith("arn:"):
                return rid.split("/", 1)[-1]
            return rid
    return None


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    logger.info("Event: %s", json.dumps(event))

    if not QUARANTINE_SG_ID:
        logger.error("QUARANTINE_SG_ID is not set")
        return {"statusCode": 500, "body": "QUARANTINE_SG_ID not configured"}

    detail = event.get("detail") or {}
    findings = detail.get("findings") or []
    if not findings:
        logger.info("No findings in event")
        return {"statusCode": 200, "body": "No findings"}

    finding = findings[0]
    instance_id = _extract_instance_id(finding)
    if not instance_id:
        logger.warning("Could not determine instance ID from finding")
        return {"statusCode": 200, "body": "No instance to quarantine"}

    logger.info("Quarantining instance: %s", instance_id)

    # Replace all existing SGs with the quarantine SG
    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[QUARANTINE_SG_ID],
    )

    return {"statusCode": 200, "body": f"Quarantined instance {instance_id}"}
