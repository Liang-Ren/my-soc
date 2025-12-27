import json
import logging
from typing import Any, Dict

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")


def _extract_bucket_name(finding: Dict[str, Any]) -> str | None:
    resources = finding.get("Resources") or []
    for r in resources:
        if (r.get("Type") or "").lower() == "awss3bucket":
            details = r.get("Details") or {}
            s3_details = details.get("AwsS3Bucket") or {}
            name = s3_details.get("Name")
            if name:
                return name
            # Fallback to Id, which for S3 is often the bucket ARN
            rid = r.get("Id") or ""
            if rid.startswith("arn:") and ":s3:::" in rid:
                return rid.split(":s3:::", 1)[1]
    return None


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    logger.info("Event: %s", json.dumps(event))

    detail = event.get("detail") or {}
    findings = detail.get("findings") or []
    if not findings:
        logger.info("No findings in event")
        return {"statusCode": 200, "body": "No findings"}

    finding = findings[0]
    bucket = _extract_bucket_name(finding)
    if not bucket:
        logger.warning("Could not determine bucket name from finding")
        return {"statusCode": 200, "body": "No bucket to remediate"}

    logger.info("Applying public access block to bucket: %s", bucket)

    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    return {"statusCode": 200, "body": f"Remediated bucket {bucket}"}
