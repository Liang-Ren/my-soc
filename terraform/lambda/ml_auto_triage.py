import json
import logging
import os
from typing import Any, Dict, List

import boto3


LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

RUNTIME = boto3.client("sagemaker-runtime")
SECURITY_HUB = boto3.client("securityhub")

PROJECT_PREFIX = os.environ.get("PROJECT_PREFIX", "my-soc")
ENDPOINT_NAME = os.environ.get("SAGEMAKER_ENDPOINT_NAME", "my-soc-rf-endpoint")


_SEVERITY_MAP: Dict[str, float] = {
  "INFORMATIONAL": 0.0,
  "LOW": 1.0,
  "MEDIUM": 2.0,
  "HIGH": 3.0,
  "CRITICAL": 4.0,
}


def _build_feature_vector(finding: Dict[str, Any]) -> List[float]:
  """Derive a simple 10-dim numeric feature vector from a Security Hub finding.

  This is intentionally heuristic and for lab/demo purposes only.
  """

  severity_label = (
    (finding.get("Severity") or {}).get("Label")
    or finding.get("SeverityLabel")
    or "LOW"
  )
  sev = _SEVERITY_MAP.get(str(severity_label).upper(), 1.0)

  product_name = (finding.get("ProductName") or "").lower()
  title = (finding.get("Title") or "")
  description = (finding.get("Description") or "")

  resources = finding.get("Resources") or []
  resource_types = [
    (r.get("Type") or "").lower() for r in resources
  ]

  num_resources = float(len(resources))
  num_types = float(len(finding.get("Types") or []))

  is_guardduty = 1.0 if "guardduty" in product_name else 0.0
  is_config = 1.0 if "config" in product_name else 0.0

  title_len_norm = float(min(len(title), 300)) / 300.0
  desc_len_norm = float(min(len(description), 2000)) / 2000.0

  has_public = 1.0 if "public" in title.lower() or "public" in description.lower() else 0.0
  has_s3 = 1.0 if any("s3" in t for t in resource_types) else 0.0

  # 10 features total for the RandomForestClassifier
  return [
    float(sev),          # 0: severity bucket
    num_resources,       # 1: number of resources on the finding
    num_types,           # 2: number of Types attached
    is_guardduty,        # 3: is this a GuardDuty finding
    is_config,           # 4: is this a Config finding
    title_len_norm,      # 5: normalised title length
    desc_len_norm,       # 6: normalised description length
    has_public,          # 7: hint for exposure findings
    has_s3,              # 8: S3-related
    0.0,                 # 9: spare/dummy feature
  ]


def _invoke_endpoint(features: List[float]) -> float | None:
  if not ENDPOINT_NAME:
    LOGGER.error("SAGEMAKER_ENDPOINT_NAME is not configured")
    return None

  payload = ",".join(str(f) for f in features)

  try:
    resp = RUNTIME.invoke_endpoint(
      EndpointName=ENDPOINT_NAME,
      ContentType="text/csv",
      Body=payload.encode("utf-8"),
    )
  except Exception:
    LOGGER.exception("Error invoking SageMaker endpoint")
    return None

  body = resp.get("Body")
  if not body:
    LOGGER.error("Empty Body in SageMaker response")
    return None

  raw = body.read().decode("utf-8").strip()

  try:
    parsed = json.loads(raw)
  except json.JSONDecodeError:
    LOGGER.error("Failed to decode prediction JSON: %s", raw)
    return None

  if isinstance(parsed, list) and parsed:
    try:
      return float(parsed[0])
    except (TypeError, ValueError):
      LOGGER.error("Prediction is not numeric: %r", parsed[0])
      return None

  LOGGER.error("Unexpected prediction payload: %r", parsed)
  return None


def _should_escalate(score: float) -> bool:
  """Simple threshold over the model output.

  The demo RandomForestClassifier is trained on synthetic labels; we simply
  treat scores >= 0.5 as "escalate".
  """

  return score >= 0.5


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
  detail = event.get("detail") or {}
  findings = detail.get("findings") or []

  if not findings:
    return {"statusCode": 200, "body": json.dumps({"message": "No findings in event"})}

  escalated: List[str] = []
  skipped: List[Dict[str, Any]] = []

  for finding in findings:
    finding_id = finding.get("Id") or "<unknown>"
    workflow_status = ((finding.get("Workflow") or {}).get("Status") or "").upper()

    # Avoid looping: if already NOTIFIED, we don't touch it again.
    if workflow_status == "NOTIFIED":
      skipped.append({"id": finding_id, "reason": "already_notified"})
      continue

    features = _build_feature_vector(finding)
    score = _invoke_endpoint(features)
    if score is None:
      skipped.append({"id": finding_id, "reason": "invoke_failed"})
      continue

    if not _should_escalate(score):
      skipped.append({"id": finding_id, "reason": f"score={score}"})
      continue

    product_arn = finding.get("ProductArn")
    if not product_arn or finding_id == "<unknown>":
      skipped.append({"id": finding_id, "reason": "missing_product_arn_or_id"})
      continue

    try:
      SECURITY_HUB.batch_update_findings(
        FindingIdentifiers=[{"Id": finding_id, "ProductArn": product_arn}],
        Workflow={"Status": "NOTIFIED"},
        Note={
          "Text": f"[{PROJECT_PREFIX}] Auto-triaged by ML endpoint; score={score:.3f}",
          "UpdatedBy": f"{PROJECT_PREFIX}-ml-auto-triage",
        },
      )
      escalated.append(finding_id)
    except Exception:
      LOGGER.exception("Failed to update finding %s", finding_id)
      skipped.append({"id": finding_id, "reason": "batch_update_failed"})

  return {
    "statusCode": 200,
    "body": json.dumps({
      "escalated_findings": escalated,
      "skipped_findings": skipped,
    }),
  }
