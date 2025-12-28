import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple
from urllib.parse import quote_plus

import boto3
from boto3.dynamodb.conditions import Attr


DDB = boto3.resource("dynamodb")
SNS = boto3.client("sns")

PROJECT_PREFIX = os.environ.get("PROJECT_PREFIX", "my-soc")
INCIDENT_TABLE_NAME = os.environ.get("INCIDENT_TABLE_NAME", "")
KILLCHAIN_SNS_TOPIC_ARN = os.environ.get("KILLCHAIN_SNS_TOPIC_ARN", "")


def _now_utc() -> datetime:
  return datetime.now(timezone.utc)


def _extract_host_id(finding: Dict[str, Any]) -> str | None:
  """Best-effort extraction of a host identifier from a Security Hub finding."""

  resources = finding.get("Resources") or []
  for r in resources:
    r_type = (r.get("Type") or "").strip()
    r_id = r.get("Id")

    if r_type in ("AwsEc2Instance", "AwsEc2NetworkInterface") and r_id:
      return r_id

  if resources:
    return resources[0].get("Id")

  return None


def _extract_tactics(finding: Dict[str, Any]) -> List[str]:
  """Derive a simple list of tactics from the finding's Types.

  This mirrors the daily aggregator's simple ATT&CK-style mapping so
  incidents are consistent regardless of whether they were created by
  rules or manual escalation.
  """

  tactics = set()

  for t in finding.get("Types") or []:
    parts = [p for p in t.split("/") if p]
    if parts:
      tactics.add(parts[-1])

  if not tactics:
    severity = (finding.get("Severity") or {}).get("Label") or "LOW"
    if severity.upper() in ("CRITICAL", "HIGH"):
      tactics.add("Execution")
    else:
      tactics.add("Discovery")

  return sorted(tactics)


def _build_finding_summary(finding: Dict[str, Any], region: str, tactics: List[str]) -> Dict[str, Any]:
  finding_id = finding.get("Id") or "<unknown-id>"

  encoded_id = quote_plus(finding_id)
  url = (
    f"https://{region}.console.aws.amazon.com/securityhub/home?region={region}"
    f"#/findings?search=id%3D{encoded_id}"
  )

  title = finding.get("Title") or "Security Hub finding"
  severity = (finding.get("Severity", {}) or {}).get("Label") or finding.get("SeverityLabel") or "UNKNOWN"

  return {
    "id": finding_id,
    "title": title,
    "severity": severity,
    "region": region,
    "url": url,
    "tactics": tactics,
  }


def _group_escalated_findings(event: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
  """Group escalated findings from the event by host.

  We don't enforce a tactics-count threshold here: if an analyst (or
  later ML) escalates the finding, we always respect that decision.
  """

  detail = event.get("detail") or {}
  findings = detail.get("findings") or []

  grouped: Dict[str, Dict[str, Any]] = {}
  default_region = event.get("region") or os.environ.get("AWS_REGION", "us-east-1")

  for f in findings:
    # Derive a stable host identifier; fall back to finding id if needed
    host_id = _extract_host_id(f) or f.get("Id") or "UNKNOWN-HOST"

    region = f.get("Region") or default_region
    tactics = _extract_tactics(f)

    host_entry = grouped.setdefault(
      host_id,
      {
        "tactics": set(),
        "findings": [],
        "region": region,
      },
    )

    host_entry["tactics"].update(tactics)
    host_entry["findings"].append(_build_finding_summary(f, region, tactics))

  return grouped


def _upsert_incident_for_host(
  table,
  host_id: str,
  host_data: Dict[str, Any],
  now_iso: str,
) -> Tuple[str, bool]:
  """Create or update an incident for a given host.

  Returns (incident_id, is_new).
  """

  tactics = sorted(list(host_data.get("tactics") or []))
  findings = host_data.get("findings") or []

  # Look for an existing OPEN incident for this host
  scan_resp = table.scan(
    FilterExpression=Attr("host_id").eq(host_id) & Attr("status").eq("OPEN"),
  )
  items = scan_resp.get("Items") or []

  if items:
    incident = items[0]
    incident_id = incident["incident_id"]

    table.update_item(
      Key={"incident_id": incident_id},
      UpdateExpression=(
        "SET findings = list_append(if_not_exists(findings, :empty), :new_f), "
        "findings_count = if_not_exists(findings_count, :zero) + :inc, "
        "updated_at = :now, "
        "tactics = :tactics"
      ),
      ExpressionAttributeValues={
        ":empty": [],
        ":new_f": findings,
        ":zero": 0,
        ":inc": len(findings),
        ":now": now_iso,
        ":tactics": tactics,
      },
    )

    return incident_id, False

  incident_id = str(uuid.uuid4())

  item = {
    "incident_id": incident_id,
    "project": PROJECT_PREFIX,
    "host_id": host_id,
    "created_at": now_iso,
    "updated_at": now_iso,
    "status": "OPEN",
    "tactics": tactics,
    "findings_count": len(findings),
    "findings": findings,
    "source": "ManualEscalation",
  }

  table.put_item(Item=item)

  return incident_id, True


def _send_sns_for_host(
  host_id: str,
  incident_id: str,
  host_data: Dict[str, Any],
  is_new: bool,
  now_iso: str,
) -> None:
  tactics = sorted(list(host_data.get("tactics") or []))
  findings = host_data.get("findings") or []
  region = host_data.get("region") or os.environ.get("AWS_REGION", "us-east-1")

  action = "NEW" if is_new else "UPDATED"

  subject = (
    f"[{PROJECT_PREFIX}] Escalated incident ({action}) for host {host_id} - "
    f"{len(tactics)} tactics, {len(findings)} newly escalated finding(s)"
  )[:100]

  lines = [
    f"Project: {PROJECT_PREFIX}",
    f"Region: {region}",
    f"Host: {host_id}",
    f"Incident ID: {incident_id}",
    f"Status: {'NEW (from escalation)' if is_new else 'EXISTING (appended from escalation)'}",
    f"Tactics (union): {', '.join(tactics) if tactics else 'N/A'}",
    f"Updated at: {now_iso}",
    "",
    "=== Newly escalated findings ===",
  ]

  for f in findings:
    lines.append(
      f"- [{f['severity']}] {f['title']} (Id: {f['id']}) -> {f['url']} | Tactics: {', '.join(f.get('tactics') or [])}"
    )

  lines.extend(
    [
      "",
      f"Incident record stored/updated in DynamoDB table: {INCIDENT_TABLE_NAME}",
      "Escalation source: Workflow.Status = NOTIFIED (manual or ML)",
    ]
  )

  body = "\n".join(lines)

  SNS.publish(TopicArn=KILLCHAIN_SNS_TOPIC_ARN, Subject=subject, Message=body)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
  if not INCIDENT_TABLE_NAME or not KILLCHAIN_SNS_TOPIC_ARN:
    return {"statusCode": 500, "body": "INCIDENT_TABLE_NAME or KILLCHAIN_SNS_TOPIC_ARN not set"}

  grouped = _group_escalated_findings(event)

  if not grouped:
    return {"statusCode": 200, "body": json.dumps({"message": "No findings to escalate"})}

  table = DDB.Table(INCIDENT_TABLE_NAME)
  now = _now_utc()
  now_iso = now.isoformat()

  processed_hosts = 0
  incidents_created = 0
  incidents_updated = 0

  for host_id, host_data in grouped.items():
    incident_id, is_new = _upsert_incident_for_host(table, host_id, host_data, now_iso)
    _send_sns_for_host(host_id, incident_id, host_data, is_new, now_iso)

    processed_hosts += 1
    if is_new:
      incidents_created += 1
    else:
      incidents_updated += 1

  return {
    "statusCode": 200,
    "body": json.dumps({
      "message": "Escalation processing completed",
      "hosts_with_escalations": processed_hosts,
      "incidents_created": incidents_created,
      "incidents_updated": incidents_updated,
    }),
  }
