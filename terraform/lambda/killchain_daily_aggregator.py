import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple
from urllib.parse import quote_plus

import boto3
from boto3.dynamodb.conditions import Attr


SECURITY_HUB = boto3.client("securityhub")
DDB = boto3.resource("dynamodb")
SNS = boto3.client("sns")

PROJECT_PREFIX = os.environ.get("PROJECT_PREFIX", "my-soc")
INCIDENT_TABLE_NAME = os.environ.get("INCIDENT_TABLE_NAME", "")
KILLCHAIN_SNS_TOPIC_ARN = os.environ.get("KILLCHAIN_SNS_TOPIC_ARN", "")
DAYS_LOOKBACK = int(os.environ.get("DAYS_LOOKBACK", "30"))


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

  This is a lightweight approximation: we take the last component of each
  Security Hub type string (which often aligns with ATT&CK-style categories),
  and fall back to generic labels when Types are missing.
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


def _paginate_findings() -> List[Dict[str, Any]]:
  """Fetch findings from Security Hub over the lookback window."""

  paginator = SECURITY_HUB.get_paginator("get_findings")

  filters: Dict[str, Any] = {
    "RecordState": [
      {"Value": "ACTIVE", "Comparison": "EQUALS"},
    ],
    "CreatedAt": [
      {"DateRange": {"Value": DAYS_LOOKBACK, "Unit": "DAYS"}},
    ],
  }

  findings: List[Dict[str, Any]] = []

  for page in paginator.paginate(Filters=filters):
    findings.extend(page.get("Findings", []))

  return findings


def _group_by_host_and_tactics(findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
  """Group findings by host and aggregate tactics per host."""

  grouped: Dict[str, Dict[str, Any]] = {}
  default_region = SECURITY_HUB.meta.region_name or os.environ.get("AWS_REGION", "us-east-1")

  for f in findings:
    host_id = _extract_host_id(f)
    if not host_id:
      continue

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
    f"[{PROJECT_PREFIX}] Kill-chain incident ({action}) for host {host_id} - "
    f"{len(tactics)} tactics, {len(findings)} finding(s)"
  )[:100]

  lines = [
    f"Project: {PROJECT_PREFIX}",
    f"Region: {region}",
    f"Host: {host_id}",
    f"Incident ID: {incident_id}",
    f"Status: {'NEW' if is_new else 'EXISTING (appended)'}",
    f"Tactics: {', '.join(tactics) if tactics else 'N/A'}",
    f"Updated at: {now_iso}",
    "",
    "=== Included findings (last window) ===",
  ]

  for f in findings:
    lines.append(
      f"- [{f['severity']}] {f['title']} (Id: {f['id']}) -> {f['url']} | Tactics: {', '.join(f.get('tactics') or [])}"
    )

  lines.extend(
    [
      "",
      f"Incident record stored/updated in DynamoDB table: {INCIDENT_TABLE_NAME}",
    ]
  )

  body = "\n".join(lines)

  SNS.publish(TopicArn=KILLCHAIN_SNS_TOPIC_ARN, Subject=subject, Message=body)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
  if not INCIDENT_TABLE_NAME or not KILLCHAIN_SNS_TOPIC_ARN:
    return {"statusCode": 500, "body": "INCIDENT_TABLE_NAME or KILLCHAIN_SNS_TOPIC_ARN not set"}

  findings = _paginate_findings()

  if not findings:
    return {"statusCode": 200, "body": json.dumps({"message": "No findings in lookback window"})}

  grouped = _group_by_host_and_tactics(findings)

  table = DDB.Table(INCIDENT_TABLE_NAME)
  now = _now_utc()
  now_iso = now.isoformat()

  processed_hosts = 0
  incidents_created = 0
  incidents_updated = 0

  for host_id, host_data in grouped.items():
    tactics = host_data.get("tactics") or set()

    # Only raise/append incidents when a host has 2+ distinct tactics
    if len(tactics) < 2:
      continue

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
      "message": "Kill-chain daily aggregation completed",
      "hosts_with_incidents": processed_hosts,
      "incidents_created": incidents_created,
      "incidents_updated": incidents_updated,
    }),
  }
