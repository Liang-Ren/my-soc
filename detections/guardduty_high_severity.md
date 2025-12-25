# Scenario 4: High-Severity GuardDuty Findings

- **Threat**: GuardDuty detects behavior strongly associated with compromise.
- **MITRE ATT&CK**: depends on specific finding type, e.g.
  - `Recon:EC2/Portscan` → `TA0043 – Reconnaissance`
  - `UnauthorizedAccess:EC2/SSHBruteForce` → `T1110 – Brute Force`
  - `CredentialAccess:IAMUser/AnomalousBehavior` → `T1078 – Valid Accounts`
- **When to use (triage)**: When multiple HIGH/CRITICAL GuardDuty findings are firing (and already sent through Security Hub / SNS in this lab), use these Athena queries to cluster by resource, finding type, and time window to see campaigns and kill‑chains instead of isolated alerts.

## Key log sources

- **GuardDuty** findings
- **VPC Flow Logs** / **CloudTrail** for context and correlation

## Example Athena query on GuardDuty findings (if exported to S3)

```sql
SELECT
  findingtype,
  severity,
  accountid,
  region,
  COUNT(*) as cnt
FROM guardduty_findings -- replace with your actual table name
WHERE severity >= 7
GROUP BY findingtype, severity, accountid, region
ORDER BY cnt DESC;
```

### How to get this table via Security Lake + Athena

1. **Enable Security Lake for Security Hub / GuardDuty** in the same region:
  - In the AWS console, go to **Security Lake → Data sources**.
  - Enable **Security Hub findings** (which already include GuardDuty, Config, Macie, Inspector, etc.).
  - Security Lake will start writing normalized findings into an S3 data lake and create a Glue database with tables.

2. **Find the Glue database and table names** created by Security Lake:
  - Go to **AWS Glue → Data Catalog → Databases**, look for a database like `amazon_security_lake_glue_db_...`.
  - Inside that database, look for the table that holds **security findings** (the exact name depends on your Security Lake setup).

3. **Query in Athena**:
  - Open **Athena**, select the Security Lake database in the top-left dropdown.
  - Use a query like the example above, but replace `guardduty_findings` with the real table name from step 2.
  - Optionally add extra filters (e.g. specific `findingtype` patterns like `UnauthorizedAccess:%` or `Recon:%`).

## Security Hub + Kill-chain

- All GuardDuty findings are sent to **Security Hub**.
- This lab configures an EventBridge rule:
  - Source: `aws.securityhub`
  - Detail-type: `Security Hub Findings - Imported`
  - Filter: `Severity.Label` in [`HIGH`, `CRITICAL`]
  - Target: SNS `my-soc-killchain-topic`

This gives you a simple **kill-chain notification path** for high-severity detections.
