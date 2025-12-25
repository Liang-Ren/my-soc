# Scenario 1: Account Takeover via Console Login

- **Threat**: Stolen credentials used to log into the AWS console.
- **MITRE ATT&CK**:
  - Initial Access: `T1078 – Valid Accounts`
  - Defense Evasion: `T1078.004 – Cloud Accounts`
- **When to use (triage)**: After a GuardDuty / Security Hub alert about anomalous or suspicious console login activity, use these queries to validate many‑failures‑then‑success patterns and to investigate source IPs, geos, and user agents.

## Key log sources

- **CloudTrail**: `ConsoleLogin` events
- **GuardDuty**: findings like `UnauthorizedAccess:ConsoleLogin`

## Important CloudTrail fields

- `eventName` = `ConsoleLogin`
- `responseElements.ConsoleLogin` = `Success` / `Failure`
- `sourceIPAddress`
- `userIdentity.arn` / `userIdentity.userName`
- `userAgent`

## Sample CloudWatch Logs Insights query (CloudTrail)

```sql
fields @timestamp, userIdentity.arn, sourceIPAddress, userAgent, @message
| filter eventName = "ConsoleLogin"
| filter responseElements.ConsoleLogin = "Success"
| sort @timestamp desc
| limit 50
```

## Detection idea: many failures then success

```sql
fields @timestamp, userIdentity.arn as user, sourceIPAddress as src_ip, responseElements.ConsoleLogin as result
| filter eventName = "ConsoleLogin"
| stats
    count(*) as attempts,
    min(@timestamp) as first_seen,
    max(@timestamp) as last_seen
  by bin(15m), user, src_ip, result
| filter result = "Failure" and attempts >= 5
| sort last_seen desc
```

## GuardDuty mapping

Watch for GuardDuty findings such as:

- `UnauthorizedAccess:ConsoleLogin`
- `UnauthorizedAccess:IAMUser/ConsoleLogin`

All such findings are automatically sent to **Security Hub**, and then to the SNS topic in this lab for kill-chain reporting.
