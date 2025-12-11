# Scenario 2: Privilege Abuse (Over-Privileged IAM)

- **Threat**: An IAM user/role with excessive permissions (e.g. `*:*`) performs risky operations.
- **MITRE ATT&CK**:
  - Privilege Escalation: `T1068`, `T1098`
  - Defense Evasion: `T1078`

## Key log sources

- **CloudTrail**: API calls like `AttachUserPolicy`, `PutUserPolicy`, `AssumeRole`, `CreateAccessKey`, `DeleteTrail`, etc.
- **GuardDuty**: privilege-escalation related findings

## Important CloudTrail fields

- `eventName`
- `eventSource`
- `userIdentity.arn`
- `requestParameters.policyDocument` (look for `"Action": "*"`, `"Resource": "*"`)

## Sample CloudWatch Logs Insights query: detecting `*:*` policies

```sql
fields @timestamp, eventName, userIdentity.arn, requestParameters.policyDocument
| filter eventSource = "iam.amazonaws.com"
| filter eventName in ["PutUserPolicy", "PutRolePolicy", "CreatePolicyVersion", "AttachUserPolicy", "AttachRolePolicy"]
| filter requestParameters.policyDocument like '"Action":"*"'
  and requestParameters.policyDocument like '"Resource":"*"'
| sort @timestamp desc
| limit 50
```

## GuardDuty mapping

Look for findings such as:

- `PrivilegeEscalation:IAMUser/AdministrativePermissions`
- `Policy:IAMUser/RootCredentialUsage`

These map to privilege-abuse techniques and are surfaced via Security Hub in this lab.
