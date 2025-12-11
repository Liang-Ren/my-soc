# Playbook – Scenario 1: Account Takeover (Console Login)

## 1. Detection

- Trigger: Security Hub / GuardDuty finding about suspicious ConsoleLogin
- Supporting detections:
  - CloudTrail query for many failures then a success from same IP + user

## 2. Triage

- Confirm whether the user expected this login (contact user / ticket)
- Check:
  - Source IP / ASN / country
  - User agent (browser vs script)
  - Time of day / business hours

## 3. Containment

- Disable or lock the affected IAM user
- Revoke active sessions and access keys
- If using federated identity, revoke SSO sessions

## 4. Eradication

- Rotate credentials (passwords, access keys)
- Review and clean up any new IAM policies / roles created recently

## 5. Recovery

- Restore least-privilege access
- Add MFA if not already enabled

## 6. Lessons Learned

- Update baseline IAM guardrails (password policy, MFA requirements)
- Improve monitoring thresholds or alert routing if detection was too noisy/late.
