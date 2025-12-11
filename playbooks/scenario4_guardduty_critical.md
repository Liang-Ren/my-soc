# Playbook – Scenario 4: Critical GuardDuty Finding

## 1. Detection

- Trigger: HIGH/CRITICAL GuardDuty finding routed via Security Hub → EventBridge → SNS (kill-chain topic)

## 2. Triage

- Identify resource(s) involved (EC2 instance, IAM user, access key)
- Validate severity and scope using additional logs (VPC Flow Logs, CloudTrail)

## 3. Containment

Depending on resource type:

- EC2:
  - Isolate instance via security group or stop instance
  - Snapshot volumes for forensics
- IAM user / key:
  - Disable key, revoke sessions, rotate credentials

## 4. Eradication

- Remove malicious software, unauthorized users, backdoors, and persistence mechanisms
- Patch vulnerabilities (use Inspector2 recommendations)

## 5. Recovery

- Restore services from clean AMIs / backups
- Re-enable connectivity with hardened controls

## 6. Lessons Learned

- Update detection rules / thresholds
- Improve network segmentation and access control
- Incorporate findings into tabletop exercises.
