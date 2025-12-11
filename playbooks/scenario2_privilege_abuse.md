# Playbook – Scenario 2: Privilege Abuse

## 1. Detection

- Trigger: Security Hub / GuardDuty finding related to privilege escalation
- Supporting detections:
  - CloudTrail queries for policy changes that introduce `Action: "*"` and `Resource: "*"`

## 2. Triage

- Identify the IAM user/role behind the change
- Check change ticket / change window

## 3. Containment

- Detach or revert the risky policy
- If necessary, disable the principal or remove its ability to assume high-privilege roles

## 4. Eradication

- Replace broad policies with least-privilege ones
- Review other principals for similar misconfigurations

## 5. Recovery

- Validate that necessary business functions still work with new policies
- Document approved privileged roles and access request process
