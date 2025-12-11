# Playbook – Scenario 3: Public S3 Bucket

## 1. Detection

- Trigger: Config rule / Security Hub finding that S3 bucket is public
- Optionally correlated with CloudTrail events `PutBucketAcl` / `PutBucketPolicy`

## 2. Triage

- Identify the bucket owner / application
- Determine if any sensitive data is stored

## 3. Containment

- Immediately apply S3 Block Public Access
- Remove bucket policy statements with `Principal: "*"`
- If necessary, temporarily restrict all access while investigating

## 4. Eradication

- Implement proper access controls (VPC endpoints, IAM conditions, per-principal access)
- Clean up any third-party tools that require public access

## 5. Recovery

- Re-enable intended access paths only (e.g. private app, signed URLs)
- Add S3 guardrails (Config rules, SCPs) to prevent regressions
