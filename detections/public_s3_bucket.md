# Scenario 3: Public S3 Bucket

- **Threat**: A storage bucket containing sensitive data is accidentally exposed to the internet.
- **MITRE ATT&CK**:
  - Collection: `T1530 – Data from Cloud Storage`
  - Exfiltration: `T1567.002 – Exfiltration to Cloud Storage`

## Key log sources

- **AWS Config**: rules `S3_BUCKET_PUBLIC_READ_PROHIBITED`, `S3_BUCKET_PUBLIC_WRITE_PROHIBITED`
- **CloudTrail**: `PutBucketAcl`, `PutBucketPolicy`

## Important CloudTrail fields

- `eventName` in [`PutBucketAcl`, `PutBucketPolicy`]
- `requestParameters.AccessControlPolicy` / `requestParameters.AccessControlList`
- `requestParameters.policy` (look for `"Principal": "*"`)

## Sample CloudWatch Logs Insights query: risky S3 policy/Acl changes

```sql
fields @timestamp, eventName, userIdentity.arn, requestParameters.bucketName, requestParameters.policy
| filter eventSource = "s3.amazonaws.com"
| filter eventName in ["PutBucketAcl", "PutBucketPolicy"]
| filter requestParameters.policy like '"Principal":"*"'
| sort @timestamp desc
| limit 50
```

## Config / Security Hub integration

- Config rules in this lab automatically flag public S3 buckets.
- Security Hub ingests these as findings and forwards **HIGH/CRITICAL** ones to the SNS kill-chain topic.
