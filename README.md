# my-soc – Terraform SOC Lab (Threat Model → Detection → Response)

> Goal: Show pipeline **Threat Model → Detection → Response** on AWS using Terraform + native security services.

This repo defines a small **SOC lab** in AWS:

- **Assets**: 1 Application Load Balancer + 2 web servers (HTTP only, page says `"hello, Liang from my-soc."`)
- **Log sources**: VPC Flow Logs, CloudTrail, AWS Config (baseline), Security Hub, GuardDuty (CloudWatch Agent + DNS logs can be added as extensions)
- **Attack scenarios (4)**:
  1. Account takeover (ConsoleLogin)
  2. Privilege abuse (over-privileged IAM)
  3. Public S3 bucket
  4. High-severity GuardDuty findings
- **Outputs**:
  - Detections: ready-to-run queries and rule ideas (CloudWatch Logs Insights/Athena) under `detections/`
  - All findings flow into **Security Hub**, and HIGH/CRITICAL ones go to an **SNS kill-chain topic**
  - Playbooks (Containment/Eradication/Recovery) under `playbooks/`

---

## 1. Architecture Overview

High-level architecture:

- **Network & compute**
  - 1 VPC (`10.10.0.0/16`)
  - 2 public subnets (in 2 AZs)
  - 1 Application Load Balancer in front of 2 EC2 web servers
  - Web servers run a tiny Apache site returning `"hello, Liang from my-soc."`
- **Logging & detection**
  - CloudTrail → encrypted S3 log bucket + CloudWatch Logs
  - VPC Flow Logs → CloudWatch Logs
  - AWS Config recorder + S3 delivery + selected managed rules 
  - GuardDuty detector enabled
  - Security Hub enabled with CIS + Foundational Best Practices
  - Macie2 account + Inspector2 enabled for EC2/ECR/Lambda
- **Kill-chain notifications**
  - EventBridge rule listens for **Security Hub high/critical findings**
  - Matching findings are sent to an SNS topic `my-soc-killchain-topic`
  - You can subscribe email/SMS/HTTP endpoints for demo purposes

---

## 2. Terraform Layout

Directory: `terraform/`

- `providers.tf` – Terraform + AWS provider
- `variables.tf` – region, CIDRs, instance type, name prefix
- `networking_infra.tf` – VPC, public subnets, IGW, route tables, security groups, ALB, target group, 2 web EC2s
- `logging_and_security.tf` –
  - Encrypted S3 logs bucket (CloudTrail/Config)
  - CloudTrail (multi-region) + CloudWatch Logs
  - VPC Flow Logs → CloudWatch Logs
  - AWS Config recorder + delivery channel + S3 public access rules
  - GuardDuty, Security Hub, Macie2, Inspector2
  - EventBridge rule + SNS topic for Security Hub HIGH/CRITICAL findings (kill-chain path)
- `outputs.tf` – ALB DNS name, logs bucket name, GuardDuty detector ID, SNS topic ARN

### Quick Start

```bash
cd terraform

# (optional) customize region
# export TF_VAR_aws_region=us-east-1

terraform init
terraform plan
terraform apply
```

After apply finishes, Terraform will output:

- `alb_dns_name` – open in browser to see `hello, Liang from my-soc.`
- `logs_bucket_name` – where CloudTrail/Config logs go
- `securityhub_killchain_topic_arn` – SNS topic for high/critical findings

---

## 3. Detection Content (detections/)

Directory: `detections/`

For each scenario you have:

1. `cloudtrail_account_takeover.md`
   - Threat: stolen credentials used for Console login
   - MITRE: `T1078 Valid Accounts`, `T1078.004 Cloud Accounts`
   - Key fields: `eventName=ConsoleLogin`, `responseElements.ConsoleLogin`, `sourceIPAddress`, `userAgent`
   - Ready-to-run CloudWatch Insights query for "many failures then success" patterns
2. `privilege_abuse.md`
   - Threat: over-privileged IAM principal changing/using `*:*` policies
   - MITRE: `T1098 Account Manipulation`, `T1068 Exploitation for Privilege Escalation`
   - Key fields: IAM policy documents with `"Action":"*"` and `"Resource":"*"`
   - Query examples for dangerous IAM policy changes
3. `public_s3_bucket.md`
   - Threat: public S3 bucket used for data exposure/exfiltration
   - MITRE: `T1530 Data from Cloud Storage`, `T1567.002 Exfiltration to Cloud Storage`
   - Key: Config rules + CloudTrail `PutBucketAcl`/`PutBucketPolicy`
4. `guardduty_high_severity.md`
   - Threat: HIGH/CRITICAL GuardDuty findings
   - Mapping to various ATT&CK techniques depending on finding type
   - Example Athena query over exported GuardDuty findings

Notes: In production, these queries would be encoded as SIEM/Security Lake alert rules; here they are shown as Insights/Athena queries for validation and demo. 

---

## 4. Response Playbooks (playbooks/)

Directory: `playbooks/`

Each `.md` describes **Containment/Eradication/Recovery** for:

1. `scenario1_account_takeover.md` – ConsoleLogin takeover
2. `scenario2_privilege_abuse.md` – IAM privilege abuse
3. `scenario3_public_s3.md` – public S3 bucket exposure
4. `scenario4_guardduty_critical.md` – critical GuardDuty finding

In a real SOC, playbooks are not just documentation – they are often **codified and partially automated**:

- An orchestration layer (SOAR/Step Functions/Lambda/SSM Automation) encodes the playbook steps:
  - Automatically enrich context (asset info, owner, geo-IP, recent activity).
  - Perform **safe** actions (tag resources, open tickets, notify Slack/Teams).
  - For high‑confidence scenarios (e.g. clearly public S3 buckets), optionally perform **auto‑remediation** (block public access, revoke keys), often behind an approval step.
- Analysts keep a **human-readable runbook** (like the files in `playbooks/`) in sync with the executable workflow.

This lab focuses on making the response logic explicit in Markdown first; the next step would be to translate these playbooks into EventBridge → Lambda/SSM Automation/SOAR workflows, so that containment and eradication steps can be triggered automatically or with one‑click approval.

---

## 5. How Logs & Findings Flow

1. **Web traffic** hits ALB → EC2 web servers.
2. **VPC Flow Logs** capture network metadata for detection of scans/suspicious traffic.
3. **CloudTrail** records API activity (login attempts, IAM policy changes, S3 policy changes, etc.).
4. **AWS Config** continuously evaluates S3 public access rules.
5. **GuardDuty** analyzes CloudTrail, VPC Flow, DNS, etc. and generates findings.
6. **Security Hub** aggregates:
   - GuardDuty findings
   - Config rule violations/findings
   - Macie/Inspector issues/findings 
7. **EventBridge** rule matches HIGH/CRITICAL Security Hub findings and forwards them to **SNS kill-chain topic**.

This matches the end-to-end story: **Threat Model → Detection → Kill-chain report → (manual or automated) Response**.

---

## 6. How to Pitch This Project

- **One-liner**: "Built a Terraform-based AWS SOC lab (ALB + web servers) with CloudTrail, VPC Flow Logs, Config, GuardDuty, Security Hub, and kill-chain notifications, plus detection content and IR playbooks mapped to MITRE ATT&CK."
- **Problem you solve**: Provide a reproducible lab to test and demonstrate cloud threat detection and incident response workflows.
- **Tech stack**: Terraform, AWS (VPC, EC2, ALB, S3, CloudTrail, Config, GuardDuty, Security Hub, Macie2, Inspector2, SNS, EventBridge).
- **Talking points**:
  - How each log source contributes to detection
  - How Security Hub + EventBridge + SNS form a simple kill-chain pipeline
  - How you mapped scenarios to MITRE and wrote playbooks for Containment/Eradication/Recovery.

---

## 7. Next Steps/Extensions

- Add **CloudWatch Agent** on web servers to push OS/app logs
- Enable **Route 53 Resolver query logging** for DNS visibility
- Export logs to **Athena/OpenSearch** for deeper correlation
- Automate manual analysis/query/detections parts (queries in CloudWatch Insights/Athena) 
- Automate/semi-auto manual response actions (containments/eradications/recovery) 
- Generate consolidated **kill-chain Incident** as per MITRE ATT&CK TTP patterns 
  - Define TTP/kill-chain pattern（YAML/JSON）
  - Tag findings with tactics
  - Daily **Lambda/Python** to pivot/group findings (in the last 1-3 months) by host/user  
  - Pattern Matched → HIGH Incident Triggered 
- **ML-driven** findings triage to HIGH Incident fully automated 
- **CloudGoat** simulates threats → Best practice **GCFR** responses 
- Integrate with ticketing/chat (e.g. send SNS notifications into Slack, Jira) 
