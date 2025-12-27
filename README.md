# my-soc: Terraform SOC Lab (Threat Model → Detection → Response/Automation/MITRE/ML)

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

## 3. Triage & Analysis Content (detections/)

Directory: `detections/`

These are **second-stage triage / analysis queries** you run **after an initial alert** from GuardDuty / Security Hub. They help you confirm, scope, and understand the root cause of an incident.

For each scenario you have:

1. `cloudtrail_account_takeover.md`
  - Threat: stolen credentials used for Console login
  - MITRE: `T1078 Valid Accounts`, `T1078.004 Cloud Accounts`
  - When to use: after a GuardDuty / Security Hub login‑related alert (e.g. anomalous console login, brute force) to validate "many failures then success" patterns and investigate IPs / devices.
2. `privilege_abuse.md`
  - Threat: over-privileged IAM principal changing/using `*:*` policies
  - MITRE: `T1098 Account Manipulation`, `T1068 Exploitation for Privilege Escalation`
  - When to use: after a privilege‑escalation / new‑admin‑role type finding in GuardDuty / Security Hub to review exact IAM policy changes.
3. `public_s3_bucket.md`
  - Threat: public S3 bucket used for data exposure/exfiltration
  - MITRE: `T1530 Data from Cloud Storage`, `T1567.002 Exfiltration to Cloud Storage`
  - When to use: after Config / Security Hub flags a public S3 bucket to confirm which bucket, who changed it, and potential exposure window.
4. `guardduty_high_severity.md`
  - Threat: HIGH/CRITICAL GuardDuty findings
  - Mapping to various ATT&CK techniques depending on finding type
  - When to use: when there are multiple high‑severity findings and you want to group them by resource / type / time (via Athena) to see campaigns or kill‑chain patterns.

**End-to-end usage (Alert → Triage → Response)**

Each detection file is meant to be used in an end‑to‑end flow:

- **Scenario 1 – Account takeover**: GuardDuty / Security Hub raises login‑related findings → you triage with `cloudtrail_account_takeover.md` (ConsoleLogin patterns, IP/UA/geo, follow‑up API calls) → you execute response steps in `playbooks/scenario1_account_takeover.md`.
- **Scenario 2 – Privilege abuse**: Security Hub / Config / GuardDuty flags risky IAM changes → you triage with `privilege_abuse.md` (who changed which policy, and how it was used) → you follow `playbooks/scenario2_privilege_abuse.md` to roll back permissions and harden IAM.
- **Scenario 3 – Public S3 bucket**: Config / Security Hub detects a public bucket → you triage with `public_s3_bucket.md` (which bucket, who changed it, whether it was accessed) → you run `playbooks/scenario3_public_s3.md` to block public access and assess exposure.
- **Scenario 4 – High‑severity GuardDuty campaign**: multiple HIGH/CRITICAL GuardDuty findings fire → you triage with `guardduty_high_severity.md` (group by resource / principal / time via Athena) → you apply `playbooks/scenario4_guardduty_critical.md` to contain impacted resources.

Notes: In production, these queries would be encoded as SIEM/Security Lake **alert/analytics rules**; here they are shown as Insights/Athena/OpenSearch queries for validation, triage, and threat hunting. 

---

## 4. Response Playbooks & Automation (playbooks/ + Lambda)

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

In this lab, several response actions are already automated or semi-automated with Terraform + Lambda (see `terraform/response_automation.tf` + `terraform/lambda/`):

-- **Scenario 1 – Account Takeover**  
  - Stays fully manual by design: you follow `playbooks/scenario1_account_takeover.md` step by step (disable credentials, revoke sessions, reset MFA, notify user, etc.).

- **Scenario 2 – Privilege Abuse (semi-automatic rollback)**  
  - An HTTP API `aws_apigatewayv2_api.iam_rollback_api` fronts the Lambda `iam_privilege_rollback_stub.py`.  
  - For privilege-abuse findings, the triage email contains an **“Approve IAM rollback”** link that calls this API.  
  - Today the Lambda only logs that an approval was received (good for demoing the approval flow); you can extend it to implement real IAM policy rollback so the "revert permissions" step in the playbook becomes one-click.

- **Scenario 3 – Public S3 Bucket (auto-remediation)**  
  - Security Hub S3 public findings (resource type `AwsS3Bucket`) trigger the EventBridge rule `aws_cloudwatch_event_rule.s3_public_auto_remediate`.  
  - That rule calls the Lambda `s3_public_auto_remediate.py`, which parses the bucket name from the finding and runs `PutBucketPublicAccessBlock` (all four Block flags set to true) to close public access.  
  - This fully automates the "immediately block public access" step from `playbooks/scenario3_public_s3.md`, so analysts can focus on data exposure assessment.

- **Scenario 4 – High-Severity GuardDuty / EC2 (semi-automatic quarantine)**  
  - Defines a Security Hub custom action `aws_securityhub_action_target.quarantine_ec2` (shown in the console with a short name like `my-soc-q-ec2`).  
  - When an analyst clicks this action on a finding with an EC2 resource, the EventBridge rule `aws_cloudwatch_event_rule.securityhub_quarantine_ec2` triggers the Lambda `quarantine_ec2.py`, which replaces the instance’s security groups with the isolation SG `aws_security_group.quarantine`.  
  - This upgrades the "quarantine affected host" step in `playbooks/scenario4_guardduty_critical.md` from fully manual to "human click, system executes".

In short:

- **Alert**: GuardDuty / Security Hub remain the initial alert sources.  
- **Triage**: `triage_automation.tf` + detections/ provide semi-automatic triage links and queries.  
- **Response**: `response_automation.tf` turns key playbook actions (closing public S3, quarantining EC2, approving IAM rollback) into one-click or fully automated workflows.

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

## 6. Advanced Logging & Analytics (New Modules)

These pieces are implemented in `terraform/advanced_logging.tf` and by updating the web EC2 instances:

- **CloudWatch Agent on web servers (OS/app logs)**
  - CloudWatch Logs → `/aws/my-soc/web-os` and `/aws/my-soc/web-app` to see OS and HTTP logs per instance.

- **Route 53 Resolver query logging for DNS visibility**
  - CloudWatch Logs → `/aws/my-soc/route53-resolver` to see DNS queries from resources in the VPC.

- **Athena + Glue Catalog foundation for deeper correlation**
  - Go to Glue Crawler → setup table data source → data formalized → advanced correlation at SQL level ready 
  - Go to Athema query whatever you want in DB `my-soc_security_logs`.

- **OpenSearch for full-text search and dashboards**
  - Stream CloudWatch Logs into OpenSearch for your full-text search and correlation query.
  - Manually setup observability search and security analytics → Indexing → SIEM Query → Alerting 

---

## 7. Semi-Automatic Triage & Analysis (Lambda + SNS)

Implemented in `terraform/triage_automation.tf` + `terraform/lambda/triage_links_handler.py`.

- **Trigger**: existing EventBridge rule for HIGH/CRITICAL Security Hub findings now also invokes a Lambda (`my-soc-triage-links`).
- **Logic**: the Lambda inspects the finding and classifies it into one of the 4 lab scenarios:
  - Account takeover → `detections/cloudtrail_account_takeover.md` / `playbooks/scenario1_account_takeover.md`
  - Privilege abuse → `detections/privilege_abuse.md` / `playbooks/scenario2_privilege_abuse.md`
  - Public S3 bucket → `detections/public_s3_bucket.md` / `playbooks/scenario3_public_s3.md`
  - Other high-severity GuardDuty → `detections/guardduty_high_severity.md` / `playbooks/scenario4_guardduty_critical.md`
- **Output**: publishes an email to SNS topic `${var.project_prefix}-triage-topic` (subscribed to `liang.ren@live.ca`) containing:
  - Severity, finding ID, and a **Security Hub finding URL** (best-effort deep link).
  - Which scenario to use, and which detections/playbook docs to open.
  - Short triage hints (which log sources / queries to run).

This turns the detections/ content into a **semi-automatic triage helper**: once an alert fires, you receive an email that points you directly to the right scenario, finding page, and analysis steps.

---

## 8. How to Pitch This Project

- **One-liner**: "Built a Terraform-based AWS SOC lab (ALB + web servers) with CloudTrail, VPC Flow Logs, Config, GuardDuty, Security Hub, and kill-chain notifications, plus detection content and IR playbooks mapped to MITRE ATT&CK."
- **Problem you solve**: Provide a reproducible lab to test and demonstrate cloud threat detection and incident response workflows.
- **Tech stack**: Terraform, AWS (VPC, EC2, ALB, S3, CloudTrail, Config, GuardDuty, Security Hub, Macie2, Inspector2, SNS, EventBridge).
- **Talking points**:
  - How each log source contributes to detection
  - How Security Hub + EventBridge + SNS form a simple kill-chain pipeline
  - How you mapped scenarios to MITRE and wrote playbooks for Containment/Eradication/Recovery.

---

## 9. Build a consolidated **kill-chain Incident**

This lab now has a **simulated Incident Manager** built from Security Hub + Lambda + DynamoDB + SNS:

- **Daily consolidated kill-chain view (second-level alert)**  
  - Implemented by `aws_lambda_function.killchain_daily_aggregator` in `terraform/incident_manager.tf` + `terraform/lambda/killchain_daily_aggregator.py`.  
  - Tag findings with **tactics** by parsing `Finding.Types`.  
  - Run a daily **Lambda** job every 24 hours to pull ACTIVE Security Hub findings over the last 1 month, then group them by **host** and aggregated **tactics**.  
  - When a host has findings involving **2 or more distinct tactics**, raise or append to an incident in the DynamoDB table `${var.project_prefix}-killchain-incidents` and send a consolidated email via the kill-chain SNS topic.  
  - If a host already has an open incident (`status = OPEN`), the Lambda **attaches the new findings group to that incident** (updates `findings` and `tactics`) instead of creating a new one.

This gives you a consolidated kill-chain **Incident** per host, summarizing multi-tactic activity over time in DynamoDB and email.

---

## 10. Next Steps/Extensions
 
- Add **ML-driven** triage to promote suspicious finding clusters to HIGH incidents automatically. 
- Use **CloudGoat** to simulate realistic threats and validate best-practice responses.
