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

Notes: In production, these queries would be encoded as SIEM/Security Lake **alert/analytics rules**; here they are shown as Insights/Athena/OpenSearch queries for validation, triage, and threat hunting. 

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

## 9. End-to-End Walkthroughs (Alert → Triage → Response)

These examples are designed for demos/interviews so you can clearly explain **what happens from the first alert to final response**.

### Walkthrough 1 – Account Takeover (Console Login)

1. **Initial alert (GuardDuty/Security Hub)**  
  - Simulate suspicious console activity (wrong passwords, login from unusual IP).  
  - GuardDuty raises findings like `UnauthorizedAccess:IAMUser/ConsoleLogin` or `Recon:IAMUser/NetworkPermissions`, which are aggregated in **Security Hub**.  
  - If severity is HIGH/CRITICAL, the finding also goes through **EventBridge → SNS kill-chain topic**.
2. **Triage / analysis (detections/)**  
  - Open `detections/cloudtrail_account_takeover.md`.  
  - Run the suggested **CloudWatch Logs Insights** or **Athena** queries against CloudTrail to:  
    - Confirm the exact **ConsoleLogin** pattern (many failures then success).  
    - Enrich with IP, UA, geo, and recent API calls by that principal.  
  - Decide whether this is truly suspicious vs. a user mistake.
3. **Response (playbooks/)**  
  - Open `playbooks/scenario1_account_takeover.md`.  
  - Walk through **Containment → Eradication → Recovery**: disable credentials, revoke sessions, rotate keys, reset MFA, notify user, and document the incident.

When you present this: emphasize how **GuardDuty gives the first signal**, and `detections/cloudtrail_account_takeover.md` + `playbooks/scenario1_account_takeover.md` give you a structured way to go from signal → root cause → action.

### Walkthrough 2 – Privilege Abuse (Over-Privileged IAM)

1. **Initial alert (Security Hub / Config / GuardDuty)**  
  - Make or simulate a risky IAM change (attach `*:*` permissions, create a new admin role, etc.).  
  - AWS managed standards in **Security Hub** and **Config rules** will flag non-compliant IAM policies; GuardDuty may also detect suspicious IAM activity.  
2. **Triage / analysis (detections/)**  
  - Open `detections/privilege_abuse.md`.  
  - Use the IAM-focused CloudTrail queries to:  
    - Identify **who** changed which policy, on which resource, and **when**.  
    - See whether the new privileges were actually used for sensitive APIs.  
3. **Response (playbooks/)**  
  - Open `playbooks/scenario2_privilege_abuse.md`.  
  - Follow the playbook to roll back risky IAM changes, validate legitimate business need, and harden IAM baselines.

When you present this: highlight how **compliance-style findings** (Security Hub, Config) turn into an **incident** once you see suspicious use of new privileges, and how the playbook standardizes the rollback.

### Walkthrough 3 – Public S3 Bucket Exposure

1. **Initial alert (Config / Security Hub)**  
  - Create or modify an S3 bucket to be public.  
  - **AWS Config** and **Security Hub** detect the public bucket and raise findings (e.g., S3.1 controls).  
2. **Triage / analysis (detections/)**  
  - Open `detections/public_s3_bucket.md`.  
  - Use the provided queries to:  
    - Confirm which bucket is public and which policy change caused it.  
    - Check access logs / CloudTrail to see whether the bucket has already been accessed externally.  
3. **Response (playbooks/)**  
  - Open `playbooks/scenario3_public_s3.md`.  
  - Execute the steps to immediately block public access, validate whether data was exposed, notify data owners, and plan longer-term remediations.

When you present this: stress that this is a **classic cloud data exposure** scenario and that you have a clear, repeatable runbook from alert to closure.

---

## 10. Next Steps/Extensions

- Automate/semi-auto manual response actions (containments/eradications/recovery) 
- Generate consolidated **kill-chain Incident** as per MITRE ATT&CK TTP patterns 
  - Define TTP/kill-chain pattern（YAML/JSON）
  - Tag findings with tactics
  - Daily **Lambda/Python** to pivot/group findings (in the last 1-3 months) by host/user  
  - Pattern Matched → HIGH Incident Triggered 
- **ML-driven** findings triage to HIGH Incident fully automated 
- **CloudGoat** simulates threats → Best practice responses 
