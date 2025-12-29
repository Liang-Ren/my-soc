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

- **Manual escalation from findings (Workflow.Status = NOTIFIED)**  
  - Implemented by `aws_lambda_function.escalate_finding_to_incident` in `terraform/incident_manager.tf` + `terraform/lambda/escalate_finding_to_incident.py`.  
  - When an analyst opens a Security Hub finding and sets **Workflow.Status = NOTIFIED**, an EventBridge rule `aws_cloudwatch_event_rule.securityhub_escalated` forwards that event to the escalation Lambda.  
  - The Lambda groups the escalated findings by host, creates a new **OPEN** incident (or appends to an existing one) in the same DynamoDB table `${var.project_prefix}-killchain-incidents`, and sends an email via the kill-chain SNS topic describing the newly escalated findings.  
  - This makes "Escalated to Incident" a simple UI action: change Workflow to NOTIFIED, and the system immediately turns the finding into a tracked incident.

Together, these give you consolidated kill-chain **Incidents** per host, both from rule-based daily aggregation and from on-demand analyst escalation, all stored in DynamoDB and surfaced via email.

---

## 10. ML-driven Triage (Finding to Incident Automatically)

This lab includes the **training side** of an ML model that can later be used to decide
whether a single Security Hub finding should be escalated to an incident automatically.

- **Model shape**: a real `RandomForestClassifier` implemented with scikit-learn.
- **Training data**: synthetic binary classification data generated inside the script
  (no need to manage a separate dataset for this demo).
- **Training script**: `ml/train_random_forest.py`.
- **Model export**: SageMaker writes the trained model artifact to the S3 bucket
  `${var.project_prefix}-ml-models-${account_id}` under the `artifacts/` prefix.

### 10.1 Infrastructure Terraform creates

Implemented in `terraform/ml_training.tf`:

- An S3 bucket for models: `${var.project_prefix}-ml-models-${account_id}`.
- A SageMaker execution role `aws_iam_role.sagemaker_execution` with permissions to:
  - Read/write the ML models bucket.
  - Write training logs to `/aws/sagemaker/*` in CloudWatch Logs.
- An S3 object `aws_s3_object.ml_training_code` that uploads your local
  `ml/train_random_forest.tar.gz` to the bucket under `code/train_random_forest.tar.gz`.

After `terraform apply` succeeds, the **code and IAM role are ready**, but we
start the actual SageMaker training job via AWS CLI.

### 10.2 Start the SageMaker training job (PowerShell + AWS CLI)

Prerequisites:

- You have already run `terraform apply` in `terraform/`.
- `ml/train_random_forest.tar.gz` exists locally and was uploaded by Terraform
  as `code/train_random_forest.tar.gz` into the ML models bucket.
- AWS CLI is installed and configured to use the same account/region.

Steps (run in PowerShell):

```powershell
$jobName = "my-soc-random-forest"   
$region  = "us-east-1"            
$accountId = (aws sts get-caller-identity --query Account --output text)
$roleArn = "arn:aws:iam::$accountId:role/my-soc-sagemaker-execution-role"
$bucket  = "my-soc-ml-models-$accountId"
$codeKey = "code/train_random_forest.tar.gz"
$image   = "683313688378.dkr.ecr.$region.amazonaws.com/sagemaker-scikit-learn:1.0-1-cpu-py3"
aws sagemaker create-training-job `
  --region $region `
  --training-job-name $jobName `
  --role-arn $roleArn `
  --algorithm-specification TrainingImage=$image,TrainingInputMode=File `
  --resource-config InstanceType=ml.m5.large,InstanceCount=1,VolumeSizeInGB=10 `
  --stopping-condition MaxRuntimeInSeconds=3600 `
  --output-data-config S3OutputPath=s3://$bucket/artifacts/ `
  --hyper-parameters "n-estimators=100,max-depth=5,sagemaker_program=train_random_forest.py,sagemaker_submit_directory=s3://$bucket/$codeKey"
```

What happens:
- SageMaker launches the official scikit-learn container in your account.
- The container downloads your training script tarball from `s3://$bucket/$codeKey`.
- The script generates synthetic data, trains a `RandomForestClassifier`, and saves
  the model into `/opt/ml/model/model.joblib`.
- SageMaker uploads `/opt/ml/model` as a tarball to `s3://$bucket/artifacts/...`.

### 10.3 Deploy a real-time inference endpoint (SageMaker)

Once the training job `my-soc-random-forest` has completed successfully and
written `model.tar.gz` into the ML models bucket, you can expose a real-time
inference API using a SageMaker endpoint.

#### 10.3.1. **Create a SageMaker model** (binds the artifact + image + entrypoint):

   The scikit-learn container needs to know **which Python script to run** and
   where to download it from. We point it at the same training script tarball
   used for training and set the entrypoint to `train_random_forest.py`.

   ```powershell
   $region    = "us-east-1"
   $accountId = (aws sts get-caller-identity --query Account --output text)
   $bucket    = "my-soc-ml-models-$accountId"
   $modelName = "my-soc-rf-model"
   $image     = "683313688378.dkr.ecr.$region.amazonaws.com/sagemaker-scikit-learn:1.0-1-cpu-py3"
   $roleArn   = aws iam get-role --role-name my-soc-sagemaker-execution-role --query "Role.Arn" --output text
   $modelData       = "s3://$bucket/artifacts/my-soc-random-forest/output/model.tar.gz"
   $submitDirectory = "s3://$bucket/code/train_random_forest.tar.gz"
   $primaryContainer = "Image=$image,ModelDataUrl=$modelData,Environment={SAGEMAKER_PROGRAM=train_random_forest.py,SAGEMAKER_SUBMIT_DIRECTORY=$submitDirectory}"
   aws sagemaker create-model `
     --region $region `
     --model-name $modelName `
     --primary-container $primaryContainer `
     --execution-role-arn $roleArn
   ```

#### 10.3.2. **Create an endpoint config** (instance type/count, traffic routing):

   ```powershell
   $configName = "my-soc-rf-endpoint-config"
   aws sagemaker create-endpoint-config `
     --region $region `
     --endpoint-config-name $configName `
     --production-variants "VariantName=AllTraffic,ModelName=$modelName,InitialInstanceCount=1,InstanceType=ml.m5.large"
   ```

#### 10.3.3. **Create the real-time endpoint** (the actual API):

   ```powershell
   $endpointName = "my-soc-rf-endpoint"
   aws sagemaker create-endpoint `
     --region $region `
     --endpoint-name $endpointName `
     --endpoint-config-name $configName
   ```

   Wait until the endpoint status becomes `InService` in the SageMaker console
   or via `aws sagemaker describe-endpoint`.

#### 10.3.4. **Call the endpoint for a prediction** (example, CSV input):

   The default scikit-learn container expects tabular features, commonly as a
   single CSV line. Assuming the model was trained on 10 numeric features:

   ```powershell
   $endpointName = "my-soc-rf-endpoint"
   $region       = "us-east-1"
   aws sagemaker-runtime invoke-endpoint `
     --region $region `
     --endpoint-name $endpointName `
     --content-type text/csv `
     --body fileb://ml/payload.csv `
     ml/output.json
   Get-Content .\ml\output.json
   ```

### 10.4 ML Auto-Triage from Security Hub Findings

Terraform now wires an **ML auto-triage Lambda** that calls this SageMaker
endpoint for **every imported Security Hub finding**:

- Implemented by `aws_lambda_function.ml_auto_triage` in `terraform/triage_automation.tf` + `terraform/lambda/ml_auto_triage.py`.
- Triggered by `aws_cloudwatch_event_rule.securityhub_all_for_ml`, which matches all
  `Security Hub Findings - Imported` events (all severities).
- For each finding, the Lambda:
  - Extracts a simple 10-dimension feature vector (severity bucket, number of resources,
    product hints, title/description length, S3/public hints, etc.).
  - Calls the SageMaker endpoint (`my-soc-rf-endpoint` by default) using
    `sagemaker-runtime.invoke_endpoint` with `text/csv` payload.
  - Interprets the model output as a score (e.g., `[0]` or `[1]`) and, if the score
    exceeds a simple threshold, sets `Workflow.Status = NOTIFIED` on that finding via
    `securityhub.batch_update_findings` and adds a **Note** indicating it was
    auto-triaged by ML.
  - Skips findings that are already `Workflow.Status = NOTIFIED` to avoid loops with
    the manual escalation pipeline.

Once a finding is updated to `Workflow.Status = NOTIFIED`, the **existing** EventBridge
rule `aws_cloudwatch_event_rule.securityhub_escalated` and the
`escalate_finding_to_incident` Lambda (Section 9) treat it exactly the same as a
manual analyst escalation: a kill-chain incident is created/updated in DynamoDB and a
consolidated incident email is sent via the kill-chain SNS topic.

### 10.5 Notes on Terraform Rebuild (Destroy & Apply)

The following manual CLI needed after **Destroy** 
- 10.2 aws sagemaker create-training-job (if re-training for new model.tar.gz)
- 10.3.1–10.3.3 create-model / create-endpoint-config / create-endpoint
- 10.3.4 invoke-endpoint verification (optional)

---

## 11. Next Steps/Extensions
 
- Use **CloudGoat** to simulate realistic threats and validate best-practice responses.
