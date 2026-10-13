# AWS AI Discovery Agent — Read-Only Cloud AI Inventory & Governance POC

A complete, production-grade Proof of Concept (POC) that discovers AI and Machine Learning resources across AWS accounts using Boto3, inspects non-sensitive configuration and metadata, normalizes findings into a canonical schema, persists inventory in SQLite via SQLAlchemy, evaluates assets for **Shadow AI** risks, and visualizes findings in a modern executive Streamlit dashboard.

---

## Table of Contents
1. [Executive Summary & Capabilities](#1-executive-summary--capabilities)
2. [Architecture & Discovery Layers](#2-architecture--discovery-layers)
3. [Safety & Security Constraints](#3-safety--security-constraints)
4. [Prerequisites & Installation](#4-prerequisites--installation)
5. [Quick Start: Offline Mock Mode](#5-quick-start-offline-mock-mode)
6. [Live AWS Discovery](#6-live-aws-discovery)
7. [Streamlit Dashboard Walkthrough](#7-streamlit-dashboard-walkthrough)
8. [CLI Reference](#8-cli-reference)
9. [Database Schema & Sample Queries](#9-database-schema--sample-queries)
10. [Confidence Scoring & Explainable Risk Framework](#10-confidence-scoring--explainable-risk-framework)
11. [Shadow AI Detection & Governance](#11-shadow-ai-detection--governance)
12. [Least-Privilege IAM Policy](#12-least-privilege-iam-policy)
13. [Discovery Gaps & Technical Limitations](#13-discovery-gaps--technical-limitations)
14. [Testing Suite](#14-testing-suite)
15. [Troubleshooting Guide](#15-troubleshooting-guide)

---

## 1. Executive Summary & Capabilities

AWS does not offer a single API that conclusively catalogs every AI workload. Organizations frequently accumulate ungoverned AI assets:
- **Managed AI:** Fine-tuned Bedrock models, SageMaker endpoints, Lex bots, Comprehend classifiers.
- **Custom AI Hosting:** EC2 GPU instances (`g5`, `p4`, `inf2`), ECS containers running vLLM/Triton, or oversized Lambda functions.
- **External AI Integrations:** Serverless Lambdas or API Gateways embedding API keys and sending corporate data to third-party providers (OpenAI, Anthropic, Cohere, Pinecone).

The **AWS AI Discovery Agent** addresses this challenge through non-destructive, read-only multi-service enumeration, strict least-privilege principles, transparent evidence logging, and an explainable governance engine.

---

## 2. Architecture & Discovery Layers

```
                      +-----------------------------------+
                      |      AWS AI Discovery Engine      |
                      +-----------------------------------+
                                       |
       +-------------------------------+-------------------------------+
       |                               |                               |
[Layer 1: Direct APIs]     [Layer 2: Resource Explorer]     [Layer 3: Config Inspection]
  - Amazon Bedrock           - Cross-Service Index Views      - Lambda Env Var Keys Only
  - Amazon SageMaker AI      - Resource ARN Normalization     - API Gateway Routes
  - Comprehend / Rekognition                                  - Step Functions Definitions
  - Textract / Transcribe                                     - EC2 GPU & AI Tag Heuristics
  - Polly / Lex / Kendra                                      - ECS Container Image Tags
       |                               |                               |
       +-------------------------------+-------------------------------+
                                       |
                       [Layer 4: Non-Destructive Telemetry]
                         - CloudTrail Event History
                         - Administrative API Timestamps
                                       |
                        +------------------------------+
                        |      Unified Normalizer      |
                        |   - Deduplication by Key     |
                        |   - Explainable Risk Engine  |
                        |   - Strict Owner Resolution  |
                        +------------------------------+
                                       |
                        +------------------------------+
                        |   SQLAlchemy / SQLite DB     |
                        |   (ai_resources, scan_runs)  |
                        +------------------------------+
                                       |
                 +---------------------+---------------------+
                 |                                           |
     +-----------------------+                   +-----------------------+
     |   CLI Management      |                   |  Streamlit Dashboard  |
     |   (python -m src.cli) |                   |  (Interactive Portal) |
     +-----------------------+                   +-----------------------+
```

### Discovery Layers
1. **Layer 1: Direct Service APIs:** Paginates official Boto3 clients across Bedrock, SageMaker, Comprehend, Rekognition, Textract, Transcribe, Polly, Lex V2, Translate, Personalize, Forecast, and Kendra.
2. **Layer 2: General Resource Discovery:** Integrates with AWS Resource Explorer 2 to identify cross-region resources and deduplicate against direct findings.
3. **Layer 3: Configuration & Application Inspection:** Inspects non-sensitive metadata (container image names, instance types, integration targets, Step Functions state graphs, and Lambda environment variable **names only**).
4. **Layer 4: Activity Telemetry:** Evaluates CloudTrail Event History for management events (e.g. `InvokeModel`, `InvokeEndpoint`, `UpdateService`) within a configurable lookback window without altering logging configurations.

---

## 3. Safety & Security Constraints

- **Strict Read-Only:** Exclusively calls `List*`, `Describe*`, `Get*`, and `Search*` operations.
- **Zero Model Invocations:** Never calls `InvokeModel` or starts inference jobs. Zero inference costs incurred.
- **Zero Resource Mutation:** Never modifies, creates, tags, or deletes AWS resources.
- **Strict Secret Protection:**
  - Lambda environment variable **values** are never retrieved, serialized, or logged. Only key names (e.g. `OPENAI_API_KEY`) are evaluated.
  - Payloads, prompts, and training data are excluded.
  - Logging layers sanitize any inadvertently matched credentials via regex redaction.
- **No Silent Fallback:** In `aws` mode, if credentials are missing or expired, the agent fails fast with an explicit error. It **never** silently switches to synthetic mock data.

---

## 4. Prerequisites & Installation

- **Python:** 3.11 or newer (tested on Python 3.11, 3.12, 3.13, and 3.14).
- **AWS CLI:** Configured if scanning real AWS accounts.

### Step 1: Clone and Set Up Virtual Environment

```bash
# Clone or navigate to the repository directory
cd ai_discovery

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Initialize Database and Environment Configuration

```bash
# Copy example environment configuration
cp .env.example .env

# Initialize database schema
python -m src.cli init-db
```

---

## 5. Quick Start: Offline Mock Mode

Mock mode requires **zero AWS credentials**. It populates realistic synthetic AI assets (fine-tuned Bedrock models, production SageMaker endpoints, GPU EC2 instances, and shadow Lambda integrations) for instant local demonstration.

```bash
# 1. Run full offline mock discovery scan
python -m src.cli scan --mode mock

# 2. View discovered AI inventory
python -m src.cli inventory list

# 3. Evaluate potential Shadow AI findings
python -m src.cli shadow-ai

# 4. Launch executive Streamlit dashboard
streamlit run src/dashboard/app.py
```

The dashboard will open automatically in your browser at `http://localhost:8501`.

---

## 6. Live AWS Discovery

### Step 1: Configure AWS Credentials
Ensure your environment has valid credentials via environment variables, IAM role, or AWS profile:

```bash
# Option A: Standard AWS Profile
export AWS_PROFILE=my-security-audit-profile

# Option B: Environment Variables
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1
```

### Step 2: Run Live Scan

```bash
# Scan default enabled regions using default profile
python -m src.cli scan --mode aws

# Scan specific regions using a named profile
python -m src.cli scan --mode aws --profile audit-profile --regions us-east-1,us-west-2,ap-south-1

# View scan audit trail
python -m src.cli scan-history
```

If permissions are denied for specific services (e.g. `AccessDenied` on `bedrock:ListCustomModels`), the scan logs a partial warning, completes the remaining services, and records the error in the `scan_runs` database table.

---

## 7. Streamlit Dashboard Walkthrough

Launch the dashboard:
```bash
streamlit run src/dashboard/app.py
```

### Dashboard Pages
1. **📊 Executive Overview:**
   - Real-time KPI cards: Total Assets, Confirmed AI Models, Suspected Infrastructure, Unregistered Assets, Unowned Assets.
   - Interactive breakdown charts: Assets by AWS Service, Assets by Governance Risk Level, and Regional Distribution.
2. **📦 AI Inventory:**
   - Multi-parameter filterable table (by Service, Region, AI Category, Risk Level, and Free-Text Search).
   - Deep Resource Inspector displaying complete ARN, owner resolution source, tag key-values, discovery evidence trail, and documented coverage limitations.
   - 1-Click Governance Approval form to immediately register discovered resources into the approved inventory.
3. **⚠️ Potential Shadow AI:**
   - Automated evaluation of all assets against governance security rules.
   - Categorized findings (Critical, High, Medium, Low) with explainable rationale, exact evidence, and actionable remediation steps.
4. **📜 Scan History:**
   - Full ledger of all previous scan executions (scan ID, status, runtime, discovered/updated counts, and attempted vs failed API calls).
   - Drill-down inspector for API errors and permission gaps.
5. **⚙️ Configuration & Scan:**
   - Interactive scan trigger supporting both Mock Mode and Real AWS Mode with custom regions.
   - Complete viewer for the generated least-privilege IAM policy.

---

## 8. CLI Reference

| Command | Options | Description |
|---|---|---|
| `python -m src.cli init-db` | `--db-url <URL>` | Initializes database tables |
| `python -m src.cli scan` | `--mode [mock\|aws]`, `--profile <NAME>`, `--regions <R1,R2>` | Executes discovery scan |
| `python -m src.cli inventory list` | `--format [table\|json\|csv]`, `--service <SVC>`, `--risk <RISK>`, `--owner <OWNER>` | Lists discovered AI resources with filters |
| `python -m src.cli inventory export` | `--format [csv\|json]`, `--output <FILE>` | Exports complete AI inventory to disk |
| `python -m src.cli scan-history` | `--limit <N>` | Displays previous scan runs |
| `python -m src.cli shadow-ai` | None | Runs rules engine and prints Shadow AI findings |
| `python -m src.cli allowlist add` | `--key <KEY>`, `--name <NAME>`, `--owner <OWNER>`, `--reference <REF>` | Registers an approved AI resource |
| `python -m src.cli allowlist list` | None | Lists all registered approved assets |
| `python -m src.cli generate-policy` | `--output <FILE>` | Exports least-privilege IAM policy JSON |

---

## 9. Database Schema & Sample Queries

### Core Tables
- `ai_resources`: Canonical inventory of discovered AI assets.
- `scan_runs`: Historical ledger of scan runs, coverage, and errors.
- `discovery_evidence`: Audit trail of individual evidence items.
- `approved_ai_resources`: Governance allowlist of authorized AI resources.

### Sample SQLite Queries

```sql
-- 1. Count AI resources by Category and Service
SELECT ai_category, service_name, COUNT(*) AS total
FROM ai_resources
GROUP BY ai_category, service_name
ORDER BY total DESC;

-- 2. Identify all Critical and High-Risk Unregistered Assets
SELECT resource_name, service_name, region, owner, risk_level, detection_method
FROM ai_resources
WHERE approval_status != 'approved' AND risk_level IN ('critical', 'high')
ORDER BY risk_level ASC;

-- 3. Find Resources Referencing External AI Providers
SELECT resource_name, service_name, owner, configuration_summary_json
FROM ai_resources
WHERE ai_category = 'ai_integration';

-- 4. Audit Preservation of First Discovered Timestamp
SELECT resource_key, first_discovered_at, last_scanned_at,
       (julianday(last_scanned_at) - julianday(first_discovered_at)) * 86400 AS age_in_seconds
FROM ai_resources;
```

---

## 10. Confidence Scoring & Explainable Risk Framework

### Confidence Scoring
- **0.98:** Direct AWS managed AI service entity (Bedrock custom models, SageMaker endpoints, Comprehend classifiers).
- **0.85 – 0.90:** High-confidence compute infrastructure (EC2 GPU instance with AI tags/frameworks or ECS ML container).
- **0.75 – 0.80:** Confirmed application integration (Lambda environment variable names matching external AI keys or Step Functions state graphs).
- **0.50 – 0.65:** Heuristic inference (unnamed GPU instance family or high-memory serverless function).

### Explainable Risk Level
- **CRITICAL:** Unregistered external AI integrations (e.g. Lambda embedding OpenAI or Anthropic API keys) where customer data may leave the cloud boundary.
- **HIGH:** Active, unregistered managed AI endpoints or models with unknown ownership.
- **MEDIUM:** Unregistered potential AI hosting infrastructure or unowned idle resources.
- **LOW:** Officially registered in approved allowlist with designated owner and verified telemetry.
- **INFORMATIONAL:** Read-only foundation model catalog references or developmental test resources.

### Ownership Resolution Hierarchy
1. **Explicit Owner Tags:** Evaluates tag keys in strict priority order: `Owner`, `owner`, `Team`, `team`, `CreatedBy`, `ManagedBy`, `AppOwner`, `Contact`.
2. **Documented Resource Metadata:** Evaluates deployment creator ARNs.
3. **Unresolved Fallback:** Explicitly records `"unknown"` and source `"unresolved"`. The engine **never** guesses a human identity.

---

## 11. Shadow AI Detection & Governance

The governance engine compares discovered assets against `approved_ai_resources` to identify risks:

| Finding Type | Trigger Condition | Severity | Recommended Action |
|---|---|---|---|
| `potential_external_ai_integration` | Lambda or Step Function referencing external AI keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, etc.) | **CRITICAL** | Verify Data Processing Agreement (DPA); ensure secrets are stored in AWS Secrets Manager, not plaintext env vars. |
| `unregistered_ai_resource` | Active managed AI endpoint or model not present in the allowlist | **HIGH** / **MEDIUM** | Review with team lead. Register in allowlist or initiate decommissioning. |
| `unknown_owner` | AI resource lacks owner tags or creator metadata | **MEDIUM** | Tag resource with designated team owner and cost center. |
| `potential_ai_hosting` | GPU compute instance or ML container running without formal registration | **MEDIUM** | Confirm workload purpose and verify whether open-weight models are hosted. |
| `unknown_activity` | Active AI resource with no recent CloudTrail management events | **LOW** | Verify whether resource is idle and eligible for decommissioning. |

---

## 12. Least-Privilege IAM Policy

A complete policy document is provided in [`aws_discovery_iam_policy.json`](file:///c:/Users/ayush/OneDrive/Desktop/ai_discovery/aws_discovery_iam_policy.json).

### Policy Design Principles
- **No Wildcard Admin:** Restricts actions to exact `List*`, `Describe*`, `Get*`, and `Search*` operations.
- **Zero Write/Delete:** Contains zero `Create`, `Update`, `Delete`, `Put`, or `Invoke` actions.
- **Service Breakdown:**
  - Bedrock: `bedrock:ListCustomModels`, `bedrock:ListFoundationModels`, `bedrock-agent:ListAgents`, etc.
  - SageMaker: `sagemaker:ListEndpoints`, `sagemaker:DescribeEndpoint`, `sagemaker:ListModels`, etc.
  - Infrastructure: `ec2:DescribeInstances`, `ecs:ListClusters`, `ecs:DescribeServices`, `lambda:ListFunctions`.
  - Integrations: `apigateway:GET`, `states:DescribeStateMachine`.
  - Telemetry: `cloudtrail:LookupEvents`.

---

## 13. Discovery Gaps & Technical Limitations

A successful discovery scan does **not** guarantee 100% visibility into all AI activities. The following architectural limitations are formally documented:

1. **Guest OS Opacity:** Read-only `ec2:DescribeInstances` inspects instance types and tags, but cannot inspect active RAM or disk processes inside the virtual machine. A custom PyTorch model running inside a standard `c5.large` instance cannot be detected without an in-guest agent.
2. **CloudTrail Management vs Data Events:** `cloudtrail:LookupEvents` primarily catalogs management plane actions (e.g. `CreateEndpoint`, `UpdateService`). High-volume inference requests (`bedrock:InvokeModel`, `sagemaker:InvokeEndpoint`) generate **data events**, which require dedicated CloudWatch Trails or S3 event logging.
3. **Lambda Code Opacity:** The agent reads environment variable **keys** only. It does not decompile zip files or download function source code.
4. **Third-Party Inference Proxies:** Outbound HTTP requests to external AI APIs made from private VPC subnets with NAT Gateways are invisible without VPC Flow Log inspection.

---

## 14. Testing Suite

The project includes an automated test suite implemented with `pytest` and `botocore.stub.Stubber`. All tests run completely offline without AWS credentials and without incurring charges.

```bash
# Run the complete test suite
pytest -v
```

### Covered Test Scenarios
- **API Pagination:** Verifies Bedrock and SageMaker pagination across multiple continuation tokens without truncation.
- **Metadata Normalization:** Validates canonical key construction, tags parsing, and JSON serialization.
- **Deduplication & Timestamps:** Proves `first_discovered_at` is preserved across multiple scan runs while `last_scanned_at` updates.
- **Fail-Fast AWS Mode:** Verifies that live AWS mode raises an explicit `RuntimeError` on missing credentials and never silently falls back to mock data.
- **AccessDenied Resilience:** Confirms `AccessDeniedException` is recorded as a regional warning without halting scans of other services.
- **Secret Redaction:** Asserts that API keys, tokens, and AWS access keys are redacted from logs and evidence.
- **Shadow AI Evaluation:** Verifies detection of external AI keys, unowned assets, and unregistered models.

---

## 15. Troubleshooting Guide

| Issue | Cause | Resolution |
|---|---|---|
| `No AWS credentials discovered` | Scan was invoked with `--mode aws` but no AWS credentials exist in the environment. | Set `AWS_PROFILE` or AWS environment variables, or run with `--mode mock`. |
| `AccessDenied on bedrock:*` | The caller IAM identity lacks permissions for Amazon Bedrock in the target region. | Attach `aws_discovery_iam_policy.json` to the IAM role. |
| `Unsupported region error` | A service (e.g. Bedrock Agent or Forecast) is not available in that specific region. | The agent handles this automatically by logging a regional warning and continuing. |
| `Database is locked` | SQLite file is being accessed by multiple concurrent writes. | SQLite handles sequential reads/writes. If high concurrency is needed, set `DATABASE_URL` to PostgreSQL. |
