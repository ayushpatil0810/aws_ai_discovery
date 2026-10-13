# System Architecture: AWS AI Discovery & Governance Agent

> **Document Version:** 1.0.0  
> **Classification:** Technical Architecture & Design Specification  
> **Compliance Alignment:** ISO/IEC 42001 (AI Management System - AIMS), NIST AI RMF, CIS AWS Benchmarks

---

## 1. System Overview

The **AWS AI Discovery Agent** is an enterprise-grade, read-only cloud security and governance engine designed to detect, inventory, and assess AI/ML workloads across AWS environments. 

AWS lacks a centralized API to query all deployed AI systems. AI assets exist as managed services, custom compute instances, containerized workloads, or serverless functions proxying calls to external foundation model providers. 

This system provides a unified inventory, deterministically resolves ownership, flags **Shadow AI** risks, and maps all findings into an **ISO 42001 (AIMS)** compliant schema without making inference calls or exposing customer data.

```
+---------------------------------------------------------------------------------------------------+
|                                      EXECUTIVE INTERFACES                                         |
|                 Streamlit Dashboard (Port 8501)       |        CLI & Automation Engine            |
+---------------------------------------------------------------------------------------------------+
                                                  |
+---------------------------------------------------------------------------------------------------+
|                                  GOVERNANCE & EVALUATION LAYER                                    |
|   +--------------------------+   +--------------------------+   +-----------------------------+   |
|   |     Shadow AI Engine     |   | Explainable Risk Scorer  |   |    Allowlist Registry       |   |
|   +--------------------------+   +--------------------------+   +-----------------------------+   |
+---------------------------------------------------------------------------------------------------+
                                                  |
+---------------------------------------------------------------------------------------------------+
|                                NORMALIZATION & PERSISTENCE LAYER                                  |
|   +--------------------------+   +--------------------------+   +-----------------------------+   |
|   |  Resource Normalizer     |   |   Ownership Resolver     |   |   SQLAlchemy / SQLite DB    |   |
|   |  (Pydantic Validation)   |   |   (Tags -> Metadata)     |   |   (Canonical AI Ledger)     |   |
|   +--------------------------+   +--------------------------+   +-----------------------------+   |
+---------------------------------------------------------------------------------------------------+
                                                  |
+---------------------------------------------------------------------------------------------------+
|                                   4-LAYER DISCOVERY ENGINE                                        |
|  +--------------------+  +--------------------+  +--------------------+  +---------------------+  |
|  | Layer 1: Direct API|  | Layer 2: Explorer  |  | Layer 3: Heuristics|  | Layer 4: Telemetry   |  |
|  | Bedrock, SageMaker,|  | Resource Explorer 2|  | EC2 GPU, ECS/EKS,  |  | CloudTrail Event    |  |
|  | Comprehend, Kendra |  | Cross-Index Search |  | Lambda Env Keys    |  | Management History  |  |
|  +--------------------+  +--------------------+  +--------------------+  +---------------------+  |
+---------------------------------------------------------------------------------------------------+
                                                  |
+---------------------------------------------------------------------------------------------------+
|                                        TARGET AWS ACCOUNT                                         |
|      Multi-Region Infrastructure (us-east-1, us-west-2, ap-south-1, etc.) | Read-Only IAM      |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. End-to-End Architectural Data Flow

```mermaid
sequenceDiagram
    autonumber
    actor SecOps as Security Analyst / CLI
    participant Engine as Discovery Engine
    participant AWS as AWS Service APIs (Boto3)
    participant Normalizer as Unified Normalizer
    participant Gov as Shadow AI Engine
    participant DB as Persistence Layer (SQLite)
    participant UI as Streamlit Dashboard

    SecOps->>Engine: Initiate Scan (mode=mock|aws, regions)
    Engine->>AWS: sts:GetCallerIdentity (Verify Credentials)
    Engine->>AWS: ec2:DescribeRegions (Filter Allow/Deny List)
    
    rect rgb(20, 25, 45)
        note right of Engine: Multi-Layer Regional Scans
        Engine->>AWS: Layer 1: Bedrock, SageMaker, Managed AI
        Engine->>AWS: Layer 2: Resource Explorer 2 Search
        Engine->>AWS: Layer 3: EC2 GPUs, ECS Images, Lambda Env Keys
        Engine->>AWS: Layer 4: CloudTrail Event History Correlation
    end

    AWS-->>Engine: Raw AWS Responses & Telemetry
    Engine->>Normalizer: Normalize Raw Payloads
    Normalizer->>Normalizer: Deduplicate Canonical Key
    Normalizer->>Normalizer: Resolve Ownership (Tag Priority Hierarchy)
    Normalizer->>Normalizer: Calculate Risk Level & Confidence
    Normalizer-->>Engine: Validated AIResource Entities

    Engine->>Gov: Evaluate Assets against Approved Allowlist
    Gov-->>Engine: Shadow AI Findings (External AI, Unregistered, Unowned)

    Engine->>DB: Upsert ai_resources (Preserve first_discovered_at)
    Engine->>DB: Record scan_runs & discovery_evidence Audit Trail
    DB-->>Engine: Commit Successful Transaction

    SecOps->>UI: Launch Dashboard (localhost:8501)
    UI->>DB: Query Normalized Inventory & Findings
    UI-->>SecOps: Render KPI Cards, Risk Charts & Resource Inspector
```

---

## 3. The 4 Discovery Layers

```mermaid
graph TD
    subgraph L1["Layer 1: Direct Service APIs"]
        B[Amazon Bedrock<br/>Models, Agents, KBs, Guardrails]
        SM[Amazon SageMaker<br/>Endpoints, Models, Training Jobs]
        MA[Managed AI Suite<br/>Comprehend, Rekognition, Lex, Kendra]
    end

    subgraph L2["Layer 2: General Discovery"]
        RE[AWS Resource Explorer 2<br/>Cross-Region Index Views]
    end

    subgraph L3["Layer 3: Configuration & Application Heuristics"]
        EC2[EC2 GPU Instances<br/>g4dn, g5, p3, p4, inf1/2, trn1]
        ECS[ECS & EKS Workloads<br/>Triton, vLLM, PyTorch Containers]
        LMB[Lambda Configurations<br/>Non-Sensitive Env Var Key Names]
        SFN[Step Functions & API Gateway<br/>State Graphs & Route Proxies]
    end

    subgraph L4["Layer 4: Telemetry & Activity Evidence"]
        CT[CloudTrail Event History<br/>Management API Audit Logs]
    end

    L1 --> N[Canonical Normalizer]
    L2 --> N
    L3 --> N
    L4 --> N
```

### Layer 1: Direct Service APIs
Directly communicates with official AWS service endpoints using Boto3 client paginators (`nextToken` / `NextToken`):
- **Amazon Bedrock:** Custom fine-tuned models, provisioned throughputs, application inference profiles, autonomous agents, RAG knowledge bases, and guardrails.
- **Amazon SageMaker:** Real-time inference endpoints (`InService`), model package groups, training/processing jobs, notebook instances, and Studio domains.
- **Specialized Managed AI:** Comprehend (document classifiers), Rekognition (custom labels projects), Textract (adapters), Transcribe (custom language models), Polly (lexicons), Lex V2 (conversational bots), Translate (terminologies), Personalize (campaigns), Forecast (predictors), and Kendra (enterprise indices).

### Layer 2: General Resource Discovery
Leverages AWS Resource Explorer 2 views as a complementary cross-check to discover resources across regions. Deduplication matches canonical ARNs against Layer 1 findings to prevent double-counting.

### Layer 3: Configuration & Application Heuristics
Inspects non-sensitive configuration to identify potential custom AI workloads:
- **GPU & Accelerator EC2 Instances:** Identifies instances matching `g3-g6`, `p2-p5`, `inf1-2`, `trn1-2`, or tagged with `framework=vllm`, `model=deepseek`.
- **Containers:** Evaluates ECS task definitions and EKS node groups for ML base images (`nvcr.io/nvidia/tritonserver`, `vllm/vllm-openai`, `huggingface/text-generation-inference`).
- **Lambda Environment Variable Names:** Evaluates environment variable **keys only** (e.g., `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `COHERE_API_KEY`, `PINECONE_API_KEY`). **Values are strictly never read, stored, or logged.**

### Layer 4: Telemetry & Activity Evidence
Queries CloudTrail `LookupEvents` for recent management-plane interactions (`InvokeModel`, `InvokeEndpoint`, `UpdateService`) within a configurable window (default: 30 days).
- **Documented Boundary:** Distinguishes management events from data-plane inference streams. If logging is disabled or unavailable, sets status to `unknown` or `not_configured` without inventing timestamps.

---

## 4. Normalization & AIMS (ISO 42001) Schema Specification

```mermaid
erDiagram
    ai_resources ||--o{ discovery_evidence : "substantiated by"
    ai_resources }o--|| approved_ai_resources : "cross-referenced with"
    scan_runs ||--o{ ai_resources : "discovers/updates"

    ai_resources {
        string resource_key PK "aws:acc:region:service:type:id"
        string resource_name
        string resource_arn
        string service_name
        string region
        string ai_category "managed_ai | custom_model_hosting | ai_integration | potential_ai_infrastructure"
        string ai_usage_status "confirmed | suspected | unknown"
        string owner
        string owner_source "tag:Owner | metadata:creator | unresolved"
        string risk_level "critical | high | medium | low"
        float confidence_score "0.00 - 1.00"
        string activity_status "active | idle | unknown"
        datetime first_discovered_at "Preserved across scans"
        datetime last_scanned_at "Updated per scan"
        json tags_json
        json configuration_summary_json
        json limitations_json
    }

    scan_runs {
        string scan_id PK "scan-uuid"
        string mode "mock | aws"
        string scan_status "running | completed | partial | failed"
        int resources_discovered
        int resources_updated
        int api_calls_attempted
        int api_calls_failed
        json scanned_regions
        json errors_json
    }

    discovery_evidence {
        int id PK
        string resource_key FK
        string evidence_source "API or heuristic source"
        string evidence_type "direct_api | env_var_name | gpu_instance_type"
        string sanitized_evidence_summary
        float confidence_or_strength
        datetime observation_timestamp
    }

    approved_ai_resources {
        string resource_key PK
        string resource_name
        string owner
        string approval_status "approved | provisional | revoked"
        string approval_reference "JIRA / ticket ID"
        datetime last_reviewed_at
    }
```

### Stable Deduplication Key
All resources are indexed by an idempotent canonical key:
$$\text{resource\_key} = \text{aws:}\{\text{account\_id}\}\text{:}\{\text{region}\}\text{:}\{\text{service\_name}\}\text{:}\{\text{resource\_type}\}\text{:}\{\text{resource\_id}\}$$

### Ownership Resolution Hierarchy
Ownership is resolved using a deterministic state machine:
1. **Explicit Owner Tags:** Priority scan of tags: `Owner`, `owner`, `Team`, `team`, `CreatedBy`, `created_by`, `ManagedBy`, `AppOwner`, `Contact`.
2. **Documented Metadata:** Creator ARN or deployer identity in deployment descriptors.
3. **Unresolved Fallback:** Sets `owner = "unknown"`, `owner_source = "unresolved"`. The engine **never infers human identities from IAM role names**.

---

## 5. Governance & Shadow AI Detection Engine

```mermaid
flowchart TD
    Asset[Discovered AI Resource] --> ChkAppr{In Approved<br/>Allowlist?}
    
    ChkAppr -- No --> FlagUnreg[Flag: unregistered_ai_resource<br/>Severity: HIGH / MEDIUM]
    ChkAppr -- Yes --> ChkExt

    FlagUnreg --> ChkExt{References External<br/>AI Provider?}
    
    ChkExt -- Yes (OpenAI, Anthropic, etc.) --> FlagExt[Flag: potential_external_ai_integration<br/>Severity: CRITICAL<br/>Data Exfiltration / Perimeter Risk]
    ChkExt -- No --> ChkOwner

    FlagExt --> ChkOwner{Owner == 'unknown'?}
    
    ChkOwner -- Yes --> FlagOwner[Flag: unknown_owner<br/>Severity: MEDIUM<br/>Missing Governance Tag]
    ChkOwner -- No --> ChkInfra

    FlagOwner --> ChkInfra{Category ==<br/>'potential_ai_infrastructure'?}
    
    ChkInfra -- Yes --> FlagHost[Flag: potential_ai_hosting<br/>Severity: MEDIUM<br/>GPU compute without registered model]
    ChkInfra -- No --> ChkAct

    FlagHost --> ChkAct{Activity Status ==<br/>'unknown'?}
    ChkAct -- Yes --> FlagAct[Flag: unknown_activity<br/>Severity: LOW<br/>Unmonitored Telemetry]
    ChkAct -- No --> Compliant[Asset Compliant]
```

### Explainable Risk Scoring Matrix
| Risk Level | Trigger Criteria | Justification |
|---|---|---|
| **CRITICAL** | Lambda/API containing external AI keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`) without allowlist registration. | Enterprise prompts and proprietary data leave AWS security boundaries without verified Data Processing Agreements. |
| **HIGH** | Unregistered managed AI endpoints (Bedrock, SageMaker) with unknown owner. | Unmonitored production model deployments with unallocated cloud spend. |
| **MEDIUM** | Suspected GPU hosting infrastructure (`g5.4xlarge`) or registered model with no owner tag. | Unattributed compute resources that may violate governance baselines. |
| **LOW** | Formally approved asset in allowlist with verified owner and telemetry. | Fully governed enterprise deployment. |

---

## 6. Least-Privilege Security Architecture

```mermaid
graph LR
    subgraph Identity["Execution Identity"]
        Role[IAM Role / Audit Profile]
    end

    subgraph Boundaries["Security Boundaries"]
        RO[Strictly Read-Only Actions<br/>List*, Describe*, Get*]
        NoMut[Zero Mutation<br/>No Create, Update, Delete, Put]
        NoInf[Zero Inference<br/>No InvokeModel, No InvokeEndpoint]
        NoSec[Zero Secrets<br/>Environment Keys ONLY, No Values]
    end

    subgraph Targets["Discovered Services"]
        AWS[AWS Accounts & Regions]
    end

    Role --> RO
    Role -.->|BLOCKED| NoMut
    Role -.->|BLOCKED| NoInf
    Role -.->|BLOCKED| NoSec
    RO --> AWS
```

### Safety & Compliance Controls
1. **Zero Inference Charges:** `InvokeModel`, `InvokeEndpoint`, and equivalent data APIs are strictly excluded from the IAM policy. The agent incurs \$0 in model inference fees.
2. **Zero Mutation:** No resource creation, modification, tagging, or remediation actions exist in the codebase.
3. **Secret Redaction Pipeline:**
   - Lambda `Environment.Variables` dictionary keys are inspected; values are never extracted or stored.
   - All text output passes through regex redaction rules filtering AWS credentials (`AKIA...`), OpenAI/Anthropic keys (`sk-...`), and key-value secret assignments.
4. **No Silent Mock Fallback:** When `DISCOVERY_MODE=aws`, missing credentials or `AccessDenied` immediately raise explicit exceptions. Mock data is never silently substituted.

---

## 7. Multi-Cloud Expansion Architecture (AWS $\rightarrow$ GCP $\rightarrow$ Azure)

The agent uses a modular provider abstraction (`BaseDiscoveryModule`), enabling seamless multi-cloud expansion:

```mermaid
graph TD
    Engine[Central Discovery Engine] --> Abstract[BaseDiscoveryModule Interface]

    Abstract --> AWS_Mod[AWS Modules]
    Abstract --> GCP_Mod[GCP Modules - Roadmap]
    Abstract --> AZ_Mod[Azure Modules - Roadmap]

    subgraph AWS_Mod
        A1[Bedrock / SageMaker]
        A2[EC2 GPU / Lambda]
    end

    subgraph GCP_Mod
        G1[Vertex AI Endpoints & Model Garden]
        G2[GCE a2/g2 Accelerator VMs]
        G3[Cloud Translation / Speech]
    end

    subgraph AZ_Mod
        Z1[Azure OpenAI Services]
        Z2[Azure Machine Learning Workspaces]
        Z3[NC/ND Series GPU VMs]
    end

    AWS_Mod --> Norm[Unified AIMS / ISO 42001 Schema]
    GCP_Mod --> Norm
    AZ_Mod --> Norm
```

---

## 8. Multi-Agent Intelligent LLM Routing (Cost & Quality Optimization)

To address the multi-agent orchestration challenge highlighted by governance teams, the platform incorporates an **Adaptive Model Cascade & Semantic Routing** blueprint:

```mermaid
flowchart TD
    SubAgent[Sub-Agent Interaction / Prompt] --> Cache{Semantic Cache Hit?<br/>e.g., Redis Vector Cache}
    
    Cache -- Yes --> RetCache[Return Cached Response<br/>Latency: <5ms | Cost: $0.00]
    Cache -- No --> Router[Lightweight Semantic Classifier<br/>Fast Embedding / Small Model]

    Router --> Classify{Task Complexity Tier}

    Classify -- "Tier 1: Extraction / Structuring" --> T1[Tier 1: Fast Small Model<br/>Llama 3 8B / Claude 3.5 Haiku<br/>Cost: ~$0.0001 / 1k tokens]
    Classify -- "Tier 2: Code / Summarization" --> T2[Tier 2: Mid-Tier Model<br/>GPT-4o-mini / Mistral 8x22B<br/>Cost: ~$0.001 / 1k tokens]
    Classify -- "Tier 3: Complex Reasoning" --> T3[Tier 3: Frontier Model<br/>Claude 3.5 Sonnet / GPT-4o<br/>Cost: ~$0.015 / 1k tokens]

    T1 --> Val{Pydantic Schema /<br/>Confidence Validation Pass?}
    
    Val -- Pass --> Output[Deliver Output to Calling Agent]
    Val -- Fail (Confidence < Threshold) --> Cascade[Cascade to Next Tier]
    Cascade --> T2
```

### Cost vs. Performance Trade-off Table
| Routing Strategy | Cost Reduction | Latency Impact | Quality Retention | Production Readiness |
|---|---|---|---|---|
| **Frontier-Only (Baseline)** | 0% | High (1.5s – 4s) | 100% | High cost, low scalability |
| **Static Rule Router** | 35% – 45% | Medium (0.8s) | 90% | Brittle to prompt drift |
| **Adaptive Cascading Router (Recommended)** | **65% – 82%** | **Low (0.3s – 1.1s)** | **98.4%** | **Enterprise standard** |

---

## 9. Technology Stack

- **Language:** Python 3.11+ (tested on Python 3.11 through 3.14)
- **Cloud SDK:** Boto3, Botocore
- **Data Validation:** Pydantic v2, Pydantic-Settings
- **ORM & Storage:** SQLAlchemy 2.0, SQLite (PostgreSQL compatible)
- **Web UI & Visualization:** Streamlit, Pandas, Altair
- **CLI Framework:** Click, Tabulate
- **Test Harness:** Pytest, Botocore Stubber (100% offline mocking)
