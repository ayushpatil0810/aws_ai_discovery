"""Synthetic mock data provider for offline demonstration and CI testing without AWS credentials."""

from datetime import datetime, timedelta
from typing import List
from src.config import (
    AICategory,
    AIUsageStatus,
    RiskLevel,
    ApprovalStatus,
    ActivityStatus,
    utc_now,
)
from src.inventory.schema import AIResourceCreate, EvidenceItem, DiscoveryLimitation
from src.inventory.normalizer import ResourceNormalizer


def get_mock_resources(account_id: str = "123456789012", regions: List[str] = None) -> List[AIResourceCreate]:
    """
    Generate realistic synthetic AI resources across managed AI, infrastructure, and integrations.
    Explicitly labeled as synthetic demonstration data.
    """
    if not regions:
        regions = ["us-east-1", "us-west-2", "ap-south-1"]

    primary_region = regions[0] if regions else "us-east-1"
    secondary_region = regions[1] if len(regions) > 1 else primary_region
    now = utc_now()
    two_days_ago = now - timedelta(days=2)
    twenty_days_ago = now - timedelta(days=20)

    resources: List[AIResourceCreate] = [
        # 1. Amazon Bedrock Custom Model
        ResourceNormalizer.normalize(
            account_id=account_id,
            region=primary_region,
            service_name="bedrock",
            resource_type="custom_model",
            resource_id="anthropic.claude-3-haiku-finance-ft-v1",
            resource_name="claude-3-haiku-finance-ft-v1",
            resource_arn=f"arn:aws:bedrock:{primary_region}:{account_id}:custom-model/anthropic.claude-3-haiku-finance-ft-v1",
            description="Fine-tuned Claude 3 Haiku for financial summarization and analysis",
            ai_category=AICategory.MANAGED_AI,
            ai_usage_status=AIUsageStatus.CONFIRMED,
            detection_method="direct_service_api:ListCustomModels",
            model_provider="Anthropic",
            model_id="anthropic.claude-3-haiku-20240307-v1:0:custom",
            tags={"Owner": "ai-finance-team", "Environment": "Production", "Project": "FinGenAI"},
            configuration_summary={
                "baseModelArn": "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0",
                "hyperparameters": {"epochCount": "3", "batchSize": "16"},
                "synthetic_mode": True
            },
            evidence=[
                EvidenceItem(
                    evidence_source="bedrock:ListCustomModels",
                    evidence_type="direct_api",
                    sanitized_summary="Custom fine-tuned Bedrock model confirmed in account",
                    confidence=0.99
                )
            ],
            activity_status=ActivityStatus.ACTIVE,
            last_used_at=two_days_ago,
            usage_evidence_source="cloudtrail:InvokeModel",
            is_approved=True
        ),

        # 2. Amazon Bedrock Agent
        ResourceNormalizer.normalize(
            account_id=account_id,
            region=primary_region,
            service_name="bedrock-agent",
            resource_type="agent",
            resource_id="AGT987ABC123",
            resource_name="CustomerSupportAutonomousAgent",
            resource_arn=f"arn:aws:bedrock:{primary_region}:{account_id}:agent/AGT987ABC123",
            description="Multi-action agent orchestration engine for customer support requests",
            ai_category=AICategory.MANAGED_AI,
            ai_usage_status=AIUsageStatus.CONFIRMED,
            detection_method="direct_service_api:ListAgents",
            model_provider="Amazon",
            model_id="anthropic.claude-3-5-sonnet-20240620-v1:0",
            tags={"team": "customer-ops", "ServiceTier": "Tier-1"},
            configuration_summary={
                "agentStatus": "PREPARED",
                "idleSessionTTLInSeconds": 1800,
                "synthetic_mode": True
            },
            evidence=[
                EvidenceItem(
                    evidence_source="bedrock-agent:ListAgents",
                    evidence_type="direct_api",
                    sanitized_summary="Bedrock Agent configured with attached action groups",
                    confidence=0.98
                )
            ],
            activity_status=ActivityStatus.ACTIVE,
            last_used_at=now - timedelta(hours=5),
            usage_evidence_source="cloudtrail:InvokeAgent",
            is_approved=True
        ),

        # 3. Amazon SageMaker Production Endpoint
        ResourceNormalizer.normalize(
            account_id=account_id,
            region=secondary_region,
            service_name="sagemaker",
            resource_type="endpoint",
            resource_id="fraud-detection-xgb-prod",
            resource_name="fraud-detection-xgb-prod",
            resource_arn=f"arn:aws:sagemaker:{secondary_region}:{account_id}:endpoint/fraud-detection-xgb-prod",
            description="Real-time transaction fraud scoring endpoint",
            ai_category=AICategory.CUSTOM_MODEL_HOSTING,
            ai_usage_status=AIUsageStatus.CONFIRMED,
            detection_method="direct_service_api:ListEndpoints",
            endpoint_identifier="fraud-detection-xgb-prod",
            tags={"Owner": "risk-engineering", "Environment": "Production", "CostCenter": "CC-9041"},
            configuration_summary={
                "EndpointStatus": "InService",
                "InstanceType": "ml.m5.xlarge",
                "InitialInstanceCount": 2,
                "synthetic_mode": True
            },
            evidence=[
                EvidenceItem(
                    evidence_source="sagemaker:ListEndpoints",
                    evidence_type="direct_api",
                    sanitized_summary="SageMaker InService endpoint hosting XGBoost classification model",
                    confidence=0.99
                )
            ],
            activity_status=ActivityStatus.ACTIVE,
            last_used_at=now - timedelta(minutes=15),
            usage_evidence_source="cloudtrail:InvokeEndpoint",
            is_approved=True
        ),

        # 4. Amazon SageMaker Unregistered / Unowned Shadow Endpoint
        ResourceNormalizer.normalize(
            account_id=account_id,
            region=primary_region,
            service_name="sagemaker",
            resource_type="endpoint",
            resource_id="test-sdxl-imagegen-dev",
            resource_name="test-sdxl-imagegen-dev",
            resource_arn=f"arn:aws:sagemaker:{primary_region}:{account_id}:endpoint/test-sdxl-imagegen-dev",
            description="Experimental Stable Diffusion XL diffusion endpoint deployed by contractor",
            ai_category=AICategory.CUSTOM_MODEL_HOSTING,
            ai_usage_status=AIUsageStatus.CONFIRMED,
            detection_method="direct_service_api:ListEndpoints",
            model_provider="StabilityAI",
            model_id="stabilityai/stable-diffusion-xl-base-1.0",
            endpoint_identifier="test-sdxl-imagegen-dev",
            tags={},  # Intentionally untagged / unowned to trigger Shadow AI finding
            configuration_summary={
                "EndpointStatus": "InService",
                "InstanceType": "ml.g5.2xlarge",
                "InitialInstanceCount": 1,
                "synthetic_mode": True
            },
            evidence=[
                EvidenceItem(
                    evidence_source="sagemaker:ListEndpoints",
                    evidence_type="direct_api",
                    sanitized_summary="InService GPU endpoint (ml.g5.2xlarge) detected without ownership tags",
                    confidence=0.98
                )
            ],
            limitations=[
                DiscoveryLimitation(
                    limitation_code="MISSING_TAGS",
                    message="No ownership or environment tags assigned to high-cost GPU endpoint",
                    potential_impact="Inability to allocate cloud spending and verify authorization"
                )
            ],
            activity_status=ActivityStatus.UNKNOWN,
            is_approved=False
        ),

        # 5. EC2 Dedicated GPU Instance (Potential Custom AI Infrastructure)
        ResourceNormalizer.normalize(
            account_id=account_id,
            region=primary_region,
            service_name="ec2",
            resource_type="instance",
            resource_id="i-08a7b6c5d4e3f2109",
            resource_name="vllm-deepseek-sandbox",
            resource_arn=f"arn:aws:ec2:{primary_region}:{account_id}:instance/i-08a7b6c5d4e3f2109",
            description="EC2 GPU instance running vLLM server with DeepSeek open weights",
            ai_category=AICategory.POTENTIAL_AI_INFRASTRUCTURE,
            ai_usage_status=AIUsageStatus.SUSPECTED,
            detection_method="heuristic_config_analysis:gpu_family",
            tags={"team": "research-dev", "Name": "vllm-deepseek-sandbox", "framework": "vllm"},
            configuration_summary={
                "InstanceType": "g5.4xlarge",
                "State": "running",
                "Accelerators": "1x NVIDIA A10G 24GB",
                "Platform": "Linux/UNIX",
                "spec": "NVIDIA A10G GPU accelerator with vLLM keywords in tag metadata",
                "synthetic_mode": True
            },
            evidence=[
                EvidenceItem(
                    evidence_source="ec2:DescribeInstances",
                    evidence_type="gpu_instance_type",
                    sanitized_summary="Instance belongs to g5 GPU family (NVIDIA A10G) commonly used for LLM inference",
                    confidence=0.85
                ),
                EvidenceItem(
                    evidence_source="ec2:DescribeInstances",
                    evidence_type="tag_heuristic",
                    sanitized_summary="Tag metadata contains framework 'vllm' and name 'deepseek'",
                    confidence=0.90
                )
            ],
            limitations=[
                DiscoveryLimitation(
                    limitation_code="OPAQUE_GUEST_OS",
                    message="Read-only EC2 describe cannot inspect guest OS memory or active model weights",
                    potential_impact="Cannot verify whether model inference is currently active inside the instance"
                )
            ],
            activity_status=ActivityStatus.UNKNOWN,
            is_approved=False
        ),

        # 6. Lambda Function with External AI Secrets / Integrations (Shadow AI Exfiltration Risk)
        ResourceNormalizer.normalize(
            account_id=account_id,
            region=primary_region,
            service_name="lambda",
            resource_type="function",
            resource_id="customer-support-openai-summarizer",
            resource_name="customer-support-openai-summarizer",
            resource_arn=f"arn:aws:lambda:{primary_region}:{account_id}:function:customer-support-openai-summarizer",
            description="Serverless trigger sending customer transcripts to OpenAI GPT-4 API",
            ai_category=AICategory.AI_INTEGRATION,
            ai_usage_status=AIUsageStatus.CONFIRMED,
            detection_method="non_sensitive_metadata_inspection:env_keys",
            tags={"CreatedBy": "intern-analyst", "Department": "CustomerExperience"},
            configuration_summary={
                "Runtime": "python3.11",
                "MemorySize": 1024,
                "Timeout": 60,
                # CRITICAL: Only environment variable names are captured, NEVER secret values!
                "environment_variable_keys": ["OPENAI_API_KEY", "OPENAI_ORG_ID", "SLACK_WEBHOOK_URL"],
                "synthetic_mode": True
            },
            evidence=[
                EvidenceItem(
                    evidence_source="lambda:ListFunctions",
                    evidence_type="env_var_name",
                    sanitized_summary="Function environment configuration contains external AI credential keys: ['OPENAI_API_KEY', 'OPENAI_ORG_ID']",
                    confidence=0.95
                )
            ],
            limitations=[
                DiscoveryLimitation(
                    limitation_code="SECRETS_NOT_INSPECTED",
                    message="Environment variable values and source code are strictly not fetched per read-only compliance policy",
                    potential_impact="Cannot verify whether credentials are live or rate-limited"
                )
            ],
            activity_status=ActivityStatus.ACTIVE,
            last_used_at=twenty_days_ago,
            usage_evidence_source="cloudtrail:Invoke",
            is_external_ai=True,
            is_approved=False
        ),

        # 7. ECS Service hosting Triton Inference Server (Custom Model Hosting)
        ResourceNormalizer.normalize(
            account_id=account_id,
            region=secondary_region,
            service_name="ecs",
            resource_type="service",
            resource_id="triton-embedding-cluster/embedding-service",
            resource_name="embedding-service",
            resource_arn=f"arn:aws:ecs:{secondary_region}:{account_id}:service/triton-cluster/embedding-service",
            description="Containerized Triton Inference Server hosting BGE embeddings",
            ai_category=AICategory.CUSTOM_MODEL_HOSTING,
            ai_usage_status=AIUsageStatus.CONFIRMED,
            detection_method="heuristic_config_analysis:container_image",
            tags={"Owner": "search-ranking-team", "Environment": "Production"},
            configuration_summary={
                "image_name": "nvcr.io/nvidia/tritonserver:24.02-py3",
                "task_cpu": "4096",
                "task_memory": "16384",
                "synthetic_mode": True
            },
            evidence=[
                EvidenceItem(
                    evidence_source="ecs:DescribeTaskDefinition",
                    evidence_type="ai_container_image",
                    sanitized_summary="Container image 'nvcr.io/nvidia/tritonserver:24.02-py3' matches known inference server registry",
                    confidence=0.95
                )
            ],
            activity_status=ActivityStatus.ACTIVE,
            last_used_at=now - timedelta(hours=1),
            usage_evidence_source="cloudtrail:UpdateService",
            is_approved=True
        ),

        # 8. Amazon Comprehend Document Classifier
        ResourceNormalizer.normalize(
            account_id=account_id,
            region=primary_region,
            service_name="comprehend",
            resource_type="document_classifier",
            resource_id="LegalDocClassifierV2",
            resource_name="LegalDocClassifierV2",
            resource_arn=f"arn:aws:comprehend:{primary_region}:{account_id}:document-classifier/LegalDocClassifierV2",
            description="Custom document classifier for compliance contract categorization",
            ai_category=AICategory.MANAGED_AI,
            ai_usage_status=AIUsageStatus.CONFIRMED,
            detection_method="direct_service_api:ListDocumentClassifiers",
            tags={"Owner": "compliance-tech", "Status": "Trained"},
            configuration_summary={
                "LanguageCode": "en",
                "Status": "TRAINED",
                "synthetic_mode": True
            },
            evidence=[
                EvidenceItem(
                    evidence_source="comprehend:ListDocumentClassifiers",
                    evidence_type="direct_api",
                    sanitized_summary="Comprehend Custom Document Classifier in TRAINED state",
                    confidence=0.98
                )
            ],
            activity_status=ActivityStatus.IDLE,
            last_used_at=now - timedelta(days=45),
            usage_evidence_source="cloudtrail:ClassifyDocument",
            is_approved=True
        ),

        # 9. Amazon Lex V2 Banking Assistant Bot
        ResourceNormalizer.normalize(
            account_id=account_id,
            region=primary_region,
            service_name="lex",
            resource_type="lex_v2_bot",
            resource_id="BOT778899",
            resource_name="RetailBankingAssistantBot",
            resource_arn=f"arn:aws:lex:{primary_region}:{account_id}:bot/BOT778899",
            description="Conversational bot managing account balance and transfer intents",
            ai_category=AICategory.MANAGED_AI,
            ai_usage_status=AIUsageStatus.CONFIRMED,
            detection_method="direct_service_api:ListBots",
            tags={"team": "retail-banking", "ManagedBy": "Terraform"},
            configuration_summary={
                "botStatus": "Available",
                "idleSessionTTLInSeconds": 300,
                "synthetic_mode": True
            },
            evidence=[
                EvidenceItem(
                    evidence_source="lex:ListBots",
                    evidence_type="direct_api",
                    sanitized_summary="Amazon Lex V2 conversational bot confirmed",
                    confidence=0.98
                )
            ],
            activity_status=ActivityStatus.ACTIVE,
            last_used_at=now - timedelta(hours=8),
            usage_evidence_source="cloudtrail:RecognizeText",
            is_approved=True
        ),

        # 10. Amazon Kendra Enterprise Search Index
        ResourceNormalizer.normalize(
            account_id=account_id,
            region=primary_region,
            service_name="kendra",
            resource_type="index",
            resource_id="kendra-idx-docs-891",
            resource_name="EnterpriseWikiKendraIndex",
            resource_arn=f"arn:aws:kendra:{primary_region}:{account_id}:index/kendra-idx-docs-891",
            description="Intelligent search and question-answering index over Confluence and S3",
            ai_category=AICategory.MANAGED_AI,
            ai_usage_status=AIUsageStatus.CONFIRMED,
            detection_method="direct_service_api:ListIndices",
            tags={"Owner": "knowledge-management", "CostCenter": "CC-2010"},
            configuration_summary={
                "Edition": "ENTERPRISE_EDITION",
                "Status": "ACTIVE",
                "synthetic_mode": True
            },
            evidence=[
                EvidenceItem(
                    evidence_source="kendra:ListIndices",
                    evidence_type="direct_api",
                    sanitized_summary="Kendra Enterprise Index active with document sync connectors",
                    confidence=0.98
                )
            ],
            activity_status=ActivityStatus.ACTIVE,
            last_used_at=now - timedelta(hours=2),
            usage_evidence_source="cloudtrail:Query",
            is_approved=True
        ),

        # 11. Step Functions AI Orchestration Pipeline
        ResourceNormalizer.normalize(
            account_id=account_id,
            region=primary_region,
            service_name="states",
            resource_type="state_machine",
            resource_id="SM-MultimodalInvoiceWorkflow",
            resource_name="MultimodalInvoiceWorkflow",
            resource_arn=f"arn:aws:states:{primary_region}:{account_id}:stateMachine:MultimodalInvoiceWorkflow",
            description="Step Functions workflow coordinating Textract, Bedrock Titan, and validation",
            ai_category=AICategory.AI_INTEGRATION,
            ai_usage_status=AIUsageStatus.CONFIRMED,
            detection_method="non_sensitive_metadata_inspection:task_states",
            tags={"Owner": "accounts-payable", "Environment": "Staging"},
            configuration_summary={
                "type": "STANDARD",
                "integration_targets": [
                    "arn:aws:states:::bedrock:invokeModel",
                    "arn:aws:states:::textract:detectDocumentText"
                ],
                "synthetic_mode": True
            },
            evidence=[
                EvidenceItem(
                    evidence_source="states:DescribeStateMachine",
                    evidence_type="task_integration",
                    sanitized_summary="State machine contains tasks integrating with Bedrock and Textract",
                    confidence=0.92
                )
            ],
            activity_status=ActivityStatus.ACTIVE,
            last_used_at=now - timedelta(days=1),
            usage_evidence_source="cloudtrail:StartExecution",
            is_approved=True
        )
    ]

    return resources
