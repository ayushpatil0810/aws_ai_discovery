"""Service registry mapping modules to AWS services, APIs, required IAM permissions, and detection methods."""

import json
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class ServiceRegistryEntry:
    module_name: str
    service_name: str
    resource_types: List[str]
    api_operations: List[str]
    required_iam_actions: List[str]
    optional_iam_actions: List[str] = field(default_factory=list)
    detection_method: str = "direct_service_api"
    resource_level_support: bool = False
    description: str = ""


# Master Service Registry of all supported discovery modules
SERVICE_REGISTRY: List[ServiceRegistryEntry] = [
    ServiceRegistryEntry(
        module_name="bedrock",
        service_name="bedrock",
        resource_types=[
            "foundation_model",
            "custom_model",
            "provisioned_throughput",
            "inference_profile",
            "agent",
            "knowledge_base",
            "guardrail"
        ],
        api_operations=[
            "bedrock:ListFoundationModels",
            "bedrock:ListCustomModels",
            "bedrock:ListProvisionedModelThroughputs",
            "bedrock:ListInferenceProfiles",
            "bedrock:ListGuardrails",
            "bedrock-agent:ListAgents",
            "bedrock-agent:ListKnowledgeBases"
        ],
        required_iam_actions=[
            "bedrock:ListFoundationModels",
            "bedrock:GetFoundationModel",
            "bedrock:ListCustomModels",
            "bedrock:ListProvisionedModelThroughputs",
            "bedrock:ListInferenceProfiles",
            "bedrock:ListGuardrails",
            "bedrock:ListTagsForResource",
            "bedrock-agent:ListAgents",
            "bedrock-agent:ListKnowledgeBases",
            "bedrock-agent:ListTagsForResource"
        ],
        detection_method="direct_service_api",
        description="Discovers foundation models metadata, custom fine-tuned models, provisioned throughputs, agents, knowledge bases, and guardrails."
    ),
    ServiceRegistryEntry(
        module_name="sagemaker",
        service_name="sagemaker",
        resource_types=[
            "endpoint",
            "model",
            "training_job",
            "processing_job",
            "notebook_instance",
            "domain"
        ],
        api_operations=[
            "sagemaker:ListEndpoints",
            "sagemaker:DescribeEndpoint",
            "sagemaker:ListModels",
            "sagemaker:DescribeModel",
            "sagemaker:ListTrainingJobs",
            "sagemaker:ListProcessingJobs",
            "sagemaker:ListNotebookInstances",
            "sagemaker:ListDomains",
            "sagemaker:ListTags"
        ],
        required_iam_actions=[
            "sagemaker:ListEndpoints",
            "sagemaker:DescribeEndpoint",
            "sagemaker:ListModels",
            "sagemaker:DescribeModel",
            "sagemaker:ListTrainingJobs",
            "sagemaker:ListProcessingJobs",
            "sagemaker:ListNotebookInstances",
            "sagemaker:ListDomains",
            "sagemaker:ListTags"
        ],
        detection_method="direct_service_api",
        description="Discovers active inference endpoints, registered model packages, training jobs, notebook instances, and SageMaker Studio domains."
    ),
    ServiceRegistryEntry(
        module_name="managed_ai",
        service_name="managed_ai_suite",
        resource_types=[
            "comprehend_classifier",
            "comprehend_endpoint",
            "rekognition_project",
            "rekognition_stream_processor",
            "textract_adapter",
            "transcribe_custom_model",
            "polly_lexicon",
            "lex_v2_bot",
            "translate_terminology",
            "personalize_campaign",
            "forecast_predictor",
            "kendra_index"
        ],
        api_operations=[
            "comprehend:ListDocumentClassifiers",
            "comprehend:ListEndpoints",
            "comprehend:ListEntityRecognizers",
            "rekognition:DescribeProjects",
            "rekognition:ListStreamProcessors",
            "textract:ListAdapters",
            "transcribe:ListLanguageModels",
            "transcribe:ListVocabularies",
            "polly:ListLexicons",
            "lex:ListBots",
            "translate:ListTerminologies",
            "personalize:ListCampaigns",
            "personalize:ListSolutions",
            "forecast:ListPredictors",
            "kendra:ListIndices"
        ],
        required_iam_actions=[
            "comprehend:ListDocumentClassifiers",
            "comprehend:ListEndpoints",
            "comprehend:ListEntityRecognizers",
            "comprehend:ListTagsForResource",
            "rekognition:DescribeProjects",
            "rekognition:ListStreamProcessors",
            "textract:ListAdapters",
            "transcribe:ListLanguageModels",
            "transcribe:ListVocabularies",
            "polly:ListLexicons",
            "lex:ListBots",
            "translate:ListTerminologies",
            "personalize:ListCampaigns",
            "personalize:ListSolutions",
            "forecast:ListPredictors",
            "kendra:ListIndices"
        ],
        detection_method="direct_service_api",
        description="Inspects specialized AWS managed AI services across text, vision, speech, search, translation, and personalization."
    ),
    ServiceRegistryEntry(
        module_name="infrastructure",
        service_name="compute_infrastructure",
        resource_types=[
            "ec2_gpu_instance",
            "ecs_ai_service",
            "eks_ai_cluster",
            "lambda_high_compute_function"
        ],
        api_operations=[
            "ec2:DescribeInstances",
            "ecs:ListClusters",
            "ecs:ListServices",
            "ecs:DescribeServices",
            "ecs:DescribeTaskDefinition",
            "eks:ListClusters",
            "eks:DescribeCluster",
            "eks:ListNodegroups",
            "lambda:ListFunctions"
        ],
        required_iam_actions=[
            "ec2:DescribeInstances",
            "ecs:ListClusters",
            "ecs:ListServices",
            "ecs:DescribeServices",
            "ecs:DescribeTaskDefinition",
            "eks:ListClusters",
            "eks:DescribeCluster",
            "eks:ListNodegroups",
            "lambda:ListFunctions"
        ],
        detection_method="heuristic_config_analysis",
        description="Identifies potential custom AI hosting on GPU instances, ML container images, or oversized serverless functions."
    ),
    ServiceRegistryEntry(
        module_name="integrations",
        service_name="app_integrations",
        resource_types=[
            "api_gateway_ai_proxy",
            "lambda_external_ai_integration",
            "stepfunctions_ai_statemachine"
        ],
        api_operations=[
            "apigateway:GET",
            "lambda:ListFunctions",
            "states:ListStateMachines",
            "states:DescribeStateMachine"
        ],
        required_iam_actions=[
            "apigateway:GET",
            "lambda:ListFunctions",
            "states:ListStateMachines",
            "states:DescribeStateMachine"
        ],
        detection_method="non_sensitive_metadata_inspection",
        description="Inspects Lambda non-sensitive environment variable names, API Gateway route integrations, and Step Function states for external AI references."
    ),
    ServiceRegistryEntry(
        module_name="resource_explorer",
        service_name="resource-explorer-2",
        resource_types=[
            "cross_service_ai_index"
        ],
        api_operations=[
            "resource-explorer-2:Search"
        ],
        required_iam_actions=[
            "resource-explorer-2:Search"
        ],
        detection_method="resource_explorer_search",
        description="Optional cross-checking of account resources using AWS Resource Explorer 2 views."
    ),
    ServiceRegistryEntry(
        module_name="activity",
        service_name="cloudtrail",
        resource_types=[
            "cloudtrail_management_events"
        ],
        api_operations=[
            "cloudtrail:LookupEvents"
        ],
        required_iam_actions=[
            "cloudtrail:LookupEvents"
        ],
        detection_method="cloudtrail_event_history",
        description="Correlates non-destructive CloudTrail management events to observe recent administrative and invocation calls."
    ),
]


def generate_iam_policy(include_optional: bool = True) -> Dict[str, Any]:
    """
    Generate a strictly read-only, least-privilege IAM policy document covering all discovery modules.
    Excludes any write, update, delete, or model inference actions.
    """
    actions = set()
    for entry in SERVICE_REGISTRY:
        actions.update(entry.required_iam_actions)
        if include_optional:
            actions.update(entry.optional_iam_actions)

    # Add core identity verification and region discovery actions
    actions.add("sts:GetCallerIdentity")
    actions.add("ec2:DescribeRegions")

    sorted_actions = sorted(list(actions))

    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowReadOnlyAIDiscovery",
                "Effect": "Allow",
                "Action": sorted_actions,
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:RequestedRegion": [
                            # Scoped per deployment or account region policy
                        ]
                    }
                } if False else None
            }
        ]
    }


def write_iam_policy_file(filepath: str = "aws_discovery_iam_policy.json") -> None:
    """Generate and serialize the IAM policy to a file."""
    policy = generate_iam_policy(include_optional=True)
    # Clean None values
    statement = policy["Statement"][0]
    if statement.get("Condition") is None:
        del statement["Condition"]

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(policy, f, indent=2)
