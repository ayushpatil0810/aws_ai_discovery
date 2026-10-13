"""Unit tests for AWS discovery modules using botocore Stubber for pagination, AccessDenied, and metadata extraction."""

import datetime
import boto3
from botocore.stub import Stubber
import pytest

from src.discovery.base import ScanContext
from src.discovery.aws.bedrock import BedrockDiscoveryModule
from src.discovery.aws.sagemaker import SageMakerDiscoveryModule
from src.discovery.aws.infrastructure import InfrastructureDiscoveryModule
from src.discovery.aws.integrations import IntegrationsDiscoveryModule
from src.discovery.aws.activity import ActivityEnrichmentModule
from src.inventory.normalizer import ResourceNormalizer
from src.config import AICategory, AIUsageStatus, ActivityStatus


def test_bedrock_pagination_with_stubber():
    """Verify that Bedrock module properly paginates using nextToken without truncating results."""
    bedrock_client = boto3.client("bedrock", region_name="us-east-1")
    agent_client = boto3.client("bedrock-agent", region_name="us-east-1")

    with Stubber(bedrock_client) as b_stub, Stubber(agent_client) as a_stub:
        # Page 1: returns model-1 and nextToken="token123"
        b_stub.add_response(
            "list_custom_models",
            {
                "modelSummaries": [
                    {
                        "modelArn": "arn:aws:bedrock:us-east-1:123456789012:custom-model/model-1",
                        "modelName": "model-1",
                        "baseModelArn": "arn:aws:bedrock:us-east-1::foundation-model/titan-v1",
                        "baseModelName": "titan-v1",
                        "creationTime": datetime.datetime(2025, 1, 1)
                    }
                ],
                "nextToken": "token123"
            },
            expected_params={}
        )
        # Stub tags for model-1
        b_stub.add_response(
            "list_tags_for_resource",
            {"tags": [{"key": "Owner", "value": "bedrock-team"}]},
            expected_params={"resourceARN": "arn:aws:bedrock:us-east-1:123456789012:custom-model/model-1"}
        )

        # Page 2: returns model-2 and no nextToken
        b_stub.add_response(
            "list_custom_models",
            {
                "modelSummaries": [
                    {
                        "modelArn": "arn:aws:bedrock:us-east-1:123456789012:custom-model/model-2",
                        "modelName": "model-2",
                        "baseModelArn": "arn:aws:bedrock:us-east-1::foundation-model/claude-v2",
                        "baseModelName": "claude-v2",
                        "creationTime": datetime.datetime(2025, 1, 2)
                    }
                ]
            },
            expected_params={"nextToken": "token123"}
        )
        # Stub tags for model-2
        b_stub.add_response(
            "list_tags_for_resource",
            {"tags": [{"key": "Owner", "value": "data-team"}]},
            expected_params={"resourceARN": "arn:aws:bedrock:us-east-1:123456789012:custom-model/model-2"}
        )

        # Empty provisioned throughputs
        b_stub.add_response("list_provisioned_model_throughputs", {"provisionedModelSummaries": []}, expected_params={})
        # Empty inference profiles
        b_stub.add_response("list_inference_profiles", {"inferenceProfileSummaries": []}, expected_params={})
        # Empty guardrails
        b_stub.add_response("list_guardrails", {"guardrails": []}, expected_params={})

        # Agent client responses
        a_stub.add_response("list_agents", {"agentSummaries": []}, expected_params={})
        a_stub.add_response("list_knowledge_bases", {"knowledgeBaseSummaries": []}, expected_params={})

        def mock_get_client(service_name):
            if service_name == "bedrock":
                return bedrock_client
            elif service_name == "bedrock-agent":
                return agent_client
            raise ValueError(service_name)

        mock_ctx = ScanContext(
            account_id="123456789012",
            region="us-east-1",
            is_mock=False,
            client_override=mock_get_client
        )

        module = BedrockDiscoveryModule()
        result = module.discover(mock_ctx)

        # Verify both models across pages were discovered
        discovered_names = [r.resource_name for r in result.resources]
        assert "model-1" in discovered_names
        assert "model-2" in discovered_names
        assert len(result.resources) == 2


def test_sagemaker_access_denied_handled_gracefully():
    """Verify that AccessDenied on SageMaker APIs is safely recorded as an error and does not crash."""
    sm_client = boto3.client("sagemaker", region_name="us-east-1")

    with Stubber(sm_client) as stub:
        stub.add_client_error(
            "list_endpoints",
            service_error_code="AccessDeniedException",
            service_message="User is not authorized to perform sagemaker:ListEndpoints",
            http_status_code=403
        )

        mock_ctx = ScanContext(
            account_id="123456789012",
            region="us-east-1",
            is_mock=False,
            client_override=lambda s: sm_client
        )

        module = SageMakerDiscoveryModule()
        result = module.discover(mock_ctx)

        assert result.api_calls_failed >= 1
        assert len(result.errors) >= 1
        assert result.errors[0]["error_code"] == "AccessDeniedException"
        assert len(result.resources) == 0


def test_lambda_integrations_only_collects_keys_not_values():
    """Verify that Lambda non-sensitive inspection collects KEY names only and never values."""
    lambda_client = boto3.client("lambda", region_name="us-east-1")

    with Stubber(lambda_client) as stub:
        stub.add_response(
            "list_functions",
            {
                "Functions": [
                    {
                        "FunctionName": "ai-summarizer-fn",
                        "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:ai-summarizer-fn",
                        "Runtime": "python3.11",
                        "MemorySize": 512,
                        "Timeout": 30,
                        "Environment": {
                            "Variables": {
                                "OPENAI_API_KEY": "sk-super-secret-must-not-be-stored",
                                "ANTHROPIC_API_KEY": "sk-ant-another-secret",
                                "OTHER_VAR": "hello"
                            }
                        }
                    }
                ]
            },
            expected_params={"MaxItems": 50}
        )

        from unittest.mock import MagicMock
        apigw_mock = MagicMock()
        apigw_mock.get_apis.return_value = {"Items": []}
        sfn_mock = MagicMock()
        sfn_mock.list_state_machines.return_value = {"stateMachines": []}

        def mock_get_client(service_name):
            if service_name == "lambda":
                return lambda_client
            elif service_name == "apigatewayv2":
                return apigw_mock
            elif service_name == "stepfunctions":
                return sfn_mock
            raise ValueError(service_name)

        mock_ctx = ScanContext(
            account_id="123456789012",
            region="us-east-1",
            is_mock=False,
            client_override=mock_get_client
        )

        module = IntegrationsDiscoveryModule()
        result = module.discover(mock_ctx)

        assert len(result.resources) == 1
        res = result.resources[0]
        assert res.resource_name == "ai-summarizer-fn"
        
        # Verify stored keys
        env_keys = res.configuration_summary.get("environment_variable_keys", [])
        assert "OPENAI_API_KEY" in env_keys
        assert "ANTHROPIC_API_KEY" in env_keys
        
        # Verify secret values are ABSOLUTELY NOT stored in configuration or evidence
        config_str = str(res.configuration_summary)
        evidence_str = str(res.evidence)
        assert "sk-super-secret" not in config_str
        assert "sk-super-secret" not in evidence_str
        assert "sk-ant" not in config_str


def test_activity_telemetry_marks_unknown_when_logs_unavailable():
    """Verify that when CloudTrail lookup returns no events, status is marked unknown with documented limitations."""
    ct_client = boto3.client("cloudtrail", region_name="us-east-1")

    with Stubber(ct_client) as stub:
        # Mock empty event response for each query
        for _ in range(4):
            stub.add_response(
                "lookup_events",
                {"Events": []}
            )

        mock_ctx = ScanContext(
            account_id="123456789012",
            region="us-east-1",
            is_mock=False,
            client_override=lambda s: ct_client
        )

        test_res = ResourceNormalizer.normalize(
            account_id="123456789012",
            region="us-east-1",
            service_name="bedrock",
            resource_type="custom_model",
            resource_id="m1",
            resource_name="m1",
            ai_category=AICategory.MANAGED_AI,
            ai_usage_status=AIUsageStatus.CONFIRMED,
            detection_method="direct_service_api"
        )

        activity_module = ActivityEnrichmentModule()
        activity_module.enrich_resources([test_res], mock_ctx)

        # Status should be unknown because no events were seen
        assert test_res.activity_status == ActivityStatus.UNKNOWN
        # Documented limitation must be attached
        lim_codes = [l.limitation_code for l in test_res.limitations]
        assert "MANAGEMENT_EVENTS_ONLY" in lim_codes
