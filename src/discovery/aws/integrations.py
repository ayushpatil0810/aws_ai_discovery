"""Integrations discovery module: Lambda non-sensitive environment keys, API Gateway integrations, and Step Functions definitions."""

import json
import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from src.discovery.base import BaseDiscoveryModule, ScanContext, DiscoveryResult
from src.config import AICategory, AIUsageStatus, EXTERNAL_AI_PROVIDERS, setup_logging
from src.inventory.schema import AIResourceCreate, EvidenceItem, DiscoveryLimitation
from src.inventory.normalizer import ResourceNormalizer
from src.discovery.aws_session import execute_with_backoff

logger = setup_logging()

# Fast lookup for known external AI credential key signatures
KNOWN_EXTERNAL_AI_KEY_NAMES = set()
for p in EXTERNAL_AI_PROVIDERS:
    for k in p["env_keys"]:
        KNOWN_EXTERNAL_AI_KEY_NAMES.add(k.upper())


class IntegrationsDiscoveryModule(BaseDiscoveryModule):
    """Discovers application components integrating with AWS AI services or external AI vendors."""

    @property
    def service_name(self) -> str:
        return "app_integrations"

    @property
    def module_name(self) -> str:
        return "integrations"

    def discover(self, ctx: ScanContext) -> DiscoveryResult:
        result = DiscoveryResult()

        self._discover_lambda_external_integrations(ctx, result)
        self._discover_apigateway_integrations(ctx, result)
        self._discover_stepfunctions_workflows(ctx, result)

        return result

    def _discover_lambda_external_integrations(self, ctx: ScanContext, result: DiscoveryResult):
        """
        Inspect Lambda function configurations for environment variable KEY names.
        CRITICAL COMPLIANCE RULE:
        Only KEY names are collected. Values are NEVER fetched, stored, or logged!
        """
        try:
            client = ctx.get_client("lambda")
            result.api_calls_attempted += 1
            resp = execute_with_backoff(lambda: client.list_functions(MaxItems=50))
            for fn in resp.get("Functions", []):
                fn_name = fn.get("FunctionName", "")
                fn_arn = fn.get("FunctionArn", "")
                env_dict = fn.get("Environment", {}).get("Variables", {})

                # Extract only key names!
                key_names = list(env_dict.keys())
                matching_keys = [k for k in key_names if k.upper() in KNOWN_EXTERNAL_AI_KEY_NAMES]

                if matching_keys:
                    res = ResourceNormalizer.normalize(
                        account_id=ctx.account_id,
                        region=ctx.region,
                        service_name="lambda",
                        resource_type="function",
                        resource_id=fn_name,
                        resource_name=fn_name,
                        resource_arn=fn_arn,
                        description=f"Lambda function configured with external AI credential keys: {matching_keys}",
                        ai_category=AICategory.AI_INTEGRATION,
                        ai_usage_status=AIUsageStatus.CONFIRMED,
                        detection_method="non_sensitive_metadata_inspection:env_keys",
                        tags=fn.get("Tags", {}),
                        configuration_summary={
                            "Runtime": fn.get("Runtime", ""),
                            "Timeout": fn.get("Timeout", 0),
                            "MemorySize": fn.get("MemorySize", 0),
                            "environment_variable_keys": matching_keys,  # ONLY NAMES
                        },
                        evidence=[
                            EvidenceItem(
                                evidence_source="lambda:ListFunctions",
                                evidence_type="env_var_name",
                                sanitized_summary=f"Non-sensitive environment keys reference external AI provider: {matching_keys}",
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
                        is_external_ai=True
                    )
                    result.resources.append(res)
        except ClientError as e:
            result.api_calls_failed += 1
            result.warnings.append({"service": "lambda", "error": str(e)})

    def _discover_apigateway_integrations(self, ctx: ScanContext, result: DiscoveryResult):
        """Discover API Gateway HTTP/REST APIs pointing to AI endpoints or with AI naming."""
        try:
            client = ctx.get_client("apigatewayv2")
            result.api_calls_attempted += 1
            resp = execute_with_backoff(lambda: client.get_apis())
            for api in resp.get("Items", []):
                api_id = api.get("ApiId", "")
                name = api.get("Name", api_id)
                protocol = api.get("ProtocolType", "HTTP")

                # Check if API Gateway name references AI
                is_ai_api = any(kw in name.lower() for kw in ["ai", "llm", "chat", "genai", "bedrock", "sagemaker"])
                if is_ai_api:
                    res = ResourceNormalizer.normalize(
                        account_id=ctx.account_id,
                        region=ctx.region,
                        service_name="apigateway",
                        resource_type="api",
                        resource_id=api_id,
                        resource_name=name,
                        resource_arn=f"arn:aws:apigateway:{ctx.region}::/apis/{api_id}",
                        description=f"API Gateway ({protocol}) with AI routing signatures: {name}",
                        ai_category=AICategory.AI_INTEGRATION,
                        ai_usage_status=AIUsageStatus.SUSPECTED,
                        detection_method="non_sensitive_metadata_inspection:apigateway_name",
                        configuration_summary={"protocol": protocol, "apiEndpoint": api.get("ApiEndpoint", "")},
                        evidence=[
                            EvidenceItem(
                                evidence_source="apigatewayv2:GetApis",
                                evidence_type="api_gateway_name_heuristic",
                                sanitized_summary=f"API Gateway name '{name}' matches AI proxy pattern",
                                confidence=0.75
                            )
                        ]
                    )
                    result.resources.append(res)
        except ClientError as e:
            result.api_calls_failed += 1
            result.warnings.append({"service": "apigatewayv2", "error": str(e)})

    def _discover_stepfunctions_workflows(self, ctx: ScanContext, result: DiscoveryResult):
        """
        Inspect Step Functions state machine definitions in memory for Bedrock or SageMaker task integration.
        No payloads or execution histories are downloaded.
        """
        try:
            client = ctx.get_client("stepfunctions")
            result.api_calls_attempted += 1
            resp = execute_with_backoff(lambda: client.list_state_machines(maxResults=25))
            for sm in resp.get("stateMachines", []):
                arn = sm.get("stateMachineArn", "")
                name = sm.get("name", "")

                try:
                    result.api_calls_attempted += 1
                    desc = execute_with_backoff(lambda: client.describe_state_machine(stateMachineArn=arn))
                    definition_str = desc.get("definition", "{}")
                    
                    # Search definition for AI service integrations
                    ai_targets = []
                    for service_kw in ["bedrock", "sagemaker", "comprehend", "rekognition", "textract"]:
                        if f":::{service_kw}:" in definition_str.lower():
                            ai_targets.append(service_kw)

                    if ai_targets:
                        res = ResourceNormalizer.normalize(
                            account_id=ctx.account_id,
                            region=ctx.region,
                            service_name="states",
                            resource_type="state_machine",
                            resource_id=name,
                            resource_name=name,
                            resource_arn=arn,
                            description=f"Step Functions state machine coordinating AI services: {', '.join(ai_targets)}",
                            ai_category=AICategory.AI_INTEGRATION,
                            ai_usage_status=AIUsageStatus.CONFIRMED,
                            detection_method="non_sensitive_metadata_inspection:state_machine_definition",
                            configuration_summary={"ai_services_integrated": ai_targets},
                            evidence=[
                                EvidenceItem(
                                    evidence_source="states:DescribeStateMachine",
                                    evidence_type="workflow_task_integration",
                                    sanitized_summary=f"State machine coordinates tasks integrating with: {', '.join(ai_targets)}",
                                    confidence=0.92
                                )
                            ]
                        )
                        result.resources.append(res)
                except ClientError:
                    result.api_calls_failed += 1
        except ClientError as e:
            result.api_calls_failed += 1
            result.warnings.append({"service": "stepfunctions", "error": str(e)})
