"""Amazon Bedrock discovery module: custom models, agents, knowledge bases, and provisioned throughputs."""

import logging
from typing import List
from botocore.exceptions import ClientError

from src.discovery.base import BaseDiscoveryModule, ScanContext, DiscoveryResult
from src.config import AICategory, AIUsageStatus, ActivityStatus, setup_logging
from src.inventory.schema import AIResourceCreate, EvidenceItem, DiscoveryLimitation
from src.inventory.normalizer import ResourceNormalizer
from src.discovery.aws_session import execute_with_backoff

logger = setup_logging()


class BedrockDiscoveryModule(BaseDiscoveryModule):
    """Discovers account-owned Amazon Bedrock resources."""

    @property
    def service_name(self) -> str:
        return "bedrock"

    @property
    def module_name(self) -> str:
        return "bedrock"

    def discover(self, ctx: ScanContext) -> DiscoveryResult:
        result = DiscoveryResult()

        # 1. Inspect Bedrock Control Plane (Custom Models, Provisioned Throughput, Inference Profiles, Guardrails)
        try:
            bedrock_client = ctx.get_client("bedrock")
            self._discover_custom_models(bedrock_client, ctx, result)
            self._discover_provisioned_throughputs(bedrock_client, ctx, result)
            self._discover_inference_profiles(bedrock_client, ctx, result)
            self._discover_guardrails(bedrock_client, ctx, result)
        except ClientError as e:
            result.api_calls_failed += 1
            code = e.response.get("Error", {}).get("Code", "ClientError")
            msg = e.response.get("Error", {}).get("Message", str(e))
            logger.warning(f"Bedrock control plane error in {ctx.region} ({code}): {msg}")
            result.errors.append({
                "service": "bedrock",
                "region": ctx.region,
                "error_code": code,
                "message": msg
            })
        except Exception as e:
            result.api_calls_failed += 1
            logger.warning(f"Unexpected error inspecting Bedrock in {ctx.region}: {e}")
            result.errors.append({
                "service": "bedrock",
                "region": ctx.region,
                "error_code": "UnexpectedException",
                "message": str(e)
            })

        # 2. Inspect Bedrock Agents and Knowledge Bases
        try:
            agent_client = ctx.get_client("bedrock-agent")
            self._discover_agents(agent_client, ctx, result)
            self._discover_knowledge_bases(agent_client, ctx, result)
        except ClientError as e:
            result.api_calls_failed += 1
            code = e.response.get("Error", {}).get("Code", "ClientError")
            msg = e.response.get("Error", {}).get("Message", str(e))
            logger.warning(f"Bedrock agent plane error in {ctx.region} ({code}): {msg}")
            result.errors.append({
                "service": "bedrock-agent",
                "region": ctx.region,
                "error_code": code,
                "message": msg
            })
        except Exception as e:
            result.api_calls_failed += 1
            logger.warning(f"Unexpected error inspecting Bedrock Agent in {ctx.region}: {e}")
            result.errors.append({
                "service": "bedrock-agent",
                "region": ctx.region,
                "error_code": "UnexpectedException",
                "message": str(e)
            })

        return result

    def _discover_custom_models(self, client, ctx: ScanContext, result: DiscoveryResult):
        """List and normalize custom fine-tuned models."""
        next_token = None
        while True:
            result.api_calls_attempted += 1
            kwargs = {}
            if next_token:
                kwargs["nextToken"] = next_token

            resp = execute_with_backoff(lambda: client.list_custom_models(**kwargs))
            model_summaries = resp.get("modelSummaries", [])

            for m in model_summaries:
                model_name = m.get("modelName", "unknown-model")
                model_arn = m.get("modelArn", "")
                base_model_arn = m.get("baseModelArn", "")
                
                # Fetch tags if supported
                tags = {}
                if model_arn:
                    tags = self._get_resource_tags(client, model_arn, result)

                res = ResourceNormalizer.normalize(
                    account_id=ctx.account_id,
                    region=ctx.region,
                    service_name="bedrock",
                    resource_type="custom_model",
                    resource_id=model_name,
                    resource_name=model_name,
                    resource_arn=model_arn,
                    description=f"Bedrock custom model fine-tuned from {base_model_arn}",
                    ai_category=AICategory.MANAGED_AI,
                    ai_usage_status=AIUsageStatus.CONFIRMED,
                    detection_method="direct_service_api:ListCustomModels",
                    model_provider="Custom/Bedrock",
                    model_id=m.get("baseModelName", base_model_arn),
                    tags=tags,
                    configuration_summary={
                        "baseModelArn": base_model_arn,
                        "creationTime": str(m.get("creationTime", "")),
                    },
                    evidence=[
                        EvidenceItem(
                            evidence_source="bedrock:ListCustomModels",
                            evidence_type="direct_api",
                            sanitized_summary=f"Custom fine-tuned model '{model_name}' discovered in account",
                            confidence=0.99
                        )
                    ]
                )
                result.resources.append(res)

            next_token = resp.get("nextToken")
            if not next_token:
                break

    def _discover_provisioned_throughputs(self, client, ctx: ScanContext, result: DiscoveryResult):
        """List and normalize provisioned model throughputs."""
        next_token = None
        while True:
            result.api_calls_attempted += 1
            kwargs = {}
            if next_token:
                kwargs["nextToken"] = next_token

            resp = execute_with_backoff(lambda: client.list_provisioned_model_throughputs(**kwargs))
            summaries = resp.get("provisionedModelSummaries", [])

            for p in summaries:
                name = p.get("provisionedModelName", "unknown-provisioned-model")
                arn = p.get("provisionedModelArn", "")
                model_arn = p.get("modelArn", "")
                status = p.get("status", "UNKNOWN")

                tags = self._get_resource_tags(client, arn, result) if arn else {}

                res = ResourceNormalizer.normalize(
                    account_id=ctx.account_id,
                    region=ctx.region,
                    service_name="bedrock",
                    resource_type="provisioned_throughput",
                    resource_id=name,
                    resource_name=name,
                    resource_arn=arn,
                    description=f"Provisioned Model Throughput for {model_arn}",
                    ai_category=AICategory.MANAGED_AI,
                    ai_usage_status=AIUsageStatus.CONFIRMED,
                    detection_method="direct_service_api:ListProvisionedModelThroughputs",
                    endpoint_identifier=name,
                    tags=tags,
                    configuration_summary={
                        "modelArn": model_arn,
                        "status": status,
                        "modelUnits": p.get("modelUnits", 0)
                    },
                    evidence=[
                        EvidenceItem(
                            evidence_source="bedrock:ListProvisionedModelThroughputs",
                            evidence_type="direct_api",
                            sanitized_summary=f"Provisioned model throughput active: {name} (Status: {status})",
                            confidence=0.99
                        )
                    ]
                )
                result.resources.append(res)

            next_token = resp.get("nextToken")
            if not next_token:
                break

    def _discover_inference_profiles(self, client, ctx: ScanContext, result: DiscoveryResult):
        """List system-defined or application inference profiles."""
        if not hasattr(client, "list_inference_profiles"):
            return

        next_token = None
        while True:
            result.api_calls_attempted += 1
            kwargs = {}
            if next_token:
                kwargs["nextToken"] = next_token

            try:
                resp = execute_with_backoff(lambda: client.list_inference_profiles(**kwargs))
            except ClientError as e:
                # Some regions or IAM roles may not support this operation yet
                result.warnings.append({"warning": f"list_inference_profiles not supported or denied: {e}"})
                break

            summaries = resp.get("inferenceProfileSummaries", [])
            for p in summaries:
                # Focus on application/account-specific profiles
                profile_type = p.get("type", "")
                if profile_type == "APPLICATION":
                    name = p.get("inferenceProfileName", "")
                    arn = p.get("inferenceProfileArn", "")
                    res = ResourceNormalizer.normalize(
                        account_id=ctx.account_id,
                        region=ctx.region,
                        service_name="bedrock",
                        resource_type="inference_profile",
                        resource_id=p.get("inferenceProfileId", name),
                        resource_name=name,
                        resource_arn=arn,
                        description="Bedrock Application Inference Profile",
                        ai_category=AICategory.MANAGED_AI,
                        ai_usage_status=AIUsageStatus.CONFIRMED,
                        detection_method="direct_service_api:ListInferenceProfiles",
                        configuration_summary={"status": p.get("status", "")},
                        evidence=[
                            EvidenceItem(
                                evidence_source="bedrock:ListInferenceProfiles",
                                evidence_type="direct_api",
                                sanitized_summary=f"Application inference profile configured: {name}",
                                confidence=0.95
                            )
                        ]
                    )
                    result.resources.append(res)

            next_token = resp.get("nextToken")
            if not next_token:
                break

    def _discover_guardrails(self, client, ctx: ScanContext, result: DiscoveryResult):
        """List Bedrock Guardrails configured in the account."""
        if not hasattr(client, "list_guardrails"):
            return

        next_token = None
        while True:
            result.api_calls_attempted += 1
            kwargs = {}
            if next_token:
                kwargs["nextToken"] = next_token

            try:
                resp = execute_with_backoff(lambda: client.list_guardrails(**kwargs))
            except ClientError:
                break

            for g in resp.get("guardrails", []):
                name = g.get("name", "")
                g_id = g.get("id", "")
                arn = g.get("arn", "")
                res = ResourceNormalizer.normalize(
                    account_id=ctx.account_id,
                    region=ctx.region,
                    service_name="bedrock",
                    resource_type="guardrail",
                    resource_id=g_id,
                    resource_name=name,
                    resource_arn=arn,
                    description=g.get("description", "Bedrock Safety Guardrail"),
                    ai_category=AICategory.MANAGED_AI,
                    ai_usage_status=AIUsageStatus.CONFIRMED,
                    detection_method="direct_service_api:ListGuardrails",
                    configuration_summary={"status": g.get("status", "")},
                    evidence=[
                        EvidenceItem(
                            evidence_source="bedrock:ListGuardrails",
                            evidence_type="direct_api",
                            sanitized_summary=f"Bedrock content safety guardrail configured: {name}",
                            confidence=0.95
                        )
                    ]
                )
                result.resources.append(res)

            next_token = resp.get("nextToken")
            if not next_token:
                break

    def _discover_agents(self, client, ctx: ScanContext, result: DiscoveryResult):
        """List and normalize Bedrock Agents."""
        next_token = None
        while True:
            result.api_calls_attempted += 1
            kwargs = {}
            if next_token:
                kwargs["nextToken"] = next_token

            resp = execute_with_backoff(lambda: client.list_agents(**kwargs))
            summaries = resp.get("agentSummaries", [])

            for a in summaries:
                agent_id = a.get("agentId", "")
                agent_name = a.get("agentName", "")
                status = a.get("agentStatus", "")
                
                # Agents ARN format: arn:aws:bedrock:region:account:agent/agentId
                arn = f"arn:aws:bedrock:{ctx.region}:{ctx.account_id}:agent/{agent_id}"
                tags = self._get_resource_tags(client, arn, result)

                res = ResourceNormalizer.normalize(
                    account_id=ctx.account_id,
                    region=ctx.region,
                    service_name="bedrock-agent",
                    resource_type="agent",
                    resource_id=agent_id,
                    resource_name=agent_name,
                    resource_arn=arn,
                    description=f"Bedrock Autonomous Agent ({status})",
                    ai_category=AICategory.MANAGED_AI,
                    ai_usage_status=AIUsageStatus.CONFIRMED,
                    detection_method="direct_service_api:ListAgents",
                    tags=tags,
                    configuration_summary={
                        "agentStatus": status,
                        "updatedAt": str(a.get("updatedAt", ""))
                    },
                    evidence=[
                        EvidenceItem(
                            evidence_source="bedrock-agent:ListAgents",
                            evidence_type="direct_api",
                            sanitized_summary=f"Bedrock Agent discovered: {agent_name} (ID: {agent_id})",
                            confidence=0.98
                        )
                    ]
                )
                result.resources.append(res)

            next_token = resp.get("nextToken")
            if not next_token:
                break

    def _discover_knowledge_bases(self, client, ctx: ScanContext, result: DiscoveryResult):
        """List and normalize Bedrock Knowledge Bases (RAG)."""
        next_token = None
        while True:
            result.api_calls_attempted += 1
            kwargs = {}
            if next_token:
                kwargs["nextToken"] = next_token

            resp = execute_with_backoff(lambda: client.list_knowledge_bases(**kwargs))
            summaries = resp.get("knowledgeBaseSummaries", [])

            for kb in summaries:
                kb_id = kb.get("knowledgeBaseId", "")
                name = kb.get("name", "")
                status = kb.get("status", "")
                arn = f"arn:aws:bedrock:{ctx.region}:{ctx.account_id}:knowledge-base/{kb_id}"

                res = ResourceNormalizer.normalize(
                    account_id=ctx.account_id,
                    region=ctx.region,
                    service_name="bedrock-agent",
                    resource_type="knowledge_base",
                    resource_id=kb_id,
                    resource_name=name,
                    resource_arn=arn,
                    description=f"Bedrock Knowledge Base for RAG retrieval ({status})",
                    ai_category=AICategory.MANAGED_AI,
                    ai_usage_status=AIUsageStatus.CONFIRMED,
                    detection_method="direct_service_api:ListKnowledgeBases",
                    configuration_summary={
                        "status": status,
                        "updatedAt": str(kb.get("updatedAt", ""))
                    },
                    evidence=[
                        EvidenceItem(
                            evidence_source="bedrock-agent:ListKnowledgeBases",
                            evidence_type="direct_api",
                            sanitized_summary=f"Bedrock Knowledge Base active: {name} (ID: {kb_id})",
                            confidence=0.98
                        )
                    ]
                )
                result.resources.append(res)

            next_token = resp.get("nextToken")
            if not next_token:
                break

    def _get_resource_tags(self, client, resource_arn: str, result: DiscoveryResult) -> dict:
        """Fetch tags for a Bedrock resource if supported and authorized."""
        if not hasattr(client, "list_tags_for_resource"):
            return {}
        try:
            result.api_calls_attempted += 1
            resp = execute_with_backoff(lambda: client.list_tags_for_resource(resourceARN=resource_arn))
            raw_tags = resp.get("tags", {})
            if isinstance(raw_tags, dict):
                return raw_tags
            elif isinstance(raw_tags, list):
                return {t.get("key", t.get("Key", "")): t.get("value", t.get("Value", "")) for t in raw_tags}
        except ClientError:
            result.api_calls_failed += 1
        return {}
