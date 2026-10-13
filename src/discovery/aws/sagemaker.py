"""Amazon SageMaker discovery module: endpoints, models, training jobs, notebook instances, and domains."""

import logging
from typing import Dict, List, Any
from botocore.exceptions import ClientError

from src.discovery.base import BaseDiscoveryModule, ScanContext, DiscoveryResult
from src.config import AICategory, AIUsageStatus, setup_logging
from src.inventory.schema import AIResourceCreate, EvidenceItem
from src.inventory.normalizer import ResourceNormalizer
from src.discovery.aws_session import execute_with_backoff

logger = setup_logging()


class SageMakerDiscoveryModule(BaseDiscoveryModule):
    """Discovers account-owned Amazon SageMaker models and compute infrastructure."""

    @property
    def service_name(self) -> str:
        return "sagemaker"

    @property
    def module_name(self) -> str:
        return "sagemaker"

    def discover(self, ctx: ScanContext) -> DiscoveryResult:
        result = DiscoveryResult()
        try:
            client = ctx.get_client("sagemaker")
            self._discover_endpoints(client, ctx, result)
            self._discover_models(client, ctx, result)
            self._discover_training_jobs(client, ctx, result)
            self._discover_notebook_instances(client, ctx, result)
            self._discover_domains(client, ctx, result)
        except ClientError as e:
            result.api_calls_failed += 1
            code = e.response.get("Error", {}).get("Code", "ClientError")
            msg = e.response.get("Error", {}).get("Message", str(e))
            logger.warning(f"SageMaker discovery error in {ctx.region} ({code}): {msg}")
            result.errors.append({
                "service": "sagemaker",
                "region": ctx.region,
                "error_code": code,
                "message": msg
            })
        except Exception as e:
            result.api_calls_failed += 1
            logger.warning(f"Unexpected error inspecting SageMaker in {ctx.region}: {e}")
            result.errors.append({
                "service": "sagemaker",
                "region": ctx.region,
                "error_code": "UnexpectedException",
                "message": str(e)
            })

        return result

    def _discover_endpoints(self, client, ctx: ScanContext, result: DiscoveryResult):
        """List and describe SageMaker inference endpoints."""
        next_token = None
        while True:
            result.api_calls_attempted += 1
            kwargs = {}
            if next_token:
                kwargs["NextToken"] = next_token

            resp = execute_with_backoff(lambda: client.list_endpoints(**kwargs))
            endpoints = resp.get("Endpoints", [])

            for ep in endpoints:
                name = ep.get("EndpointName", "")
                arn = ep.get("EndpointArn", "")
                status = ep.get("EndpointStatus", "UNKNOWN")

                tags = self._get_tags(client, arn, result)

                # Fetch detailed endpoint configuration
                details = {}
                try:
                    result.api_calls_attempted += 1
                    desc = execute_with_backoff(lambda: client.describe_endpoint(EndpointName=name))
                    prod_variants = desc.get("ProductionVariants", [])
                    variant_info = []
                    for v in prod_variants:
                        variant_info.append({
                            "VariantName": v.get("VariantName", ""),
                            "InstanceType": v.get("InstanceType", ""),
                            "InitialInstanceCount": v.get("InitialInstanceCount", 0),
                            "CurrentInstanceCount": v.get("CurrentInstanceCount", 0),
                        })
                    details["ProductionVariants"] = variant_info
                    details["EndpointConfigName"] = desc.get("EndpointConfigName", "")
                except ClientError:
                    result.api_calls_failed += 1

                details["EndpointStatus"] = status

                res = ResourceNormalizer.normalize(
                    account_id=ctx.account_id,
                    region=ctx.region,
                    service_name="sagemaker",
                    resource_type="endpoint",
                    resource_id=name,
                    resource_name=name,
                    resource_arn=arn,
                    description=f"SageMaker Inference Endpoint (Status: {status})",
                    ai_category=AICategory.CUSTOM_MODEL_HOSTING,
                    ai_usage_status=AIUsageStatus.CONFIRMED,
                    detection_method="direct_service_api:ListEndpoints",
                    endpoint_identifier=name,
                    tags=tags,
                    configuration_summary=details,
                    evidence=[
                        EvidenceItem(
                            evidence_source="sagemaker:ListEndpoints",
                            evidence_type="direct_api",
                            sanitized_summary=f"SageMaker endpoint deployed: {name} (Status: {status})",
                            confidence=0.99
                        )
                    ]
                )
                result.resources.append(res)

            next_token = resp.get("NextToken")
            if not next_token:
                break

    def _discover_models(self, client, ctx: ScanContext, result: DiscoveryResult):
        """List SageMaker registered model entities."""
        next_token = None
        while True:
            result.api_calls_attempted += 1
            kwargs = {}
            if next_token:
                kwargs["NextToken"] = next_token

            resp = execute_with_backoff(lambda: client.list_models(**kwargs))
            models = resp.get("Models", [])

            for m in models:
                name = m.get("ModelName", "")
                arn = m.get("ModelArn", "")

                tags = self._get_tags(client, arn, result)

                res = ResourceNormalizer.normalize(
                    account_id=ctx.account_id,
                    region=ctx.region,
                    service_name="sagemaker",
                    resource_type="model",
                    resource_id=name,
                    resource_name=name,
                    resource_arn=arn,
                    description=f"SageMaker Model Artifact ({name})",
                    ai_category=AICategory.CUSTOM_MODEL_HOSTING,
                    ai_usage_status=AIUsageStatus.CONFIRMED,
                    detection_method="direct_service_api:ListModels",
                    tags=tags,
                    configuration_summary={"creationTime": str(m.get("CreationTime", ""))},
                    evidence=[
                        EvidenceItem(
                            evidence_source="sagemaker:ListModels",
                            evidence_type="direct_api",
                            sanitized_summary=f"SageMaker model package discovered: {name}",
                            confidence=0.98
                        )
                    ]
                )
                result.resources.append(res)

            next_token = resp.get("NextToken")
            if not next_token:
                break

    def _discover_training_jobs(self, client, ctx: ScanContext, result: DiscoveryResult):
        """List recent SageMaker training jobs."""
        result.api_calls_attempted += 1
        try:
            resp = execute_with_backoff(lambda: client.list_training_jobs(MaxResults=25))
            jobs = resp.get("TrainingJobSummaries", [])
            for j in jobs:
                name = j.get("TrainingJobName", "")
                arn = j.get("TrainingJobArn", "")
                status = j.get("TrainingJobStatus", "")

                res = ResourceNormalizer.normalize(
                    account_id=ctx.account_id,
                    region=ctx.region,
                    service_name="sagemaker",
                    resource_type="training_job",
                    resource_id=name,
                    resource_name=name,
                    resource_arn=arn,
                    description=f"SageMaker Training Job ({status})",
                    ai_category=AICategory.CUSTOM_MODEL_HOSTING,
                    ai_usage_status=AIUsageStatus.CONFIRMED,
                    detection_method="direct_service_api:ListTrainingJobs",
                    configuration_summary={
                        "status": status,
                        "creationTime": str(j.get("CreationTime", "")),
                        "endTime": str(j.get("TrainingEndTime", ""))
                    },
                    evidence=[
                        EvidenceItem(
                            evidence_source="sagemaker:ListTrainingJobs",
                            evidence_type="direct_api",
                            sanitized_summary=f"SageMaker training job discovered: {name} (Status: {status})",
                            confidence=0.98
                        )
                    ]
                )
                result.resources.append(res)
        except ClientError:
            result.api_calls_failed += 1

    def _discover_notebook_instances(self, client, ctx: ScanContext, result: DiscoveryResult):
        """List SageMaker classic notebook instances."""
        result.api_calls_attempted += 1
        try:
            resp = execute_with_backoff(lambda: client.list_notebook_instances(MaxResults=25))
            for nb in resp.get("NotebookInstances", []):
                name = nb.get("NotebookInstanceName", "")
                arn = nb.get("NotebookInstanceArn", "")
                status = nb.get("NotebookInstanceStatus", "")
                inst_type = nb.get("InstanceType", "")

                tags = self._get_tags(client, arn, result)

                res = ResourceNormalizer.normalize(
                    account_id=ctx.account_id,
                    region=ctx.region,
                    service_name="sagemaker",
                    resource_type="notebook_instance",
                    resource_id=name,
                    resource_name=name,
                    resource_arn=arn,
                    description=f"SageMaker Jupyter Notebook ({inst_type})",
                    ai_category=AICategory.CUSTOM_MODEL_HOSTING,
                    ai_usage_status=AIUsageStatus.CONFIRMED,
                    detection_method="direct_service_api:ListNotebookInstances",
                    tags=tags,
                    configuration_summary={
                        "status": status,
                        "instanceType": inst_type
                    },
                    evidence=[
                        EvidenceItem(
                            evidence_source="sagemaker:ListNotebookInstances",
                            evidence_type="direct_api",
                            sanitized_summary=f"SageMaker notebook instance: {name} ({inst_type})",
                            confidence=0.98
                        )
                    ]
                )
                result.resources.append(res)
        except ClientError:
            result.api_calls_failed += 1

    def _discover_domains(self, client, ctx: ScanContext, result: DiscoveryResult):
        """List SageMaker Studio Domains."""
        result.api_calls_attempted += 1
        try:
            resp = execute_with_backoff(lambda: client.list_domains(MaxResults=25))
            for d in resp.get("Domains", []):
                domain_id = d.get("DomainId", "")
                name = d.get("DomainName", domain_id)
                arn = d.get("DomainArn", "")
                status = d.get("Status", "")

                res = ResourceNormalizer.normalize(
                    account_id=ctx.account_id,
                    region=ctx.region,
                    service_name="sagemaker",
                    resource_type="domain",
                    resource_id=domain_id,
                    resource_name=name,
                    resource_arn=arn,
                    description=f"SageMaker Studio ML Domain ({status})",
                    ai_category=AICategory.CUSTOM_MODEL_HOSTING,
                    ai_usage_status=AIUsageStatus.CONFIRMED,
                    detection_method="direct_service_api:ListDomains",
                    configuration_summary={"status": status},
                    evidence=[
                        EvidenceItem(
                            evidence_source="sagemaker:ListDomains",
                            evidence_type="direct_api",
                            sanitized_summary=f"SageMaker Studio Domain: {name} (ID: {domain_id})",
                            confidence=0.98
                        )
                    ]
                )
                result.resources.append(res)
        except ClientError:
            result.api_calls_failed += 1

    def _get_tags(self, client, resource_arn: str, result: DiscoveryResult) -> dict:
        """Fetch SageMaker resource tags safely."""
        if not resource_arn:
            return {}
        try:
            result.api_calls_attempted += 1
            resp = execute_with_backoff(lambda: client.list_tags(ResourceArn=resource_arn))
            raw = resp.get("Tags", [])
            return {t.get("Key", ""): t.get("Value", "") for t in raw if "Key" in t}
        except ClientError:
            result.api_calls_failed += 1
            return {}
