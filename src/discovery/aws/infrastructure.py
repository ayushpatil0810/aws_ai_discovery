"""Infrastructure discovery module: EC2 GPU/AI instances, ECS AI services, EKS clusters, and high-compute Lambda."""

import logging
import re
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from src.discovery.base import BaseDiscoveryModule, ScanContext, DiscoveryResult
from src.config import AICategory, AIUsageStatus, setup_logging
from src.inventory.schema import AIResourceCreate, EvidenceItem, DiscoveryLimitation
from src.inventory.normalizer import ResourceNormalizer
from src.discovery.aws_session import execute_with_backoff

logger = setup_logging()

# GPU and specialized AI accelerator instance families
AI_INSTANCE_FAMILY_PATTERNS = [
    re.compile(r"^g[3-6][a-z0-9]*\."),      # g3, g4dn, g4ad, g5, g5g, g6, gr6
    re.compile(r"^p[2-5][a-z0-9]*\."),      # p2, p3, p3dn, p4d, p4de, p5, p5e
    re.compile(r"^inf[1-2]\."),             # Inferentia 1, 2
    re.compile(r"^trn[1-2][a-z0-9]*\."),    # Trainium 1, 2
    re.compile(r"^dl[1-2]\."),              # Habana Gaudi
]

AI_KEYWORDS = ["ai", "ml", "llm", "vllm", "pytorch", "tensorflow", "huggingface", "ollama", "triton", "diffusion", "rag", "embedding"]


def is_ai_instance_type(instance_type: str) -> bool:
    """Check if an instance type belongs to an AWS AI accelerator or GPU family."""
    if not instance_type:
        return False
    return any(p.match(instance_type.lower()) for p in AI_INSTANCE_FAMILY_PATTERNS)


def has_ai_tag_or_name(tags: Dict[str, str], name: str) -> bool:
    """Check if tags or resource name contain AI/ML keywords."""
    combined = (name + " " + " ".join(f"{k} {v}" for k, v in tags.items())).lower()
    return any(kw in combined for kw in AI_KEYWORDS)


class InfrastructureDiscoveryModule(BaseDiscoveryModule):
    """Discovers compute infrastructure with potential custom AI workloads."""

    @property
    def service_name(self) -> str:
        return "compute_infrastructure"

    @property
    def module_name(self) -> str:
        return "infrastructure"

    def discover(self, ctx: ScanContext) -> DiscoveryResult:
        result = DiscoveryResult()

        self._discover_ec2(ctx, result)
        self._discover_ecs(ctx, result)
        self._discover_eks(ctx, result)
        self._discover_lambda_infrastructure(ctx, result)

        return result

    def _discover_ec2(self, ctx: ScanContext, result: DiscoveryResult):
        """Discover EC2 instances with GPU/accelerators or explicit AI tags."""
        try:
            client = ctx.get_client("ec2")
            result.api_calls_attempted += 1
            resp = execute_with_backoff(lambda: client.describe_instances())

            for reservation in resp.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    inst_id = inst.get("InstanceId", "")
                    inst_type = inst.get("InstanceType", "")
                    state = inst.get("State", {}).get("Name", "")

                    # Extract tags
                    tags = {t.get("Key", ""): t.get("Value", "") for t in inst.get("Tags", []) if "Key" in t}
                    name = tags.get("Name", inst_id)

                    is_gpu = is_ai_instance_type(inst_type)
                    has_ai_tags = has_ai_tag_or_name(tags, name)

                    # Only register if there is tangible evidence
                    if is_gpu or has_ai_tags:
                        evidence = []
                        if is_gpu:
                            evidence.append(
                                EvidenceItem(
                                    evidence_source="ec2:DescribeInstances",
                                    evidence_type="gpu_instance_type",
                                    sanitized_summary=f"Instance {inst_id} uses AI accelerator/GPU instance family '{inst_type}'",
                                    confidence=0.85
                                )
                            )
                        if has_ai_tags:
                            evidence.append(
                                EvidenceItem(
                                    evidence_source="ec2:DescribeInstances",
                                    evidence_type="tag_heuristic",
                                    sanitized_summary=f"Instance tags or name contain AI keywords: {name}",
                                    confidence=0.75
                                )
                            )

                        res = ResourceNormalizer.normalize(
                            account_id=ctx.account_id,
                            region=ctx.region,
                            service_name="ec2",
                            resource_type="instance",
                            resource_id=inst_id,
                            resource_name=name,
                            resource_arn=f"arn:aws:ec2:{ctx.region}:{ctx.account_id}:instance/{inst_id}",
                            description=f"EC2 Instance ({inst_type}, {state}) with potential AI workload",
                            ai_category=AICategory.POTENTIAL_AI_INFRASTRUCTURE,
                            ai_usage_status=AIUsageStatus.SUSPECTED,
                            detection_method="heuristic_config_analysis:ec2_gpu_or_tags",
                            tags=tags,
                            configuration_summary={
                                "InstanceType": inst_type,
                                "State": state,
                                "LaunchTime": str(inst.get("LaunchTime", ""))
                            },
                            evidence=evidence,
                            limitations=[
                                DiscoveryLimitation(
                                    limitation_code="OPAQUE_GUEST_OS",
                                    message="Read-only EC2 describe cannot inspect guest OS memory or active model weights",
                                    potential_impact="Cannot verify whether model inference is currently active inside the instance"
                                )
                            ]
                        )
                        result.resources.append(res)
        except ClientError as e:
            result.api_calls_failed += 1
            result.warnings.append({"service": "ec2", "error": str(e)})

    def _discover_ecs(self, ctx: ScanContext, result: DiscoveryResult):
        """Discover ECS services running known AI container images or task definitions."""
        try:
            client = ctx.get_client("ecs")
            result.api_calls_attempted += 1
            resp = execute_with_backoff(lambda: client.list_clusters())
            cluster_arns = resp.get("clusterArns", [])

            for cluster_arn in cluster_arns[:5]:  # limit clusters per region
                cluster_name = cluster_arn.split("/")[-1]
                result.api_calls_attempted += 1
                svc_resp = execute_with_backoff(lambda: client.list_services(cluster=cluster_arn))
                for svc_arn in svc_resp.get("serviceArns", []):
                    svc_name = svc_arn.split("/")[-1]
                    if has_ai_tag_or_name({}, svc_name):
                        res = ResourceNormalizer.normalize(
                            account_id=ctx.account_id,
                            region=ctx.region,
                            service_name="ecs",
                            resource_type="service",
                            resource_id=f"{cluster_name}/{svc_name}",
                            resource_name=svc_name,
                            resource_arn=svc_arn,
                            description=f"ECS Service in cluster '{cluster_name}' matching AI workload naming",
                            ai_category=AICategory.POTENTIAL_AI_INFRASTRUCTURE,
                            ai_usage_status=AIUsageStatus.SUSPECTED,
                            detection_method="heuristic_config_analysis:ecs_service_name",
                            configuration_summary={"cluster": cluster_name},
                            evidence=[
                                EvidenceItem(
                                    evidence_source="ecs:ListServices",
                                    evidence_type="service_name_heuristic",
                                    sanitized_summary=f"ECS service '{svc_name}' matches AI workload naming pattern",
                                    confidence=0.75
                                )
                            ]
                        )
                        result.resources.append(res)
        except ClientError as e:
            result.api_calls_failed += 1
            result.warnings.append({"service": "ecs", "error": str(e)})

    def _discover_eks(self, ctx: ScanContext, result: DiscoveryResult):
        """Discover EKS clusters and inspect node groups for GPU instance types."""
        try:
            client = ctx.get_client("eks")
            result.api_calls_attempted += 1
            resp = execute_with_backoff(lambda: client.list_clusters())
            for c_name in resp.get("clusters", [])[:5]:
                try:
                    result.api_calls_attempted += 1
                    ng_resp = execute_with_backoff(lambda: client.list_nodegroups(clusterName=c_name))
                    for ng in ng_resp.get("nodegroups", []):
                        if has_ai_tag_or_name({}, ng) or has_ai_tag_or_name({}, c_name):
                            res = ResourceNormalizer.normalize(
                                account_id=ctx.account_id,
                                region=ctx.region,
                                service_name="eks",
                                resource_type="nodegroup",
                                resource_id=f"{c_name}/{ng}",
                                resource_name=f"{c_name}-{ng}",
                                resource_arn=f"arn:aws:eks:{ctx.region}:{ctx.account_id}:nodegroup/{c_name}/{ng}",
                                description=f"EKS Nodegroup in cluster '{c_name}' with AI naming signatures",
                                ai_category=AICategory.POTENTIAL_AI_INFRASTRUCTURE,
                                ai_usage_status=AIUsageStatus.SUSPECTED,
                                detection_method="heuristic_config_analysis:eks_nodegroup",
                                configuration_summary={"clusterName": c_name, "nodegroup": ng},
                                evidence=[
                                    EvidenceItem(
                                        evidence_source="eks:ListNodegroups",
                                        evidence_type="cluster_name_heuristic",
                                        sanitized_summary=f"EKS nodegroup '{ng}' in cluster '{c_name}' matches AI workload naming pattern",
                                        confidence=0.75
                                    )
                                ]
                            )
                            result.resources.append(res)
                except ClientError:
                    result.api_calls_failed += 1
        except ClientError as e:
            result.api_calls_failed += 1
            result.warnings.append({"service": "eks", "error": str(e)})

    def _discover_lambda_infrastructure(self, ctx: ScanContext, result: DiscoveryResult):
        """Discover Lambda functions with high compute capacity (Memory >= 3008MB) or container packaging."""
        try:
            client = ctx.get_client("lambda")
            result.api_calls_attempted += 1
            resp = execute_with_backoff(lambda: client.list_functions(MaxItems=50))
            for fn in resp.get("Functions", []):
                fn_name = fn.get("FunctionName", "")
                fn_arn = fn.get("FunctionArn", "")
                memory = fn.get("MemorySize", 128)
                pkg_type = fn.get("PackageType", "Zip")
                ephemeral = fn.get("EphemeralStorage", {}).get("Size", 512)

                is_high_compute = memory >= 3008 or ephemeral > 1024
                has_name_kw = has_ai_tag_or_name({}, fn_name)

                if (is_high_compute and has_name_kw) or (pkg_type == "Image" and has_name_kw):
                    res = ResourceNormalizer.normalize(
                        account_id=ctx.account_id,
                        region=ctx.region,
                        service_name="lambda",
                        resource_type="function",
                        resource_id=fn_name,
                        resource_name=fn_name,
                        resource_arn=fn_arn,
                        description=f"Lambda high-compute function ({memory}MB, {pkg_type}) with AI workload naming",
                        ai_category=AICategory.POTENTIAL_AI_INFRASTRUCTURE,
                        ai_usage_status=AIUsageStatus.SUSPECTED,
                        detection_method="heuristic_config_analysis:lambda_high_compute",
                        configuration_summary={
                            "MemorySize": memory,
                            "PackageType": pkg_type,
                            "EphemeralStorageMB": ephemeral,
                            "Runtime": fn.get("Runtime", "Container")
                        },
                        evidence=[
                            EvidenceItem(
                                evidence_source="lambda:ListFunctions",
                                evidence_type="high_compute_heuristic",
                                sanitized_summary=f"Lambda function has high memory ({memory}MB) or container packaging and AI naming keywords",
                                confidence=0.70
                            )
                        ]
                    )
                    result.resources.append(res)
        except ClientError as e:
            result.api_calls_failed += 1
            result.warnings.append({"service": "lambda", "error": str(e)})
