"""AWS Resource Explorer 2 cross-checking discovery module."""

import logging
from typing import List
from botocore.exceptions import ClientError

from src.discovery.base import BaseDiscoveryModule, ScanContext, DiscoveryResult
from src.config import AICategory, AIUsageStatus, setup_logging
from src.inventory.schema import AIResourceCreate, EvidenceItem
from src.inventory.normalizer import ResourceNormalizer
from src.discovery.aws_session import execute_with_backoff

logger = setup_logging()


class ResourceExplorerDiscoveryModule(BaseDiscoveryModule):
    """Cross-checks AI resource types using AWS Resource Explorer 2 indexed views."""

    @property
    def service_name(self) -> str:
        return "resource-explorer-2"

    @property
    def module_name(self) -> str:
        return "resource_explorer"

    def discover(self, ctx: ScanContext) -> DiscoveryResult:
        result = DiscoveryResult()
        try:
            client = ctx.get_client("resource-explorer-2")
            result.api_calls_attempted += 1

            # Query for AI-related resource types
            query_string = (
                "resourcetype:bedrock:* OR resourcetype:sagemaker:endpoint "
                "OR resourcetype:comprehend:* OR resourcetype:kendra:*"
            )
            resp = execute_with_backoff(lambda: client.search(QueryString=query_string, MaxResults=50))
            
            for item in resp.get("Resources", []):
                arn = item.get("Arn", "")
                res_type = item.get("ResourceType", "unknown")
                service = item.get("Service", "aws")
                res_region = item.get("Region", ctx.region)

                res_id = arn.split("/")[-1] if "/" in arn else arn.split(":")[-1]

                res = ResourceNormalizer.normalize(
                    account_id=ctx.account_id,
                    region=res_region,
                    service_name=service,
                    resource_type=res_type.split(":")[-1],
                    resource_id=res_id,
                    resource_name=res_id,
                    resource_arn=arn,
                    description=f"Discovered via AWS Resource Explorer 2 indexing ({res_type})",
                    ai_category=AICategory.MANAGED_AI,
                    ai_usage_status=AIUsageStatus.CONFIRMED,
                    detection_method="resource_explorer_search",
                    evidence=[
                        EvidenceItem(
                            evidence_source="resource-explorer-2:Search",
                            evidence_type="indexed_catalog",
                            sanitized_summary=f"Resource Explorer indexed match for ARN {arn}",
                            confidence=0.90
                        )
                    ]
                )
                result.resources.append(res)
        except ClientError as e:
            # Resource Explorer may not be turned on in this region or account
            code = e.response.get("Error", {}).get("Code", "")
            if code in ["UnauthorizedException", "ResourceNotFoundException", "AccessDeniedException"]:
                result.coverage_notes.append(f"Resource Explorer is not configured or accessible in {ctx.region} ({code})")
            else:
                result.api_calls_failed += 1
                result.warnings.append({"service": "resource-explorer-2", "error": str(e)})
        except Exception as e:
            result.coverage_notes.append(f"Resource Explorer unavailable: {e}")

        return result
