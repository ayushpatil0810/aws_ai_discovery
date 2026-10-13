"""Central discovery orchestration engine coordinating multi-region, multi-module scans."""

import uuid
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional

from src.config import Settings, ScanMode, ScanStatus, setup_logging, utc_now
from src.inventory.schema import AIResourceCreate, ScanRunCreate
from src.inventory.database import get_db
from src.inventory.repository import InventoryRepository
from src.discovery.base import ScanContext, BaseDiscoveryModule
from src.discovery.aws_session import AWSSessionManager
from src.discovery.mock_provider import get_mock_resources
from src.discovery.aws.bedrock import BedrockDiscoveryModule
from src.discovery.aws.sagemaker import SageMakerDiscoveryModule
from src.discovery.aws.managed_ai import ManagedAIDiscoveryModule
from src.discovery.aws.infrastructure import InfrastructureDiscoveryModule
from src.discovery.aws.integrations import IntegrationsDiscoveryModule
from src.discovery.aws.resource_explorer import ResourceExplorerDiscoveryModule
from src.discovery.aws.activity import ActivityEnrichmentModule

logger = setup_logging()


class DiscoveryEngine:
    """Orchestrates comprehensive AI discovery across configured AWS regions and modules."""

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or Settings()
        self.session_manager = AWSSessionManager(self.settings)

    def run_scan(
        self,
        mode: Optional[ScanMode] = None,
        regions: Optional[List[str]] = None,
        profile: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute a full discovery scan.
        Mode can be explicit or configured in Settings.
        """
        effective_mode = mode or self.settings.discovery_mode
        scan_id = f"scan-{uuid.uuid4().hex[:12]}"
        start_time = utc_now()

        logger.info(f"Starting AI Discovery scan [{scan_id}] in mode: {effective_mode.value.upper()}")

        if effective_mode == ScanMode.MOCK:
            return self._run_mock_scan(scan_id, regions)
        else:
            return self._run_aws_scan(scan_id, regions, profile)

    def _run_mock_scan(self, scan_id: str, requested_regions: Optional[List[str]] = None) -> Dict[str, Any]:
        """Execute mock/offline discovery using synthetic dataset."""
        account_id = "123456789012"
        target_regions = requested_regions or self.settings.target_regions or ["us-east-1", "us-west-2", "ap-south-1"]

        # Record scan start in DB
        with get_db(self.settings.database_url) as session:
            repo = InventoryRepository(session)
            repo.record_scan_start(
                ScanRunCreate(
                    scan_id=scan_id,
                    mode=ScanMode.MOCK,
                    account_id=account_id,
                    requested_regions=target_regions,
                    scanned_regions=target_regions,
                    scan_status=ScanStatus.RUNNING,
                    configuration_summary={"description": "Offline Demonstration Mode with Synthetic AI Assets"}
                )
            )

        # Generate mock resources
        mock_resources = get_mock_resources(account_id=account_id, regions=target_regions)

        discovered_count = 0
        updated_count = 0

        with get_db(self.settings.database_url) as session:
            repo = InventoryRepository(session)
            for res in mock_resources:
                _, is_new = repo.upsert_resource(res)
                if is_new:
                    discovered_count += 1
                else:
                    updated_count += 1

            repo.record_scan_finish(
                scan_id=scan_id,
                status=ScanStatus.COMPLETED.value,
                scanned_regions=target_regions,
                discovered_count=discovered_count,
                updated_count=updated_count,
                api_calls_attempted=len(mock_resources),
                api_calls_failed=0,
                errors=[],
                warnings=[]
            )

        logger.info(f"Mock scan completed. Discovered: {discovered_count}, Updated: {updated_count}")
        return {
            "scan_id": scan_id,
            "mode": "mock",
            "account_id": account_id,
            "status": "completed",
            "scanned_regions": target_regions,
            "discovered_count": discovered_count,
            "updated_count": updated_count,
            "api_calls_attempted": len(mock_resources),
            "api_calls_failed": 0,
            "errors": [],
            "warnings": []
        }

    def _run_aws_scan(
        self,
        scan_id: str,
        requested_regions: Optional[List[str]] = None,
        profile: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute live AWS scan against real AWS APIs.
        CRITICAL: Never fall back to mock data if credentials or APIs fail.
        """
        if profile:
            self.settings.aws_profile = profile

        # Validate caller credentials
        identity = self.session_manager.validate_credentials()
        account_id = identity["account_id"]
        caller_arn = identity["arn"]

        # Resolve target regions
        target_regions = self.session_manager.discover_regions(requested_regions)
        scanned_regions = []
        all_errors = []
        all_warnings = []
        total_attempted = 0
        total_failed = 0

        with get_db(self.settings.database_url) as session:
            repo = InventoryRepository(session)
            repo.record_scan_start(
                ScanRunCreate(
                    scan_id=scan_id,
                    mode=ScanMode.AWS,
                    account_id=account_id,
                    requested_regions=target_regions,
                    scanned_regions=[],
                    scan_status=ScanStatus.RUNNING,
                    configuration_summary={
                        "caller_arn": caller_arn,
                        "profile": self.settings.aws_profile or "default",
                        "modules": {
                            "bedrock": self.settings.module_bedrock,
                            "sagemaker": self.settings.module_sagemaker,
                            "managed_ai": self.settings.module_managed_ai,
                            "infrastructure": self.settings.module_infrastructure,
                            "integrations": self.settings.module_integrations,
                            "resource_explorer": self.settings.module_resource_explorer,
                            "activity": self.settings.module_activity,
                        }
                    }
                )
            )

        # Assemble enabled discovery modules
        modules: List[BaseDiscoveryModule] = []
        if self.settings.module_bedrock:
            modules.append(BedrockDiscoveryModule())
        if self.settings.module_sagemaker:
            modules.append(SageMakerDiscoveryModule())
        if self.settings.module_managed_ai:
            modules.append(ManagedAIDiscoveryModule())
        if self.settings.module_infrastructure:
            modules.append(InfrastructureDiscoveryModule())
        if self.settings.module_integrations:
            modules.append(IntegrationsDiscoveryModule())
        if self.settings.module_resource_explorer:
            modules.append(ResourceExplorerDiscoveryModule())

        activity_module = ActivityEnrichmentModule() if self.settings.module_activity else None

        session_obj = self.session_manager.get_session()
        all_discovered_resources: Dict[str, AIResourceCreate] = {}

        # Scan each region
        for region in target_regions:
            logger.info(f"Scanning region: {region} ({len(modules)} modules)")
            ctx = ScanContext(
                account_id=account_id,
                region=region,
                is_mock=False,
                lookback_days=self.settings.activity_lookback_days,
                session=session_obj
            )

            regional_resources: List[AIResourceCreate] = []

            for mod in modules:
                try:
                    res_result = mod.discover(ctx)
                    total_attempted += res_result.api_calls_attempted
                    total_failed += res_result.api_calls_failed
                    all_errors.extend(res_result.errors)
                    all_warnings.extend(res_result.warnings)
                    regional_resources.extend(res_result.resources)
                except Exception as e:
                    total_failed += 1
                    err = {"module": mod.module_name, "region": region, "error": str(e)}
                    logger.error(f"Error in module {mod.module_name} in {region}: {e}")
                    all_errors.append(err)

            # Optional Activity Enrichment per region
            if activity_module and regional_resources:
                try:
                    activity_module.enrich_resources(regional_resources, ctx)
                except Exception as e:
                    all_warnings.append({"module": "activity", "region": region, "warning": str(e)})

            # Deduplicate by canonical resource_key
            for r in regional_resources:
                all_discovered_resources[r.resource_key] = r

            scanned_regions.append(region)

        # Upsert into database
        discovered_count = 0
        updated_count = 0

        with get_db(self.settings.database_url) as session:
            repo = InventoryRepository(session)
            for res in all_discovered_resources.values():
                _, is_new = repo.upsert_resource(res)
                if is_new:
                    discovered_count += 1
                else:
                    updated_count += 1

            status = ScanStatus.PARTIAL.value if (all_errors and len(all_discovered_resources) > 0) else (
                ScanStatus.FAILED.value if (all_errors and len(all_discovered_resources) == 0) else ScanStatus.COMPLETED.value
            )

            repo.record_scan_finish(
                scan_id=scan_id,
                status=status,
                scanned_regions=scanned_regions,
                discovered_count=discovered_count,
                updated_count=updated_count,
                api_calls_attempted=total_attempted,
                api_calls_failed=total_failed,
                errors=all_errors,
                warnings=all_warnings
            )

        logger.info(
            f"AWS scan finished [{status}]. Discovered: {discovered_count}, Updated: {updated_count}, "
            f"Calls attempted: {total_attempted}, Failed: {total_failed}"
        )

        return {
            "scan_id": scan_id,
            "mode": "aws",
            "account_id": account_id,
            "caller_arn": caller_arn,
            "status": status,
            "scanned_regions": scanned_regions,
            "discovered_count": discovered_count,
            "updated_count": updated_count,
            "api_calls_attempted": total_attempted,
            "api_calls_failed": total_failed,
            "errors": all_errors,
            "warnings": all_warnings
        }
