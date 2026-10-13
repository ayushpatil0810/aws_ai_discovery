"""Repository layer handling resource upserts, query filtering, scan history, and allowlists."""

import json
from datetime import datetime
from typing import List, Optional, Dict, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import select, update, and_, or_, desc

from src.inventory.models import (
    AIResourceModel,
    ScanRunModel,
    DiscoveryEvidenceModel,
    ApprovedAIResourceModel,
)
from src.inventory.schema import (
    AIResourceCreate,
    ScanRunCreate,
    ApprovedAIResourceCreate,
)
from src.config import ApprovalStatus, utc_now


class InventoryRepository:
    """Provides transactional persistence and query operations for AI discovery."""

    def __init__(self, session: Session):
        self.session = session

    def upsert_resource(self, resource_in: AIResourceCreate) -> Tuple[AIResourceModel, bool]:
        """
        Upsert an AI resource by its stable resource_key.
        Preserves original `first_discovered_at`.
        Updates `last_scanned_at` and latest configuration/evidence.
        Returns (model, is_new).
        """
        existing = self.session.execute(
            select(AIResourceModel).where(AIResourceModel.resource_key == resource_in.resource_key)
        ).scalar_one_or_none()

        now = utc_now()
        tags_json = json.dumps(resource_in.tags)
        config_json = json.dumps(resource_in.configuration_summary)
        evidence_json = json.dumps([e.model_dump(mode="json") for e in resource_in.evidence])
        limitations_json = json.dumps([l.model_dump(mode="json") for l in resource_in.limitations])

        # Check if the resource is in the approved allowlist
        approved = self.is_resource_approved(resource_in.resource_key, resource_in.resource_arn)
        effective_approval = ApprovalStatus.APPROVED.value if approved else resource_in.approval_status.value

        if existing:
            # Preserve existing first_discovered_at
            existing.last_scanned_at = now
            existing.resource_name = resource_in.resource_name
            existing.description = resource_in.description or existing.description
            existing.resource_arn = resource_in.resource_arn or existing.resource_arn
            existing.ai_category = resource_in.ai_category.value
            existing.ai_usage_status = resource_in.ai_usage_status.value
            existing.detection_method = resource_in.detection_method
            existing.model_provider = resource_in.model_provider or existing.model_provider
            existing.model_id = resource_in.model_id or existing.model_id
            existing.endpoint_identifier = resource_in.endpoint_identifier or existing.endpoint_identifier
            
            # Prefer non-unknown owner if newly discovered
            if resource_in.owner != "unknown" or existing.owner == "unknown":
                existing.owner = resource_in.owner
                existing.owner_source = resource_in.owner_source

            existing.tags_json = tags_json
            existing.configuration_summary_json = config_json
            
            if resource_in.last_used_at:
                existing.last_used_at = resource_in.last_used_at
            if resource_in.activity_status.value != "unknown":
                existing.activity_status = resource_in.activity_status.value
            if resource_in.usage_frequency:
                existing.usage_frequency = resource_in.usage_frequency
            if resource_in.usage_evidence_source:
                existing.usage_evidence_source = resource_in.usage_evidence_source

            existing.approval_status = effective_approval
            existing.risk_level = resource_in.risk_level.value
            existing.confidence_score = resource_in.confidence_score
            existing.evidence_json = evidence_json
            existing.limitations_json = limitations_json
            existing.updated_at = now

            self._record_evidence(resource_in.resource_key, resource_in.evidence)
            return existing, False

        else:
            # Insert brand new resource
            model = AIResourceModel(
                resource_key=resource_in.resource_key,
                cloud_provider=resource_in.cloud_provider,
                account_id=resource_in.account_id,
                region=resource_in.region,
                service_name=resource_in.service_name,
                resource_type=resource_in.resource_type,
                resource_id=resource_in.resource_id,
                resource_arn=resource_in.resource_arn,
                resource_name=resource_in.resource_name,
                description=resource_in.description,
                ai_category=resource_in.ai_category.value,
                ai_usage_status=resource_in.ai_usage_status.value,
                detection_method=resource_in.detection_method,
                model_provider=resource_in.model_provider,
                model_id=resource_in.model_id,
                endpoint_identifier=resource_in.endpoint_identifier,
                owner=resource_in.owner,
                owner_source=resource_in.owner_source,
                tags_json=tags_json,
                configuration_summary_json=config_json,
                first_discovered_at=resource_in.first_discovered_at or now,
                last_scanned_at=now,
                last_used_at=resource_in.last_used_at,
                activity_status=resource_in.activity_status.value,
                usage_frequency=resource_in.usage_frequency,
                usage_window_start=resource_in.usage_window_start,
                usage_window_end=resource_in.usage_window_end,
                usage_evidence_source=resource_in.usage_evidence_source,
                data_sensitivity=resource_in.data_sensitivity,
                approval_status=effective_approval,
                risk_level=resource_in.risk_level.value,
                confidence_score=resource_in.confidence_score,
                evidence_json=evidence_json,
                limitations_json=limitations_json,
                created_at=now,
                updated_at=now,
            )
            self.session.add(model)
            self._record_evidence(resource_in.resource_key, resource_in.evidence)
            return model, True

    def _record_evidence(self, resource_key: str, evidence_items: list):
        """Append granular evidence items into discovery_evidence audit table."""
        for ev in evidence_items:
            ev_model = DiscoveryEvidenceModel(
                resource_key=resource_key,
                evidence_source=ev.evidence_source,
                evidence_type=ev.evidence_type,
                sanitized_evidence_summary=ev.sanitized_summary,
                observation_timestamp=ev.observation_timestamp,
                confidence_or_strength=ev.confidence,
                relevant_time_window=ev.relevant_time_window,
            )
            self.session.add(ev_model)

    def query_inventory(
        self,
        service_name: Optional[str] = None,
        region: Optional[str] = None,
        ai_category: Optional[str] = None,
        risk_level: Optional[str] = None,
        approval_status: Optional[str] = None,
        activity_status: Optional[str] = None,
        owner: Optional[str] = None,
        search_query: Optional[str] = None,
    ) -> List[AIResourceModel]:
        """Query inventory with flexible composite filtering."""
        stmt = select(AIResourceModel)
        filters = []

        if service_name:
            filters.append(AIResourceModel.service_name == service_name.lower())
        if region:
            filters.append(AIResourceModel.region == region.lower())
        if ai_category:
            filters.append(AIResourceModel.ai_category == ai_category.lower())
        if risk_level:
            filters.append(AIResourceModel.risk_level == risk_level.lower())
        if approval_status:
            filters.append(AIResourceModel.approval_status == approval_status.lower())
        if activity_status:
            filters.append(AIResourceModel.activity_status == activity_status.lower())
        if owner:
            if owner == "unknown":
                filters.append(AIResourceModel.owner == "unknown")
            else:
                filters.append(AIResourceModel.owner.ilike(f"%{owner}%"))
        if search_query:
            q = f"%{search_query.strip()}%"
            filters.append(
                or_(
                    AIResourceModel.resource_name.ilike(q),
                    AIResourceModel.resource_id.ilike(q),
                    AIResourceModel.resource_arn.ilike(q),
                    AIResourceModel.description.ilike(q),
                    AIResourceModel.model_id.ilike(q),
                )
            )

        if filters:
            stmt = stmt.where(and_(*filters))

        stmt = stmt.order_by(desc(AIResourceModel.last_scanned_at))
        return list(self.session.execute(stmt).scalars().all())

    def get_by_key(self, resource_key: str) -> Optional[AIResourceModel]:
        return self.session.execute(
            select(AIResourceModel).where(AIResourceModel.resource_key == resource_key)
        ).scalar_one_or_none()

    # --- Allowlist management ---
    def is_resource_approved(self, resource_key: str, resource_arn: Optional[str] = None) -> bool:
        stmt = select(ApprovedAIResourceModel).where(
            or_(
                ApprovedAIResourceModel.resource_key == resource_key,
                (ApprovedAIResourceModel.resource_key == resource_arn) if resource_arn else False
            )
        )
        approved = self.session.execute(stmt).scalar_one_or_none()
        return approved is not None and approved.approval_status == ApprovalStatus.APPROVED.value

    def add_to_allowlist(self, approval_in: ApprovedAIResourceCreate) -> ApprovedAIResourceModel:
        existing = self.session.execute(
            select(ApprovedAIResourceModel).where(ApprovedAIResourceModel.resource_key == approval_in.resource_key)
        ).scalar_one_or_none()

        now = utc_now()
        if existing:
            existing.resource_name = approval_in.resource_name
            existing.owner = approval_in.owner
            existing.approval_status = approval_in.approval_status.value
            existing.approval_reference = approval_in.approval_reference
            existing.notes = approval_in.notes
            existing.last_reviewed_at = now
            existing.updated_at = now
            return existing
        else:
            model = ApprovedAIResourceModel(
                resource_key=approval_in.resource_key,
                resource_name=approval_in.resource_name,
                owner=approval_in.owner,
                approval_status=approval_in.approval_status.value,
                approval_reference=approval_in.approval_reference,
                notes=approval_in.notes,
                last_reviewed_at=approval_in.last_reviewed_at,
                created_at=now,
                updated_at=now,
            )
            self.session.add(model)
            # Also update existing inventory status if present
            self.session.execute(
                update(AIResourceModel)
                .where(AIResourceModel.resource_key == approval_in.resource_key)
                .values(approval_status=approval_in.approval_status.value)
            )
            return model

    def list_allowlist(self) -> List[ApprovedAIResourceModel]:
        return list(self.session.execute(select(ApprovedAIResourceModel)).scalars().all())

    # --- Scan runs logging ---
    def record_scan_start(self, scan_in: ScanRunCreate) -> ScanRunModel:
        model = ScanRunModel(
            scan_id=scan_in.scan_id,
            mode=scan_in.mode.value,
            account_id=scan_in.account_id,
            requested_regions_json=json.dumps(scan_in.requested_regions),
            scanned_regions_json=json.dumps(scan_in.scanned_regions),
            scan_status=scan_in.scan_status.value,
            resources_discovered=scan_in.resources_discovered,
            resources_updated=scan_in.resources_updated,
            api_calls_attempted=scan_in.api_calls_attempted,
            api_calls_failed=scan_in.api_calls_failed,
            errors_json=json.dumps(scan_in.errors),
            warnings_json=json.dumps(scan_in.warnings),
            configuration_summary_json=json.dumps(scan_in.configuration_summary),
            start_time=scan_in.start_time,
            finish_time=scan_in.finish_time,
        )
        self.session.add(model)
        self.session.flush()
        return model

    def record_scan_finish(
        self,
        scan_id: str,
        status: str,
        scanned_regions: List[str],
        discovered_count: int,
        updated_count: int,
        api_calls_attempted: int,
        api_calls_failed: int,
        errors: List[dict],
        warnings: List[dict]
    ) -> Optional[ScanRunModel]:
        scan = self.session.execute(
            select(ScanRunModel).where(ScanRunModel.scan_id == scan_id)
        ).scalar_one_or_none()
        if scan:
            scan.scan_status = status
            scan.scanned_regions_json = json.dumps(scanned_regions)
            scan.resources_discovered = discovered_count
            scan.resources_updated = updated_count
            scan.api_calls_attempted = api_calls_attempted
            scan.api_calls_failed = api_calls_failed
            scan.errors_json = json.dumps(errors)
            scan.warnings_json = json.dumps(warnings)
            scan.finish_time = utc_now()
        return scan

    def list_scan_runs(self, limit: int = 20) -> List[ScanRunModel]:
        return list(
            self.session.execute(
                select(ScanRunModel).order_by(desc(ScanRunModel.start_time)).limit(limit)
            ).scalars().all()
        )
