"""SQLAlchemy ORM models for AI discovery inventory, evidence, scan logs, and allowlists."""

from datetime import datetime
import json
from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    DateTime,
    Text,
    Index,
)
from sqlalchemy.orm import declarative_base
from src.config import utc_now

Base = declarative_base()


class AIResourceModel(Base):
    """Normalized repository of all discovered AI-related cloud resources."""
    __tablename__ = "ai_resources"

    id = Column(Integer, primary_key=True, autoincrement=True)
    resource_key = Column(String(255), unique=True, nullable=False, index=True)
    cloud_provider = Column(String(32), default="AWS", nullable=False)
    account_id = Column(String(32), nullable=False, index=True)
    region = Column(String(32), nullable=False, index=True)
    service_name = Column(String(64), nullable=False, index=True)
    resource_type = Column(String(64), nullable=False, index=True)
    resource_id = Column(String(255), nullable=False)
    resource_arn = Column(String(512), nullable=True, index=True)
    resource_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    ai_category = Column(String(64), nullable=False, index=True)
    ai_usage_status = Column(String(32), nullable=False, index=True)
    detection_method = Column(String(64), nullable=False)
    model_provider = Column(String(64), nullable=True)
    model_id = Column(String(128), nullable=True)
    endpoint_identifier = Column(String(255), nullable=True)
    owner = Column(String(128), default="unknown", nullable=False, index=True)
    owner_source = Column(String(64), default="unresolved", nullable=False)
    
    # JSON-encoded payloads for flexibility across databases
    tags_json = Column(Text, default="{}", nullable=False)
    configuration_summary_json = Column(Text, default="{}", nullable=False)
    
    first_discovered_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_scanned_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_used_at = Column(DateTime, nullable=True)
    activity_status = Column(String(32), default="unknown", nullable=False, index=True)
    usage_frequency = Column(String(64), nullable=True)
    usage_window_start = Column(DateTime, nullable=True)
    usage_window_end = Column(DateTime, nullable=True)
    usage_evidence_source = Column(String(128), nullable=True)

    data_sensitivity = Column(String(32), default="unknown", nullable=False)
    approval_status = Column(String(32), default="unknown", nullable=False, index=True)
    risk_level = Column(String(32), default="medium", nullable=False, index=True)
    confidence_score = Column(Float, nullable=False)
    
    evidence_json = Column(Text, default="[]", nullable=False)
    limitations_json = Column(Text, default="[]", nullable=False)
    
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    __table_args__ = (
        Index("idx_res_svc_cat", "service_name", "ai_category"),
        Index("idx_res_risk_appr", "risk_level", "approval_status"),
    )

    def get_tags(self) -> dict:
        try:
            return json.loads(self.tags_json or "{}")
        except Exception:
            return {}

    def get_configuration_summary(self) -> dict:
        try:
            return json.loads(self.configuration_summary_json or "{}")
        except Exception:
            return {}

    def get_evidence(self) -> list:
        try:
            return json.loads(self.evidence_json or "[]")
        except Exception:
            return []

    def get_limitations(self) -> list:
        try:
            return json.loads(self.limitations_json or "[]")
        except Exception:
            return []


class ScanRunModel(Base):
    """Historical ledger of discovery scan executions."""
    __tablename__ = "scan_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(64), unique=True, nullable=False, index=True)
    mode = Column(String(32), nullable=False)  # mock or aws
    account_id = Column(String(32), nullable=False)
    requested_regions_json = Column(Text, default="[]", nullable=False)
    scanned_regions_json = Column(Text, default="[]", nullable=False)
    scan_status = Column(String(32), default="running", nullable=False)
    resources_discovered = Column(Integer, default=0, nullable=False)
    resources_updated = Column(Integer, default=0, nullable=False)
    api_calls_attempted = Column(Integer, default=0, nullable=False)
    api_calls_failed = Column(Integer, default=0, nullable=False)
    errors_json = Column(Text, default="[]", nullable=False)
    warnings_json = Column(Text, default="[]", nullable=False)
    configuration_summary_json = Column(Text, default="{}", nullable=False)
    start_time = Column(DateTime, default=utc_now, nullable=False)
    finish_time = Column(DateTime, nullable=True)

    def get_requested_regions(self) -> list:
        try:
            return json.loads(self.requested_regions_json or "[]")
        except Exception:
            return []

    def get_scanned_regions(self) -> list:
        try:
            return json.loads(self.scanned_regions_json or "[]")
        except Exception:
            return []

    def get_errors(self) -> list:
        try:
            return json.loads(self.errors_json or "[]")
        except Exception:
            return []

    def get_warnings(self) -> list:
        try:
            return json.loads(self.warnings_json or "[]")
        except Exception:
            return []


class DiscoveryEvidenceModel(Base):
    """Granular audit trail of discovery evidence items."""
    __tablename__ = "discovery_evidence"

    id = Column(Integer, primary_key=True, autoincrement=True)
    resource_key = Column(String(255), nullable=False, index=True)
    evidence_source = Column(String(128), nullable=False)
    evidence_type = Column(String(64), nullable=False)
    sanitized_evidence_summary = Column(Text, nullable=False)
    observation_timestamp = Column(DateTime, default=utc_now, nullable=False)
    confidence_or_strength = Column(Float, nullable=False)
    relevant_time_window = Column(String(128), nullable=True)


class ApprovedAIResourceModel(Base):
    """Allowlist of officially authorized AI resources."""
    __tablename__ = "approved_ai_resources"

    id = Column(Integer, primary_key=True, autoincrement=True)
    resource_key = Column(String(255), unique=True, nullable=False, index=True)
    resource_name = Column(String(255), nullable=False)
    owner = Column(String(128), nullable=False)
    approval_status = Column(String(32), default="approved", nullable=False)
    approval_reference = Column(String(255), nullable=True)
    notes = Column(Text, nullable=True)
    last_reviewed_at = Column(DateTime, default=utc_now, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)
