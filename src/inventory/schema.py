"""Pydantic validation models for AI resources, scan executions, and governance findings."""

from datetime import datetime
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, field_validator
from src.config import (
    AICategory,
    AIUsageStatus,
    RiskLevel,
    ApprovalStatus,
    ActivityStatus,
    ScanMode,
    ScanStatus,
    utc_now,
)


class EvidenceItem(BaseModel):
    """An individual piece of evidence supporting resource discovery or risk classification."""
    evidence_source: str = Field(..., description="API or component that generated this evidence, e.g. 'bedrock:ListFoundationModels'")
    evidence_type: str = Field(..., description="Type of evidence, e.g. 'direct_api', 'env_var_name', 'gpu_instance_type'")
    sanitized_summary: str = Field(..., description="Sanitized description of the evidence without secrets or payloads")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Strength of this single piece of evidence (0.0 to 1.0)")
    observation_timestamp: datetime = Field(default_factory=utc_now)
    relevant_time_window: Optional[str] = Field(None, description="Queried time window if applicable")


class DiscoveryLimitation(BaseModel):
    """A documented limitation encountered during resource inspection."""
    limitation_code: str = Field(..., description="Standard code, e.g. 'NO_DATA_EVENTS', 'LAMBDA_ENV_VALUES_OPAQUE'")
    message: str = Field(..., description="Human-readable explanation of what could not be inspected and why")
    potential_impact: str = Field(..., description="What might be missed due to this limitation")


class AIResourceCreate(BaseModel):
    """Pydantic model representing a newly discovered or updated normalized AI resource."""
    resource_key: str = Field(..., description="Stable unique identifier: 'aws:{account}:{region}:{service}:{type}:{id}'")
    cloud_provider: str = Field(default="AWS")
    account_id: str
    region: str
    service_name: str
    resource_type: str
    resource_id: str
    resource_arn: Optional[str] = None
    resource_name: str
    description: Optional[str] = None
    ai_category: AICategory
    ai_usage_status: AIUsageStatus
    detection_method: str = Field(..., description="Methodology, e.g. 'direct_service_api', 'heuristic_config_analysis'")
    model_provider: Optional[str] = None
    model_id: Optional[str] = None
    endpoint_identifier: Optional[str] = None
    owner: str = Field(default="unknown")
    owner_source: str = Field(default="unresolved", description="How ownership was resolved, e.g. 'tag:Owner', 'none'")
    tags: Dict[str, str] = Field(default_factory=dict)
    configuration_summary: Dict[str, Any] = Field(default_factory=dict)
    
    first_discovered_at: Optional[datetime] = None
    last_scanned_at: datetime = Field(default_factory=utc_now)
    last_used_at: Optional[datetime] = None
    activity_status: ActivityStatus = ActivityStatus.UNKNOWN
    usage_frequency: Optional[str] = None
    usage_window_start: Optional[datetime] = None
    usage_window_end: Optional[datetime] = None
    usage_evidence_source: Optional[str] = None

    data_sensitivity: str = Field(default="unknown")
    approval_status: ApprovalStatus = ApprovalStatus.UNKNOWN
    
    # Explainable Risk Level & Confidence Score
    risk_level: RiskLevel = Field(default=RiskLevel.MEDIUM)
    confidence_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Explainable confidence score: 0.95+ for managed service endpoints/models; 0.70-0.90 for high-confidence infrastructure; <0.60 for heuristics"
    )
    evidence: List[EvidenceItem] = Field(default_factory=list)
    limitations: List[DiscoveryLimitation] = Field(default_factory=list)

    @field_validator("resource_key")
    @classmethod
    def validate_resource_key(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("resource_key must not be empty")
        return v.strip()


class AIResourceRead(AIResourceCreate):
    """Schema for reading persisted AI resources."""
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ScanRunCreate(BaseModel):
    """Creation schema for a discovery scan execution log."""
    scan_id: str
    mode: ScanMode
    account_id: str
    requested_regions: List[str]
    scanned_regions: List[str] = Field(default_factory=list)
    scan_status: ScanStatus = ScanStatus.RUNNING
    resources_discovered: int = 0
    resources_updated: int = 0
    api_calls_attempted: int = 0
    api_calls_failed: int = 0
    errors: List[Dict[str, Any]] = Field(default_factory=list)
    warnings: List[Dict[str, Any]] = Field(default_factory=list)
    configuration_summary: Dict[str, Any] = Field(default_factory=dict)
    start_time: datetime = Field(default_factory=utc_now)
    finish_time: Optional[datetime] = None


class ScanRunRead(ScanRunCreate):
    """Schema for reading scan run history."""
    id: int
    model_config = {"from_attributes": True}


class ApprovedAIResourceCreate(BaseModel):
    """Schema for registering an authorized AI resource."""
    resource_key: str
    resource_name: str
    owner: str
    approval_status: ApprovalStatus = ApprovalStatus.APPROVED
    approval_reference: Optional[str] = None
    notes: Optional[str] = None
    last_reviewed_at: datetime = Field(default_factory=utc_now)


class ApprovedAIResourceRead(ApprovedAIResourceCreate):
    """Schema for reading approved AI resource entries."""
    id: int
    created_at: datetime
    updated_at: datetime
    model_config = {"from_attributes": True}


class ShadowAIFinding(BaseModel):
    """Schema for a governance finding generated by the Shadow AI evaluation engine."""
    finding_id: str
    finding_type: str = Field(..., description="e.g. 'unregistered_ai_resource', 'unknown_owner', 'potential_external_ai_integration'")
    resource_key: str
    resource_name: str
    service_name: str
    region: str
    severity: RiskLevel
    title: str
    rationale: str
    evidence_summary: str
    recommended_actions: List[str]
    detected_at: datetime = Field(default_factory=utc_now)
