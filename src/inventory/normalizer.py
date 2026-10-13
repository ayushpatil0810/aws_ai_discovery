"""Dedicated normalizer converting provider-specific API responses into the unified AI inventory schema."""

from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from src.config import (
    AICategory,
    AIUsageStatus,
    RiskLevel,
    ApprovalStatus,
    ActivityStatus,
    sanitize_string,
)
from src.inventory.schema import AIResourceCreate, EvidenceItem, DiscoveryLimitation

# Tag keys evaluated in priority order for ownership resolution
OWNER_TAG_KEYS = [
    "Owner",
    "owner",
    "Team",
    "team",
    "CreatedBy",
    "created_by",
    "ManagedBy",
    "managed_by",
    "AppOwner",
    "app_owner",
    "Contact",
    "contact"
]


def resolve_owner(
    tags: Dict[str, str],
    documented_metadata: Optional[Dict[str, Any]] = None
) -> Tuple[str, str]:
    """
    Resolve resource ownership in strict priority order:
    1. Explicit owner tags
    2. Documented metadata exposed by resource/deployment
    3. Fallback to 'unknown' with explanation
    """
    if tags:
        for tag_key in OWNER_TAG_KEYS:
            for k, v in tags.items():
                if k.lower() == tag_key.lower() and v and v.strip():
                    return v.strip(), f"tag:{k}"

    if documented_metadata:
        for meta_key in ["creator", "createdBy", "ownerArn", "author", "deployer"]:
            val = documented_metadata.get(meta_key)
            if val and isinstance(val, str) and val.strip():
                return val.strip(), f"metadata:{meta_key}"

    return "unknown", "unresolved"


def calculate_explainable_risk(
    category: AICategory,
    usage_status: AIUsageStatus,
    owner: str,
    has_external_ai: bool = False,
    is_approved: bool = False,
    activity_status: ActivityStatus = ActivityStatus.UNKNOWN
) -> RiskLevel:
    """
    Explainable risk evaluation rule:
    - Critical: Unregistered external AI integration (data exfiltration/compliance risk) or unowned active endpoints
    - High: Unregistered managed AI / custom model hosting with unknown owner
    - Medium: Potential AI infrastructure or unowned idle resource
    - Low: Approved and owned AI resource
    - Informational: Fully governed or read-only foundation model catalog item
    """
    if has_external_ai and not is_approved:
        return RiskLevel.CRITICAL

    if is_approved:
        if owner != "unknown" and activity_status == ActivityStatus.ACTIVE:
            return RiskLevel.LOW
        return RiskLevel.MEDIUM

    if category in [AICategory.CUSTOM_MODEL_HOSTING, AICategory.MANAGED_AI]:
        if owner == "unknown":
            return RiskLevel.HIGH
        return RiskLevel.HIGH if usage_status == AIUsageStatus.CONFIRMED else RiskLevel.MEDIUM

    if category == AICategory.AI_INTEGRATION:
        return RiskLevel.HIGH if not is_approved else RiskLevel.MEDIUM

    if category == AICategory.POTENTIAL_AI_INFRASTRUCTURE:
        return RiskLevel.MEDIUM

    return RiskLevel.LOW


def calculate_confidence_score(
    category: AICategory,
    usage_status: AIUsageStatus,
    evidence_count: int,
    is_direct_api: bool
) -> float:
    """
    Documented confidence scoring:
    - 0.98: Direct AWS managed AI service / model endpoint
    - 0.85-0.90: Custom model hosting with explicit container/model evidence
    - 0.75-0.80: Confirmed AI integration (API gateway / Lambda env keys)
    - 0.50-0.65: Heuristic detection (EC2 GPU instance type, high memory lambda)
    """
    if is_direct_api and category in [AICategory.MANAGED_AI, AICategory.CUSTOM_MODEL_HOSTING]:
        return 0.98
    if category == AICategory.AI_INTEGRATION:
        return 0.80 if evidence_count >= 2 else 0.70
    if category == AICategory.POTENTIAL_AI_INFRASTRUCTURE:
        if usage_status == AIUsageStatus.CONFIRMED:
            return 0.85
        return 0.60
    return 0.50


def build_resource_key(
    account_id: str,
    region: str,
    service_name: str,
    resource_type: str,
    resource_id: str
) -> str:
    """Generate a canonical, stable deduplication key."""
    clean_account = (account_id or "unknown").strip().lower()
    clean_region = (region or "global").strip().lower()
    clean_svc = (service_name or "unknown").strip().lower()
    clean_type = (resource_type or "resource").strip().lower()
    clean_id = (resource_id or "id").strip().lower()
    return f"aws:{clean_account}:{clean_region}:{clean_svc}:{clean_type}:{clean_id}"


class ResourceNormalizer:
    """Normalizes disparate raw AWS findings into the canonical AIResourceCreate schema."""

    @staticmethod
    def normalize(
        account_id: str,
        region: str,
        service_name: str,
        resource_type: str,
        resource_id: str,
        resource_name: str,
        ai_category: AICategory,
        ai_usage_status: AIUsageStatus,
        detection_method: str,
        resource_arn: Optional[str] = None,
        description: Optional[str] = None,
        model_provider: Optional[str] = None,
        model_id: Optional[str] = None,
        endpoint_identifier: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None,
        configuration_summary: Optional[Dict[str, Any]] = None,
        evidence: Optional[List[EvidenceItem]] = None,
        limitations: Optional[List[DiscoveryLimitation]] = None,
        activity_status: ActivityStatus = ActivityStatus.UNKNOWN,
        last_used_at: Optional[datetime] = None,
        usage_frequency: Optional[str] = None,
        usage_evidence_source: Optional[str] = None,
        is_external_ai: bool = False,
        is_approved: bool = False,
    ) -> AIResourceCreate:
        """Create a validated, normalized AI resource record."""
        clean_tags = tags or {}
        clean_config = configuration_summary or {}
        clean_evidence = evidence or []
        clean_limitations = limitations or []

        # Resolve owner
        owner, owner_source = resolve_owner(clean_tags, clean_config.get("metadata"))

        # Calculate risk and confidence
        risk = calculate_explainable_risk(
            category=ai_category,
            usage_status=ai_usage_status,
            owner=owner,
            has_external_ai=is_external_ai,
            is_approved=is_approved,
            activity_status=activity_status
        )

        is_direct = "direct" in detection_method.lower()
        confidence = calculate_confidence_score(
            category=ai_category,
            usage_status=ai_usage_status,
            evidence_count=len(clean_evidence),
            is_direct_api=is_direct
        )

        res_key = build_resource_key(account_id, region, service_name, resource_type, resource_id)

        # Sanitize descriptions and summaries
        safe_description = sanitize_string(description) if description else None

        return AIResourceCreate(
            resource_key=res_key,
            cloud_provider="AWS",
            account_id=account_id,
            region=region,
            service_name=service_name,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_arn=resource_arn,
            resource_name=resource_name,
            description=safe_description,
            ai_category=ai_category,
            ai_usage_status=ai_usage_status,
            detection_method=detection_method,
            model_provider=model_provider,
            model_id=model_id,
            endpoint_identifier=endpoint_identifier,
            owner=owner,
            owner_source=owner_source,
            tags=clean_tags,
            configuration_summary=clean_config,
            activity_status=activity_status,
            last_used_at=last_used_at,
            usage_frequency=usage_frequency,
            usage_evidence_source=usage_evidence_source,
            risk_level=risk,
            confidence_score=confidence,
            approval_status=ApprovalStatus.APPROVED if is_approved else ApprovalStatus.UNREGISTERED,
            evidence=clean_evidence,
            limitations=clean_limitations,
        )
