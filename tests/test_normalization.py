"""Tests for resource normalization, ownership resolution, risk calculation, and sanitization."""

import pytest
from src.config import AICategory, AIUsageStatus, RiskLevel, ActivityStatus, sanitize_string
from src.inventory.normalizer import (
    ResourceNormalizer,
    resolve_owner,
    calculate_explainable_risk,
    calculate_confidence_score,
    build_resource_key,
)


def test_resolve_owner_tag_priority():
    """Verify that Owner tag takes precedence over other metadata."""
    tags = {"Owner": "data-platform-team", "team": "secondary-team"}
    metadata = {"creator": "arn:aws:iam::123:user/johndoe"}
    owner, source = resolve_owner(tags, metadata)
    assert owner == "data-platform-team"
    assert source == "tag:Owner"


def test_resolve_owner_metadata_fallback():
    """Verify metadata fallback when no owner tags exist."""
    tags = {"Environment": "Production"}
    metadata = {"creator": "arn:aws:iam::123:user/johndoe"}
    owner, source = resolve_owner(tags, metadata)
    assert owner == "arn:aws:iam::123:user/johndoe"
    assert source == "metadata:creator"


def test_resolve_owner_unknown():
    """Verify unresolved owner returns 'unknown'."""
    tags = {"Environment": "Production"}
    metadata = {}
    owner, source = resolve_owner(tags, metadata)
    assert owner == "unknown"
    assert source == "unresolved"


def test_build_resource_key_canonical():
    """Verify canonical, stable deduplication key generation."""
    key = build_resource_key("123456789012", "us-east-1", "sagemaker", "endpoint", "fraud-model-prod")
    assert key == "aws:123456789012:us-east-1:sagemaker:endpoint:fraud-model-prod"


def test_calculate_explainable_risk_rules():
    """Verify explainable risk calculation rules."""
    # Unregistered external AI is CRITICAL
    risk_ext = calculate_explainable_risk(
        category=AICategory.AI_INTEGRATION,
        usage_status=AIUsageStatus.CONFIRMED,
        owner="some-user",
        has_external_ai=True,
        is_approved=False
    )
    assert risk_ext == RiskLevel.CRITICAL

    # Unregistered managed AI with unknown owner is HIGH
    risk_high = calculate_explainable_risk(
        category=AICategory.MANAGED_AI,
        usage_status=AIUsageStatus.CONFIRMED,
        owner="unknown",
        has_external_ai=False,
        is_approved=False
    )
    assert risk_high == RiskLevel.HIGH

    # Approved and owned is LOW
    risk_low = calculate_explainable_risk(
        category=AICategory.MANAGED_AI,
        usage_status=AIUsageStatus.CONFIRMED,
        owner="ml-team",
        has_external_ai=False,
        is_approved=True,
        activity_status=ActivityStatus.ACTIVE
    )
    assert risk_low == RiskLevel.LOW


def test_calculate_confidence_score_semantics():
    """Verify confidence score ranges."""
    # Direct managed service is 0.98
    score_managed = calculate_confidence_score(AICategory.MANAGED_AI, AIUsageStatus.CONFIRMED, 1, is_direct_api=True)
    assert score_managed == 0.98

    # Heuristic compute is 0.60
    score_heuristic = calculate_confidence_score(AICategory.POTENTIAL_AI_INFRASTRUCTURE, AIUsageStatus.SUSPECTED, 1, is_direct_api=False)
    assert score_heuristic == 0.60


def test_sanitize_string_redaction():
    """Verify that credentials, tokens, and AWS keys are redacted."""
    raw_token = "Bearer sk-abcdef1234567890abcdef123456"
    sanitized_tok = sanitize_string(raw_token)
    assert "[REDACTED_API_KEY]" in sanitized_tok
    assert "sk-abcdef" not in sanitized_tok

    raw_aws = "User AKIAIOSFODNN7EXAMPLE logged in"
    sanitized_aws = sanitize_string(raw_aws)
    assert "[REDACTED_AWS_KEY]" in sanitized_aws
    assert "AKIAIOSFODNN7EXAMPLE" not in sanitized_aws

    raw_kv = "Connecting with secret='my-super-secret-pwd'"
    sanitized_kv = sanitize_string(raw_kv)
    assert "[REDACTED]" in sanitized_kv
    assert "my-super-secret-pwd" not in sanitized_kv
