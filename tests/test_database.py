"""Tests for repository persistence, upserts, first_discovered_at preservation, and filtering."""

from datetime import datetime, timedelta
import pytest
from src.config import AICategory, AIUsageStatus, ScanMode, ScanStatus
from src.inventory.schema import AIResourceCreate, EvidenceItem, ScanRunCreate, ApprovedAIResourceCreate
from src.inventory.repository import InventoryRepository


def test_upsert_resource_preserves_first_discovered_at(test_db_session):
    """
    CRITICAL REQUIREMENT:
    Ensure that subsequent discovery scans update `last_scanned_at`
    while strictly preserving the original `first_discovered_at` timestamp.
    """
    repo = InventoryRepository(test_db_session)
    original_time = datetime(2025, 1, 1, 12, 0, 0)

    # First discovery
    res1 = AIResourceCreate(
        resource_key="aws:123456789012:us-east-1:bedrock:custom_model:test-model",
        account_id="123456789012",
        region="us-east-1",
        service_name="bedrock",
        resource_type="custom_model",
        resource_id="test-model",
        resource_name="test-model",
        ai_category=AICategory.MANAGED_AI,
        ai_usage_status=AIUsageStatus.CONFIRMED,
        detection_method="direct_service_api",
        owner="team-alpha",
        first_discovered_at=original_time,
        confidence_score=0.98,
        tags={"Owner": "team-alpha"}
    )

    model1, is_new1 = repo.upsert_resource(res1)
    test_db_session.flush()
    assert is_new1 is True
    assert model1.first_discovered_at == original_time

    # Second discovery scan (e.g., 30 days later)
    later_time = datetime(2025, 1, 31, 14, 0, 0)
    res2 = AIResourceCreate(
        resource_key="aws:123456789012:us-east-1:bedrock:custom_model:test-model",
        account_id="123456789012",
        region="us-east-1",
        service_name="bedrock",
        resource_type="custom_model",
        resource_id="test-model",
        resource_name="test-model-updated-name",
        ai_category=AICategory.MANAGED_AI,
        ai_usage_status=AIUsageStatus.CONFIRMED,
        detection_method="direct_service_api",
        owner="team-beta",
        first_discovered_at=later_time,  # Should be ignored on upsert
        confidence_score=0.98,
        tags={"Owner": "team-beta"}
    )

    model2, is_new2 = repo.upsert_resource(res2)
    test_db_session.flush()
    assert is_new2 is False
    # Verify first_discovered_at remained the original 2025-01-01!
    assert model2.first_discovered_at == original_time
    # Verify details were updated
    assert model2.resource_name == "test-model-updated-name"
    assert model2.owner == "team-beta"


def test_inventory_query_filtering(test_db_session):
    """Verify multi-criteria filtering on inventory repository."""
    repo = InventoryRepository(test_db_session)

    res_a = AIResourceCreate(
        resource_key="aws:123:us-east-1:bedrock:custom_model:model-a",
        account_id="123",
        region="us-east-1",
        service_name="bedrock",
        resource_type="custom_model",
        resource_id="model-a",
        resource_name="model-a",
        ai_category=AICategory.MANAGED_AI,
        ai_usage_status=AIUsageStatus.CONFIRMED,
        detection_method="direct_service_api",
        confidence_score=0.98
    )
    res_b = AIResourceCreate(
        resource_key="aws:123:us-west-2:sagemaker:endpoint:ep-b",
        account_id="123",
        region="us-west-2",
        service_name="sagemaker",
        resource_type="endpoint",
        resource_id="ep-b",
        resource_name="ep-b",
        ai_category=AICategory.CUSTOM_MODEL_HOSTING,
        ai_usage_status=AIUsageStatus.CONFIRMED,
        detection_method="direct_service_api",
        confidence_score=0.98
    )
    repo.upsert_resource(res_a)
    repo.upsert_resource(res_b)
    test_db_session.flush()

    # Filter by service
    results_bedrock = repo.query_inventory(service_name="bedrock")
    assert len(results_bedrock) == 1
    assert results_bedrock[0].resource_name == "model-a"

    # Filter by region
    results_west = repo.query_inventory(region="us-west-2")
    assert len(results_west) == 1
    assert results_west[0].resource_name == "ep-b"


def test_allowlist_workflow(test_db_session):
    """Verify adding resources to approved allowlist."""
    repo = InventoryRepository(test_db_session)
    key = "aws:123:us-east-1:sagemaker:endpoint:prod-endpoint"

    # Initially unapproved
    assert repo.is_resource_approved(key) is False

    # Add to allowlist
    repo.add_to_allowlist(
        ApprovedAIResourceCreate(
            resource_key=key,
            resource_name="prod-endpoint",
            owner="security-team",
            approval_reference="JIRA-1234"
        )
    )
    test_db_session.flush()

    # Now approved
    assert repo.is_resource_approved(key) is True
