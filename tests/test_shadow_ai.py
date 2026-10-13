"""Tests for the Shadow AI detection rules engine."""

import pytest
from src.config import RiskLevel, AICategory, AIUsageStatus, ActivityStatus, ApprovalStatus
from src.inventory.models import AIResourceModel
from src.governance.shadow_ai import ShadowAIEngine


def test_shadow_ai_unregistered_resource():
    """Verify that an unapproved AI resource triggers unregistered_ai_resource finding."""
    engine = ShadowAIEngine()
    res = AIResourceModel(
        resource_key="aws:123:us-east-1:bedrock:custom_model:unregistered-llm",
        resource_name="unregistered-llm",
        service_name="bedrock",
        region="us-east-1",
        ai_category=AICategory.MANAGED_AI.value,
        ai_usage_status=AIUsageStatus.CONFIRMED.value,
        approval_status=ApprovalStatus.UNREGISTERED.value,
        owner="ml-team",
        detection_method="direct_service_api",
        activity_status=ActivityStatus.ACTIVE.value
    )

    findings = engine.evaluate_resource(res, is_approved=False)
    types = [f.finding_type for f in findings]
    assert "unregistered_ai_resource" in types
    
    unreg_finding = next(f for f in findings if f.finding_type == "unregistered_ai_resource")
    assert unreg_finding.severity == RiskLevel.HIGH


def test_shadow_ai_unknown_owner():
    """Verify that a resource with owner='unknown' triggers unknown_owner finding."""
    engine = ShadowAIEngine()
    res = AIResourceModel(
        resource_key="aws:123:us-east-1:sagemaker:endpoint:orphan-endpoint",
        resource_name="orphan-endpoint",
        service_name="sagemaker",
        region="us-east-1",
        ai_category=AICategory.CUSTOM_MODEL_HOSTING.value,
        ai_usage_status=AIUsageStatus.CONFIRMED.value,
        approval_status=ApprovalStatus.APPROVED.value,
        owner="unknown",
        detection_method="direct_service_api",
        activity_status=ActivityStatus.ACTIVE.value
    )

    findings = engine.evaluate_resource(res, is_approved=True)
    types = [f.finding_type for f in findings]
    assert "unknown_owner" in types


def test_shadow_ai_external_provider_integration():
    """Verify that Lambda with external AI env keys triggers CRITICAL external AI integration finding."""
    engine = ShadowAIEngine()
    res = AIResourceModel(
        resource_key="aws:123:us-east-1:lambda:function:chat-worker",
        resource_name="chat-worker",
        service_name="lambda",
        region="us-east-1",
        ai_category=AICategory.AI_INTEGRATION.value,
        ai_usage_status=AIUsageStatus.CONFIRMED.value,
        approval_status=ApprovalStatus.UNREGISTERED.value,
        owner="dev-team",
        detection_method="non_sensitive_metadata_inspection",
        configuration_summary_json='{"environment_variable_keys": ["OPENAI_API_KEY", "TIMEOUT"]}',
        activity_status=ActivityStatus.ACTIVE.value
    )

    findings = engine.evaluate_resource(res, is_approved=False)
    types = [f.finding_type for f in findings]
    assert "potential_external_ai_integration" in types

    ext_finding = next(f for f in findings if f.finding_type == "potential_external_ai_integration")
    assert ext_finding.severity == RiskLevel.CRITICAL
    assert "OpenAI credential key 'OPENAI_API_KEY'" in ext_finding.evidence_summary


def test_shadow_ai_potential_hosting():
    """Verify that EC2 GPU instance triggers potential_ai_hosting finding."""
    engine = ShadowAIEngine()
    res = AIResourceModel(
        resource_key="aws:123:us-east-1:ec2:instance:i-12345678",
        resource_name="gpu-runner",
        service_name="ec2",
        region="us-east-1",
        ai_category=AICategory.POTENTIAL_AI_INFRASTRUCTURE.value,
        ai_usage_status=AIUsageStatus.SUSPECTED.value,
        approval_status=ApprovalStatus.UNREGISTERED.value,
        owner="dev-team",
        detection_method="heuristic_config_analysis",
        configuration_summary_json='{"spec": "NVIDIA A10G"}',
        activity_status=ActivityStatus.UNKNOWN.value
    )

    findings = engine.evaluate_resource(res, is_approved=False)
    types = [f.finding_type for f in findings]
    assert "potential_ai_hosting" in types
    assert "unknown_activity" in types
