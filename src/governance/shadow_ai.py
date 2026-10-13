"""Shadow AI and governance risk evaluation engine."""

import uuid
from typing import List, Dict, Any, Optional
from src.config import (
    RiskLevel,
    ApprovalStatus,
    AICategory,
    AIUsageStatus,
    ActivityStatus,
    EXTERNAL_AI_PROVIDERS,
)
from src.inventory.schema import ShadowAIFinding
from src.inventory.models import AIResourceModel


class ShadowAIEngine:
    """Evaluates inventory assets against security policies to identify Shadow AI and compliance gaps."""

    def evaluate_resource(
        self,
        resource: AIResourceModel,
        is_approved: bool = False
    ) -> List[ShadowAIFinding]:
        """Generate explainable findings for a single inventory resource."""
        findings: List[ShadowAIFinding] = []
        tags = resource.get_tags()
        config = resource.get_configuration_summary()

        # 1. Check Unregistered AI Resource
        if not is_approved and resource.approval_status != ApprovalStatus.APPROVED.value:
            severity = RiskLevel.HIGH if resource.ai_category in [
                AICategory.MANAGED_AI.value,
                AICategory.CUSTOM_MODEL_HOSTING.value
            ] else RiskLevel.MEDIUM

            findings.append(
                ShadowAIFinding(
                    finding_id=f"SHADOW-{uuid.uuid4().hex[:8].upper()}",
                    finding_type="unregistered_ai_resource",
                    resource_key=resource.resource_key,
                    resource_name=resource.resource_name,
                    service_name=resource.service_name,
                    region=resource.region,
                    severity=severity,
                    title=f"Unregistered AI Resource: {resource.resource_name}",
                    rationale=(
                        f"Resource is actively classified as {resource.ai_category} "
                        f"with usage status '{resource.ai_usage_status}', but does not exist in the approved AI inventory."
                    ),
                    evidence_summary=f"Discovered via {resource.detection_method}. Category: {resource.ai_category}.",
                    recommended_actions=[
                        "Verify with business stakeholders if this AI deployment is intended.",
                        "If legitimate, register in approved inventory with business owner and risk assessment.",
                        "If unauthorized, initiate decommissioning or access restriction procedures."
                    ]
                )
            )

        # 2. Check Unknown Owner
        if resource.owner == "unknown":
            findings.append(
                ShadowAIFinding(
                    finding_id=f"OWNER-{uuid.uuid4().hex[:8].upper()}",
                    finding_type="unknown_owner",
                    resource_key=resource.resource_key,
                    resource_name=resource.resource_name,
                    service_name=resource.service_name,
                    region=resource.region,
                    severity=RiskLevel.MEDIUM,
                    title=f"Unowned AI Asset: {resource.resource_name}",
                    rationale="Resource lacks mandatory ownership metadata or tags (e.g., Owner, Team, CreatedBy).",
                    evidence_summary="Ownership resolution attempted across standard tags and metadata, returned 'unknown'.",
                    recommended_actions=[
                        "Tag resource with designated team/individual owner using mandatory tag schema.",
                        "Establish operational and budget accountability."
                    ]
                )
            )

        # 3. Check External AI Provider Integrations (Data Exfiltration / Privacy Risk)
        external_ai_evidence = self._check_external_ai_integration(resource, config)
        if external_ai_evidence:
            findings.append(
                ShadowAIFinding(
                    finding_id=f"EXTAI-{uuid.uuid4().hex[:8].upper()}",
                    finding_type="potential_external_ai_integration",
                    resource_key=resource.resource_key,
                    resource_name=resource.resource_name,
                    service_name=resource.service_name,
                    region=resource.region,
                    severity=RiskLevel.CRITICAL if not is_approved else RiskLevel.MEDIUM,
                    title=f"External AI Provider Reference in {resource.resource_name}",
                    rationale=(
                        "Resource configuration exposes references or integration points to external AI vendors "
                        "(e.g., OpenAI, Anthropic, Cohere, Pinecone). Customer payloads or prompts may leave the AWS security boundary."
                    ),
                    evidence_summary=external_ai_evidence,
                    recommended_actions=[
                        "Inspect integration destination to confirm what data is transmitted externally.",
                        "Ensure third-party AI provider has approved enterprise DPA and security review.",
                        "Audit access controls and API key storage (verify Secrets Manager is used, not plaintext env vars)."
                    ]
                )
            )

        # 4. Check Potential AI Hosting (Compute Infrastructure with Unconfirmed AI)
        if resource.ai_category == AICategory.POTENTIAL_AI_INFRASTRUCTURE.value:
            findings.append(
                ShadowAIFinding(
                    finding_id=f"HOST-{uuid.uuid4().hex[:8].upper()}",
                    finding_type="potential_ai_hosting",
                    resource_key=resource.resource_key,
                    resource_name=resource.resource_name,
                    service_name=resource.service_name,
                    region=resource.region,
                    severity=RiskLevel.MEDIUM,
                    title=f"Potential Custom AI Infrastructure: {resource.resource_name}",
                    rationale=(
                        "High-capacity compute (GPU acceleration, ML container image, or AI runtime libraries) "
                        "detected without formal registration as an approved ML workload."
                    ),
                    evidence_summary=f"Instance/workload specs or container images indicate AI/ML capability: {config.get('spec', 'N/A')}",
                    recommended_actions=[
                        "Confirm workload purpose with the infrastructure team.",
                        "Verify whether proprietary or open-weights models are hosted here."
                    ]
                )
            )

        # 5. Check Unknown Activity
        if resource.activity_status in [ActivityStatus.UNKNOWN.value, ActivityStatus.NOT_CONFIGURED.value]:
            findings.append(
                ShadowAIFinding(
                    finding_id=f"ACT-{uuid.uuid4().hex[:8].upper()}",
                    finding_type="unknown_activity",
                    resource_key=resource.resource_key,
                    resource_name=resource.resource_name,
                    service_name=resource.service_name,
                    region=resource.region,
                    severity=RiskLevel.LOW,
                    title=f"Unmonitored AI Activity: {resource.resource_name}",
                    rationale="No recent telemetry, invocation logs, or CloudTrail events could be verified for this AI resource.",
                    evidence_summary=f"Activity status is '{resource.activity_status}'. Coverage limitations: {resource.get_limitations()}",
                    recommended_actions=[
                        "Ensure CloudTrail management and data logging are enabled for the service.",
                        "Evaluate whether resource is idle and eligible for decommissioning to save costs."
                    ]
                )
            )

        return findings

    def _check_external_ai_integration(
        self,
        resource: AIResourceModel,
        config: Dict[str, Any]
    ) -> Optional[str]:
        """Inspect non-sensitive config, env keys, or endpoints for external AI vendor signatures."""
        env_keys = config.get("environment_variable_keys", [])
        integrations = config.get("integration_targets", [])
        image_name = config.get("image_name", "")

        matches = []
        for provider in EXTERNAL_AI_PROVIDERS:
            # Check env var names (only keys, values are never fetched)
            for key in env_keys:
                if any(k.lower() == key.lower() for k in provider["env_keys"]):
                    matches.append(f"{provider['name']} credential key '{key}' present in environment configuration")

            # Check integration endpoints or step function states
            for target in integrations:
                for kw in provider["keywords"]:
                    if kw in str(target).lower():
                        matches.append(f"{provider['name']} endpoint target '{target}'")

            # Check container image keywords
            for kw in provider["keywords"]:
                if kw in image_name.lower():
                    matches.append(f"{provider['name']} container signature in '{image_name}'")

        if matches:
            return "; ".join(matches)
        return None

    def evaluate_inventory(
        self,
        resources: List[AIResourceModel],
        approved_keys: Optional[List[str]] = None
    ) -> List[ShadowAIFinding]:
        """Evaluate a collection of inventory resources."""
        appr = set(approved_keys or [])
        all_findings = []
        for res in resources:
            is_appr = (res.resource_key in appr) or (res.approval_status == ApprovalStatus.APPROVED.value)
            all_findings.extend(self.evaluate_resource(res, is_approved=is_appr))
        return all_findings
