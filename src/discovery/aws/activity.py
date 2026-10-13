"""Activity enrichment module using non-destructive CloudTrail Event History."""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from botocore.exceptions import ClientError

from src.discovery.base import ScanContext
from src.config import ActivityStatus, setup_logging, utc_now
from src.inventory.schema import AIResourceCreate, EvidenceItem, DiscoveryLimitation
from src.discovery.aws_session import execute_with_backoff

logger = setup_logging()

# AWS AI event sources in CloudTrail
AI_EVENT_SOURCES = [
    "bedrock.amazonaws.com",
    "sagemaker.amazonaws.com",
    "comprehend.amazonaws.com",
    "rekognition.amazonaws.com",
    "kendra.amazonaws.com",
    "lex.amazonaws.com",
    "transcribe.amazonaws.com",
    "translate.amazonaws.com"
]


class ActivityEnrichmentModule:
    """Enriches discovered resources with non-destructive CloudTrail management event activity."""

    def enrich_resources(self, resources: List[AIResourceCreate], ctx: ScanContext) -> None:
        """
        Query CloudTrail LookupEvents for recent activity associated with discovered AI resources.
        Explicitly notes that Event History covers management events and not all data plane invocations.
        Never invents timestamps or frequencies.
        """
        if ctx.is_mock or not resources:
            return

        end_time = utc_now()
        start_time = end_time - timedelta(days=ctx.lookback_days)
        window_str = f"{start_time.strftime('%Y-%m-%d')} to {end_time.strftime('%Y-%m-%d')}"

        try:
            client = ctx.get_client("cloudtrail")
        except Exception as e:
            logger.warning(f"CloudTrail client initialization failed in {ctx.region}: {e}")
            self._apply_fallback_status(resources, ActivityStatus.NOT_CONFIGURED, window_str)
            return

        # Query recent events by EventSource for each AI service
        observed_events_by_name: Dict[str, datetime] = {}
        lookup_errors = False

        for event_source in AI_EVENT_SOURCES[:4]:  # Prioritize primary AI services to avoid throttling
            try:
                resp = execute_with_backoff(
                    lambda: client.lookup_events(
                        LookupAttributes=[
                            {
                                "AttributeKey": "EventSource",
                                "AttributeValue": event_source
                            }
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                        MaxResults=50
                    )
                )
                for ev in resp.get("Events", []):
                    ev_time = ev.get("EventTime")
                    # Check resources referenced in the event
                    for r in ev.get("Resources", []):
                        r_name = r.get("ResourceName", "")
                        if r_name and (r_name not in observed_events_by_name or ev_time > observed_events_by_name[r_name]):
                            observed_events_by_name[r_name] = ev_time
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                logger.warning(f"CloudTrail lookup failed for {event_source} in {ctx.region} ({code}): {e}")
                lookup_errors = True
                break

        for res in resources:
            # Check if this resource has observed events
            matched_time = None
            if res.resource_name in observed_events_by_name:
                matched_time = observed_events_by_name[res.resource_name]
            elif res.resource_id in observed_events_by_name:
                matched_time = observed_events_by_name[res.resource_id]

            res.usage_window_start = start_time
            res.usage_window_end = end_time

            if matched_time:
                res.last_used_at = matched_time
                res.activity_status = ActivityStatus.ACTIVE
                res.usage_evidence_source = "cloudtrail:LookupEvents"
                res.evidence.append(
                    EvidenceItem(
                        evidence_source="cloudtrail:LookupEvents",
                        evidence_type="management_event_history",
                        sanitized_summary=f"Observed management event at {matched_time.isoformat()}",
                        confidence=0.90,
                        observation_timestamp=matched_time,
                        relevant_time_window=window_str
                    )
                )
            else:
                if lookup_errors:
                    res.activity_status = ActivityStatus.INSUFFICIENT_PERMISSIONS
                else:
                    res.activity_status = ActivityStatus.UNKNOWN

            # Explicitly append documented coverage limitations
            res.limitations.append(
                DiscoveryLimitation(
                    limitation_code="MANAGEMENT_EVENTS_ONLY",
                    message=(
                        f"CloudTrail Event History queried for window {window_str}. "
                        "Management events reflect administrative and API actions. "
                        "High-volume data plane invocations (e.g., InvokeModel or InvokeEndpoint) require data events or CloudWatch log trails."
                    ),
                    potential_impact="Inference invocations may have occurred without leaving a management event trace."
                )
            )

    def _apply_fallback_status(self, resources: List[AIResourceCreate], status: ActivityStatus, window_str: str):
        for res in resources:
            res.activity_status = status
            res.limitations.append(
                DiscoveryLimitation(
                    limitation_code="ACTIVITY_TELEMETRY_UNAVAILABLE",
                    message="CloudTrail Event History could not be accessed in this region.",
                    potential_impact="Activity status marked as unconfirmed."
                )
            )
