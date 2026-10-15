"""AWS Managed AI Services discovery module: Comprehend, Rekognition, Textract, Transcribe, Polly, Lex, Translate, Personalize, Forecast, and Kendra."""

import logging
from typing import Dict, List, Any
from botocore.exceptions import ClientError, EndpointConnectionError

from src.discovery.base import BaseDiscoveryModule, ScanContext, DiscoveryResult
from src.config import AICategory, AIUsageStatus, setup_logging
from src.inventory.schema import AIResourceCreate, EvidenceItem
from src.inventory.normalizer import ResourceNormalizer
from src.discovery.aws_session import execute_with_backoff

logger = setup_logging()


class ManagedAIDiscoveryModule(BaseDiscoveryModule):
    """Discovers account-owned resources across specialized AWS Managed AI services."""

    @property
    def service_name(self) -> str:
        return "managed_ai_suite"

    @property
    def module_name(self) -> str:
        return "managed_ai"

    def discover(self, ctx: ScanContext) -> DiscoveryResult:
        result = DiscoveryResult()

        self._discover_comprehend(ctx, result)
        self._discover_rekognition(ctx, result)
        self._discover_textract(ctx, result)
        self._discover_transcribe(ctx, result)
        self._discover_polly(ctx, result)
        self._discover_lex(ctx, result)
        self._discover_translate(ctx, result)
        self._discover_personalize(ctx, result)
        self._discover_forecast(ctx, result)
        self._discover_kendra(ctx, result)

        return result

    def _discover_comprehend(self, ctx: ScanContext, result: DiscoveryResult):
        """Comprehend custom document classifiers and endpoints."""
        try:
            client = ctx.get_client("comprehend")
            result.api_calls_attempted += 1
            resp = execute_with_backoff(lambda: client.list_document_classifiers(MaxResults=25))
            for c in resp.get("DocumentClassifierPropertiesList", []):
                arn = c.get("DocumentClassifierArn", "")
                name = arn.split("/")[-1] if "/" in arn else "comprehend-classifier"
                status = c.get("Status", "")

                res = ResourceNormalizer.normalize(
                    account_id=ctx.account_id,
                    region=ctx.region,
                    service_name="comprehend",
                    resource_type="document_classifier",
                    resource_id=name,
                    resource_name=name,
                    resource_arn=arn,
                    description=f"Comprehend Document Classifier ({status})",
                    ai_category=AICategory.MANAGED_AI,
                    ai_usage_status=AIUsageStatus.CONFIRMED,
                    detection_method="direct_service_api:ListDocumentClassifiers",
                    configuration_summary={"status": status},
                    evidence=[
                        EvidenceItem(
                            evidence_source="comprehend:ListDocumentClassifiers",
                            evidence_type="direct_api",
                            sanitized_summary=f"Comprehend Classifier discovered: {name}",
                            confidence=0.98
                        )
                    ]
                )
                result.resources.append(res)
        except (ClientError, EndpointConnectionError) as e:
            result.api_calls_failed += 1
            result.warnings.append({"service": "comprehend", "error": str(e)})

    def _discover_rekognition(self, ctx: ScanContext, result: DiscoveryResult):
        """Rekognition custom labels projects and stream processors."""
        try:
            client = ctx.get_client("rekognition")
            result.api_calls_attempted += 1
            resp = execute_with_backoff(lambda: client.describe_projects(MaxResults=25))
            for p in resp.get("ProjectDescriptions", []):
                arn = p.get("ProjectArn", "")
                name = arn.split("/")[-2] if "/" in arn else "rekognition-project"
                status = p.get("Status", "")

                res = ResourceNormalizer.normalize(
                    account_id=ctx.account_id,
                    region=ctx.region,
                    service_name="rekognition",
                    resource_type="custom_labels_project",
                    resource_id=name,
                    resource_name=name,
                    resource_arn=arn,
                    description=f"Rekognition Custom Labels Project ({status})",
                    ai_category=AICategory.MANAGED_AI,
                    ai_usage_status=AIUsageStatus.CONFIRMED,
                    detection_method="direct_service_api:DescribeProjects",
                    configuration_summary={"status": status},
                    evidence=[
                        EvidenceItem(
                            evidence_source="rekognition:DescribeProjects",
                            evidence_type="direct_api",
                            sanitized_summary=f"Rekognition Custom Labels project: {name}",
                            confidence=0.98
                        )
                    ]
                )
                result.resources.append(res)
        except (ClientError, EndpointConnectionError) as e:
            result.api_calls_failed += 1
            result.warnings.append({"service": "rekognition", "error": str(e)})

    def _discover_textract(self, ctx: ScanContext, result: DiscoveryResult):
        """Textract adapters if supported."""
        try:
            client = ctx.get_client("textract")
            if hasattr(client, "list_adapters"):
                result.api_calls_attempted += 1
                resp = execute_with_backoff(lambda: client.list_adapters(MaxResults=25))
                for a in resp.get("Adapters", []):
                    a_id = a.get("AdapterId", "")
                    name = a.get("AdapterName", a_id)
                    res = ResourceNormalizer.normalize(
                        account_id=ctx.account_id,
                        region=ctx.region,
                        service_name="textract",
                        resource_type="adapter",
                        resource_id=a_id,
                        resource_name=name,
                        description="Textract custom trained adapter",
                        ai_category=AICategory.MANAGED_AI,
                        ai_usage_status=AIUsageStatus.CONFIRMED,
                        detection_method="direct_service_api:ListAdapters",
                        evidence=[
                            EvidenceItem(
                                evidence_source="textract:ListAdapters",
                                evidence_type="direct_api",
                                sanitized_summary=f"Textract adapter configured: {name}",
                                confidence=0.95
                            )
                        ]
                    )
                    result.resources.append(res)
        except (ClientError, EndpointConnectionError) as e:
            result.api_calls_failed += 1
            result.warnings.append({"service": "textract", "error": str(e)})

    def _discover_transcribe(self, ctx: ScanContext, result: DiscoveryResult):
        """Transcribe custom language models."""
        try:
            client = ctx.get_client("transcribe")
            result.api_calls_attempted += 1
            resp = execute_with_backoff(lambda: client.list_language_models(MaxResults=25))
            for m in resp.get("Models", []):
                name = m.get("ModelName", "")
                status = m.get("ModelStatus", "")
                res = ResourceNormalizer.normalize(
                    account_id=ctx.account_id,
                    region=ctx.region,
                    service_name="transcribe",
                    resource_type="language_model",
                    resource_id=name,
                    resource_name=name,
                    description=f"Transcribe Custom Language Model ({status})",
                    ai_category=AICategory.MANAGED_AI,
                    ai_usage_status=AIUsageStatus.CONFIRMED,
                    detection_method="direct_service_api:ListLanguageModels",
                    configuration_summary={"status": status},
                    evidence=[
                        EvidenceItem(
                            evidence_source="transcribe:ListLanguageModels",
                            evidence_type="direct_api",
                            sanitized_summary=f"Transcribe custom language model: {name}",
                            confidence=0.98
                        )
                    ]
                )
                result.resources.append(res)
        except (ClientError, EndpointConnectionError) as e:
            result.api_calls_failed += 1
            result.warnings.append({"service": "transcribe", "error": str(e)})

    def _discover_polly(self, ctx: ScanContext, result: DiscoveryResult):
        """Polly custom lexicons."""
        try:
            client = ctx.get_client("polly")
            result.api_calls_attempted += 1
            resp = execute_with_backoff(lambda: client.list_lexicons())
            for l in resp.get("Lexicons", []):
                name = l.get("Name", "")
                res = ResourceNormalizer.normalize(
                    account_id=ctx.account_id,
                    region=ctx.region,
                    service_name="polly",
                    resource_type="lexicon",
                    resource_id=name,
                    resource_name=name,
                    description="Polly pronunciation lexicon",
                    ai_category=AICategory.MANAGED_AI,
                    ai_usage_status=AIUsageStatus.CONFIRMED,
                    detection_method="direct_service_api:ListLexicons",
                    evidence=[
                        EvidenceItem(
                            evidence_source="polly:ListLexicons",
                            evidence_type="direct_api",
                            sanitized_summary=f"Polly pronunciation lexicon: {name}",
                            confidence=0.95
                        )
                    ]
                )
                result.resources.append(res)
        except (ClientError, EndpointConnectionError) as e:
            result.api_calls_failed += 1
            result.warnings.append({"service": "polly", "error": str(e)})

    def _discover_lex(self, ctx: ScanContext, result: DiscoveryResult):
        """Lex V2 conversational bots."""
        try:
            client = ctx.get_client("lexv2-models")
            result.api_calls_attempted += 1
            resp = execute_with_backoff(lambda: client.list_bots(maxResults=25))
            for b in resp.get("botSummaries", []):
                bot_id = b.get("botId", "")
                name = b.get("botName", bot_id)
                status = b.get("botStatus", "")
                res = ResourceNormalizer.normalize(
                    account_id=ctx.account_id,
                    region=ctx.region,
                    service_name="lex",
                    resource_type="lex_v2_bot",
                    resource_id=bot_id,
                    resource_name=name,
                    description=f"Amazon Lex V2 Conversational Bot ({status})",
                    ai_category=AICategory.MANAGED_AI,
                    ai_usage_status=AIUsageStatus.CONFIRMED,
                    detection_method="direct_service_api:ListBots",
                    configuration_summary={"status": status},
                    evidence=[
                        EvidenceItem(
                            evidence_source="lexv2-models:ListBots",
                            evidence_type="direct_api",
                            sanitized_summary=f"Amazon Lex V2 bot: {name} (ID: {bot_id})",
                            confidence=0.98
                        )
                    ]
                )
                result.resources.append(res)
        except (ClientError, EndpointConnectionError) as e:
            result.api_calls_failed += 1
            result.warnings.append({"service": "lex", "error": str(e)})

    def _discover_translate(self, ctx: ScanContext, result: DiscoveryResult):
        """Translate custom terminologies."""
        try:
            client = ctx.get_client("translate")
            result.api_calls_attempted += 1
            resp = execute_with_backoff(lambda: client.list_terminologies(MaxResults=25))
            for t in resp.get("TerminologyPropertiesList", []):
                name = t.get("Name", "")
                arn = t.get("Arn", "")
                res = ResourceNormalizer.normalize(
                    account_id=ctx.account_id,
                    region=ctx.region,
                    service_name="translate",
                    resource_type="terminology",
                    resource_id=name,
                    resource_name=name,
                    resource_arn=arn,
                    description="Amazon Translate custom terminology",
                    ai_category=AICategory.MANAGED_AI,
                    ai_usage_status=AIUsageStatus.CONFIRMED,
                    detection_method="direct_service_api:ListTerminologies",
                    evidence=[
                        EvidenceItem(
                            evidence_source="translate:ListTerminologies",
                            evidence_type="direct_api",
                            sanitized_summary=f"Amazon Translate terminology: {name}",
                            confidence=0.95
                        )
                    ]
                )
                result.resources.append(res)
        except (ClientError, EndpointConnectionError) as e:
            result.api_calls_failed += 1
            result.warnings.append({"service": "translate", "error": str(e)})

    def _discover_personalize(self, ctx: ScanContext, result: DiscoveryResult):
        """Personalize campaigns and solutions."""
        try:
            client = ctx.get_client("personalize")
            result.api_calls_attempted += 1
            resp = execute_with_backoff(lambda: client.list_campaigns(maxResults=25))
            for c in resp.get("campaigns", []):
                arn = c.get("campaignArn", "")
                name = c.get("name", arn.split("/")[-1] if "/" in arn else "campaign")
                status = c.get("status", "")
                res = ResourceNormalizer.normalize(
                    account_id=ctx.account_id,
                    region=ctx.region,
                    service_name="personalize",
                    resource_type="campaign",
                    resource_id=name,
                    resource_name=name,
                    resource_arn=arn,
                    description=f"Amazon Personalize Recommendation Campaign ({status})",
                    ai_category=AICategory.MANAGED_AI,
                    ai_usage_status=AIUsageStatus.CONFIRMED,
                    detection_method="direct_service_api:ListCampaigns",
                    configuration_summary={"status": status},
                    evidence=[
                        EvidenceItem(
                            evidence_source="personalize:ListCampaigns",
                            evidence_type="direct_api",
                            sanitized_summary=f"Personalize campaign active: {name}",
                            confidence=0.98
                        )
                    ]
                )
                result.resources.append(res)
        except (ClientError, EndpointConnectionError) as e:
            result.api_calls_failed += 1
            result.warnings.append({"service": "personalize", "error": str(e)})

    def _discover_forecast(self, ctx: ScanContext, result: DiscoveryResult):
        """Forecast predictors (handles API deprecation or absence gracefully)."""
        try:
            client = ctx.get_client("forecast")
            result.api_calls_attempted += 1
            resp = execute_with_backoff(lambda: client.list_predictors(MaxResults=25))
            for p in resp.get("Predictors", []):
                arn = p.get("PredictorArn", "")
                name = p.get("PredictorName", arn.split("/")[-1] if "/" in arn else "predictor")
                status = p.get("Status", "")
                res = ResourceNormalizer.normalize(
                    account_id=ctx.account_id,
                    region=ctx.region,
                    service_name="forecast",
                    resource_type="predictor",
                    resource_id=name,
                    resource_name=name,
                    resource_arn=arn,
                    description=f"Amazon Forecast Predictor ({status})",
                    ai_category=AICategory.MANAGED_AI,
                    ai_usage_status=AIUsageStatus.CONFIRMED,
                    detection_method="direct_service_api:ListPredictors",
                    configuration_summary={"status": status},
                    evidence=[
                        EvidenceItem(
                            evidence_source="forecast:ListPredictors",
                            evidence_type="direct_api",
                            sanitized_summary=f"Forecast predictor discovered: {name}",
                            confidence=0.98
                        )
                    ]
                )
                result.resources.append(res)
        except (ClientError, EndpointConnectionError) as e:
            result.api_calls_failed += 1
            result.warnings.append({"service": "forecast", "error": str(e)})

    def _discover_kendra(self, ctx: ScanContext, result: DiscoveryResult):
        """Kendra enterprise search indices."""
        try:
            client = ctx.get_client("kendra")
            result.api_calls_attempted += 1
            resp = execute_with_backoff(lambda: client.list_indices(MaxResults=25))
            for idx in resp.get("IndexConfigurationSummaryItems", []):
                idx_id = idx.get("Id", "")
                name = idx.get("Name", idx_id)
                status = idx.get("Status", "")
                edition = idx.get("Edition", "")
                res = ResourceNormalizer.normalize(
                    account_id=ctx.account_id,
                    region=ctx.region,
                    service_name="kendra",
                    resource_type="index",
                    resource_id=idx_id,
                    resource_name=name,
                    description=f"Amazon Kendra Intelligent Search Index ({edition}, {status})",
                    ai_category=AICategory.MANAGED_AI,
                    ai_usage_status=AIUsageStatus.CONFIRMED,
                    detection_method="direct_service_api:ListIndices",
                    configuration_summary={"status": status, "edition": edition},
                    evidence=[
                        EvidenceItem(
                            evidence_source="kendra:ListIndices",
                            evidence_type="direct_api",
                            sanitized_summary=f"Kendra index configured: {name} (ID: {idx_id})",
                            confidence=0.98
                        )
                    ]
                )
                result.resources.append(res)
        except (ClientError, EndpointConnectionError) as e:
            result.api_calls_failed += 1
            result.warnings.append({"service": "kendra", "error": str(e)})
