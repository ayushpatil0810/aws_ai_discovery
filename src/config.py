"""Configuration and domain enumerations for the AWS AI Discovery Agent."""

import os
import re
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


def utc_now() -> datetime:
    """Return timezone-naive UTC timestamp for consistent SQLite compatibility."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class AICategory(str, Enum):
    """Broad classification of how the resource relates to AI/ML."""
    MANAGED_AI = "managed_ai"
    CUSTOM_MODEL_HOSTING = "custom_model_hosting"
    AI_INTEGRATION = "ai_integration"
    POTENTIAL_AI_INFRASTRUCTURE = "potential_ai_infrastructure"


class AIUsageStatus(str, Enum):
    """Degree of certainty that the resource is actively used for AI."""
    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    """Governance and security risk classification."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ApprovalStatus(str, Enum):
    """Governance approval state."""
    APPROVED = "approved"
    UNREGISTERED = "unregistered"
    PROVISIONAL = "provisional"
    REVOKED = "revoked"
    UNKNOWN = "unknown"


class ActivityStatus(str, Enum):
    """Activity state derived from non-destructive telemetry."""
    ACTIVE = "active"
    IDLE = "idle"
    UNKNOWN = "unknown"
    NOT_CONFIGURED = "not_configured"
    INSUFFICIENT_PERMISSIONS = "insufficient_permissions"


class ScanMode(str, Enum):
    """Execution mode: synthetic mock data or live AWS APIs."""
    MOCK = "mock"
    AWS = "aws"


class ScanStatus(str, Enum):
    """Lifecycle status of a scan run."""
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


class Settings(BaseSettings):
    """Application runtime settings with environment variable fallbacks."""
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    discovery_mode: ScanMode = Field(default=ScanMode.MOCK, alias="DISCOVERY_MODE")
    aws_access_key_id: Optional[str] = Field(default=None, alias="AWS_ACCESS_KEY_ID")
    aws_secret_access_key: Optional[str] = Field(default=None, alias="AWS_SECRET_ACCESS_KEY")
    aws_session_token: Optional[str] = Field(default=None, alias="AWS_SESSION_TOKEN")
    aws_profile: Optional[str] = Field(default=None, alias="AWS_PROFILE")
    aws_default_region: str = Field(default="us-east-1", alias="AWS_DEFAULT_REGION")
    aws_role_arn: Optional[str] = Field(default=None, alias="AWS_ROLE_ARN")
    aws_role_session_name: str = Field(default="AIDiscoverySession", alias="AWS_ROLE_SESSION_NAME")

    # Target Regions (comma separated or list)
    scan_regions: str = Field(default="us-east-1,us-west-2,ap-south-1", alias="SCAN_REGIONS")
    scan_denylist_regions: str = Field(default="", alias="SCAN_DENYLIST_REGIONS")

    # Database
    database_url: str = Field(default="sqlite:///ai_discovery.db", alias="DATABASE_URL")

    # Module toggles
    module_bedrock: bool = Field(default=True, alias="MODULE_BEDROCK")
    module_sagemaker: bool = Field(default=True, alias="MODULE_SAGEMAKER")
    module_managed_ai: bool = Field(default=True, alias="MODULE_MANAGED_AI")
    module_infrastructure: bool = Field(default=True, alias="MODULE_INFRASTRUCTURE")
    module_integrations: bool = Field(default=True, alias="MODULE_INTEGRATIONS")
    module_resource_explorer: bool = Field(default=True, alias="MODULE_RESOURCE_EXPLORER")
    module_activity: bool = Field(default=True, alias="MODULE_ACTIVITY")

    # CloudTrail Activity
    activity_lookback_days: int = Field(default=30, alias="ACTIVITY_LOOKBACK_DAYS")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    @property
    def target_regions(self) -> List[str]:
        """Parsed list of regions to scan."""
        if not self.scan_regions or not self.scan_regions.strip():
            return []
        denylist = self.denylisted_regions
        return [r.strip() for r in self.scan_regions.split(",") if r.strip() and r.strip() not in denylist]

    @property
    def denylisted_regions(self) -> List[str]:
        """Parsed list of denylisted regions."""
        if not self.scan_denylist_regions or not self.scan_denylist_regions.strip():
            return []
        return [r.strip() for r in self.scan_denylist_regions.split(",") if r.strip()]


# Known external AI service endpoints and keywords for shadow AI inspection
EXTERNAL_AI_PROVIDERS = [
    {"name": "OpenAI", "keywords": ["openai.com", "api.openai.com", "chatgpt"], "env_keys": ["OPENAI_API_KEY", "OPENAI_ORG_ID", "OPENAI_BASE_URL"]},
    {"name": "Anthropic", "keywords": ["anthropic.com", "api.anthropic.com", "claude"], "env_keys": ["ANTHROPIC_API_KEY", "CLAUDE_API_KEY"]},
    {"name": "Cohere", "keywords": ["cohere.ai", "api.cohere.ai"], "env_keys": ["COHERE_API_KEY"]},
    {"name": "Hugging Face", "keywords": ["huggingface.co", "api-inference.huggingface.co"], "env_keys": ["HF_TOKEN", "HUGGINGFACE_API_KEY", "HUGGING_FACE_HUB_TOKEN"]},
    {"name": "Replicate", "keywords": ["replicate.com", "api.replicate.com"], "env_keys": ["REPLICATE_API_TOKEN"]},
    {"name": "Pinecone", "keywords": ["pinecone.io"], "env_keys": ["PINECONE_API_KEY", "PINECONE_ENVIRONMENT"]},
    {"name": "Weaviate", "keywords": ["weaviate.io", "semi.technology"], "env_keys": ["WEAVIATE_API_KEY"]},
    {"name": "Qdrant", "keywords": ["qdrant.tech", "qdrant.io"], "env_keys": ["QDRANT_API_KEY"]},
    {"name": "DeepSeek", "keywords": ["deepseek.com", "api.deepseek.com"], "env_keys": ["DEEPSEEK_API_KEY"]},
    {"name": "Mistral AI", "keywords": ["mistral.ai", "api.mistral.ai"], "env_keys": ["MISTRAL_API_KEY"]},
    {"name": "Groq", "keywords": ["groq.com", "api.groq.com"], "env_keys": ["GROQ_API_KEY"]},
    {"name": "Perplexity", "keywords": ["perplexity.ai", "api.perplexity.ai"], "env_keys": ["PERPLEXITY_API_KEY"]}
]

# Sensitive patterns that must never be exposed or logged
SECRET_REDACTION_PATTERNS = [
    re.compile(r'(?i)(key|secret|token|password|auth|credential|cert)[=: ]+[\'"]?([^\s\'"]+)[\'"]?'),
    re.compile(r'AKIA[0-9A-Z]{16}'),
    re.compile(r'sk-[a-zA-Z0-9]{32,}'),
]


def sanitize_string(text: str) -> str:
    """Sanitize strings by redacting known key/secret patterns."""
    if not text:
        return text
    sanitized = text
    # Key-value secret patterns
    sanitized = re.sub(
        r'(?i)(key|secret|token|password|auth|credential|cert)[=: ]+[\'"]?([^\s\'"]+)[\'"]?',
        r'\1: [REDACTED]',
        sanitized
    )
    # AWS Access Key IDs
    sanitized = re.sub(r'AKIA[0-9A-Z]{16}', '[REDACTED_AWS_KEY]', sanitized)
    # Generic API tokens (OpenAI, etc.)
    sanitized = re.sub(r'sk-[a-zA-Z0-9]{20,}', '[REDACTED_API_KEY]', sanitized)
    return sanitized


def setup_logging(level: str = "INFO") -> logging.Logger:
    """Configure structured, sanitized logging."""
    logger = logging.getLogger("aws_ai_discovery")
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    return logger
