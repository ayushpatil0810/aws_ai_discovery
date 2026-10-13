"""Base classes and execution context for discovery modules."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import boto3
from pydantic import BaseModel, Field

from src.inventory.schema import AIResourceCreate


class ScanContext(BaseModel):
    """Runtime context passed to discovery modules for a scan."""
    account_id: str
    region: str
    is_mock: bool = False
    lookback_days: int = 30
    session: Optional[Any] = None  # Boto3 Session when not in mock mode
    client_override: Optional[Any] = None

    model_config = {"arbitrary_types_allowed": True, "extra": "allow"}

    def get_client(self, service_name: str):
        """Obtain a boto3 client for the specified service and region."""
        if self.client_override is not None:
            return self.client_override(service_name)
        if self.is_mock or not self.session:
            raise RuntimeError("Cannot request live boto3 client in mock context")
        return self.session.client(service_name, region_name=self.region)


class DiscoveryResult(BaseModel):
    """Normalized payload returned by a discovery module."""
    resources: List[AIResourceCreate] = Field(default_factory=list)
    api_calls_attempted: int = 0
    api_calls_failed: int = 0
    errors: List[Dict[str, Any]] = Field(default_factory=list)
    warnings: List[Dict[str, Any]] = Field(default_factory=list)
    coverage_notes: List[str] = Field(default_factory=list)


class BaseDiscoveryModule(ABC):
    """Abstract interface implemented by all service discovery modules."""

    @property
    @abstractmethod
    def service_name(self) -> str:
        """Name of the AWS service discovered (e.g. 'bedrock', 'sagemaker')."""
        pass

    @property
    @abstractmethod
    def module_name(self) -> str:
        """Unique identifier for this discovery module."""
        pass

    @abstractmethod
    def discover(self, ctx: ScanContext) -> DiscoveryResult:
        """Execute read-only discovery against the target region or mock dataset."""
        pass
