"""Governance allowlist registry operations."""

from datetime import datetime
from typing import List, Optional
from src.config import utc_now
from src.inventory.schema import ApprovedAIResourceCreate, ApprovedAIResourceRead
from src.inventory.database import get_db
from src.inventory.repository import InventoryRepository


def register_approved_resource(
    resource_key: str,
    resource_name: str,
    owner: str,
    approval_reference: Optional[str] = None,
    notes: Optional[str] = None,
    database_url: Optional[str] = None
) -> ApprovedAIResourceRead:
    """Register an approved AI resource in the governance allowlist."""
    with get_db(database_url) as session:
        repo = InventoryRepository(session)
        created = repo.add_to_allowlist(
            ApprovedAIResourceCreate(
                resource_key=resource_key,
                resource_name=resource_name,
                owner=owner,
                approval_reference=approval_reference,
                notes=notes,
                last_reviewed_at=utc_now()
            )
        )
        return ApprovedAIResourceRead.model_validate(created)


def list_approved_resources(database_url: Optional[str] = None) -> List[ApprovedAIResourceRead]:
    """List all registered approved AI resources."""
    with get_db(database_url) as session:
        repo = InventoryRepository(session)
        items = repo.list_allowlist()
        return [ApprovedAIResourceRead.model_validate(i) for i in items]
