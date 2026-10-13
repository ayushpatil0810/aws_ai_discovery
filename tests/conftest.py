"""Pytest fixtures and configuration."""

import os
import sys

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

TEST_DB_FILE = "ai_discovery_test.db"
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB_FILE}"
os.environ["DISCOVERY_MODE"] = "mock"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

from src.inventory.models import Base
from src.inventory.database import init_db


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    """Initialize test database file and clean it up after test suite completes."""
    if os.path.exists(TEST_DB_FILE):
        try:
            os.remove(TEST_DB_FILE)
        except Exception:
            pass

    init_db(f"sqlite:///{TEST_DB_FILE}")
    yield
    if os.path.exists(TEST_DB_FILE):
        try:
            os.remove(TEST_DB_FILE)
        except Exception:
            pass


@pytest.fixture(scope="function")
def test_db_session():
    """Provide a transaction-isolated session for database tests."""
    engine = create_engine(f"sqlite:///{TEST_DB_FILE}", echo=False)
    TestingSessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    session = TestingSessionLocal()
    from src.inventory.models import AIResourceModel, ApprovedAIResourceModel
    session.query(AIResourceModel).delete()
    session.query(ApprovedAIResourceModel).delete()
    session.commit()
    try:
        yield session
    finally:
        session.close()
