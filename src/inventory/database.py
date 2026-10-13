"""Database session lifecycle and schema initialization."""

import os
from contextlib import contextmanager
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from src.inventory.models import Base

# Module-level engine and sessionmaker
_engine = None
_SessionFactory = None


def get_engine(database_url: str = None):
    """Retrieve or create a thread-safe SQLAlchemy engine."""
    global _engine, _SessionFactory
    if database_url is None:
        database_url = os.getenv("DATABASE_URL", "sqlite:///ai_discovery.db")
    
    # Check if existing engine matches URL
    if _engine is None or str(_engine.url) != database_url:
        connect_args = {}
        if database_url.startswith("sqlite"):
            connect_args["check_same_thread"] = False

        _engine = create_engine(
            database_url,
            connect_args=connect_args,
            echo=False,
            future=True
        )
        _SessionFactory = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
    
    return _engine


def init_db(database_url: str = None) -> None:
    """Initialize the database schema, creating tables if they do not exist."""
    engine = get_engine(database_url)
    Base.metadata.create_all(bind=engine)


@contextmanager
def get_db(database_url: str = None) -> Generator[Session, None, None]:
    """Provide a transactional database session scope."""
    get_engine(database_url)
    session: Session = _SessionFactory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
