"""SQLAlchemy database engine and session configuration for Worker 02."""

import os
from contextlib import contextmanager
from typing import Generator, Optional
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session

Base = declarative_base()


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Enable SQLite foreign key constraints and WAL journal mode."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


class DatabaseManager:
    """Manages SQLAlchemy engine and sessions."""

    def __init__(self, db_url: Optional[str] = None):
        if not db_url:
            db_url = os.environ.get("DATABASE_URL", "sqlite:///trusttrace.db")
        self.db_url = db_url
        connect_args = {}
        if self.db_url.startswith("sqlite"):
            connect_args["check_same_thread"] = False
        self.engine = create_engine(self.db_url, connect_args=connect_args)
        self.session_factory = sessionmaker(bind=self.engine, expire_on_commit=False)

    def init_db(self):
        """Create all registered database tables."""
        Base.metadata.create_all(self.engine)

    def drop_all(self):
        """Drop all database tables (used for clean test isolation)."""
        Base.metadata.drop_all(self.engine)

    @contextmanager
    def session_scope(self) -> Generator[Session, None, None]:
        """Provide a transactional scope around a series of operations."""
        session = self.session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()


# Default singleton instance (can be overridden in tests with in-memory SQLite)
default_db = DatabaseManager()
