"""SQLAlchemy database engine and session configuration for Worker 02."""

import os
import sqlite3
from contextlib import contextmanager
from typing import Generator, Optional
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import declarative_base, sessionmaker, Session

Base = declarative_base()


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Enable SQLite foreign key constraints."""
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def sanitize_db_url(url: str) -> str:
    """Return database URL with password credentials masked."""
    if not url:
        return "<empty_url>"
    if "@" in url and "://" in url:
        try:
            scheme_rest = url.split("://", 1)
            scheme = scheme_rest[0]
            auth_host = scheme_rest[1].split("@", 1)
            user_pass = auth_host[0]
            host_path = auth_host[1]
            user = user_pass.split(":", 1)[0] if ":" in user_pass else user_pass
            return f"{scheme}://{user}:***@{host_path}"
        except Exception:
            return "<sanitized_db_url>"
    return url


def resolve_database_url(db_url: Optional[str] = None) -> str:
    """Resolve database URL following strict hierarchical priority.
    
    Priority order:
    1. Explicit db_url argument passed to constructor.
    2. TRUSTTRACE_DB_URL environment variable.
    3. TRUSTTRACE_PG_URL environment variable (when PostgreSQL is targeted).
    4. DATABASE_URL environment variable (standard 12-factor convention).
    5. Fallback default: 'sqlite:///trusttrace.db'.
    """
    if db_url and db_url.strip():
        url = db_url.strip()
    elif os.environ.get("TRUSTTRACE_DB_URL"):
        url = os.environ["TRUSTTRACE_DB_URL"].strip()
    elif os.environ.get("TRUSTTRACE_PG_URL"):
        url = os.environ["TRUSTTRACE_PG_URL"].strip()
    elif os.environ.get("DATABASE_URL"):
        url = os.environ["DATABASE_URL"].strip()
    else:
        url = "sqlite:///trusttrace.db"

    # Normalize plain postgresql:// to postgresql+psycopg2:// if no driver is specified
    if url.startswith("postgresql://") and "+psycopg" not in url:
        url = url.replace("postgresql://", "postgresql+psycopg2://", 1)
    return url


class DatabaseManager:
    """Manages SQLAlchemy engine, connection pools, and transactional sessions."""

    def __init__(self, db_url: Optional[str] = None, fail_fast: bool = False):
        self.db_url = resolve_database_url(db_url)
        connect_args = {}
        kwargs = {}
        if self.db_url.startswith("sqlite"):
            connect_args["check_same_thread"] = False
            if ":memory:" in self.db_url:
                kwargs["poolclass"] = StaticPool
        kwargs["connect_args"] = connect_args

        self.engine = create_engine(self.db_url, **kwargs)
        self.session_factory = sessionmaker(bind=self.engine, expire_on_commit=False)

        # Fail fast if PostgreSQL was explicitly requested but cannot connect
        if fail_fast or (self.is_postgres() and os.environ.get("TRUSTTRACE_FAIL_FAST_DB", "0") == "1"):
            self.verify_connection()

    def is_postgres(self) -> bool:
        """Check if the active database dialect is PostgreSQL."""
        return "postgres" in self.engine.dialect.name or "postgres" in self.db_url

    def get_dialect_name(self) -> str:
        """Return the database dialect name (e.g. 'postgresql' or 'sqlite')."""
        return self.engine.dialect.name

    def get_sanitized_url(self) -> str:
        """Return database URL with sensitive passwords masked."""
        return sanitize_db_url(self.db_url)

    def verify_connection(self) -> bool:
        """Test database connectivity, failing with sanitized diagnostics if unreachable."""
        try:
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return True
        except Exception as e:
            sanitized = self.get_sanitized_url()
            dialect = self.get_dialect_name()
            raise RuntimeError(
                f"Failed to connect to configured database at '{sanitized}' (dialect: {dialect}): {e}"
            ) from e

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
