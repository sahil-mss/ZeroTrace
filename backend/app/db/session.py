import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from backend.app.core.config import settings


# Global listener for SQLite foreign key enforcement
@event.listens_for(Engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def get_engine(db_url: str | None = None, echo: bool = False) -> Engine:
    """Creates a configured SQLAlchemy Engine reading from config or argument."""
    url = db_url or settings.DATABASE_URL
    if url.startswith("sqlite:///./") or (url.startswith("sqlite:///") and not url.startswith("sqlite:///:memory:")):
        clean_path = url.replace("sqlite:///", "")
        parent_dir = Path(clean_path).parent
        if parent_dir and not parent_dir.exists():
            parent_dir.mkdir(parents=True, exist_ok=True)

    connect_args = {"check_same_thread": False} if "sqlite" in url else {}
    return create_engine(url, echo=echo, connect_args=connect_args)


def get_session_factory(engine: Engine | None = None) -> sessionmaker[Session]:
    """Returns a sessionmaker bound to the specified or default engine."""
    eng = engine or get_engine()
    return sessionmaker(autocommit=False, autoflush=False, bind=eng)


# Default engine and sessionmaker bound to settings.DATABASE_URL
engine = get_engine()
SessionLocal = get_session_factory(engine)


@contextmanager
def get_db_session(engine_instance: Engine | None = None) -> Generator[Session, None, None]:
    """
    Context manager for transactional database operations.
    Rolls back on error and closes the session upon exit.
    """
    factory = get_session_factory(engine_instance) if engine_instance else SessionLocal
    session: Session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a database session."""
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()
