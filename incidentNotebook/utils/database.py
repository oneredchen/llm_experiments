import logging
import os
import random
import string
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Type

import pandas as pd
from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    event,
    select,
    text as sa_text,
    Index,
    Enum,
)
from sqlalchemy.orm import declarative_base, relationship, Session, sessionmaker

# ----------------------------------------------------------------------------
# Paths & Logging
# ----------------------------------------------------------------------------
BASE_DIR = Path.cwd()
DB_DIR = BASE_DIR / "db"
DB_NAME = "incident_notebook.db"
DB_PATH = DB_DIR / DB_NAME

DB_DIR.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------------
# SQLAlchemy Base & Engine helpers (SQLAlchemy 2.0 style)
# ----------------------------------------------------------------------------
Base = declarative_base()


@lru_cache(maxsize=1)
def get_engine(echo: bool = False):
    """Create (or return cached) SQLAlchemy engine. Reused across calls."""
    engine = create_engine(f"sqlite:///{DB_PATH}", echo=echo, future=True)

    # Enforce FK constraints in SQLite
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):  # noqa: ANN001
        try:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
        except Exception as e:  # pragma: no cover
            logger.warning("Failed to set SQLite PRAGMA foreign_keys=ON: %s", e)

    return engine


@lru_cache(maxsize=1)
def get_sessionmaker():
    return sessionmaker(bind=get_engine(), expire_on_commit=False, class_=Session)


def init_db() -> None:
    """Create tables if they don't exist."""
    engine = get_engine()
    Base.metadata.create_all(engine)


# ----------------------------------------------------------------------------
# Models
# ----------------------------------------------------------------------------
# Some columns have explicit length caps to help future migrations.
# Add indexes for common query fields to improve performance.


class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(32), nullable=False, unique=True, index=True)
    name = Column(String(256), nullable=False)
    status = Column(Enum("Open", "Closed", "On Hold", name="case_status"), nullable=False, default="Open")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    timeline_events = relationship("Timeline", back_populates="case", cascade="all, delete-orphan")
    host_iocs = relationship("HostIOC", back_populates="case", cascade="all, delete-orphan")
    network_iocs = relationship("NetworkIOC", back_populates="case", cascade="all, delete-orphan")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Case case_id={self.case_id} name={self.name!r} status={self.status}>"


class Timeline(Base):
    __tablename__ = "timeline"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(32), ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False, index=True)

    submitted_by = Column(String(128), nullable=False)
    date_added = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    status_tag = Column(String(64), nullable=False)
    system_name = Column(String(256), nullable=False)
    timestamp_utc = Column(DateTime(timezone=True), nullable=False, index=True)
    timestamp_type = Column(String(64), nullable=False)
    activity = Column(String(512), nullable=False)
    evidence_source = Column(String(256), nullable=False)
    details_comments = Column(Text)
    attack_alignment = Column(String(128))
    size_bytes = Column(Integer)
    hash = Column(String(128))  # consider renaming to hash_value in a migration
    notes = Column(Text)  # multiline notes

    case = relationship("Case", back_populates="timeline_events")

    __table_args__ = (
        Index("ix_timeline_case_ts", "case_id", "timestamp_utc"),
    )


class HostIOC(Base):
    __tablename__ = "host_ioc"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(32), ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False, index=True)

    submitted_by = Column(String(128), nullable=False)
    date_added = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    source = Column(String(128), nullable=False)
    status = Column(String(64), nullable=False)
    indicator_id = Column(String(256), nullable=False, unique=True, index=True)
    indicator_type = Column(String(64), nullable=False)
    indicator = Column(String(512), nullable=False)
    full_path = Column(String(1024), nullable=True)
    sha256 = Column(String(64))
    sha1 = Column(String(40))
    md5 = Column(String(32))
    type_purpose = Column(String(128))
    size_bytes = Column(Integer)
    notes = Column(Text)

    case = relationship("Case", back_populates="host_iocs")

    __table_args__ = (
        Index("ix_hostioc_case_type", "case_id", "indicator_type"),
    )


class NetworkIOC(Base):
    __tablename__ = "network_ioc"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(32), ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False, index=True)

    submitted_by = Column(String(128), nullable=False)
    date_added = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    source = Column(String(128), nullable=False)
    status = Column(String(64), nullable=False)
    indicator_id = Column(String(256), nullable=False, unique=True, index=True)
    indicator_type = Column(String(64), nullable=False)
    indicator = Column(String(512), nullable=False)
    initial_lead = Column(String(512))
    details_comments = Column(Text)
    earliest_evidence_utc = Column(DateTime(timezone=True), index=True)
    attack_alignment = Column(String(128))
    notes = Column(Text)

    case = relationship("Case", back_populates="network_iocs")

    __table_args__ = (
        Index("ix_networkioc_case_type", "case_id", "indicator_type"),
    )


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------


def generate_case_id(existing_ids) -> str:
    """Generate a unique human-readable case ID. Guard against rare collisions."""
    while True:
        numeric_part = f"{random.randint(0, 9999):04d}"
        alpha_part = "".join(random.choices(string.ascii_uppercase, k=2))
        candidate = f"CAS-{numeric_part}-{alpha_part}"
        if candidate not in existing_ids:
            return candidate


# ----------------------------------------------------------------------------
# Public API (kept for compatibility with the rest of your app)
# ----------------------------------------------------------------------------


def load_database() -> Dict[str, pd.DataFrame]:
    """
    Ensure DB exists and load all tables into DataFrames.
    Returns a dict keyed by table name.
    """
    init_db()
    engine = get_engine()
    dataframes: Dict[str, pd.DataFrame] = {}

    for table_name, table in Base.metadata.tables.items():
        try:
            stmt = select(table)
            df = pd.read_sql(stmt, engine)
            dataframes[table_name] = df
            logger.debug("Loaded table '%s' (%d rows)", table_name, len(df))
        except Exception as e:
            logger.error("Error loading table '%s': %s", table_name, e)
            dataframes[table_name] = pd.DataFrame()

    return dataframes


def create_case(case_name: str) -> str:
    """
    Create a new case and return its case_id.
    """
    init_db()
    engine = get_engine()
    SessionLocal = get_sessionmaker()

    cleaned = (case_name or "").strip()
    if not cleaned:
        raise ValueError("Case name cannot be empty")

    with SessionLocal() as session:
        existing_ids = {row.case_id for row in session.query(Case.case_id).all()}
        case_id = generate_case_id(existing_ids)
        now = datetime.now(timezone.utc)
        new_case = Case(
            case_id=case_id,
            name=cleaned,
            status="Open",
            created_at=now,
            updated_at=now,
        )
        session.add(new_case)
        session.commit()
        logger.info("Created case %s (%s)", case_id, cleaned)
        return case_id


def delete_case(case_id: str) -> bool:
    """
    Delete a case and all its associated data.
    """
    init_db()
    SessionLocal = get_sessionmaker()
    with SessionLocal() as session:
        case_to_delete = session.query(Case).filter(Case.case_id == case_id).first()
        if case_to_delete:
            session.delete(case_to_delete)
            session.commit()
            logger.info(f"Case {case_id} deleted successfully.")
            return True
        else:
            logger.warning(f"Case {case_id} not found for deletion.")
            return False

def insert_iocs(ioc_objects: List[Dict], model_class: Type[Base]) -> bool:
    """
    Insert a list of IOC objects into the database.

    Args:
        ioc_objects: A list of dictionaries representing the IOCs.
        model_class: The SQLAlchemy model class to use for insertion.

    Returns:
        True on success, False on error.
    """
    init_db()
    SessionLocal = get_sessionmaker()
    with SessionLocal() as session:
        try:
            for ioc_data in ioc_objects:
                db_ioc = model_class(**ioc_data)
                session.add(db_ioc)
            session.commit()
            logger.info(f"Successfully inserted {len(ioc_objects)} records into {model_class.__tablename__}.")
            return True
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to insert IOCs into {model_class.__tablename__}: {e}")
            return False

def insert_host_iocs(ioc_objects: List[Dict]) -> bool:
    return insert_iocs(ioc_objects, HostIOC)

def insert_network_iocs(ioc_objects: List[Dict]) -> bool:
    return insert_iocs(ioc_objects, NetworkIOC)

def insert_timeline_events(ioc_objects: List[Dict]) -> bool:
    return insert_iocs(ioc_objects, Timeline)

def get_database_dialect() -> str:
    """Return the engine dialect name (e.g., 'sqlite')."""
    return get_engine().dialect.name