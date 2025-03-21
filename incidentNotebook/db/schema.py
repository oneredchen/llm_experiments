from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime, timezone

# Create a base class for declarative models
Base = declarative_base()

# Define the Cases table schema
class Case(Base):
    __tablename__ = 'cases'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String, nullable=False, unique=True)
    name = Column(String, nullable=False)
    status = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

# Timeline table
class Timeline(Base):
    __tablename__ = 'timeline'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String, ForeignKey('cases.case_id'), nullable=False)  # Foreign key to cases table
    
    submitted_by = Column(String, nullable=False)
    date_added = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    status_tag = Column(String, nullable=False)
    system_name = Column(String, nullable=False)
    timestamp_utc = Column(DateTime, nullable=False)
    timestamp_type = Column(String, nullable=False)
    activity = Column(String, nullable=False)
    evidence_source = Column(String, nullable=False)
    details_comments = Column(Text)
    attack_alignment = Column(String)
    size_bytes = Column(Integer)
    hash = Column(String)
    notes = Column(Text)  # New field for multiline notes

    # Relationship to Case
    case = relationship("Case", backref="timeline_events")

# Host IOC table
class HostIOC(Base):
    __tablename__ = 'host_ioc'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String, ForeignKey('cases.case_id'), nullable=False)  # Foreign key to cases table
    
    submitted_by = Column(String, nullable=False)
    date_added = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    source = Column(String, nullable=False)
    status = Column(String, nullable=False)
    indicator_id = Column(String, nullable=False, unique=True)
    indicator_type = Column(String, nullable=False)
    indicator = Column(String, nullable=False)
    full_path = Column(String, nullable=False)
    sha256 = Column(String)
    sha1 = Column(String)
    md5 = Column(String)
    type_purpose = Column(String)
    size_bytes = Column(Integer)
    notes = Column(Text)  # New field for multiline investigative notes

    # Relationship to Case
    case = relationship("Case", backref="host_iocs")

# Network IOC table
class NetworkIOC(Base):
    __tablename__ = 'network_ioc'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String, ForeignKey('cases.case_id'), nullable=False)  # Foreign key to cases table
    
    submitted_by = Column(String, nullable=False)
    date_added = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    source = Column(String, nullable=False)
    status = Column(String, nullable=False)
    indicator_id = Column(String, nullable=False, unique=True)
    indicator_type = Column(String, nullable=False)
    indicator = Column(String, nullable=False)
    initial_lead = Column(String)
    details_comments = Column(String)
    earliest_evidence_utc = Column(DateTime)
    attack_alignment = Column(String)
    notes = Column(Text)  # New field for multiline investigative notes

    # Relationship to Case
    case = relationship("Case", backref="network_iocs")

