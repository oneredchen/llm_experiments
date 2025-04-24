import os
import pandas as pd
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, create_engine, select
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime, timezone

db_dir = os.path.join(os.getcwd(), "db")
db_name = "incident_notebook.db"
db_path = os.path.join(db_dir, db_name)

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
    
def load_database():
    """
    Load the SQLite database.
    """
    if not os.path.exists(db_dir):
        os.makedirs(db_dir)
    
    # Ensures DB is loaded or created should it not exist
    engine = create_engine(f"sqlite:///{db_path}", echo=True)
    Base.metadata.create_all(engine)

    # Loading each table into 
    dataframes = {}
    for table_name, table in Base.metadata.tables.items():
        # Create a select statement for the current table
        stmt = select(table)

        # Use pandas read_sql to load the table data into a DataFrame
        try:
            df = pd.read_sql(stmt, engine)
            print(df)
            dataframes[table_name] = df
            print(f"Loaded table '{table_name}' into a DataFrame.")
        except Exception as e:
            print(f"Error loading table '{table_name}': {e}")
            dataframes[table_name] = pd.DataFrame() # Return empty DataFrame on error

    print("Finished loading data.")
    return dataframes
