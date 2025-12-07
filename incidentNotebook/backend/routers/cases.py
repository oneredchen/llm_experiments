from fastapi import APIRouter, HTTPException
import pandas as pd
from typing import List
import logging
from ..models import CaseCreateRequest, CaseResponse, CaseDataResponse
from backend.utils.database import load_database, create_case, delete_case, Case

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/cases", response_model=List[CaseResponse])
def get_cases():
    logger.info("Fetching all cases")
    databases = load_database()
    cases_df = databases.get("cases")
    if cases_df is None or cases_df.empty:
        logger.info("No cases found")
        return []
    # Convert DataFrame to list of dicts
    logger.info(f"Found {len(cases_df)} cases")
    return cases_df.to_dict(orient="records")

@router.post("/cases", response_model=CaseResponse)
def create_new_case(request: CaseCreateRequest):
    logger.info(f"Creating new case: {request.name}")
    try:
        case_id = create_case(request.name)
        # Fetch the created case to return full details
        databases = load_database()
        cases_df = databases.get("cases")
        case = cases_df[cases_df["case_id"] == case_id].iloc[0].to_dict()
        logger.info(f"Case created successfully: {case_id}")
        return case
    except ValueError as e:
        logger.error(f"ValueError creating case: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error creating case: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/cases/{case_id}", response_model=CaseResponse)
def get_case(case_id: str):
    logger.info(f"Fetching case details for: {case_id}")
    databases = load_database()
    cases_df = databases.get("cases")
    if cases_df is None or cases_df.empty:
        logger.warning(f"Case {case_id} not found (no cases table)")
        raise HTTPException(status_code=404, detail="Case not found")
    
    case = cases_df[cases_df["case_id"] == case_id]
    if case.empty:
        logger.warning(f"Case {case_id} not found")
        raise HTTPException(status_code=404, detail="Case not found")
    
    return case.iloc[0].to_dict()

@router.delete("/cases/{case_id}")
def delete_existing_case(case_id: str):
    logger.info(f"Deleting case: {case_id}")
    success = delete_case(case_id)
    if not success:
        logger.warning(f"Failed to delete case: {case_id}")
        raise HTTPException(status_code=404, detail="Case not found or failed to delete")
    logger.info(f"Case {case_id} deleted successfully")
    return {"status": "success", "message": f"Case {case_id} deleted"}

@router.get("/cases/{case_id}/data", response_model=CaseDataResponse)
def get_case_data(case_id: str):
    logger.info(f"Fetching data artifacts for case: {case_id}")
    databases = load_database()
    
    # Filter by case_id
    host_ioc_df = databases.get("host_ioc")
    network_ioc_df = databases.get("network_ioc")
    timeline_df = databases.get("timeline")
    
    # helper to filter
    def filter_by_case(df):
        if df is None or df.empty:
            return []
        # Replace NaN with None to satisfy Pydantic validation
        df = df.where(pd.notnull(df), None)
        if "case_id" not in df.columns:
            return []
        return df[df["case_id"] == case_id].to_dict(orient="records")

    data = {
        "host_iocs": filter_by_case(host_ioc_df),
        "network_iocs": filter_by_case(network_ioc_df),
        "timeline_events": filter_by_case(timeline_df)
    }
    logger.info(f"Returned {len(data['host_iocs'])} host IOCs, {len(data['network_iocs'])} network IOCs, {len(data['timeline_events'])} timeline events for case {case_id}")
    return data
