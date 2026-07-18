import logging

from fastapi import APIRouter, HTTPException
from pydantic_ai.exceptions import ModelAPIError, ModelHTTPError

from ..models import ExtractionRequest, ExtractionResponse
from backend.utils import llm
from backend.utils.ioc_extraction_workflow import ioc_extraction_agent_workflow
from backend.utils.database import (
    insert_host_iocs,
    insert_network_iocs,
    insert_timeline_events
)

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("/cases/{case_id}/extract", response_model=ExtractionResponse)
def extract_iocs(case_id: str, request: ExtractionRequest):
    logger.info(f"Starting IOC extraction for case {case_id} using model {request.llm_model}")
    try:
        # Run the workflow (synchronous/blocking)
        result = ioc_extraction_agent_workflow(
            llm_model=request.llm_model,
            case_id=case_id,
            incident_description=request.incident_description,
        )

        host_iocs = result.get("host_ioc_objects", [])
        network_iocs = result.get("network_ioc_objects", [])
        timeline_events = result.get("timeline_objects", [])

        logger.info(f"Workflow finished. Extracted: {len(host_iocs)} host IOCs, {len(network_iocs)} network IOCs, {len(timeline_events)} timeline events.")

        # Insert results into database
        counts = {
            "host_iocs": 0,
            "network_iocs": 0,
            "timeline_events": 0
        }

        if host_iocs:
            host_ioc_dicts = []
            for ioc in host_iocs:
                ioc_dict = ioc.model_dump()
                ioc_dict["case_id"] = case_id
                host_ioc_dicts.append(ioc_dict)
            insert_host_iocs(host_ioc_dicts)
            counts["host_iocs"] = len(host_iocs)

        if network_iocs:
            network_ioc_dicts = []
            for ioc in network_iocs:
                ioc_dict = ioc.model_dump()
                ioc_dict["case_id"] = case_id
                network_ioc_dicts.append(ioc_dict)
            insert_network_iocs(network_ioc_dicts)
            counts["network_iocs"] = len(network_iocs)

        if timeline_events:
            timeline_event_dicts = []
            for event in timeline_events:
                event_dict = event.model_dump()
                event_dict["case_id"] = case_id
                timeline_event_dicts.append(event_dict)
            insert_timeline_events(timeline_event_dicts)
            counts["timeline_events"] = len(timeline_events)

        logger.info(f"Successfully saved extraction results for case {case_id}")

        return {
            "status": "success",
            "message": "IOC extraction completed successfully.",
            "counts": counts
        }

    except ModelHTTPError as e:
        logger.error(
            "LLM server rejected extraction for case %s using model %s "
            "with upstream status %s: %s",
            case_id,
            request.llm_model,
            e.status_code,
            e,
        )
        raise HTTPException(
            status_code=502,
            detail=(
                f"LLM server rejected model '{request.llm_model}' "
                f"(upstream status {e.status_code})."
            ),
        ) from e
    except ModelAPIError as e:
        logger.error(
            "LLM request failed for case %s using model %s: %s",
            case_id,
            request.llm_model,
            e,
        )
        raise HTTPException(
            status_code=502,
            detail=f"LLM request failed for model '{request.llm_model}'.",
        ) from e
    except Exception as e:
        logger.error(f"Error during IOC extraction for case {case_id}: {e}")
        raise HTTPException(status_code=500, detail="IOC extraction failed.") from e

@router.get("/workflow/models")
def get_models():
    """Lists models available on the configured OpenAI-compatible LLM server."""
    try:
        return {"models": llm.list_models()}
    except Exception as e:
        logger.error(f"Error fetching models from {llm.LLM_BASE_URL}: {e}")
        raise HTTPException(
            status_code=503,
            detail=f"Cannot reach LLM server at {llm.LLM_BASE_URL}. Is the server running?",
        )
