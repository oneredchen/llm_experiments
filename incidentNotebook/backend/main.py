from fastapi import FastAPI
from .routers import cases, workflow
from .models import CaseResponse
from backend.utils.logging_config import setup_logging
import logging

setup_logging()
logger = logging.getLogger(__name__)

description = """
Incident Notebook API
Convert incident descriptions into structured IOCs and timeline events using agentic workflows.
"""

logger.info("Backend initialized and logging configured at backend/logs/backend.log")

app = FastAPI(
    title="Incident Notebook API",
    description=description,
    version="0.1.0",
)

# Add CORS Middleware
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://192.168.50.84:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(cases.router, tags=["cases"])
app.include_router(workflow.router, tags=["workflow"])

@app.get("/")
def read_root():
    return {"message": "Welcome to the Incident Notebook API. Visit /docs for documentation."}
