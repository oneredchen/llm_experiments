import argparse
import logging
import os
import sys

import uvicorn
from fastapi import FastAPI

from routers.tools import router as tools_router
from routers.health import router as health_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

API_PORT = int(os.environ.get("API_PORT", 5000))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")

app = FastAPI(title="Kali Linux Tools API")

app.include_router(tools_router)
app.include_router(health_router)


@app.get("/")
async def index():
    return {"message": "Kali API"}


def parse_args():
    parser = argparse.ArgumentParser(description="Run the Kali Linux API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument(
        "--port",
        type=int,
        default=API_PORT,
        help=f"Port for the API server (default: {API_PORT})",
    )
    parser.add_argument(
        "--ip",
        type=str,
        default="127.0.0.1",
        help="IP address to bind the server to (default: 127.0.0.1)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.debug:
        DEBUG_MODE = True
        os.environ["DEBUG_MODE"] = "1"
        logger.setLevel(logging.DEBUG)

    if args.port != API_PORT:
        API_PORT = args.port

    logger.info(f"Starting Kali API on {args.ip}:{API_PORT}")
    uvicorn.run("main:app", host=args.ip, port=API_PORT, reload=DEBUG_MODE)
