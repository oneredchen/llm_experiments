import logging
import sys
from pythonjsonlogger import jsonlogger

def setup_logging():
    """Set up logging for the application."""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # Create a file handler for JSON logs
    log_handler = logging.FileHandler("logs/incident_notebook.log")
    formatter = jsonlogger.JsonFormatter("%(asctime)s %(name)s %(levelname)s %(message)s")
    log_handler.setFormatter(formatter)

    # Create a stream handler for console output
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    stream_handler.setFormatter(stream_formatter)

    logger.addHandler(log_handler)
    logger.addHandler(stream_handler)