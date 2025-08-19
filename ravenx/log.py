
from __future__ import annotations
import structlog, sys, logging

def get_logger(name: str = "ravenx"):
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ],
    )
    return structlog.get_logger(name)
