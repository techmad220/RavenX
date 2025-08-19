
from __future__ import annotations
import os
import sentry_sdk

def init_observability():
    dsn = os.getenv("SENTRY_DSN","").strip()
    if dsn:
        sentry_sdk.init(dsn=dsn, traces_sample_rate=float(os.getenv("SENTRY_TRACES", "0.1")))
