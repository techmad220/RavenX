
from __future__ import annotations
import time, random

def backoff_retry(fn, *, retries: int = 5, base: float = 0.4, cap: float = 5.0, retry_on=(Exception,)):
    last_err = None
    for i in range(retries):
        try:
            return fn()
        except retry_on as e:
            last_err = e
            sleep = min(cap, base * (2 ** i)) * (1 + 0.25 * random.random())
            time.sleep(sleep)
    if last_err:
        raise last_err
