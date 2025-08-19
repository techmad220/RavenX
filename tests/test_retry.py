
from ravenx.retry import backoff_retry

def test_backoff_retry():
    calls = {"n":0}
    def flaky():
        calls["n"] += 1
        if calls["n"] < 2:
            raise RuntimeError("boom")
        return 42
    assert backoff_retry(flaky, retries=3) == 42
