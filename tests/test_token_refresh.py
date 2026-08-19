"""
Regression tests for proactive + reactive Power BI REST token refresh.

Covers:
- proactive refresh when the cached token is older than the 20-minute TTL
- no refresh when the cached token is still fresh
- reactive one-time refresh + retry after a 401/403 response

Run: python tests/test_token_refresh.py
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from powerbi_rest_connector import PowerBIRestConnector  # noqa: E402

_failures = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f": {detail}" if detail and not cond else ""))
    if not cond:
        _failures.append(name)


class FakeResponse:
    def __init__(self, status_code=200, payload=None, headers=None, text=""):
        self.status_code = status_code
        self._payload = payload or {}
        self.headers = headers or {}
        self.text = text

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.verify = False

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        if not self.responses:
            raise RuntimeError("No fake response queued")
        return self.responses.pop(0)

    def close(self):
        return None


def test_proactive_refresh_after_ttl():
    print("\n== proactive refresh after TTL ==")
    conn = PowerBIRestConnector("tenant", "client", "secret")
    conn.session = FakeSession([
        FakeResponse(payload={"value": [{"id": "1", "name": "Workspace A"}]})
    ])
    conn.access_token = "stale-token"
    conn._token_acquired_at = time.monotonic() - conn.token_ttl_seconds - 5

    calls = []

    def fake_auth(force=False):
        calls.append(force)
        conn.access_token = "fresh-token"
        conn._token_acquired_at = time.monotonic()
        return True

    conn.authenticate = fake_auth
    workspaces = conn.list_workspaces()

    check("proactive auth called once", calls == [True], str(calls))
    check("workspace returned", len(workspaces) == 1 and workspaces[0]["name"] == "Workspace A", str(workspaces))
    auth_header = conn.session.calls[0]["headers"]["Authorization"]
    check("retried request uses fresh token", auth_header == "Bearer fresh-token", auth_header)


def test_no_refresh_when_token_fresh():
    print("\n== no proactive refresh when token fresh ==")
    conn = PowerBIRestConnector("tenant", "client", "secret")
    conn.session = FakeSession([
        FakeResponse(payload={"value": [{"id": "1", "name": "Workspace A"}]})
    ])
    conn.access_token = "fresh-enough"
    conn._token_acquired_at = time.monotonic()

    calls = []

    def fake_auth(force=False):
        calls.append(force)
        return True

    conn.authenticate = fake_auth
    workspaces = conn.list_workspaces()

    check("authenticate not called", calls == [], str(calls))
    check("workspace still returned", len(workspaces) == 1, str(workspaces))
    auth_header = conn.session.calls[0]["headers"]["Authorization"]
    check("request reuses cached token", auth_header == "Bearer fresh-enough", auth_header)


def test_reactive_refresh_on_401():
    print("\n== reactive refresh and retry on 401 ==")
    conn = PowerBIRestConnector("tenant", "client", "secret")
    conn.session = FakeSession([
        FakeResponse(status_code=401, payload={"error": "expired"}),
        FakeResponse(payload={"value": [{"id": "1", "name": "Workspace B"}]})
    ])
    conn.access_token = "expired-token"
    conn._token_acquired_at = time.monotonic()

    calls = []

    def fake_auth(force=False):
        calls.append(force)
        conn.access_token = "replacement-token"
        conn._token_acquired_at = time.monotonic()
        return True

    conn.authenticate = fake_auth
    workspaces = conn.list_workspaces()

    check("forced auth called once after 401", calls == [True], str(calls))
    check("second request executed", len(conn.session.calls) == 2, str(conn.session.calls))
    check("first request used old token", conn.session.calls[0]["headers"]["Authorization"] == "Bearer expired-token")
    check("retry used replacement token", conn.session.calls[1]["headers"]["Authorization"] == "Bearer replacement-token")
    check("workspace returned after retry", len(workspaces) == 1 and workspaces[0]["name"] == "Workspace B", str(workspaces))


def test_custom_ttl_minutes_override():
    print("\n== custom TTL override ==")
    conn = PowerBIRestConnector("tenant", "client", "secret", token_ttl_minutes=1)
    check("minutes stored", conn.token_ttl_minutes == 1, str(conn.token_ttl_minutes))
    check("seconds derived", conn.token_ttl_seconds == 60, str(conn.token_ttl_seconds))
    conn.access_token = "token"
    conn._token_acquired_at = time.monotonic() - 61
    check("custom TTL expires token", conn._token_expired() is True)


if __name__ == "__main__":
    print("=" * 70)
    print("  POWER BI REST TOKEN REFRESH TESTS")
    print("=" * 70)
    test_proactive_refresh_after_ttl()
    test_no_refresh_when_token_fresh()
    test_reactive_refresh_on_401()
    test_custom_ttl_minutes_override()
    print("\n" + "=" * 70)
    if _failures:
        print(f"  {len(_failures)} CHECK(S) FAILED: {', '.join(_failures)}")
        sys.exit(1)
    print("  ALL TOKEN REFRESH CHECKS PASSED")
    print("=" * 70)
