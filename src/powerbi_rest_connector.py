"""
Power BI REST API Connector
For listing workspaces and datasets from Power BI Service
"""
import logging
import time
from typing import Any, Dict, List, Optional
import requests
import msal
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class PowerBIRestConnector:
    """Power BI connector using REST API for workspace/dataset listing"""

    BASE_URL = "https://api.powerbi.com/v1.0/myorg"
    AUTHORITY = "https://login.microsoftonline.com/{tenant_id}"
    SCOPE = ["https://analysis.windows.net/powerbi/api/.default"]
    DEFAULT_TOKEN_TTL_MINUTES = 20
    AUTH_RETRY_STATUS_CODES = {401, 403}

    def __init__(self, tenant_id: str, client_id: str, client_secret: str, token_ttl_minutes: int = DEFAULT_TOKEN_TTL_MINUTES):
        """Initialize connector with Azure AD credentials"""
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = None
        self._token_acquired_at: Optional[float] = None
        self.token_ttl_minutes = max(1, int(token_ttl_minutes))
        self.token_ttl_seconds = self.token_ttl_minutes * 60
        self.session = requests.Session()
        self.session.verify = False

    def close(self):
        """Close the requests session"""
        if self.session:
            self.session.close()

    def __del__(self):
        """Cleanup when object is destroyed"""
        self.close()

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
        return False

    def authenticate(self, force: bool = False) -> bool:
        """Authenticate using Service Principal and get access token"""
        if not force and self.access_token and not self._token_expired():
            return True
        try:
            authority_url = self.AUTHORITY.format(tenant_id=self.tenant_id)
            app = msal.ConfidentialClientApplication(
                self.client_id,
                authority=authority_url,
                client_credential=self.client_secret,
            )

            result = app.acquire_token_for_client(scopes=self.SCOPE)

            if "access_token" in result:
                self.access_token = result["access_token"]
                self._token_acquired_at = time.monotonic()
                logger.info("Successfully authenticated to Power BI Service")
                return True
            else:
                error = result.get("error_description", "Unknown error")
                logger.error(f"Authentication failed: {error}")
                return False

        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return False

    def _token_expired(self) -> bool:
        """Return True when the cached access token is missing or older than the TTL."""
        return (
            not self.access_token
            or self._token_acquired_at is None
            or (time.monotonic() - self._token_acquired_at) >= self.token_ttl_seconds
        )

    def _ensure_authenticated(self, force: bool = False) -> bool:
        """Ensure a usable access token exists, proactively refreshing after the TTL."""
        if force or self._token_expired():
            return self.authenticate(force=True)
        return True

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make an authenticated request, retrying once after forced re-auth on 401/403."""
        if not self._ensure_authenticated():
            raise PermissionError("Authentication failed")

        request_kwargs = dict(kwargs)
        request_kwargs["headers"] = self._get_headers()
        response = self.session.request(method, url, **request_kwargs)
        if response.status_code not in self.AUTH_RETRY_STATUS_CODES:
            return response

        logger.warning("Power BI request returned %s; refreshing access token and retrying once", response.status_code)
        if not self._ensure_authenticated(force=True):
            return response

        retry_kwargs = dict(kwargs)
        retry_kwargs["headers"] = self._get_headers()
        return self.session.request(method, url, **retry_kwargs)

    def _get_headers(self) -> Dict[str, str]:
        """Get HTTP headers with authorization"""
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }

    def list_workspaces(self) -> List[Dict[str, Any]]:
        """
        List all workspaces accessible by the Service Principal
        """
        try:
            url = f"{self.BASE_URL}/groups"
            response = self._request("GET", url, timeout=30)
            response.raise_for_status()

            workspaces = response.json().get("value", [])
            logger.info(f"Found {len(workspaces)} workspace(s)")

            return [
                {
                    "id": ws["id"],
                    "name": ws["name"],
                    "type": ws.get("type", "Workspace"),
                    "state": ws.get("state", "Active"),
                }
                for ws in workspaces
            ]

        except Exception as e:
            logger.error(f"Failed to list workspaces: {str(e)}")
            return []

    def list_datasets(self, workspace_id: str) -> List[Dict[str, Any]]:
        """
        List all datasets in a workspace
        """
        try:
            url = f"{self.BASE_URL}/groups/{workspace_id}/datasets"
            response = self._request("GET", url, timeout=30)
            response.raise_for_status()

            datasets = response.json().get("value", [])
            logger.info(f"Found {len(datasets)} dataset(s)")

            return [
                {
                    "id": ds["id"],
                    "name": ds["name"],
                    "workspace_id": workspace_id,
                    "configured_by": ds.get("configuredBy", "Unknown"),
                    "is_refreshable": ds.get("isRefreshable", False),
                    "is_on_prem_gateway_required": ds.get("isOnPremGatewayRequired", False),
                }
                for ds in datasets
            ]

        except Exception as e:
            logger.error(f"Failed to list datasets: {str(e)}")
            return []


    def get_dataset(self, workspace_id: str, dataset_id: str) -> Dict[str, Any]:
        """Get dataset metadata from the Power BI REST API."""
        url = f"{self.BASE_URL}/groups/{workspace_id}/datasets/{dataset_id}"
        response = self._request("GET", url, timeout=30)
        response.raise_for_status()
        return response.json()

    def execute_dax_query(self, workspace_id: str, dataset_id: str, dax_query: str) -> List[Dict[str, Any]]:
        """Execute a read-only DAX query using the Power BI REST Execute Queries API."""
        url = f"{self.BASE_URL}/groups/{workspace_id}/datasets/{dataset_id}/executeQueries"
        payload = {
            "queries": [{"query": dax_query}],
            "serializerSettings": {"includeNulls": True},
        }
        response = self._request("POST", url, json=payload, timeout=60)
        response.raise_for_status()
        data = response.json()
        results = data.get("results") or []
        if not results:
            return []
        tables = results[0].get("tables") or []
        if not tables:
            return []
        return tables[0].get("rows") or []

    def list_tables(self, workspace_id: str, dataset_id: str) -> List[Dict[str, Any]]:
        """List tables in a dataset using INFO.VIEW.TABLES."""
        try:
            tables = self.execute_dax_query(workspace_id, dataset_id, "EVALUATE INFO.VIEW.TABLES()")
            logger.info(f"Found {len(tables)} table(s)")

            return [
                {
                    "name": table.get("Name", ""),
                    "rows": table.get("RowCount", 0),
                    "is_hidden": table.get("IsHidden", False),
                }
                for table in tables
            ]

        except Exception as e:
            logger.error(f"Failed to list tables: {str(e)}")
            return []

    def list_columns(self, workspace_id: str, dataset_id: str, table_name: str) -> List[Dict[str, Any]]:
        """List columns in a table using INFO.VIEW.COLUMNS."""
        try:
            # Filter columns for the specific table
            dax = f"EVALUATE FILTER(INFO.VIEW.COLUMNS(), [Table] = \"{table_name}\")"
            columns = self.execute_dax_query(workspace_id, dataset_id, dax)
            logger.info(f"Found {len(columns)} column(s) in table '{table_name}'")

            return [
                {
                    "name": col.get("Name", ""),
                    "data_type": col.get("DataType", ""),
                    "is_hidden": col.get("IsHidden", False),
                    "description": col.get("Description", ""),
                }
                for col in columns
            ]

        except Exception as e:
            logger.error(f"Failed to list columns: {str(e)}")
            return []

    def execute_dax(self, workspace_id: str, dataset_id: str, dax_query: str) -> List[Dict[str, Any]]:
        """Execute a DAX query and return results."""
        try:
            rows = self.execute_dax_query(workspace_id, dataset_id, dax_query)
            logger.info(f"Executed DAX query, returned {len(rows)} row(s)")
            return rows

        except Exception as e:
            logger.error(f"Failed to execute DAX: {str(e)}")
            return []

    def get_semantic_model_metadata(self, workspace_id: str, dataset_id: str) -> Dict[str, Any]:
        """Return semantic model metadata available through REST and Execute Queries."""
        dataset = self.get_dataset(workspace_id, dataset_id)
        metadata = {"dataset": dataset, "tables": [], "columns": [], "measures": [], "relationships": []}
        queries = {
            "tables": "EVALUATE INFO.VIEW.TABLES()",
            "columns": "EVALUATE INFO.VIEW.COLUMNS()",
            "measures": "EVALUATE INFO.VIEW.MEASURES()",
            "relationships": "EVALUATE INFO.VIEW.RELATIONSHIPS()",
        }
        for key, query in queries.items():
            try:
                metadata[key] = self.execute_dax_query(workspace_id, dataset_id, query)
            except Exception as exc:
                metadata[f"{key}_error"] = str(exc)
        return metadata

    # ==================== REFRESH OPERATIONS ====================

    def resolve_dataset(self, workspace_name: str, dataset_name: str):
        """Resolve a workspace+dataset name to (workspace_id, dataset_id).

        Returns (workspace_id, dataset_id, None) or (None, None, error_message).
        """
        workspaces = self.list_workspaces()
        ws = next((w for w in workspaces if w["name"] == workspace_name), None)
        if not ws:
            return None, None, f"Workspace '{workspace_name}' not found (or no access)"
        datasets = self.list_datasets(ws["id"])
        ds = next((d for d in datasets if d["name"] == dataset_name), None)
        if not ds:
            return None, None, f"Dataset '{dataset_name}' not found in workspace '{workspace_name}'"
        return ws["id"], ds["id"], None

    def get_refresh_history(self, workspace_id: str, dataset_id: str, top: int = 20) -> List[Dict[str, Any]]:
        """Get recent refresh history for a dataset (most recent first).

        Each entry: requestId, refreshType, startTime, endTime, status
        (Unknown|Completed|Failed|Disabled), serviceExceptionJson (a JSON string on failure).
        """
        url = f"{self.BASE_URL}/groups/{workspace_id}/datasets/{dataset_id}/refreshes?$top={int(top)}"
        response = self._request("GET", url, timeout=30)
        response.raise_for_status()
        return response.json().get("value", [])

    def get_datasources(self, workspace_id: str, dataset_id: str) -> List[Dict[str, Any]]:
        """Get the data sources bound to a dataset (for gateway/source diagnostics)."""
        url = f"{self.BASE_URL}/groups/{workspace_id}/datasets/{dataset_id}/datasources"
        response = self._request("GET", url, timeout=30)
        response.raise_for_status()
        return response.json().get("value", [])

    def trigger_refresh(self, workspace_id: str, dataset_id: str,
                        body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Trigger a dataset refresh. With no body, sends a standard refresh
        ({"notifyOption": "NoNotification"}) that works on Pro. A non-empty body uses the
        enhanced refresh API (Premium/PPU/Fabric) and must NOT include notifyOption.

        Returns {accepted, status_code, request_id, location, message}.
        """
        url = f"{self.BASE_URL}/groups/{workspace_id}/datasets/{dataset_id}/refreshes"
        payload = body if body else {"notifyOption": "NoNotification"}
        try:
            response = self._request("POST", url, json=payload, timeout=30)
            accepted = response.status_code in (200, 202)  # async contract is 202 Accepted
            location = response.headers.get("Location")
            return {
                "accepted": accepted,
                "status_code": response.status_code,
                "request_id": response.headers.get("x-ms-request-id") or (location.rstrip("/").split("/")[-1] if location else None),
                "location": location,
                "message": "Refresh requested" if accepted else (response.text or "")[:500],
            }
        except Exception as e:
            return {"accepted": False, "message": str(e)}

    # ==================== ADMIN / SCANNER / ACTIVITY (Wave 3) ====================
    # These require Fabric/Power BI admin rights (or an SP in an allowed security group
    # with read-only admin APIs enabled). Reads only; rate-limited by the service.

    def admin_list_workspaces(self, top: int = 100) -> List[Dict[str, Any]]:
        """List workspaces tenant-wide (admin). GET /admin/groups."""
        url = f"{self.BASE_URL}/admin/groups?$top={int(top)}"
        response = self._request("GET", url, timeout=30)
        response.raise_for_status()
        return response.json().get("value", [])

    def admin_post_workspace_info(self, workspace_ids: List[str], lineage: bool = True) -> Dict[str, Any]:
        """Start a metadata scan for up to 100 workspaces. POST /admin/workspaces/getInfo.
        Returns {id: scanId, status,...}."""
        # datasourceDetails=false: governance summary uses roles/labels/lineage only, not
        # datasource instances - keeps the scan payload small. lineage gives report->dataset links.
        url = (f"{self.BASE_URL}/admin/workspaces/getInfo"
               f"?lineage={'true' if lineage else 'false'}&datasourceDetails=false"
               f"&datasetSchema=false&datasetExpressions=false&getArtifactUsers=false")
        response = self._request("POST", url, json={"workspaces": workspace_ids[:100]}, timeout=30)
        response.raise_for_status()
        return response.json()

    def admin_get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """GET /admin/workspaces/scanStatus/{scanId}. status is a string (not a closed enum);
        known values include NotStarted, Running, Succeeded, Failed - match case-insensitively
        and treat anything else as still in progress. On Failed, inspect the .error object."""
        url = f"{self.BASE_URL}/admin/workspaces/scanStatus/{scan_id}"
        response = self._request("GET", url, timeout=30)
        response.raise_for_status()
        return response.json()

    def admin_get_scan_result(self, scan_id: str) -> Dict[str, Any]:
        """GET /admin/workspaces/scanResult/{scanId}. Returns the full workspace metadata graph."""
        url = f"{self.BASE_URL}/admin/workspaces/scanResult/{scan_id}"
        response = self._request("GET", url, timeout=60)
        response.raise_for_status()
        return response.json()

    def admin_get_activity_events(self, start_dt_iso: str, end_dt_iso: str,
                                  filter_expr: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get audit Activity Events for a window (same UTC day, <=28 days old) via
        GET /admin/activityevents. Datetimes are single-quoted UTC ISO. Pages by following
        continuationUri verbatim while continuationToken is non-null (a page may be empty but
        still have a token). Honors 429 Retry-After. Returns the accumulated entities."""
        import time as _time
        from urllib.parse import quote
        url = (f"{self.BASE_URL}/admin/activityevents"
               f"?startDateTime='{start_dt_iso}'&endDateTime='{end_dt_iso}'")
        if filter_expr:
            url += f"&$filter={quote(filter_expr)}"
        entities: List[Dict[str, Any]] = []
        for _ in range(1000):  # safety bound on pages
            response = self._request("GET", url, timeout=30)
            if response.status_code == 429:
                _time.sleep(int(response.headers.get("Retry-After", "10")))
                continue
            response.raise_for_status()
            data = response.json()
            entities.extend(data.get("activityEventEntities", []) or [])
            token = data.get("continuationToken")
            cont_uri = data.get("continuationUri")
            if not token:
                break
            url = cont_uri  # complete, correctly-encoded URL - follow verbatim, no re-encoding
        return entities

    def admin_get_activity_events_for_day(self, date: str,
                                          filter_expr: Optional[str] = None) -> List[Dict[str, Any]]:
        """Pull a full UTC day of activity events by looping 24 one-hour windows
        (the raw API allows at most ~1 hour per request). date = 'YYYY-MM-DD'."""
        events: List[Dict[str, Any]] = []
        for h in range(24):
            start = f"{date}T{h:02d}:00:00.000Z"
            end = f"{date}T{h:02d}:59:59.999Z"
            events.extend(self.admin_get_activity_events(start, end, filter_expr))
        return events
