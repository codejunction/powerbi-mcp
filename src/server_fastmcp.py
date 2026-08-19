"""
Power BI MCP Server - FastMCP-based implementation with type-safe Pydantic models.
REST-only, read-only Power BI Service access.
"""
import asyncio
import logging
import os
from typing import Optional
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from mcp.server import FastMCP
from pydantic import BaseModel

from powerbi_rest_connector import PowerBIRestConnector
from security import SecurityLayer, get_security_layer
from errors import handle_error
from models import (
    # Input models
    ListWorkspacesInput, ListDatasetsInput, ListTablesInput, ListColumnsInput,
    ExecuteDaxInput, ValidateDaxInput, GetModelInfoInput, DescribeSemanticModelInput,
    AnswerQueryPlanInput, SecurityStatusInput, SecurityAuditLogInput,
    RunBpaInput, AuditAiReadinessInput, AnalyzeModelStorageInput,
    AnalyzeQueryPerformanceInput, ModelDiffInput, PreDeployGateInput,
    RefreshDoctorInput, FindUnusedObjectsInput, ImpactAnalysisInput,
    RunDaxTestsInput, ScanReferentialIntegrityInput, GenerateMeasureSuiteInput,
    # Output models
    DaxResult, ValidationResult, QueryPlan, SecurityStatus, AuditLogEntry,
    BpaResult, AiReadinessResult, StorageAnalysis, QueryPerformanceAnalysis,
    ModelDiffResult, PreDeployCheckResult, RefreshDiagnosis, UnusedObjectsResult,
    ImpactAnalysisResult, DaxTestResult, ReferentialIntegrityResult, MeasureSuiteResult,
    # Common models
    WorkspaceInfo, DatasetInfo, TableInfo, ColumnInfo, MeasureInfo, RelationshipInfo,
)

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO")),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("powerbi-mcp")


# ============================================================================
# Application Context
# ============================================================================

class AppContext(BaseModel):
    """Application context with connectors and security layer."""
    model_config = {"arbitrary_types_allowed": True}

    rest_connector: Optional[PowerBIRestConnector] = None
    security: Optional[SecurityLayer] = None


@asynccontextmanager
async def app_lifespan(mcp: FastMCP):
    """Manage application lifecycle with type-safe context."""
    # Initialize on startup
    logger.info("Initializing Power BI MCP Server")

    tenant_id = os.getenv("TENANT_ID", "")
    client_id = os.getenv("CLIENT_ID", "")
    client_secret = os.getenv("CLIENT_SECRET", "")

    # Initialize REST connector
    rest_connector = None
    if tenant_id and client_id and client_secret:
        try:
            rest_connector = PowerBIRestConnector(tenant_id, client_id, client_secret)
            rest_connector.authenticate()
            logger.info("Successfully authenticated to Power BI Service")
        except Exception as e:
            logger.error(f"Failed to authenticate to Power BI Service: {e}")

    # Initialize security layer
    config_path = os.path.join(os.path.dirname(__file__), "..", "config", "policies.yaml")
    security = SecurityLayer(
        config_path=config_path if os.path.exists(config_path) else None,
        enable_pii_detection=os.getenv("ENABLE_PII_DETECTION", "true").lower() == "true",
        enable_audit=os.getenv("ENABLE_AUDIT", "true").lower() == "true",
        enable_policies=os.getenv("ENABLE_POLICIES", "true").lower() == "true",
    )

    try:
        yield AppContext(rest_connector=rest_connector, security=security)
    finally:
        # Cleanup on shutdown
        logger.info("Shutting down Power BI MCP Server")


# ============================================================================
# FastMCP Server
# ============================================================================

mcp = FastMCP(
    "powerbi-mcp",
    lifespan=app_lifespan,
)


# ============================================================================
# Cloud REST API Tools
# ============================================================================

@mcp.tool()
async def list_workspaces(ctx) -> list[WorkspaceInfo]:
    """List all Power BI Service workspaces accessible to the Service Principal."""
    app_ctx: AppContext = ctx.request_context.lifespan_context
    if not app_ctx.rest_connector:
        raise ValueError("REST connector not initialized")

    workspaces = await app_ctx.rest_connector.list_workspaces()
    return [WorkspaceInfo(**ws) for ws in workspaces]


@mcp.tool()
async def list_datasets(ctx, workspace_id: str) -> list[DatasetInfo]:
    """List all datasets in a Power BI Service workspace."""
    app_ctx: AppContext = ctx.request_context.lifespan_context
    if not app_ctx.rest_connector:
        raise ValueError("REST connector not initialized")

    datasets = await app_ctx.rest_connector.list_datasets(workspace_id)
    return [DatasetInfo(**ds) for ds in datasets]


@mcp.tool()
async def list_tables(ctx, workspace_name: str, dataset_name: str) -> list[TableInfo]:
    """List all tables in a Power BI Service dataset via REST API."""
    app_ctx: AppContext = ctx.request_context.lifespan_context
    if not app_ctx.rest_connector:
        raise ValueError("REST connector not initialized")

    # Get workspace ID from name
    workspaces = await app_ctx.rest_connector.list_workspaces()
    workspace_id = None
    for ws in workspaces:
        if ws.get("name") == workspace_name:
            workspace_id = ws.get("id")
            break

    if not workspace_id:
        raise ValueError(f"Workspace '{workspace_name}' not found")

    # Get dataset ID from name
    datasets = await app_ctx.rest_connector.list_datasets(workspace_id)
    dataset_id = None
    for ds in datasets:
        if ds.get("name") == dataset_name:
            dataset_id = ds.get("id")
            break

    if not dataset_id:
        raise ValueError(f"Dataset '{dataset_name}' not found")

    tables = await app_ctx.rest_connector.list_tables(workspace_id, dataset_id)
    return [TableInfo(**table) for table in tables]


@mcp.tool()
async def list_columns(
    ctx,
    workspace_name: str,
    dataset_name: str,
    table_name: str
) -> list[ColumnInfo]:
    """List columns for a table in a Power BI Service dataset."""
    app_ctx: AppContext = ctx.request_context.lifespan_context
    if not app_ctx.rest_connector:
        raise ValueError("REST connector not initialized")

    # Get workspace and dataset IDs
    workspaces = await app_ctx.rest_connector.list_workspaces()
    workspace_id = next((ws.get("id") for ws in workspaces if ws.get("name") == workspace_name), None)
    if not workspace_id:
        raise ValueError(f"Workspace '{workspace_name}' not found")

    datasets = await app_ctx.rest_connector.list_datasets(workspace_id)
    dataset_id = next((ds.get("id") for ds in datasets if ds.get("name") == dataset_name), None)
    if not dataset_id:
        raise ValueError(f"Dataset '{dataset_name}' not found")

    columns = await app_ctx.rest_connector.list_columns(workspace_id, dataset_id, table_name)
    return [ColumnInfo(**col) for col in columns]


@mcp.tool()
async def execute_dax(
    ctx,
    workspace_name: str,
    dataset_name: str,
    dax_query: str
) -> DaxResult:
    """Execute a DAX query against a Power BI Service dataset."""
    app_ctx: AppContext = ctx.request_context.lifespan_context
    if not app_ctx.rest_connector:
        raise ValueError("REST connector not initialized")

    # Apply security checks
    if app_ctx.security:
        dax_query = app_ctx.security.redact_pii(dax_query)

    # Get workspace and dataset IDs
    workspaces = await app_ctx.rest_connector.list_workspaces()
    workspace_id = next((ws.get("id") for ws in workspaces if ws.get("name") == workspace_name), None)
    if not workspace_id:
        raise ValueError(f"Workspace '{workspace_name}' not found")

    datasets = await app_ctx.rest_connector.list_datasets(workspace_id)
    dataset_id = next((ds.get("id") for ds in datasets if ds.get("name") == dataset_name), None)
    if not dataset_id:
        raise ValueError(f"Dataset '{dataset_name}' not found")

    # Execute query
    start_time = asyncio.get_event_loop().time()
    rows = await app_ctx.rest_connector.execute_dax(workspace_id, dataset_id, dax_query)
    execution_time = (asyncio.get_event_loop().time() - start_time) * 1000

    # Apply security to results
    if app_ctx.security:
        rows = [app_ctx.security.apply_policies(row) for row in rows]

    return DaxResult(
        rows=rows,
        execution_time_ms=execution_time,
        row_count=len(rows)
    )


@mcp.tool()
async def validate_dax(
    ctx,
    dax: str,
    as_measure: bool = False,
    workspace_name: str = "",
    dataset_name: str = ""
) -> ValidationResult:
    """Validate a DAX query or measure expression against the connected model."""
    app_ctx: AppContext = ctx.request_context.lifespan_context
    if not app_ctx.rest_connector:
        raise ValueError("REST connector not initialized")

    if not workspace_name or not dataset_name:
        return ValidationResult(
            valid=False,
            error="workspace_name and dataset_name are required"
        )

    # Get workspace and dataset IDs
    workspaces = await app_ctx.rest_connector.list_workspaces()
    workspace_id = next((ws.get("id") for ws in workspaces if ws.get("name") == workspace_name), None)
    if not workspace_id:
        return ValidationResult(valid=False, error=f"Workspace '{workspace_name}' not found")

    datasets = await app_ctx.rest_connector.list_datasets(workspace_id)
    dataset_id = next((ds.get("id") for ds in datasets if ds.get("name") == dataset_name), None)
    if not dataset_id:
        return ValidationResult(valid=False, error=f"Dataset '{dataset_name}' not found")

    # Wrap as measure if needed
    if as_measure:
        probe = f"EVALUATE ROW(Result, {dax})"
    else:
        probe = dax

    try:
        await app_ctx.rest_connector.execute_dax(workspace_id, dataset_id, probe)
        return ValidationResult(valid=True, probe=probe)
    except Exception as e:
        return ValidationResult(valid=False, error=str(e), probe=probe)


# ============================================================================
# Security Tools
# ============================================================================

@mcp.tool()
async def security_status(ctx) -> SecurityStatus:
    """Get the current security settings and status."""
    app_ctx: AppContext = ctx.request_context.lifespan_context
    if not app_ctx.security:
        return SecurityStatus(
            pii_detection_enabled=False,
            audit_logging_enabled=False,
            access_policies_enabled=False,
            active_policies=[]
        )

    return SecurityStatus(
        pii_detection_enabled=app_ctx.security.enable_pii,
        audit_logging_enabled=app_ctx.security.enable_audit,
        access_policies_enabled=app_ctx.security.enable_policies,
        active_policies=app_ctx.security.get_active_policies()
    )


@mcp.tool()
async def security_audit_log(ctx, count: int = 10) -> list[AuditLogEntry]:
    """View recent entries from the security audit log."""
    app_ctx: AppContext = ctx.request_context.lifespan_context
    if not app_ctx.security:
        return []

    entries = app_ctx.security.get_recent_entries(count)
    return [AuditLogEntry(**entry) for entry in entries]


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    import sys

    # Support both stdio and HTTP transports
    if len(sys.argv) > 1 and sys.argv[1] == "http":
        # Run with HTTP transport for remote access
        host = os.getenv("HOST", "0.0.0.0")
        port = int(os.getenv("PORT", "8000"))
        logger.info(f"Starting HTTP server on {host}:{port}")
        mcp.run(transport="http", host=host, port=port)
    else:
        # Run with stdio transport for local access
        logger.info("Starting stdio server")
        mcp.run(transport="stdio")
