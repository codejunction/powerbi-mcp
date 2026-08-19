"""
Power BI MCP Server - Complete FastMCP rewrite with Pydantic models and comprehensive docstrings.
REST-only, read-only Power BI Service access.
"""
import asyncio
import logging
import os
from typing import Optional
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastmcp import FastMCP
from fastmcp.dependencies import CurrentContext
from fastmcp.server.context import Context
from pydantic import BaseModel, Field

from powerbi_rest_connector import PowerBIRestConnector
from security import SecurityLayer
from models import (
    WorkspaceInfo, DatasetInfo, TableInfo, ColumnInfo,
    DaxResult, ValidationResult, SecurityStatus, AuditLogEntry,
    MeasureDefinition, BpaResult, AiReadinessResult, PreDeployCheckResult,
    SecurityScanSummary, UserActivitySummary
)
from errors import handle_error
from dax_generator import generate_suite
from model_analysis import run_bpa as run_bpa_analysis, audit_ai_readiness
from governance import summarize_scan, aggregate_activity

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


# Module-level app context (set during lifespan, accessed by tools)
_app_context: Optional[AppContext] = None


@asynccontextmanager
async def app_lifespan(mcp: FastMCP):
    """Manage application lifecycle with type-safe context."""
    global _app_context
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

    _app_context = AppContext(rest_connector=rest_connector, security=security)

    try:
        yield _app_context
    finally:
        _app_context = None
        logger.info("Shutting down Power BI MCP Server")


# ============================================================================
# FastMCP Server
# ============================================================================

mcp = FastMCP(
    "powerbi-mcp",
    lifespan=app_lifespan,
)


# ============================================================================
# Tool Definitions with MCP-standard docstrings
# ============================================================================

@mcp.tool()
async def list_workspaces(ctx: Context = CurrentContext()) -> list[WorkspaceInfo]:
    """
    List all Power BI Service workspaces accessible to the Service Principal.

    Returns a list of workspace objects containing ID, name, capacity information,
    and default dataset information. This tool requires authentication credentials
    and will return only workspaces that the Service Principal has access to.

    Returns:
        List[WorkspaceInfo]: List of workspace information objects
    """
    try:
        app_ctx = _app_context
        if not app_ctx or not app_ctx.rest_connector:
            raise ValueError("REST connector not initialized")

        workspaces = app_ctx.rest_connector.list_workspaces()
        return [WorkspaceInfo(**ws) for ws in workspaces]
    except Exception as e:
        error = handle_error(e)
        raise ValueError(f"{error.error_type}: {error.message}")


@mcp.tool()
async def list_datasets(workspace_id: str, ctx: Context = CurrentContext()) -> list[DatasetInfo]:
    """
    List all datasets in a Power BI Service workspace.

    Returns a list of dataset objects for the specified workspace ID. Each dataset
    includes information about refreshability, gateway requirements, and configuration
    details. This tool requires the workspace ID which can be obtained from
    the list_workspaces tool.

    Args:
        workspace_id: The ID of the workspace to list datasets from

    Returns:
        List[DatasetInfo]: List of dataset information objects
    """
    try:
        app_ctx = _app_context
        if not app_ctx or not app_ctx.rest_connector:
            raise ValueError("REST connector not initialized")

        datasets = app_ctx.rest_connector.list_datasets(workspace_id)
        return [DatasetInfo(**ds) for ds in datasets]
    except Exception as e:
        error = handle_error(e)
        raise ValueError(f"{error.error_type}: {error.message}")


@mcp.tool()
async def list_tables(workspace_name: str, dataset_name: str, ctx: Context = CurrentContext()) -> list[TableInfo]:
    """
    List all tables in a Power BI Service dataset via REST API.

    Returns a list of table objects for the specified workspace and dataset. Each table
    includes the table name, row count, and visibility status. This tool requires
    both workspace name and dataset name to identify the correct dataset.

    Args:
        workspace_name: The name of the workspace containing the dataset
        dataset_name: The name of the dataset to list tables from

    Returns:
        List[TableInfo]: List of table information objects
    """
    try:
        app_ctx = _app_context
        if not app_ctx or not app_ctx.rest_connector:
            raise ValueError("REST connector not initialized")

        # Get workspace ID from name
        workspaces = app_ctx.rest_connector.list_workspaces()
        workspace_id = None
        for ws in workspaces:
            if ws.get("name") == workspace_name:
                workspace_id = ws.get("id")
                break

        if not workspace_id:
            raise ValueError(f"Workspace '{workspace_name}' not found")

        # Get dataset ID from name
        datasets = app_ctx.rest_connector.list_datasets(workspace_id)
        dataset_id = None
        for ds in datasets:
            if ds.get("name") == dataset_name:
                dataset_id = ds.get("id")
                break

        if not dataset_id:
            raise ValueError(f"Dataset '{dataset_name}' not found")

        tables = app_ctx.rest_connector.list_tables(workspace_id, dataset_id)
        return [TableInfo(**table) for table in tables]
    except Exception as e:
        error = handle_error(e)
        raise ValueError(f"{error.error_type}: {error.message}")


@mcp.tool()
async def list_columns(
    workspace_name: str,
    dataset_name: str,
    table_name: str,

) -> list[ColumnInfo]:
    """
    List columns for a table in a Power BI Service dataset.

    Returns a list of column objects for the specified table within a dataset.
    Each column includes name, data type, visibility status, and optional description.
    This tool requires workspace name, dataset name, and table name to identify
    the correct table.

    Args:
        workspace_name: The name of the workspace containing the dataset
        dataset_name: The name of the dataset containing the table
        table_name: The name of the table to list columns from

    Returns:
        List[ColumnInfo]: List of column information objects
    """
    try:
        app_ctx = _app_context
        if not app_ctx or not app_ctx.rest_connector:
            raise ValueError("REST connector not initialized")

        # Get workspace and dataset IDs
        workspaces = app_ctx.rest_connector.list_workspaces()
        workspace_id = next((ws.get("id") for ws in workspaces if ws.get("name") == workspace_name), None)
        if not workspace_id:
            raise ValueError(f"Workspace '{workspace_name}' not found")

        datasets = app_ctx.rest_connector.list_datasets(workspace_id)
        dataset_id = next((ds.get("id") for ds in datasets if ds.get("name") == dataset_name), None)
        if not dataset_id:
            raise ValueError(f"Dataset '{dataset_name}' not found")

        columns = app_ctx.rest_connector.list_columns(workspace_id, dataset_id, table_name)
        return [ColumnInfo(**col) for col in columns]
    except Exception as e:
        error = handle_error(e)
        raise ValueError(f"{error.error_type}: {error.message}")


@mcp.tool()
async def execute_dax(
    workspace_name: str,
    dataset_name: str,
    dax_query: str,

) -> DaxResult:
    """
    Execute a DAX query against a Power BI Service dataset.

    Executes a read-only DAX query against the specified dataset and returns the
    results. The query is validated and executed through the Power BI REST Execute
    Queries API. Security policies are applied to both the query and results to
    protect sensitive data. Returns execution time and row count along with results.

    Args:
        workspace_name: The name of the workspace containing the dataset
        dataset_name: The name of the dataset to execute the query against
        dax_query: The DAX query to execute (e.g., 'EVALUATE SUM(Sales[Amount])')

    Returns:
        DaxResult: Object containing query results, execution time, and row count
    """
    try:
        app_ctx = _app_context
        if not app_ctx or not app_ctx.rest_connector:
            raise ValueError("REST connector not initialized")

        # Apply security checks
        if app_ctx.security:
            dax_query = app_ctx.security.redact_pii(dax_query)

        # Get workspace and dataset IDs
        workspaces = app_ctx.rest_connector.list_workspaces()
        workspace_id = next((ws.get("id") for ws in workspaces if ws.get("name") == workspace_name), None)
        if not workspace_id:
            raise ValueError(f"Workspace '{workspace_name}' not found")

        datasets = app_ctx.rest_connector.list_datasets(workspace_id)
        dataset_id = next((ds.get("id") for ds in datasets if ds.get("name") == dataset_name), None)
        if not dataset_id:
            raise ValueError(f"Dataset '{dataset_name}' not found")

        # Execute query
        start_time = asyncio.get_event_loop().time()
        rows = app_ctx.rest_connector.execute_dax(workspace_id, dataset_id, dax_query)
        execution_time = (asyncio.get_event_loop().time() - start_time) * 1000

        # Apply security to results
        if app_ctx.security:
            rows = [app_ctx.security.apply_policies(row) for row in rows]

        return DaxResult(
            rows=rows,
            execution_time_ms=execution_time,
            row_count=len(rows)
        )
    except Exception as e:
        error = handle_error(e)
        raise ValueError(f"{error.error_type}: {error.message}")


@mcp.tool()
async def validate_dax(
    dax: str,
    as_measure: bool = False,
    workspace_name: str = "",
    dataset_name: str = "",

) -> ValidationResult:
    """
    Validate a DAX query or measure expression against the connected model.

    Validates a DAX query or scalar measure expression without executing it.
    This is useful for checking syntax and semantic errors before executing queries.
    When as_measure is true, the expression is wrapped in an EVALUATE ROW
    statement for validation. Returns validation status and the probe query used.

    Args:
        dax: The DAX query or expression to validate
        as_measure: Whether to treat the input as a scalar measure expression (default: false)
        workspace_name: The name of the workspace containing the dataset
        dataset_name: The name of the dataset to validate against

    Returns:
        ValidationResult: Object containing validation status, error message, and probe query
    """
    try:
        app_ctx = _app_context
        if not app_ctx or not app_ctx.rest_connector:
            raise ValueError("REST connector not initialized")

        if not workspace_name or not dataset_name:
            return ValidationResult(
                valid=False,
                error="workspace_name and dataset_name are required"
            )

        # Get workspace and dataset IDs
        workspaces = app_ctx.rest_connector.list_workspaces()
        workspace_id = next((ws.get("id") for ws in workspaces if ws.get("name") == workspace_name), None)
        if not workspace_id:
            return ValidationResult(valid=False, error=f"Workspace '{workspace_name}' not found")

        datasets = app_ctx.rest_connector.list_datasets(workspace_id)
        dataset_id = next((ds.get("id") for ds in datasets if ds.get("name") == dataset_name), None)
        if not dataset_id:
            return ValidationResult(valid=False, error=f"Dataset '{dataset_name}' not found")

        # Wrap as measure if needed
        if as_measure:
            probe = f"EVALUATE ROW(Result, {dax})"
        else:
            probe = dax

        try:
            app_ctx.rest_connector.execute_dax(workspace_id, dataset_id, probe)
            return ValidationResult(valid=True, probe=probe)
        except Exception as e:
            return ValidationResult(valid=False, error=str(e), probe=probe)
    except Exception as e:
        error = handle_error(e)
        raise ValueError(f"{error.error_type}: {error.message}")


# ============================================================================
# Prompts
# ============================================================================

@mcp.prompt()
async def optimize_measure() -> str:
    """
    Optimize a DAX measure for better performance.

    This prompt guides the user through the process of optimizing a DAX measure
    by analyzing the current expression, identifying performance bottlenecks,
    and suggesting improvements. It includes steps for using the analyze_query_performance
    tool and applying common DAX optimization patterns.

    Returns:
        str: Guided workflow for measure optimization
    """
    return """
To optimize a DAX measure, follow these steps:

1. **Analyze Current Performance**
   - Use the analyze_query_performance tool with your measure's DAX
   - Review the execution time and identified bottlenecks

2. **Apply Optimization Patterns**
   - Use variables (VAR/RETURN) to avoid recomputation
   - Replace FILTER with boolean predicates in CALCULATE
   - Use DIVIDE instead of / for safe division
   - Consider using SUMMARIZECOLUMNS instead of SUMMARIZE + ADDCOLUMNS

3. **Validate the Optimized Version**
   - Use validate_dax to check the new expression
   - Execute the optimized measure to verify results

4. **Compare Performance**
   - Run both versions and compare execution times
   - Ensure the optimized version produces the same results
"""


@mcp.prompt()
async def explain_measure() -> str:
    """
    Explain a DAX measure's purpose and logic.

    This prompt helps understand what a DAX measure does by breaking down
    its expression, identifying the calculation logic, and explaining how
    it relates to the data model. It includes steps for using get_model_info
    and analyzing measure dependencies.

    Returns:
        str: Guided workflow for measure explanation
    """
    return """
To explain a DAX measure, follow these steps:

1. **Get Model Context**
   - Use get_model_info to understand the data model
   - Review tables, columns, and relationships

2. **Analyze the Expression**
   - Break down the DAX expression into logical parts
   - Identify key functions and calculations
   - Understand the data flow through the model

3. **Check Dependencies**
   - Use scan_measure_dependencies to see what the measure depends on
   - Review upstream and downstream dependencies

4. **Document the Purpose**
   - Summarize what the measure calculates
   - Explain the business logic behind the calculation
   - Note any special conditions or edge cases
"""


@mcp.prompt()
async def audit_model() -> str:
    """
    Audit a Power BI model for quality and best practices.

    This prompt guides through a comprehensive model audit including BPA analysis,
    AI readiness assessment, and quality checks. It includes steps for using
    run_bpa, audit_ai_readiness, and other diagnostic tools to identify issues
    and improvement opportunities.

    Returns:
        str: Guided workflow for model auditing
    """
    return """
To audit a Power BI model, follow these steps:

1. **Run Best Practice Analyzer**
   - Use analyze_bpa to check for BPA violations
   - Review the violations and their severity
   - Prioritize critical issues

2. **Assess AI Readiness**
   - Use audit_ai_readiness to check AI-friendliness
   - Review the AI readiness score and findings
   - Address naming conventions and documentation

3. **Check Model Storage**
   - Use analyze_model_storage to review storage efficiency
   - Identify large tables and compression opportunities
   - Review data types and column cardinality

4. **Validate Referential Integrity**
   - Use scan_referential_integrity to check relationships
   - Review any orphan keys or broken relationships
   - Ensure data model consistency

5. **Generate Recommendations**
   - Compile findings from all audits
   - Prioritize issues by impact and effort
   - Create an action plan for improvements
"""


@mcp.prompt()
async def document_model() -> str:
    """
    Generate documentation for a Power BI model.

    This prompt helps create comprehensive documentation for a Power BI model
    including data dictionary, measure definitions, and relationship diagrams.
    It includes steps for using describe_semantic_model and export_data_dictionary
    to generate structured documentation.

    Returns:
        str: Guided workflow for model documentation
    """
    return """
To document a Power BI model, follow these steps:

1. **Get Model Overview**
   - Use describe_semantic_model to get a high-level overview
   - Review the tables, measures, and relationships
   - Understand the model's purpose and structure

2. **Generate Data Dictionary**
   - Use export_data_dictionary to create a detailed data dictionary
   - Review the documentation coverage score
   - Add missing descriptions for tables, columns, and measures

3. **Document Measures**
   - Review all measures and their expressions
   - Add business context and usage examples
   - Document any special conditions or limitations

4. **Document Relationships**
   - Review all relationships and their purposes
   - Document cardinality and filter direction
   - Explain the data model structure

5. **Format and Publish**
   - Choose the appropriate format (Markdown or HTML)
   - Review and edit the generated documentation
   - Publish to the appropriate location
"""


# ============================================================================
# Resources
# ============================================================================

@mcp.resource("powerbi://reference/bpa-rules")
async def bpa_rules_resource() -> str:
    """
    Built-in Best Practice Analyzer rule catalog.

    This resource provides the built-in BPA rule catalog with rule definitions,
    severity levels, and remediation guidance. It serves as a reference for
    understanding what BPA checks are available and how to address violations.

    Returns:
        str: JSON-formatted BPA rule catalog
    """
    return """
{
  "rules": [
    {
      "id": "BP01",
      "name": "Use DIVIDE instead of /",
      "severity": "warning",
      "description": "Use DIVIDE function instead of / operator for safe division by zero",
      "remediation": "Replace 'x / y' with 'DIVIDE(x, y)'"
    },
    {
      "id": "BP02",
      "name": "Avoid bi-directional relationships",
      "severity": "error",
      "description": "Bi-directional relationships can cause ambiguity in filter propagation",
      "remediation": "Set cross-filtering direction to single direction"
    },
    {
      "id": "BP03",
      "name": "Use variables for performance",
      "severity": "warning",
      "description": "Variables can improve performance by avoiding recomputation",
      "remediation": "Extract repeated expressions into VAR statements"
    }
  ]
}
"""


@mcp.resource("powerbi://reference/refresh-errors")
async def refresh_errors_resource() -> str:
    """
    Known refresh failure causes and fixes.

    This resource provides a catalog of known refresh failure causes, their
    symptoms, and remediation steps. It helps diagnose and fix common dataset
    refresh issues in Power BI Service.

    Returns:
        str: JSON-formatted refresh error catalog
    """
    return """
{
  "errors": [
    {
      "code": "DM_GN_RefreshRequest_Timeout",
      "name": "Refresh timeout",
      "severity": "error",
      "description": "Refresh operation timed out",
      "remediation": "Check data source performance, reduce data volume, or increase timeout"
    },
    {
      "code": "DM_GN_RefreshGatewayOffline",
      "name": "Gateway offline",
      "severity": "error",
      "description": "On-premises data gateway is offline",
      "remediation": "Check gateway status, restart gateway service, verify network connectivity"
    },
    {
      "code": "DM_GN_RefreshUnauthorized",
      "name": "Unauthorized access",
      "severity": "error",
      "description": "Service principal lacks refresh permissions",
      "remediation": "Grant Build permission on dataset to service principal"
    }
  ]
}
"""


@mcp.resource("powerbi://cloud/{workspace}/{dataset}/schema")
async def cloud_schema_template(workspace: str, dataset: str) -> str:
    """
    Template resource for Power BI Service dataset schema.

    This resource provides a template for accessing the schema of a specific
    Power BI Service dataset. The workspace and dataset parameters are replaced
    with actual values when the resource is accessed.

    Args:
        workspace: The workspace name
        dataset: The dataset name

    Returns:
        str: Template string for dataset schema resource
    """
    return f"Schema template for workspace '{workspace}' and dataset '{dataset}'"


# ============================================================================
# Security Tools
# ============================================================================

@mcp.tool()
async def security_status() -> SecurityStatus:
    """
    Get the current security settings and status.

    Returns the current security configuration including PII detection status,
    audit logging status, access policy enforcement status, and a list of
    active security policies. This tool helps understand what security measures
    are currently active in the server.

    Returns:
        SecurityStatus: Object containing current security configuration
    """
    try:
        app_ctx = _app_context
        if not app_ctx or not app_ctx.security:
            return SecurityStatus(
                pii_detection_enabled=False,
                audit_logging_enabled=False,
                access_policies_enabled=False,
                active_policies=[]
            )

        return SecurityStatus(
            pii_detection_enabled=app_ctx.security.enable_pii_detection,
            audit_logging_enabled=app_ctx.security.enable_audit,
            access_policies_enabled=app_ctx.security.enable_policies,
            active_policies=app_ctx.security.get_active_policies()
        )
    except Exception as e:
        error = handle_error(e)
        raise ValueError(f"{error.error_type}: {error.message}")


@mcp.tool()
async def security_audit_log(count: int = 10) -> list[AuditLogEntry]:
    """
    View recent entries from the security audit log.

    Returns recent entries from the security audit log, which tracks all tool
    calls, arguments, results, and PII findings. Each entry includes timestamp,
    tool name, user information, arguments, result, and any PII that was detected.
    This is useful for monitoring server activity and security events.

    Args:
        count: Number of recent entries to show (default: 10, max: 100)

    Returns:
        List[AuditLogEntry]: List of recent audit log entries
    """
    try:
        app_ctx = _app_context
        if not app_ctx or not app_ctx.security:
            return []

        entries = app_ctx.security.get_recent_entries(count)
        return [AuditLogEntry(**entry) for entry in entries]
    except Exception as e:
        error = handle_error(e)
        raise ValueError(f"{error.error_type}: {error.message}")


# ============================================================================
# DAX Generation Tools
# ============================================================================

@mcp.tool()
async def generate_measure_suite(
    kind: str,
    table_name: Optional[str] = None,
    base_column: Optional[str] = None,
    base_measure: Optional[str] = None,

) -> list[dict]:
    """
    Generate a suite of DAX measures from a base measure or column.

    Creates a governed suite of measures including time intelligence (YTD/QTD/MTD/PY/YoY/YoY %/MoM/rolling windows),
    share-of-total ratios, ranks, and column statistics. Every generated measure carries a name,
    self-contained DAX (no dependency on other generated measures), a format string, a display folder,
    and a description.

    Args:
        kind: Pattern preset (time_intelligence, ratios, ranking, column_stats)
        table_name: Table to generate measures for
        base_column: Base column for aggregations
        base_measure: Base measure for ratios/ranking

    Returns:
        list[dict]: List of measure definitions with name, expression, format_string, display_folder, description
    """
    try:
        params = {}
        if table_name:
            params["table_name"] = table_name
        if base_column:
            params["base_column"] = base_column
        if base_measure:
            params["base_measure"] = base_measure

        measures = generate_suite(kind, **params)
        return measures
    except Exception as e:
        error = handle_error(e)
        raise ValueError(f"{error.error_type}: {error.message}")


# ============================================================================
# Model Analysis Tools
# ============================================================================

@mcp.tool()
async def analyze_bpa(model: dict) -> dict:
    """
    Run Best Practice Analyzer rules on a model.

    Analyzes a semantic model against built-in BPA rules and returns violations
    with severity levels and remediation guidance. This is a lightweight BPA that
    operates on normalized model metadata without requiring Power BI Desktop.

    Args:
        model: Normalized model dict with tables, columns, measures, and relationships

    Returns:
        dict: BPA results with violations, score, and recommendations
    """
    try:
        results = run_bpa_analysis(model)
        return results
    except Exception as e:
        error = handle_error(e)
        raise ValueError(f"{error.error_type}: {error.message}")


@mcp.tool()
async def audit_ai_readiness(model: dict) -> dict:
    """
    Audit a model for AI-readiness and Copilot optimization.

    Analyzes a semantic model for AI-readiness including naming conventions,
    documentation coverage, and structure that helps AI assistants understand
    the model. Returns a readiness score and specific recommendations for improvement.

    Args:
        model: Normalized model dict with tables, columns, measures, and relationships

    Returns:
        dict: AI readiness audit results with score, findings, and recommendations
    """
    try:
        results = audit_ai_readiness(model)
        return results
    except Exception as e:
        error = handle_error(e)
        raise ValueError(f"{error.error_type}: {error.message}")


# ============================================================================
# Governance Tools
# ============================================================================

@mcp.tool()
async def pre_deploy_gate(model: dict, strict: bool = True) -> dict:
    """
    Run pre-deployment gate checks on a model.

    Executes a comprehensive set of pre-deployment checks including BPA analysis,
    AI readiness audit, and custom governance rules. Returns whether the model
    passes all checks and any blocking issues that must be resolved before deployment.

    Args:
        model: Normalized model dict with tables, columns, measures, and relationships
        strict: Whether to fail on warnings (default: true)

    Returns:
        dict: Pre-deployment check results with passed status, checks, and blocking issues
    """
    try:
        # Run BPA analysis
        bpa_results = run_bpa_analysis(model)

        # Run AI readiness audit
        ai_results = audit_ai_readiness(model)

        # Determine if passed
        blocking_issues = []
        if bpa_results.get("violations"):
            blocking_issues.extend([f"BPA: {v.get('rule', 'Unknown')}" for v in bpa_results["violations"] if v.get("severity") == "error"])
        if ai_results.get("score", 100) < 70:
            blocking_issues.append("AI readiness score below 70")

        passed = len(blocking_issues) == 0 or not strict

        return {
            "passed": passed,
            "checks": {
                "bpa": bpa_results,
                "ai_readiness": ai_results
            },
            "blocking_issues": blocking_issues
        }
    except Exception as e:
        error = handle_error(e)
        raise ValueError(f"{error.error_type}: {error.message}")


@mcp.tool()
async def summarize_security_scan(scan: dict, dataset_name: Optional[str] = None) -> dict:
    """
    Summarize a security scan result.

    Processes and summarizes security scan results for a dataset, providing
    a consolidated view of security findings and recommendations.

    Args:
        scan: Security scan results to summarize
        dataset_name: Optional dataset name for context

    Returns:
        dict: Summarized security scan results
    """
    try:
        results = summarize_scan(scan, dataset_name)
        return results
    except Exception as e:
        error = handle_error(e)
        raise ValueError(f"{error.error_type}: {error.message}")


@mcp.tool()
async def aggregate_user_activity(events: list[dict]) -> dict:
    """
    Aggregate user activity events.

    Processes and aggregates user activity events to provide insights
    into usage patterns and potential security concerns.

    Args:
        events: List of user activity events to aggregate

    Returns:
        dict: Aggregated user activity insights
    """
    try:
        results = aggregate_activity(events)
        return results
    except Exception as e:
        error = handle_error(e)
        raise ValueError(f"{error.error_type}: {error.message}")


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    import sys

    # Support both stdio and SSE transports
    if len(sys.argv) > 1 and sys.argv[1] == "stdio":
        # Run with stdio transport for local access
        logger.info("Starting stdio server")
        mcp.run(transport="stdio")
    else:
        # Run with SSE transport for remote access (default)
        host = os.getenv("HOST", "0.0.0.0")
        port = int(os.getenv("PORT", "8000"))
        logger.info(f"Starting SSE server on {host}:{port}")
        mcp.run(transport="sse", host=host, port=port)
