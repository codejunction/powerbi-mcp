"""
Power BI MCP Server – FastMCP edition.
REST-only, read-only Power BI Service access.

All tools are type-safe (Pydantic I/O), async, and follow FastMCP 3.x standards.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from contextlib import asynccontextmanager
from typing import Any

from dotenv import load_dotenv
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from powerbi_rest_connector import PowerBIRestConnector
from security import SecurityLayer
from security.access_policy import AccessPolicyEngine
from models import (
    # discovery / listing
    WorkspaceInfo, DatasetInfo, TableInfo, ColumnInfo,
    # DAX execution & validation
    DaxResult, ValidationResult,
    # model exploration
    ModelSummaryResult, TableSummary,
    SemanticModelDescription, SemanticModel, TableDetail, ColumnDetail, MeasureDetail, RelationshipDetail,
    CandidateMeasure, QueryPlan, QueryPlanResult,
    # model quality
    BpaRunResult,
    AiReadinessResult,
    DaxLintResult, DaxRewrite,
    DaxRewriteResult,
    # storage & performance
    ModelStorageResult, TableStorageInfo,
    QueryPerfResult, ModelDiffResult,
    # governance & deployment
    ReferentialIntegrityResult, ReferentialViolation,
    PreDeployGateResult,
    BpaValidateResult,
    AuditIntegrityResult,
    # diagnostics & ops
    RefreshDoctorResult,
    UnusedObjectsResult,
    ImpactAnalysisResult, DependentObject,
    DaxTestRunResult, DaxTestCaseResult,
    # fleet / governance ops
    CrossWorkspaceLineageResult,
    FleetRefreshResult, RefreshFailure,
    UsageAnalyticsResult,
    # security & audit
    SecurityStatus, AuditEvent,
    # DAX generation
    MeasureDefinition,
)
from errors import handle_error
import dax_generator
import model_analysis
import dax_lint as _dax_lint_mod
import bpa_authoring as _bpa_authoring_mod
import refresh_diagnostics as _refresh_diag_mod
from governance import summarize_scan, aggregate_activity
from model_analysis import run_bpa as run_bpa_fn, audit_ai_readiness as ai_readiness_fn

load_dotenv()

logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO")),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("powerbi-mcp")


# ============================================================================
# Application context
# ============================================================================

class AppContext(BaseModel):
    """Holds live connectors for the duration of a server session."""
    model_config = {"arbitrary_types_allowed": True}

    rest_connector: PowerBIRestConnector | None = None
    security: SecurityLayer | None = None


_app_context: AppContext | None = None


@asynccontextmanager
async def app_lifespan(mcp: FastMCP):
    global _app_context
    logger.info("Initializing Power BI MCP Server")

    tenant_id = os.getenv("TENANT_ID", "")
    client_id = os.getenv("CLIENT_ID", "")
    client_secret = os.getenv("CLIENT_SECRET", "")

    conn: PowerBIRestConnector | None = None
    if tenant_id and client_id and client_secret:
        try:
            conn = PowerBIRestConnector(tenant_id, client_id, client_secret)
            conn.authenticate()
            logger.info("Successfully authenticated to Power BI Service")
        except Exception as e:
            logger.error("Failed to authenticate: %s", e)

    config_path = os.path.join(os.path.dirname(__file__), "..", "config", "policies.yaml")
    security = SecurityLayer(
        config_path=config_path if os.path.exists(config_path) else None,
        enable_pii_detection=os.getenv("ENABLE_PII_DETECTION", "true").lower() == "true",
        enable_audit=os.getenv("ENABLE_AUDIT", "true").lower() == "true",
        enable_policies=os.getenv("ENABLE_POLICIES", "true").lower() == "true",
    )

    _app_context = AppContext(rest_connector=conn, security=security)
    try:
        yield _app_context
    finally:
        _app_context = None
        logger.info("Shutting down Power BI MCP Server")


mcp = FastMCP("powerbi-mcp", lifespan=app_lifespan)


# ============================================================================
# Internal helpers
# ============================================================================

def _conn() -> PowerBIRestConnector:
    """Return the live REST connector or raise."""
    if not _app_context or not _app_context.rest_connector:
        raise ValueError("REST connector not initialized – check TENANT_ID/CLIENT_ID/CLIENT_SECRET")
    return _app_context.rest_connector


def _resolve_ids(conn: PowerBIRestConnector, workspace_name: str, dataset_name: str) -> tuple[str, str]:
    """Resolve workspace + dataset names to their GUIDs. Raises ValueError if not found."""
    ws = conn.list_workspaces()
    wid = next((w["id"] for w in ws if w["name"] == workspace_name), None)
    if not wid:
        raise ValueError(f"Workspace '{workspace_name}' not found")
    ds = conn.list_datasets(wid)
    did = next((d["id"] for d in ds if d["name"] == dataset_name), None)
    if not did:
        raise ValueError(f"Dataset '{dataset_name}' not found in workspace '{workspace_name}'")
    return wid, did


def _row_get(row: dict[str, Any], *names: str) -> Any:
    """Read a field from an INFO.VIEW.* row tolerating bracket/case variants."""
    for n in names:
        for k in (n, f"[{n}]", n.lower(), f"[{n.lower()}]", n.upper(), f"[{n.upper()}]"):
            if k in row:
                return row[k]
    return None


def _norm(rows: list[dict]) -> list[dict]:
    """Strip bracket noise from INFO.VIEW.* result keys."""
    return [{str(k).strip("[]"): v for k, v in r.items()} for r in (rows or [])]





async def _gather_model(workspace_name: str, dataset_name: str) -> tuple[dict[str, Any] | None, str | None]:
    """Build a normalized model dict from INFO.VIEW.* queries. Returns (model, error)."""
    conn = _conn()
    wid, did = _resolve_ids(conn, workspace_name, dataset_name)
    run = lambda q: conn.execute_dax_query(wid, did, q)
    loop = asyncio.get_event_loop()
    g = _row_get

    try:
        tables_rows = await loop.run_in_executor(None, run, "EVALUATE INFO.VIEW.TABLES()")
        cols_rows   = await loop.run_in_executor(None, run, "EVALUATE INFO.VIEW.COLUMNS()")
        meas_rows   = await loop.run_in_executor(None, run, "EVALUATE INFO.VIEW.MEASURES()")
    except Exception as e:
        return None, f"Could not read model metadata via INFO.VIEW: {e}"

    try:
        rel_rows = await loop.run_in_executor(None, run, "EVALUATE INFO.VIEW.RELATIONSHIPS()")
    except Exception:
        rel_rows = []

    tmap: dict[str, Any] = {}
    for r in tables_rows:
        nm = g(r, "Name")
        if nm:
            tmap[nm] = {"name": nm, "is_hidden": g(r, "IsHidden"),
                        "description": g(r, "Description") or "", "columns": [], "measures": []}
    for r in cols_rows:
        tn = g(r, "Table") or ""
        tmap.setdefault(tn, {"name": tn, "is_hidden": False, "description": "", "columns": [], "measures": []})
        tmap[tn]["columns"].append({
            "name": g(r, "Name"), "table": tn, "data_type": g(r, "DataType"),
            "is_hidden": g(r, "IsHidden"), "is_key": g(r, "IsKey"),
            "summarize_by": g(r, "SummarizeBy"), "sort_by": g(r, "SortByColumn"),
            "description": g(r, "Description") or "", "display_folder": g(r, "DisplayFolder"),
            "data_category": g(r, "DataCategory"),
            "is_calculated": str(g(r, "ColumnType") or "").lower() == "calculated",
            "expression": g(r, "Expression"),
        })
    for r in meas_rows:
        tn = g(r, "Table") or ""
        tmap.setdefault(tn, {"name": tn, "is_hidden": False, "description": "", "columns": [], "measures": []})
        tmap[tn]["measures"].append({
            "name": g(r, "Name"), "table": tn, "expression": g(r, "Expression"),
            "format_string": g(r, "FormatString"), "description": g(r, "Description") or "",
            "display_folder": g(r, "DisplayFolder"), "is_hidden": g(r, "IsHidden"),
            "data_type": g(r, "DataType"),
        })
    rels = [{
        "from_table": g(r, "FromTable"), "from_column": g(r, "FromColumn"),
        "to_table": g(r, "ToTable"), "to_column": g(r, "ToColumn"),
        "is_active": g(r, "IsActive"),
        "cross_filter": g(r, "CrossFilteringBehavior", "CrossFilterDirection"),
        "from_cardinality": g(r, "FromCardinality"), "to_cardinality": g(r, "ToCardinality"),
    } for r in rel_rows]

    return {"tables": list(tmap.values()), "relationships": rels}, None


def _redact(text: Any, secret: str = "") -> str:
    s = str(text) if text is not None else ""
    for pat, repl in (
        (r"(?i)(password\s*=\s*)[^;]+", r"\1***"),
        (r"(?i)(client_secret\s*=\s*)[^;&\s]+", r"\1***"),
        (r"(?i)(\bsecret\s*=\s*)[^;&\s]+", r"\1***"),
    ):
        s = re.sub(pat, repl, s)
    if secret and len(secret) >= 6:
        s = s.replace(secret, "***")
    return s


def _dax_col(table: str, column: str) -> str:
    return f"'{table.replace(chr(39), chr(39)*2)}'[{column.replace(']', ']]')}]"


def _measures_from_model(model: dict, measure_name: str | None = None) -> list[dict]:
    out = []
    for t in model.get("tables", []):
        for m in t.get("measures", []):
            if measure_name and m.get("name") != measure_name:
                continue
            out.append({"name": m.get("name"), "expression": m.get("expression") or ""})
    return out


# ============================================================================
# Prompts
# ============================================================================

@mcp.prompt()
async def optimize_measure(measure_name: str) -> str:
    """Optimize a DAX measure for better performance.

    Args:
        measure_name: The measure to optimize
    """
    return (
        f"Optimize the DAX measure [{measure_name}] in the connected model.\n"
        "1) Use analyze_query_performance on a query that exercises it to get a baseline.\n"
        "2) Use dax_lint to spot anti-patterns; dax_suggest_rewrite for concrete before/after fixes.\n"
        "3) Propose an improved expression; validate_dax it.\n"
        "4) Compare the before/after execution times with analyze_query_performance."
    )


@mcp.prompt()
async def explain_measure(measure_name: str) -> str:
    """Explain what a measure computes in plain business language.

    Args:
        measure_name: The measure to explain
    """
    return (
        f"Explain the measure [{measure_name}] in plain business language.\n"
        "Use describe_semantic_model for its DAX and model context. "
        "Describe inputs, calculation logic, filter context, and a usage example."
    )


@mcp.prompt()
async def audit_model() -> str:
    """Run a full quality and AI-readiness audit of the connected model."""
    return (
        "Audit the connected Power BI model end to end:\n"
        "1) run_bpa – note errors/warnings by category.\n"
        "2) audit_ai_readiness – descriptions/format coverage.\n"
        "3) analyze_model_storage – largest tables.\n"
        "4) scan_referential_integrity – orphan keys.\n"
        "Summarize the top issues and a prioritized remediation plan."
    )


@mcp.prompt()
async def document_model() -> str:
    """Generate human-readable documentation for the connected model."""
    return (
        "Generate documentation for the connected model.\n"
        "Use get_model_info and describe_semantic_model. "
        "Produce: overview, table-by-table (purpose, key columns), key measures (with descriptions), "
        "relationships, and any best-practice issues from run_bpa."
    )


@mcp.prompt()
async def pre_deploy_review() -> str:
    """Run a full quality gate before shipping a model/report."""
    return (
        "Run a pre-deployment quality gate on the connected model:\n"
        "1) pre_deploy_gate (fail on any BPA error).\n"
        "2) audit_ai_readiness (warn if score < 70).\n"
        "3) scan_referential_integrity (orphan keys distort totals).\n"
        "4) dax_lint (whole model) for anti-patterns.\n"
        "Summarize PASS/FAIL with blocking issues and a remediation checklist."
    )


@mcp.prompt()
async def plan_safe_rename(old_name: str, new_name: str) -> str:
    """Plan a rename that won't break visuals or downstream measures.

    Args:
        old_name: Current name
        new_name: New name
    """
    return (
        f"Plan a SAFE rename from [{old_name}] to [{new_name}].\n"
        "1) impact_analysis to see the blast radius (model dependents).\n"
        "2) Review all dependent measures before renaming.\n"
        "3) After renaming, validate_dax every dependent measure to confirm nothing broke.\n"
        "NOTE: In REST-only mode, report visual references are not auto-updated; "
        "coordinate with the report author."
    )


# ============================================================================
# Resources
# ============================================================================

@mcp.resource("powerbi://reference/bpa-rules")
async def bpa_rules_resource() -> str:
    """Built-in Best Practice Analyzer rule catalog."""
    rules = [
        {"id": r["id"], "category": r["category"], "severity": r["severity"], "name": r["name"]}
        for r in model_analysis.DEFAULT_BPA_RULES
    ]
    return json.dumps(rules, indent=2)


@mcp.resource("powerbi://reference/refresh-errors")
async def refresh_errors_resource() -> str:
    """Known refresh failure causes and fixes."""
    return json.dumps({
        "consecutive_failure_disable_threshold": _refresh_diag_mod.CONSECUTIVE_FAILURE_DISABLE_THRESHOLD,
        "rules": _refresh_diag_mod.REFRESH_ERROR_RULES,
    }, indent=2)


@mcp.resource("powerbi://cloud/{workspace}/{dataset}/schema")
async def cloud_schema(workspace: str, dataset: str) -> str:
    """Live semantic model schema via REST Execute Queries API."""
    model, err = await _gather_model(workspace, dataset)
    if err:
        return json.dumps({"error": err})
    return json.dumps(model, default=str, indent=2)


# ============================================================================
# Tools – discovery & listing
# ============================================================================

@mcp.tool()
async def list_workspaces() -> list[WorkspaceInfo]:
    """List all Power BI Service workspaces the Service Principal can access.

    Use this as the first step to discover available workspaces before calling any
    dataset-level tool. Returns workspace id, name, type, and state. Pass the id to
    list_datasets, or pass the name to any tool that accepts workspace_name.

    Returns a list of WorkspaceInfo objects with fields:
        id:    workspace GUID – required by list_datasets
        name:  display name – required by all workspace_name parameters
        type:  "Workspace" | "PersonalGroup" | etc.
        state: "Active" | "Deleted" | etc.
    """
    try:
        return [WorkspaceInfo(**ws) for ws in _conn().list_workspaces()]
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def list_datasets(workspace_id: str) -> list[DatasetInfo]:
    """List all datasets (semantic models) published to a Power BI Service workspace.

    Use this after list_workspaces to enumerate what semantic models are available.
    Returns id, name, configured_by, and is_refreshable for each dataset. Pass the
    dataset name to any tool that accepts dataset_name.

    Returns a list of DatasetInfo objects with fields:
        id:              dataset GUID
        name:            display name – used by all dataset_name parameters
        configured_by:   owner/configuring user
        is_refreshable:  whether the dataset supports scheduled refresh

    Args:
        workspace_id: Workspace GUID from list_workspaces
    """
    try:
        return [DatasetInfo(**ds) for ds in _conn().list_datasets(workspace_id)]
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def list_tables(workspace_name: str, dataset_name: str) -> list[TableInfo]:
    """List the tables in a semantic model, including hidden status.

    Queries INFO.VIEW.TABLES() via the REST Execute Queries API. Use this to discover
    valid table names before calling list_columns, execute_dax, or any tool that
    requires a table_name. Hidden tables (is_hidden=true) are included so you can
    identify them; prefer visible ones when writing DAX for end users.

    Returns a list of TableInfo objects with fields:
        name:      table name – use this in DAX and other tools
        is_hidden: whether the table is hidden from report authors

    Args:
        workspace_name: Workspace display name (from list_workspaces)
        dataset_name:   Dataset display name (from list_datasets)
    """
    try:
        conn = _conn()
        wid, did = _resolve_ids(conn, workspace_name, dataset_name)
        rows = _norm(conn.execute_dax_query(wid, did, "EVALUATE INFO.VIEW.TABLES()"))
        return [TableInfo(name=r.get("Name", ""), rows=0, is_hidden=bool(r.get("IsHidden"))) for r in rows]
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def list_columns(workspace_name: str, dataset_name: str, table_name: str) -> list[ColumnInfo]:
    """List all columns in a specific table, including data types, hidden status, and descriptions.

    Queries INFO.VIEW.COLUMNS() filtered by table name. Use this before writing DAX
    to confirm exact column names and data types. Hidden columns (is_hidden=true) are
    generally internal; visible ones are safe to reference in queries and measures.

    Returns a list of ColumnInfo objects with fields:
        name:        column name – use this verbatim in DAX: 'TableName'[ColumnName]
        data_type:   Int64, String, DateTime, Decimal, Boolean, etc.
        is_hidden:   whether hidden from report authors
        description: semantic description if set (empty string if not)

    Args:
        workspace_name: Workspace display name (from list_workspaces)
        dataset_name:   Dataset display name (from list_datasets)
        table_name:     Exact table name (from list_tables)
    """
    try:
        conn = _conn()
        wid, did = _resolve_ids(conn, workspace_name, dataset_name)
        tq = table_name.replace('"', '""')
        rows = _norm(conn.execute_dax_query(wid, did, f'EVALUATE FILTER(INFO.VIEW.COLUMNS(), [Table] = "{tq}")'))
        return [ColumnInfo(
            name=r.get("Name", ""), data_type=str(r.get("DataType", "")),
            is_hidden=bool(r.get("IsHidden")), description=r.get("Description") or None,
        ) for r in rows]
    except Exception as e:
        raise ValueError(str(handle_error(e)))


# ============================================================================
# Tools – model exploration
# ============================================================================

@mcp.tool()
async def get_model_info(workspace_name: str, dataset_name: str) -> ModelSummaryResult:
    """Return a compact structural overview of a semantic model: tables, measure counts, and relationships.

    Lighter-weight than describe_semantic_model – use this to quickly size a model and
    see which tables carry measures before drilling in. For full measure expressions,
    descriptions, and column detail use describe_semantic_model instead.

    Returns a dict with:
        dataset:       dataset name
        workspace:     workspace name
        tables:        list of {name, columns (int), measures (int), top_measures (list[str])}
                       – only visible (non-hidden) tables are included
        relationships: total relationship count

    Args:
        workspace_name: Workspace display name (from list_workspaces)
        dataset_name:   Dataset display name (from list_datasets)
    """
    try:
        model, err = await _gather_model(workspace_name, dataset_name)
        if err:
            raise ValueError(err)
        visible = [t for t in model["tables"] if not model_analysis._truthy(t.get("is_hidden"))]
        return ModelSummaryResult(
            dataset=dataset_name,
            workspace=workspace_name,
            tables=[
                TableSummary(
                    name=t["name"],
                    columns=len(t.get("columns", [])),
                    measures=len(t.get("measures", [])),
                    top_measures=[m["name"] for m in t.get("measures", [])[:10] if m.get("name")],
                )
                for t in visible
            ],
            relationships=len(model.get("relationships", [])),
        )
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def describe_semantic_model(workspace_name: str, dataset_name: str) -> SemanticModelDescription:
    """Build a complete agent-ready semantic map of a Power BI model: tables, columns, measures, relationships.

    ALWAYS call this (or get_model_info) before writing DAX or answering business questions
    so you use real, verified table/column/measure names. Returns the full model structure
    including every measure's DAX expression, format string, and description.

    Returns a dict with:
        model.tables:        list of tables, each with columns[] and measures[] (including
                             expression, format_string, description, is_hidden)
        model.relationships: list of {from_table, from_column, to_table, to_column, is_active}
        summary:             human-readable count of visible tables, measures, and relationships
        guidance:            agent workflow tips (prefer existing measures, use descriptions, etc.)

    Use answer_query_plan afterwards to match a user question to a specific measure.

    Args:
        workspace_name: Workspace display name (from list_workspaces)
        dataset_name:   Dataset display name (from list_datasets)
    """
    try:
        conn = _conn()
        wid, did = _resolve_ids(conn, workspace_name, dataset_name)
        meta = conn.get_semantic_model_metadata(wid, did)
        g = _row_get
        tables: dict[str, Any] = {}
        for r in meta.get("tables", []):
            nm = g(r, "Name")
            if nm:
                tables[nm] = {"name": nm, "is_hidden": bool(g(r, "IsHidden")),
                              "description": g(r, "Description") or "", "columns": [], "measures": []}
        for r in meta.get("columns", []):
            tn = g(r, "Table") or g(r, "TableName") or ""
            tables.setdefault(tn, {"name": tn, "is_hidden": False, "description": "", "columns": [], "measures": []})
            tables[tn]["columns"].append({
                "name": g(r, "Name"), "data_type": g(r, "DataType"),
                "is_hidden": bool(g(r, "IsHidden")), "description": g(r, "Description") or "",
            })
        for r in meta.get("measures", []):
            tn = g(r, "Table") or g(r, "TableName") or ""
            tables.setdefault(tn, {"name": tn, "is_hidden": False, "description": "", "columns": [], "measures": []})
            tables[tn]["measures"].append({
                "name": g(r, "Name"), "expression": g(r, "Expression"),
                "format_string": g(r, "FormatString"), "description": g(r, "Description") or "",
                "is_hidden": bool(g(r, "IsHidden")),
            })
        rel_models = [RelationshipDetail(
            from_table=g(r, "FromTable"), from_column=g(r, "FromColumn"),
            to_table=g(r, "ToTable"), to_column=g(r, "ToColumn"),
            is_active=g(r, "IsActive"),
        ) for r in meta.get("relationships", [])]
        table_models = [
            TableDetail(
                name=t["name"], is_hidden=t.get("is_hidden", False),
                description=t.get("description", ""),
                columns=[ColumnDetail(**c) for c in t.get("columns", [])],
                measures=[MeasureDetail(**m) for m in t.get("measures", [])],
            )
            for t in tables.values()
        ]
        visible_tables = [t for t in table_models if not t.is_hidden]
        measures_vis = [m for t in visible_tables for m in t.measures if not m.is_hidden]
        return SemanticModelDescription(
            model=SemanticModel(dataset=dataset_name, tables=table_models, relationships=rel_models),
            summary=f"{len(visible_tables)} visible table(s), {len(measures_vis)} visible measure(s), "
                    f"{len(rel_models)} relationship(s)",
            guidance=[
                "Use visible measures first for business metrics; generate DAX only when no suitable measure exists.",
                "Use table/column descriptions and relationships to choose dimensions and filters.",
                "All query execution is read-only through the Power BI REST Execute Queries API.",
            ],
        )
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def answer_query_plan(
    workspace_name: str,
    dataset_name: str,
    question: str,
    execute: bool = False,
    max_rows: int = 100,
) -> QueryPlanResult:
    """Given a natural-language question, find matching existing measures or draft a read-only DAX query.

    Use this when a user asks a business question against a Power BI model. The tool
    keyword-scores every visible measure's name and description against the question,
    returns the top 5 candidates, and produces a ready-to-run draft DAX query. If a
    good existing measure is found, prefer it over generating new DAX. Set execute=true
    to also run the draft query and return actual rows in the same call.

    Returns a dict with:
        plan.question:            the original question
        plan.candidate_measures:  list of {table, measure, score, description} ranked by relevance
        plan.draft_dax:           a ready-to-evaluate DAX query using the best candidate
        plan.recommendation:      "use_existing_measure" | "generate_exploratory_dax"
        rows:                     query results if execute=true, otherwise []

    Args:
        workspace_name: Workspace display name (from list_workspaces)
        dataset_name:   Dataset display name (from list_datasets)
        question:       Natural-language business question, e.g. "What is total revenue by region?"
        execute:        Also run the draft DAX and return rows (default: false)
        max_rows:       Row cap when execute=true (default: 100)
    """
    try:
        sem = await describe_semantic_model(workspace_name, dataset_name)
        model = sem.model
        qwords = {w.lower() for w in re.findall(r"[A-Za-z0-9_]+", question) if len(w) > 2}
        raw_candidates: list[dict[str, Any]] = []
        for table in model.tables:
            for m in table.measures:
                hay = " ".join([m.name or "", m.description or "", table.name or ""]).lower()
                score = sum(1 for w in qwords if w in hay)
                if score:
                    raw_candidates.append({"table": table.name, "measure": m.name,
                                           "score": score, "description": m.description})
        raw_candidates.sort(key=lambda x: x["score"], reverse=True)
        chosen = raw_candidates[:5]
        if chosen:
            draft_dax = f'EVALUATE ROW("{chosen[0]["measure"]}", [{chosen[0]["measure"]}])'
        else:
            first = next((t for t in model.tables if not t.is_hidden), None)
            draft_dax = f"EVALUATE TOPN({max_rows}, '{first.name}')" if first else None
        rows: list[dict[str, Any]] = []
        if execute and draft_dax:
            conn = _conn()
            wid, did = _resolve_ids(conn, workspace_name, dataset_name)
            rows = conn.execute_dax_query(wid, did, draft_dax)[:max_rows]
        return QueryPlanResult(
            plan=QueryPlan(
                question=question,
                candidate_measures=[CandidateMeasure(**c) for c in chosen],
                draft_dax=draft_dax,
                recommendation="use_existing_measure" if chosen else "generate_exploratory_dax",
            ),
            rows=rows,
        )
    except Exception as e:
        raise ValueError(str(handle_error(e)))


# ============================================================================
# Tools – DAX execution & validation
# ============================================================================

@mcp.tool()
async def execute_dax(
    workspace_name: str,
    dataset_name: str,
    dax_query: str,
    max_rows: int = 10000,
) -> DaxResult:
    """Execute a read-only DAX query against a Power BI semantic model and return rows.

    Runs the query through the REST Execute Queries API (XMLA read endpoint). Security
    policies are applied before execution (column blocking, row limits) and after
    (PII detection and masking). Always call validate_dax first if you are unsure
    whether a query is syntactically valid. Prefer using existing measures surfaced by
    answer_query_plan or describe_semantic_model over generating new DAX from scratch.

    DAX must start with EVALUATE or DEFINE … EVALUATE. Examples:
        "EVALUATE TOPN(10, Sales)"
        "EVALUATE SUMMARIZECOLUMNS('Date'[Year], \"Total\", [Total Revenue])"

    Returns a DaxResult with:
        rows:              list of row dicts, each key is a column name
        row_count:         number of rows returned (after truncation)
        execution_time_ms: wall-clock query time in milliseconds
        truncated:         true if the result was capped at max_rows

    Args:
        workspace_name: Workspace display name (from list_workspaces)
        dataset_name:   Dataset display name (from list_datasets)
        dax_query:      A valid DAX query starting with EVALUATE or DEFINE
        max_rows:       Maximum rows to return; default 10 000, hard cap 100 000
    """
    try:
        conn = _conn()
        sec = _app_context.security if _app_context else None

        if sec:
            ref_tables, ref_cols = AccessPolicyEngine.extract_references(dax_query)
            check = sec.pre_query_check(dax_query, tables=ref_tables, columns=ref_cols)
            if not check.allowed:
                raise ValueError(f"Query blocked by security policy: {check.reason}")
            cap = min(check.max_rows or max_rows, 100_000)
        else:
            cap = min(max_rows, 100_000)

        wid, did = _resolve_ids(conn, workspace_name, dataset_name)
        t0 = time.monotonic()
        rows = conn.execute_dax_query(wid, did, dax_query)
        ms = (time.monotonic() - t0) * 1000

        truncated = len(rows) > cap
        rows = rows[:cap]

        if sec:
            rows, _ = sec.process_results(rows, query=dax_query, source="cloud",
                                           model_name=dataset_name, duration_ms=ms)

        return DaxResult(
            rows=rows,
            execution_time_ms=ms,
            row_count=len(rows),
            truncated=truncated,
        )
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def validate_dax(
    workspace_name: str,
    dataset_name: str,
    dax: str,
    as_measure: bool = False,
) -> ValidationResult:
    """Validate a DAX query or scalar measure expression against the live model engine.

    Sends a minimal probe query to the Analysis Services engine and reports whether it
    parses and evaluates without error. Use this before committing any new or edited
    measure expression. Pass the raw scalar expression (not wrapped in EVALUATE) and
    set as_measure=true for measure bodies; pass a full EVALUATE … query for queries.

    Returns a ValidationResult with:
        valid: true if the DAX is syntactically and semantically correct
        error: engine error message if valid=false (null otherwise)
        probe: the exact DAX probe that was submitted to the engine

    Args:
        workspace_name: Workspace display name (from list_workspaces)
        dataset_name:   Dataset display name (from list_datasets)
        dax:            Full DAX query (starting with EVALUATE/DEFINE) or a scalar expression
        as_measure:     Set true for raw scalar expressions like "SUMX(Sales, Sales[Amount])"
                        – wraps them in EVALUATE ROW(...) automatically (default: false)
    """
    stripped = (dax or "").strip()
    upper = stripped.upper()
    if as_measure or not (upper.startswith("EVALUATE") or upper.startswith("DEFINE")):
        probe = f'EVALUATE ROW("validation", {stripped})'
    else:
        probe = stripped
    try:
        conn = _conn()
        wid, did = _resolve_ids(conn, workspace_name, dataset_name)
        # execute_dax_query raises on HTTP error (invalid DAX → 400); execute_dax swallows
        conn.execute_dax_query(wid, did, probe)
        return ValidationResult(valid=True, probe=probe)
    except Exception as e:
        return ValidationResult(valid=False, error=_redact(str(e)), probe=probe)


# ============================================================================
# Tools – model quality & BPA
# ============================================================================

@mcp.tool()
async def run_bpa(
    workspace_name: str,
    dataset_name: str,
    categories: list[str] | None = None,
    min_severity: str = "info",
) -> BpaRunResult:
    """Run the built-in Best Practice Analyzer rules against a live semantic model.

    Fetches the full model metadata via INFO.VIEW.* and runs all BPA rules, reporting
    findings by rule, severity, and category. Use this as the first step in the
    audit_model or pre_deploy_review workflows to surface structural, DAX, and
    formatting issues before they reach production.

    Available rule categories: DAX, Formatting, Performance, Maintenance, Error Prevention.
    The full rule catalog is available as the resource powerbi://reference/bpa-rules.

    Returns a dict with:
        summary.total:       total number of findings
        summary.by_severity: {"error": n, "warning": n, "info": n}
        summary.by_category: per-category counts
        findings:            list of {rule_id, name, severity, category, object, detail}
                             where object is the table/measure/column that violated the rule

    Args:
        workspace_name: Workspace display name (from list_workspaces)
        dataset_name:   Dataset display name (from list_datasets)
        categories:     Restrict to these categories only, e.g. ["DAX", "Performance"]
        min_severity:   Lowest severity to include: info | warning | error (default: info)
    """
    try:
        model, err = await _gather_model(workspace_name, dataset_name)
        if err:
            raise ValueError(err)
        return run_bpa_fn(model, categories=categories, min_severity=min_severity)
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def audit_ai_readiness(workspace_name: str, dataset_name: str) -> AiReadinessResult:
    """Score a semantic model's readiness for AI/Copilot workloads (0–100).

    Evaluates description coverage for measures, columns, and tables, plus format string
    coverage for measures. Copilot and language-model agents rely heavily on these
    descriptions to map user questions to the right fields. A score below 70 is a
    warning; below 40 means most AI answers will be unreliable. Use the recommendations
    list to prioritize what to document first.

    Returns a dict with:
        score:          0–100 composite score
        grade:          letter grade A–F
        metrics:        {measures_with_description_pct, measures_with_format_pct,
                         columns_with_description_pct, tables_with_description_pct, …}
        recommendations: prioritized list of actions to improve the score

    Args:
        workspace_name: Workspace display name (from list_workspaces)
        dataset_name:   Dataset display name (from list_datasets)
    """
    try:
        model, err = await _gather_model(workspace_name, dataset_name)
        if err:
            raise ValueError(err)
        return ai_readiness_fn(model)
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def dax_lint(
    workspace_name: str,
    dataset_name: str,
    measure_name: str | None = None,
    expression: str | None = None,
    min_severity: str = "info",
) -> DaxLintResult:
    """Static anti-pattern linter for DAX measure expressions.

    Scans for common DAX issues: unsafe division (use DIVIDE), FILTER over whole tables
    (use boolean predicates in CALCULATE), IFERROR misuse, hard-coded date literals,
    missing VAR declarations, and more. Can lint an entire model, a single named measure,
    or a raw expression string without a live model connection.

    Typical workflow: run on the whole model after initial authoring, then re-run on
    individual measures as you edit them. Follow up with dax_suggest_rewrite for
    auto-fixable before/after rewrites.

    Returns a dict with:
        summary.measures_scanned: number of expressions analysed
        summary.by_severity:      finding counts per severity level
        findings:                 list of {rule_id, severity, object, line, message, suggestion}

    Args:
        workspace_name: Workspace display name (from list_workspaces) – ignored if expression given
        dataset_name:   Dataset display name (from list_datasets) – ignored if expression given
        measure_name:   Lint only this one named measure (optional)
        expression:     Lint a raw DAX string directly, skipping the live model fetch (optional)
        min_severity:   Lowest severity to include: info | warning | error (default: info)
    """
    try:
        min_rank = _dax_lint_mod.SEVERITY_RANK.get(min_severity.lower(), 1)
        if expression:
            measures = [{"name": measure_name or "(expression)", "expression": expression}]
        else:
            model, err = await _gather_model(workspace_name, dataset_name)
            if err:
                raise ValueError(err)
            measures = _measures_from_model(model, measure_name)
        result = _dax_lint_mod.lint_measures(measures)
        if min_rank > 1:
            filtered = [f for f in result.findings
                        if _dax_lint_mod.SEVERITY_RANK.get(f.severity, 0) >= min_rank]
            return DaxLintResult(summary=result.summary, findings=filtered)
        return result
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def dax_suggest_rewrite(
    workspace_name: str,
    dataset_name: str,
    measure_name: str | None = None,
    expression: str | None = None,
) -> DaxRewriteResult:
    """Generate concrete before/after rewrite pairs for auto-fixable DAX anti-patterns.

    Companion to dax_lint: where dax_lint flags issues, this tool produces the exact
    replacement snippet you can drop in. Only covers patterns where a mechanical
    safe substitution exists (e.g. "x / y" → "DIVIDE(x, y, 0)"). Present these to
    the user for review before applying; they are not automatically committed.

    Returns a dict with:
        count:    total number of rewrite suggestions
        rewrites: list of {rule_id, line, before (original snippet), after (fixed snippet),
                  note (why this change is safe), object (measure name if from live model)}

    Args:
        workspace_name: Workspace display name (from list_workspaces) – ignored if expression given
        dataset_name:   Dataset display name (from list_datasets) – ignored if expression given
        measure_name:   Rewrite only this named measure (optional)
        expression:     Rewrite a raw DAX string directly (optional)
    """
    try:
        rewrites: list[DaxRewrite] = []
        if expression:
            rewrites = _dax_lint_mod.suggest_rewrites(measure_name or "(expression)", expression)
        else:
            model, err = await _gather_model(workspace_name, dataset_name)
            if err:
                raise ValueError(err)
            for m in _measures_from_model(model, measure_name):
                rewrites.extend(_dax_lint_mod.suggest_rewrites(m["name"], m["expression"]))
        return DaxRewriteResult(rewrites=rewrites, count=len(rewrites))
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def analyze_model_storage(workspace_name: str, dataset_name: str) -> ModelStorageResult:
    """Analyse per-table row counts to identify the largest fact tables in a semantic model.

    Issues a COUNTROWS DAX query per visible table and sorts the results largest-first.
    Use this to understand model scale, find unexpectedly large tables, and decide where
    to focus aggregation or partition strategies. VertiPaq byte-level sizes are not
    available in REST-only mode; use DAX Studio for column-level compression stats.

    Returns a dict with:
        table_count: number of visible tables
        total_rows:  sum of all visible-table row counts
        tables:      list (up to 50, sorted by row_count desc) of
                     {name, row_count, column_count, measure_count}
                     row_count is null if COUNTROWS failed for a table

    Args:
        workspace_name: Workspace display name (from list_workspaces)
        dataset_name:   Dataset display name (from list_datasets)
    """
    try:
        conn = _conn()
        wid, did = _resolve_ids(conn, workspace_name, dataset_name)
        run = lambda q: conn.execute_dax_query(wid, did, q)
        loop = asyncio.get_event_loop()

        model, err = await _gather_model(workspace_name, dataset_name)
        if err:
            raise ValueError(err)

        visible = [t for t in model["tables"] if not model_analysis._truthy(t.get("is_hidden"))]
        rows_by_table: dict[str, int | None] = {}
        for t in visible:
            nm = t["name"]
            try:
                res = await loop.run_in_executor(None, run, f"EVALUATE ROW(\"r\", COUNTROWS('{nm}'))")
                val = next(iter(res[0].values()), None) if res else None
                rows_by_table[nm] = int(val) if val is not None else None
            except Exception:
                rows_by_table[nm] = None

        ranked = sorted(visible, key=lambda t: (rows_by_table.get(t["name"]) or 0), reverse=True)
        return ModelStorageResult(
            table_count=len(visible),
            total_rows=sum(v for v in rows_by_table.values() if v),
            tables=[
                TableStorageInfo(
                    name=t["name"],
                    row_count=rows_by_table.get(t["name"]),
                    column_count=len(t.get("columns", [])),
                    measure_count=len(t.get("measures", [])),
                )
                for t in ranked[:50]
            ],
        )
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def analyze_query_performance(
    workspace_name: str,
    dataset_name: str,
    dax: str,
) -> QueryPerfResult:
    """Time a DAX query end-to-end and surface heuristic optimization hints.

    Executes the query, measures wall-clock duration, and applies static pattern checks
    to generate actionable hints. Use this before and after optimizing a measure to
    establish a performance baseline and confirm improvement. For deep storage-engine
    vs formula-engine breakdown, use DAX Studio Server Timings directly.

    Returns a dict with:
        duration_ms: end-to-end execution time in milliseconds
        row_count:   number of rows returned
        hints:       list of optimization advice strings, e.g. slow-query warning,
                     large-result warning, FILTER() overuse, SUMMARIZE+ADDCOLUMNS pattern

    Args:
        workspace_name: Workspace display name (from list_workspaces)
        dataset_name:   Dataset display name (from list_datasets)
        dax:            A valid DAX query (must start with EVALUATE or DEFINE)
    """
    try:
        conn = _conn()
        wid, did = _resolve_ids(conn, workspace_name, dataset_name)
        loop = asyncio.get_event_loop()
        t0 = time.monotonic()
        rows = await loop.run_in_executor(None, conn.execute_dax_query, wid, did, dax)
        ms = (time.monotonic() - t0) * 1000
        row_count = len(rows) if isinstance(rows, list) else 0

        hints = []
        up = dax.upper()
        if ms > 2000:
            hints.append(f"Slow ({ms:.0f} ms). Check relationship cardinality and avoid row-by-row iterators over large fact tables.")
        if row_count > 10_000:
            hints.append(f"Large result ({row_count:,} rows). Add TOPN / SUMMARIZECOLUMNS filters.")
        if up.count("FILTER(") >= 3:
            hints.append("Multiple FILTER() calls; prefer CALCULATE with boolean filters or KEEPFILTERS where possible.")
        if "ADDCOLUMNS(" in up and "SUMMARIZE(" in up:
            hints.append("SUMMARIZE+ADDCOLUMNS pattern; SUMMARIZECOLUMNS is usually faster and safer.")
        if not hints:
            hints.append("No obvious red flags. For storage-engine vs formula-engine timings, use DAX Studio Server Timings.")

        return QueryPerfResult(duration_ms=round(ms, 1), row_count=row_count, hints=hints)
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def model_diff(
    workspace_name: str,
    dataset_name: str,
    baseline_path: str,
) -> ModelDiffResult:
    """Compare a saved model snapshot against the current live model and report changes.

    Loads a JSON baseline (saved by serialising the output of get_model_info/describe_semantic_model
    to disk) and diffs it against the live model fetched now. Reports added/removed/changed
    tables, columns, measures, and relationships. Useful for change-review before a release
    or after an unexpected model change.

    To create a baseline: call describe_semantic_model, save the "model" key as JSON,
    then pass that file path as baseline_path when you want to compare later.

    Returns a dict with:
        markdown:           human-readable diff summary in Markdown
        added_tables:       list of new table names
        removed_tables:     list of removed table names
        changed_tables:     list of table names with column/measure changes
        added_measures:     list of {table, name} for new measures
        removed_measures:   list of {table, name} for removed measures
        changed_measures:   list of {table, name, before_expr, after_expr}

    Args:
        workspace_name: Workspace display name (from list_workspaces)
        dataset_name:   Dataset display name (from list_datasets)
        baseline_path:  Absolute path to a JSON file containing a previously saved model dict
    """
    try:
        with open(baseline_path, encoding="utf-8") as f:
            before = json.load(f)
        after, err = await _gather_model(workspace_name, dataset_name)
        if err:
            raise ValueError(err)
        return model_analysis.diff_models(before, after)
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def scan_referential_integrity(
    workspace_name: str,
    dataset_name: str,
    max_samples: int = 5,
) -> ReferentialIntegrityResult:
    """Check every active relationship for orphan keys that would land in the blank row.

    For each active relationship, executes EXCEPT(DISTINCT(fact[FK]), DISTINCT(dim[PK]))
    to count fact keys with no matching dimension row. Orphan keys silently appear in
    Power BI's hidden blank row and distort totals and ratios. Include this in the
    pre_deploy_review workflow before publishing a model.

    Returns a dict with:
        checked:    number of active relationships evaluated
        clean:      true if no orphan-key violations were found
        violations: list of objects per violating relationship:
            relationship: "FactTable[FK] -> DimTable[PK]" notation
            orphan_keys:  count of missing dimension keys
            samples:      up to max_samples example orphan key values
            error:        set instead of orphan_keys if the check query failed

    Args:
        workspace_name: Workspace display name (from list_workspaces)
        dataset_name:   Dataset display name (from list_datasets)
        max_samples:    How many example orphan keys to show per violation (default: 5, max: 100)
    """
    try:
        conn = _conn()
        wid, did = _resolve_ids(conn, workspace_name, dataset_name)
        run = lambda q: conn.execute_dax_query(wid, did, q)
        loop = asyncio.get_event_loop()
        model, err = await _gather_model(workspace_name, dataset_name)
        if err:
            raise ValueError(err)
        n = max(1, min(100, max_samples))
        checked, violations = 0, []
        for r in model.get("relationships", []):
            ft, fc, tt, tc = r.get("from_table"), r.get("from_column"), r.get("to_table"), r.get("to_column")
            if not all([ft, fc, tt, tc]):
                continue
            active = r.get("is_active", True)
            if isinstance(active, str):
                active = active.strip().lower() in ("true", "1", "yes")
            if not active:
                continue
            fcol, tcol = _dax_col(ft, fc), _dax_col(tt, tc)
            try:
                res = await loop.run_in_executor(None, run,
                    f"EVALUATE ROW(\"Orphans\", COUNTROWS(EXCEPT(DISTINCT({fcol}), DISTINCT({tcol}))))")
                count = int(list(res[0].values())[0] or 0) if res else 0
            except Exception as qe:
                violations.append({"relationship": f"{ft}[{fc}] -> {tt}[{tc}]", "error": str(qe)})
                continue
            checked += 1
            if count > 0:
                samples: list = []
                try:
                    sr = await loop.run_in_executor(None, run,
                        f"EVALUATE TOPN({n}, EXCEPT(DISTINCT({fcol}), DISTINCT({tcol})))")
                    samples = [list(x.values())[0] for x in (sr or [])]
                except Exception:
                    pass
                violations.append({"relationship": f"{ft}[{fc}] -> {tt}[{tc}]",
                                   "orphan_keys": count, "samples": samples})
        clean = len([v for v in violations if v.get("orphan_keys", 0) > 0]) == 0
        return ReferentialIntegrityResult(
            checked=checked,
            violations=[ReferentialViolation(**v) for v in violations],
            clean=clean,
        )
    except Exception as e:
        raise ValueError(str(handle_error(e)))


# ============================================================================
# Tools – governance & deployment
# ============================================================================

@mcp.tool()
async def pre_deploy_gate(
    workspace_name: str,
    dataset_name: str,
    min_ai_score: int = 60,
    block_on_warnings: bool = False,
) -> PreDeployGateResult:
    """Run a combined BPA + AI-readiness quality gate and return a machine-readable PASS/FAIL.

    Fetches the live model, runs the Best Practice Analyzer and the AI-readiness audit,
    and applies the configured thresholds to produce a single passed boolean. Use this
    in CI/deployment pipelines or as a final check before promoting a model to production.
    For interactive review use run_bpa and audit_ai_readiness separately.

    PASS conditions (all must hold):
      1. Zero BPA findings at error severity
      2. AI-readiness score >= min_ai_score
      3. If block_on_warnings=true: zero BPA warnings too

    Returns a dict with:
        passed:       true if all gate conditions are met
        bpa_errors:   count of error-severity BPA findings
        bpa_warnings: count of warning-severity BPA findings
        ai_score:     AI-readiness score (0–100)
        blocking:     list of "rule_id: object" strings for the blocking errors

    Args:
        workspace_name:    Workspace display name (from list_workspaces)
        dataset_name:      Dataset display name (from list_datasets)
        min_ai_score:      Minimum AI-readiness score to pass, 0–100 (default: 60)
        block_on_warnings: Block the gate on BPA warnings too (default: false)
    """
    try:
        model, err = await _gather_model(workspace_name, dataset_name)
        if err:
            raise ValueError(err)
        bpa = run_bpa_fn(model)
        ai = ai_readiness_fn(model)
        errors = [f for f in bpa["findings"] if f["severity"] == "error"]
        warnings = [f for f in bpa["findings"] if f["severity"] == "warning"]
        passed = (
            len(errors) == 0
            and ai["score"] >= min_ai_score
            and (not block_on_warnings or len(warnings) == 0)
        )
        return PreDeployGateResult(
            passed=passed,
            bpa_errors=len(errors),
            bpa_warnings=len(warnings),
            ai_score=ai["score"],
            blocking=[f"{f['rule_id']}: {f['object']}" for f in errors],
        )
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def bpa_validate_rules(
    rules: str,
    fix: bool = False,
) -> BpaValidateResult:
    """Validate a custom BPA rules JSON for structural and schema correctness.

    Use this before deploying custom BPA rules to catch missing required fields,
    invalid expression syntax, duplicate rule IDs, and unsupported operators. Each
    BPA rule object requires: id (string), name (string), severity (error|warning|info),
    category (string), and condition (Python-style expression evaluated against a table,
    column, or measure dict).

    Returns a dict with:
        valid:      true only if there are zero errors (warnings are acceptable)
        rule_count: number of rule objects parsed
        errors:     list of {rule_id, index, message} for blocking issues
        warnings:   list of {rule_id, index, message} for non-blocking issues
        fixed_json: corrected JSON string (only present when fix=true and fixes were applied)

    Args:
        rules: JSON string containing an array of BPA rule objects
        fix:   Attempt to auto-correct minor issues like missing fields (default: false)
    """
    try:
        return _bpa_authoring_mod.validate_rules(rules, fix=fix)
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def verify_audit_integrity() -> AuditIntegrityResult:
    """Verify that the SHA-256 hash chain of the security audit log has not been tampered with.

    The audit log appends a running hash chain so any retroactive edit breaks all
    subsequent entries. Use this periodically or after a suspected security incident
    to confirm log integrity. An INTACT result means no entries have been altered or
    deleted; TAMPERED means the chain is broken and the log may have been modified.

    Returns a dict with:
        valid:        true if the hash chain is intact
        checked:      number of log entries verified
        message:      human-readable verdict
        broken_line:  line number where the chain first breaks (only if valid=false)
    """
    try:
        if not _app_context or not _app_context.security:
            return AuditIntegrityResult(valid=True, checked=0, message="Security layer not active.")
        return _app_context.security.verify_audit_integrity()
    except Exception as e:
        raise ValueError(str(handle_error(e)))


# ============================================================================
# Tools – diagnostics & ops
# ============================================================================

@mcp.tool()
async def refresh_doctor(workspace_name: str, dataset_name: str, history_count: int = 10) -> RefreshDoctorResult:
    """Diagnose dataset refresh failures by fetching history and classifying the root cause.

    Retrieves up to history_count refresh attempts from the REST API, identifies failures,
    and maps the serviceExceptionJson error text to a known cause + remediation pair.
    Use this whenever a dataset's scheduled refresh is failing or a user reports stale data.
    Power BI auto-disables a scheduled refresh after 4 consecutive failures.

    Common failure causes surfaced: credential expiry, gateway offline, data source
    unreachable, capacity throttling, row-level security mismatch, and transient timeouts.
    The full error rule catalog is at powerbi://reference/refresh-errors.

    Returns a dict with:
        completed:           count of Completed refreshes in the window
        failed:              count of Failed refreshes in the window
        consecutive_failures: leading consecutive failure count (triggers auto-disable warning at 3)
        most_recent_status:  status string of the latest refresh
        most_recent_end:     ISO timestamp of the latest refresh end
        diagnosis:           {cause, remediation} for the most recent failure (null if none)
        warning:             auto-disable warning string if consecutive_failures >= 3 (else null)

    Args:
        workspace_name: Workspace display name (from list_workspaces)
        dataset_name:   Dataset display name (from list_datasets)
        history_count:  Number of recent refresh records to examine (default: 10, max ~30 days)
    """
    try:
        conn = _conn()
        loop = asyncio.get_event_loop()
        wid, did, err = await loop.run_in_executor(None, conn.resolve_dataset, workspace_name, dataset_name)
        if err:
            raise ValueError(err)
        history = await loop.run_in_executor(None, conn.get_refresh_history, wid, did, history_count)
        if not history:
            return RefreshDoctorResult(completed=0, failed=0, consecutive_failures=0,
                                       most_recent_status=None, most_recent_end=None,
                                       warning="No refresh history found (dataset may never have refreshed, or history expired ~30 days).")

        completed = sum(1 for h in history if str(h.get("status")) == "Completed")
        failed = [h for h in history if str(h.get("status")) == "Failed"]
        consecutive = 0
        for h in history:
            s = str(h.get("status"))
            if s == "Failed":
                consecutive += 1
            elif s in ("Completed", "Disabled"):
                break

        diag_raw = None
        if failed:
            err_text = failed[0].get("serviceExceptionJson") or ""
            diag_raw = _refresh_diag_mod.classify_refresh_error(err_text)

        return RefreshDoctorResult(
            completed=completed,
            failed=len(failed),
            consecutive_failures=consecutive,
            most_recent_status=history[0].get("status"),
            most_recent_end=history[0].get("endTime"),
            diagnosis=diag_raw,
            warning=(
                f"{consecutive} consecutive failure(s). Power BI auto-disables a refresh schedule "
                f"after {_refresh_diag_mod.CONSECUTIVE_FAILURE_DISABLE_THRESHOLD} consecutive failures."
                if consecutive >= _refresh_diag_mod.CONSECUTIVE_FAILURE_DISABLE_THRESHOLD - 1 else None
            ),
        )
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def find_unused_objects(workspace_name: str, dataset_name: str) -> UnusedObjectsResult:
    """Identify measures and columns not referenced by any other model calculation.

    Queries INFO.CALCDEPENDENCY() to find all referenced objects, then reports everything
    that is neither referenced by another measure nor involved in a relationship. Use
    this during a model cleanup sprint to safely remove dead weight before publishing.

    IMPORTANT LIMITATION: INFO.CALCDEPENDENCY requires write permission on the model.
    In REST read-only mode this tool returns an error dict instead of results. Also,
    report visual usage is not checked – objects used only by report visuals (not by
    other model objects) will appear unused and should not be deleted without confirming
    with the report author.

    Returns a dict with:
        unused_measures:   list of "Table[Measure]" strings for unreferenced measures
        unused_columns:    list of "Table[Column]" strings for unreferenced columns
        note:              reminder about the report-visual limitation
        error:             present instead of the above if INFO.CALCDEPENDENCY is unavailable

    Args:
        workspace_name: Workspace display name (from list_workspaces)
        dataset_name:   Dataset display name (from list_datasets)
    """
    try:
        conn = _conn()
        wid, did = _resolve_ids(conn, workspace_name, dataset_name)
        run = lambda q: conn.execute_dax_query(wid, did, q)
        loop = asyncio.get_event_loop()
        model, err = await _gather_model(workspace_name, dataset_name)
        if err:
            raise ValueError(err)
        try:
            dep_rows = await loop.run_in_executor(None, run, "EVALUATE INFO.CALCDEPENDENCY()")
        except Exception as e:
            return UnusedObjectsResult(
                error=(
                    f"INFO.CALCDEPENDENCY unavailable: {e}. "
                    "This DMV needs write permission on the model (not available in REST read-only mode)."
                ),
            )
        used: set[tuple[str, str]] = set()
        for r in dep_rows:
            rt = _row_get(r, "REFERENCED_TABLE")
            ro = _row_get(r, "REFERENCED_OBJECT")
            if rt and ro:
                used.add((str(rt), str(ro)))
        for rel in model.get("relationships", []):
            if rel.get("from_table") and rel.get("from_column"):
                used.add((rel["from_table"], rel["from_column"]))
            if rel.get("to_table") and rel.get("to_column"):
                used.add((rel["to_table"], rel["to_column"]))
        unused_cols, unused_measures = [], []
        for t in model.get("tables", []):
            tn = t.get("name")
            for c in t.get("columns", []):
                if (tn, c.get("name")) not in used:
                    unused_cols.append(f"{tn}[{c.get('name')}]")
            for m in t.get("measures", []):
                if (tn, m.get("name")) not in used:
                    unused_measures.append(f"{tn}[{m.get('name')}]")
        return UnusedObjectsResult(
            unused_measures=unused_cols[:200],
            unused_columns=unused_measures[:200],
            note="Report visual usage is NOT checked in REST-only mode.",
        )
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def impact_analysis(
    workspace_name: str,
    dataset_name: str,
    object_name: str,
    table_name: str | None = None,
) -> ImpactAnalysisResult:
    """Find all model objects that depend on a given measure or column (blast radius analysis).

    Queries INFO.CALCDEPENDENCY() to list every measure and calculated column that
    references the named object, directly or transitively. Run this before renaming,
    editing, or deleting any measure or column to understand what could break. When
    safe_to_change=true, nothing in the model references the object (though report
    visuals are not checked in REST-only mode).

    LIMITATION: INFO.CALCDEPENDENCY requires write permission on the model. In REST
    read-only mode an error dict is returned instead of dependency results.

    Returns a dict with:
        object_name:     the queried object name
        table_name:      the table scope used (if provided)
        dependent_count: number of objects that reference this one
        dependents:      list of {type, table, object} for each dependent
        safe_to_change:  true if dependent_count == 0 (no model-level dependents)
        error:           present instead of the above if INFO.CALCDEPENDENCY is unavailable

    Args:
        workspace_name: Workspace display name (from list_workspaces)
        dataset_name:   Dataset display name (from list_datasets)
        object_name:    Measure or column name to analyse, e.g. "Total Revenue" or "Date"
        table_name:     Restrict the search to this table to avoid ambiguous names (optional)
    """
    try:
        conn = _conn()
        wid, did = _resolve_ids(conn, workspace_name, dataset_name)
        run = lambda q: conn.execute_dax_query(wid, did, q)
        loop = asyncio.get_event_loop()
        esc = object_name.replace('"', '""')
        filt = f'[REFERENCED_OBJECT] = "{esc}"'
        if table_name:
            et = table_name.replace('"', '""')
            filt = f'[REFERENCED_TABLE] = "{et}" && {filt}'
        try:
            rows = await loop.run_in_executor(None, run, f"EVALUATE FILTER(INFO.CALCDEPENDENCY(), {filt})")
        except Exception as e:
            # INFO.CALCDEPENDENCY requires write permission; return a graceful error model
            return ImpactAnalysisResult(
                object_name=object_name,
                table_name=table_name,
                error=(
                    f"INFO.CALCDEPENDENCY unavailable: {e}. "
                    "This DMV needs write permission on the model (not available in REST read-only mode)."
                ),
            )
        dependents = [
            DependentObject(
                type=_row_get(r, "OBJECT_TYPE"),
                table=_row_get(r, "TABLE"),
                object=_row_get(r, "OBJECT"),
            )
            for r in rows[:200]
        ]
        return ImpactAnalysisResult(
            object_name=object_name,
            table_name=table_name,
            dependent_count=len(dependents),
            dependents=dependents,
            safe_to_change=len(dependents) == 0,
        )
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def run_dax_tests(
    workspace_name: str,
    dataset_name: str,
    tests: list[dict],
) -> DaxTestRunResult:
    """Execute a list of DAX regression tests and compare results to expected values.

    Each test executes a DAX expression and optionally asserts its scalar result equals
    an expected value within an optional numeric tolerance. Tests without an "expected"
    key run in INFO mode (result is reported but not graded). Use this to build a
    regression suite that catches accidental measure breaks after model changes.

    Each test dict schema:
        name      (str, optional):   human label shown in results
        dax       (str, required):   DAX query returning a single scalar value, e.g.
                                     'EVALUATE ROW("v", [Total Revenue])'
        expected  (any, optional):   expected scalar value; omit to run without assertion
        tolerance (float, optional): absolute numeric tolerance for float comparisons (default: 0)

    Returns a dict with:
        passed:     count of tests that returned the expected value
        total:      count of tests with an expected value (PASS/FAIL, not INFO)
        all_passed: true if passed == total and total > 0
        results:    list of {name, status (PASS|FAIL|INFO|ERROR), detail}

    Args:
        workspace_name: Workspace display name (from list_workspaces)
        dataset_name:   Dataset display name (from list_datasets)
        tests:          List of test case dicts (see schema above)
    """
    try:
        conn = _conn()
        wid, did = _resolve_ids(conn, workspace_name, dataset_name)
        run = lambda q: conn.execute_dax_query(wid, did, q)
        loop = asyncio.get_event_loop()

        results = []
        passed = 0
        for t in tests:
            name = t.get("name", (t.get("dax") or "test")[:40])
            dq = t.get("dax")
            if not dq:
                results.append({"name": name, "status": "ERROR", "detail": "no dax"})
                continue
            try:
                rows = await loop.run_in_executor(None, run, dq)
                actual = next(iter(rows[0].values()), None) if rows else None
            except Exception as e:
                results.append({"name": name, "status": "ERROR", "detail": str(e)[:200]})
                continue
            if "expected" not in t:
                results.append({"name": name, "status": "INFO", "detail": f"actual={actual}"})
                continue
            ok, detail = model_analysis.dax_test_verdict(actual, t["expected"], t.get("tolerance", 0))
            results.append({"name": name, "status": "PASS" if ok else "FAIL", "detail": detail})
            if ok:
                passed += 1

        graded = [r for r in results if r["status"] in ("PASS", "FAIL")]
        total = len(graded)
        return DaxTestRunResult(
            passed=passed,
            total=total,
            all_passed=total > 0 and passed == total,
            results=[DaxTestCaseResult(**r) for r in results],
        )
    except Exception as e:
        raise ValueError(str(handle_error(e)))


# ============================================================================
# Tools – fleet / governance ops (admin-gated)
# ============================================================================

@mcp.tool()
async def cross_workspace_lineage(
    workspace_ids: list[str] | None = None,
    dataset_name: str | None = None,
    cache_path: str | None = None,
) -> CrossWorkspaceLineageResult:
    """Build a tenant-wide dataset inventory and lineage summary using the Admin Scanner API.

    Triggers a workspace-info scan, polls until it completes (up to ~5 min), then
    summarises RLS coverage, sensitivity label coverage, and dataset lineage. Use this
    for tenant-level governance audits. Optionally restrict to specific workspace GUIDs
    and/or focus the output on a single dataset name.

    REQUIRES: Service Principal must be in an allowed security group with the tenant-level
    read-only admin APIs enabled (Power BI admin settings). Scans are asynchronous;
    use cache_path to store results and avoid re-scanning on every call.

    Returns a dict with (via summarize_scan):
        workspace_count:              number of workspaces scanned
        dataset_count:                total datasets found
        datasets_without_rls:         list of datasets with no row-level security roles
        datasets_without_labels:      list of datasets with no sensitivity label
        dataset_detail:               lineage and config for dataset_name if provided

    Args:
        workspace_ids: Workspace GUIDs to scan; auto-discovers up to 100 workspaces if omitted
        dataset_name:  Focus lineage output on this dataset display name (optional)
        cache_path:    File path to save/reload the raw scan JSON (avoid re-scanning)
    """
    try:
        conn = _conn()
        loop = asyncio.get_event_loop()
        scan = None
        if cache_path:
            try:
                with open(cache_path, encoding="utf-8") as f:
                    scan = json.load(f)
            except Exception:
                pass
        if scan is None:
            ids = workspace_ids or []
            if not ids:
                ws = await loop.run_in_executor(None, conn.admin_list_workspaces, 100)
                ids = [w["id"] for w in ws if w.get("id")]
            ids = ids[:100]
            if not ids:
                raise ValueError("No workspaces found to scan.")
            started = await loop.run_in_executor(None, conn.admin_post_workspace_info, ids, True)
            scan_id = started.get("id")
            if not scan_id:
                raise ValueError(f"Scan did not start: {started}")
            for _ in range(20):
                st = await loop.run_in_executor(None, conn.admin_get_scan_status, scan_id)
                status = str(st.get("status", "")).lower()
                if status == "succeeded":
                    break
                if status == "failed":
                    raise ValueError(f"Scan failed: {st.get('error') or st}")
                await asyncio.sleep(15)
            else:
                raise ValueError("Scan still running after the wait. Retry with cache_path.")
            scan = await loop.run_in_executor(None, conn.admin_get_scan_result, scan_id)
            if cache_path:
                try:
                    with open(cache_path, "w", encoding="utf-8") as f:
                        json.dump(scan, f)
                except Exception:
                    pass
        return summarize_scan(scan, dataset_name=dataset_name)
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def fleet_refresh_monitor(workspace_ids: list[str]) -> FleetRefreshResult:
    """Check the last refresh status of every refreshable dataset across multiple workspaces.

    Iterates over all refreshable datasets in each workspace, fetches the most recent
    refresh record, and surfaces every dataset whose last refresh failed together with
    a root-cause classification. Use this for a fleet-wide health check or to build a
    refresh-failure alert dashboard. For single-dataset diagnosis with full history, use
    refresh_doctor instead.

    Returns a dict with:
        checked:      total refreshable datasets inspected
        failed_count: number of datasets whose last refresh failed
        failures:     list of {dataset (name), end_time (ISO), cause (string)} per failure

    Args:
        workspace_ids: List of workspace GUIDs to inspect (from list_workspaces)
    """
    try:
        conn = _conn()
        loop = asyncio.get_event_loop()
        failures, checked = [], 0
        for wid in workspace_ids:
            try:
                datasets = await loop.run_in_executor(None, conn.list_datasets, wid)
            except Exception:
                continue
            for ds in datasets:
                if not ds.get("is_refreshable"):
                    continue
                checked += 1
                try:
                    hist = await loop.run_in_executor(None, conn.get_refresh_history, wid, ds["id"], 1)
                except Exception:
                    continue
                if hist and str(hist[0].get("status")) == "Failed":
                    diag = _refresh_diag_mod.classify_refresh_error(hist[0].get("serviceExceptionJson") or "")
                    failures.append(RefreshFailure(dataset=ds["name"], end_time=hist[0].get("endTime"), cause=diag.cause))
        return FleetRefreshResult(checked=checked, failed_count=len(failures), failures=failures)
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def usage_and_orphan_analytics(date: str | None = None, filter: str | None = None) -> UsageAnalyticsResult:
    """Fetch and aggregate tenant-wide Power BI activity events for a single UTC day.

    Calls the Admin Activity Events API and aggregates all events into top-users,
    top-reports, and per-activity-type counts. Use this to identify heavily used
    assets, unused reports (orphan candidates), and active users for a given date.
    Data is typically available with a ~30 minute delay; events expire after 28 days.

    REQUIRES: Service Principal with read-only admin APIs enabled.

    Returns a dict with:
        total_events:        total event count for the day
        distinct_users:      number of unique users
        top_users:           list of {userId, count} sorted by activity desc
        top_reports:         list of {reportName, count} sorted by view count desc
        by_activity:         dict of activityType → count

    Args:
        date:   UTC date in YYYY-MM-DD format; defaults to yesterday if omitted
        filter: Optional OData $filter expression, e.g. "Activity eq 'ViewReport'"
    """
    try:
        from datetime import datetime, timezone, timedelta
        conn = _conn()
        if not date:
            date = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
        loop = asyncio.get_event_loop()
        events = await loop.run_in_executor(None, conn.admin_get_activity_events_for_day, date, filter)
        return aggregate_activity(events)
    except Exception as e:
        raise ValueError(str(handle_error(e)))


# ============================================================================
# Tools – security & audit
# ============================================================================

@mcp.tool()
async def security_status() -> SecurityStatus:
    """Return the current runtime security configuration of this MCP server session.

    Shows which of the three security subsystems are active: PII detection (masks
    phone numbers, emails, IDs in query results), audit logging (tamper-evident hash
    chain of every query), and access policies (column/table blocking rules from
    config/policies.yaml). Check this before querying sensitive datasets to understand
    what protection is in place.

    Returns a SecurityStatus with:
        pii_detection_enabled:   true if results are scanned and masked for PII patterns
        audit_logging_enabled:   true if every query is recorded in the audit log
        access_policies_enabled: true if column/table blocking policies are enforced
        active_policies:         list of table names that have at least one column policy
    """
    try:
        if not _app_context or not _app_context.security:
            return SecurityStatus(pii_detection_enabled=False, audit_logging_enabled=False,
                                  access_policies_enabled=False, active_policies=[])
        sec = _app_context.security
        summary = sec.get_policy_summary()
        return SecurityStatus(
            pii_detection_enabled=sec.enable_pii_detection,
            audit_logging_enabled=sec.enable_audit,
            access_policies_enabled=sec.enable_policies,
            active_policies=summary.tables_with_policies,
        )
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def security_audit_log(count: int = 10) -> list[AuditEvent]:
    """Return recent entries from the server's tamper-evident security audit log.

    The audit log records every query that passes through execute_dax, including the
    query text, dataset, timestamp, and whether any PII was detected or rows were
    blocked by policy. Use this to review what queries have been run, by whom, and
    whether any sensitive data was accessed. Use verify_audit_integrity to confirm the
    log has not been altered.

    Each entry includes:
        timestamp:   ISO-8601 when the event was recorded
        event_type:  "query", "policy_block", "pii_detected", etc.
        query:       the DAX query text (may be redacted for secrets)
        dataset:     dataset name
        row_count:   rows returned after policies were applied

    Args:
        count: Number of most-recent entries to return (default: 10, max: 100)
    """
    try:
        if not _app_context or not _app_context.security:
            return []
        sec = _app_context.security
        if not sec.audit_logger:
            return []
        return [AuditEvent(**e) for e in sec.audit_logger.get_recent_events(min(count, 100))]
    except Exception as e:
        raise ValueError(str(handle_error(e)))


# ============================================================================
# Tools – DAX generation
# ============================================================================

@mcp.tool()
async def generate_measure_suite(
    kind: str,
    base_measure: str | None = None,
    date_column: str | None = None,
    dimension_columns: list[str] | None = None,
    column: str | None = None,
    variants: list[str] | None = None,
    display_folder: str | None = None,
) -> list[MeasureDefinition]:
    """Generate a ready-to-use set of governed DAX measures from a base measure or column.

    Produces complete measure definitions including name, expression, format_string,
    display_folder, and description. All expressions follow DAX best practices (DIVIDE
    for ratios, CALCULATE with date intelligence functions, VAR/RETURN for readability).

    Supported kinds and their required parameters:

        time_intelligence  – YTD, MTD, QTD, prior-year, rolling-12 and more.
                             Requires: base_measure (e.g. "Total Sales"),
                                       date_column (e.g. "Date[Date]")
                             Optional: variants (subset of time-intel variants to generate)

        ratios             – % of total and % of dimension slices.
                             Requires: base_measure,
                                       dimension_columns (e.g. ["Product[Category]"])

        ranking            – RANKX over dimension columns.
                             Requires: base_measure, dimension_columns

        column_stats       – SUM, AVERAGE, MIN, MAX, DISTINCTCOUNT for a fact column.
                             Requires: column (e.g. "Sales[Amount]")

    Each returned measure dict contains:
        name:           display name for the measure
        expression:     the DAX scalar expression (without the leading "[MeasureName] =")
        format_string:  e.g. "#,##0", "#,##0.00", "0.0%"
        display_folder: folder name for the Fields pane
        description:    plain-language description suitable for Copilot

    Args:
        kind:              time_intelligence | ratios | ranking | column_stats
        base_measure:      Name of the existing base measure (required for time_intelligence/ratios/ranking)
        date_column:       Full column reference e.g. "Date[Date]" (required for time_intelligence)
        dimension_columns: List of full column refs e.g. ["Product[Category]"] (required for ratios/ranking)
        column:            Full column reference e.g. "Sales[Amount]" (required for column_stats)
        variants:          Subset of time-intelligence variants to generate (optional)
        display_folder:    Override the display folder name (optional)
    """
    try:
        params = {k: v for k, v in {
            "base_measure": base_measure, "date_column": date_column,
            "dimension_columns": dimension_columns, "column": column,
            "variants": variants, "display_folder": display_folder,
        }.items() if v is not None}
        return dax_generator.generate_suite(kind, **params)
    except Exception as e:
        raise ValueError(str(handle_error(e)))


# ============================================================================
# Tools – governance helpers
# ============================================================================

@mcp.tool()
async def summarize_security_scan(scan: dict, dataset_name: str | None = None) -> CrossWorkspaceLineageResult:
    """Produce a governance summary from a raw Admin Scanner JSON payload.

    Extracts RLS coverage, sensitivity label coverage, and dataset lineage from the
    Admin Scanner result object. Use this to process a scan result that was obtained
    externally or loaded from a file, without re-triggering the scan. For a full
    end-to-end scan + summary in one call, use cross_workspace_lineage instead.

    Returns a dict with:
        workspace_count:          number of workspaces in the scan
        dataset_count:            total datasets found
        datasets_without_rls:     list of dataset names with no RLS roles configured
        datasets_without_labels:  list of dataset names with no sensitivity label
        dataset_detail:           full lineage/config for dataset_name if provided

    Args:
        scan:         Raw Admin Scanner scan result JSON (from cross_workspace_lineage or file)
        dataset_name: Narrow the output to this specific dataset name (optional)
    """
    try:
        return summarize_scan(scan, dataset_name=dataset_name)
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def aggregate_user_activity(events: list[dict]) -> UsageAnalyticsResult:
    """Aggregate a list of Power BI activity event objects into a usage summary.

    Processes raw activity event objects (as returned by usage_and_orphan_analytics or
    fetched directly from the Admin Activity Events API) and summarises them into
    top users, top reports/datasets, and per-activity-type counts. Use this when you
    already have a batch of event objects from a prior call and want to re-aggregate
    or filter them without re-fetching.

    Returns a dict with:
        total_events:   count of events processed
        distinct_users: count of unique user identities
        top_users:      list of {userId, count} sorted descending
        top_reports:    list of {reportName, count} sorted descending
        by_activity:    dict of activityType → count

    Args:
        events: List of activity event dicts (each must have activityEventType and userId)
    """
    try:
        return aggregate_activity(events)
    except Exception as e:
        raise ValueError(str(handle_error(e)))


# ============================================================================
# Entry point
# ============================================================================

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "stdio":
        logger.info("Starting stdio server")
        mcp.run(transport="stdio")
    else:
        host = os.getenv("HOST", "0.0.0.0")
        port = int(os.getenv("PORT", "8000"))
        logger.info("Starting SSE server on %s:%s", host, port)
        mcp.run(transport="sse", host=host, port=port)
