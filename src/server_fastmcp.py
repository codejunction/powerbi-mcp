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
    WorkspaceInfo, DatasetInfo, TableInfo, ColumnInfo,
    DaxResult, ValidationResult, SecurityStatus,
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
    """List all Power BI Service workspaces accessible to the Service Principal."""
    try:
        return [WorkspaceInfo(**ws) for ws in _conn().list_workspaces()]
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def list_datasets(workspace_id: str) -> list[DatasetInfo]:
    """List all datasets in a Power BI Service workspace.

    Args:
        workspace_id: Workspace GUID (from list_workspaces)
    """
    try:
        return [DatasetInfo(**ds) for ds in _conn().list_datasets(workspace_id)]
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def list_tables(workspace_name: str, dataset_name: str) -> list[TableInfo]:
    """List visible tables in a dataset via REST Execute Queries (INFO.VIEW.TABLES).

    Args:
        workspace_name: Workspace display name
        dataset_name: Dataset/semantic model display name
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
    """List columns for a table via REST Execute Queries (INFO.VIEW.COLUMNS).

    Args:
        workspace_name: Workspace display name
        dataset_name: Dataset/semantic model display name
        table_name: Table name to inspect
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
async def get_model_info(workspace_name: str, dataset_name: str) -> dict:
    """Return a concise summary of tables, column counts, measure counts, and relationships.

    Args:
        workspace_name: Workspace display name
        dataset_name: Dataset/semantic model display name
    """
    try:
        model, err = await _gather_model(workspace_name, dataset_name)
        if err:
            raise ValueError(err)
        visible = [t for t in model["tables"] if not model_analysis._truthy(t.get("is_hidden"))]
        return {
            "dataset": dataset_name,
            "workspace": workspace_name,
            "tables": [
                {
                    "name": t["name"],
                    "columns": len(t.get("columns", [])),
                    "measures": len(t.get("measures", [])),
                    "top_measures": [m["name"] for m in t.get("measures", [])[:10]],
                }
                for t in visible
            ],
            "relationships": len(model.get("relationships", [])),
        }
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def describe_semantic_model(workspace_name: str, dataset_name: str) -> dict:
    """Build an agent-ready semantic map: visible tables, columns, measures, relationships, descriptions.

    Use this before answering business questions so the agent uses real object names.

    Args:
        workspace_name: Workspace display name
        dataset_name: Dataset/semantic model display name
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
        rels = [{
            "from_table": g(r, "FromTable"), "from_column": g(r, "FromColumn"),
            "to_table": g(r, "ToTable"), "to_column": g(r, "ToColumn"),
            "is_active": g(r, "IsActive"),
        } for r in meta.get("relationships", [])]
        model = {"dataset": dataset_name, "tables": list(tables.values()), "relationships": rels}
        visible_tables = [t for t in model["tables"] if not t.get("is_hidden")]
        measures = [m for t in visible_tables for m in t.get("measures", []) if not m.get("is_hidden")]
        return {
            "model": model,
            "summary": f"{len(visible_tables)} visible table(s), {len(measures)} visible measure(s), "
                       f"{len(rels)} relationship(s)",
            "guidance": [
                "Use visible measures first for business metrics; generate DAX only when no suitable measure exists.",
                "Use table/column descriptions and relationships to choose dimensions and filters.",
                "All query execution is read-only through the Power BI REST Execute Queries API.",
            ],
        }
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def answer_query_plan(
    workspace_name: str,
    dataset_name: str,
    question: str,
    execute: bool = False,
    max_rows: int = 100,
) -> dict:
    """Given a natural-language question, suggest existing measures or generate a draft DAX query.

    Args:
        workspace_name: Workspace display name
        dataset_name: Dataset/semantic model display name
        question: The business question to answer
        execute: Whether to also execute the draft query (default: false)
        max_rows: Row cap when execute=true (default: 100)
    """
    try:
        sem = await describe_semantic_model(workspace_name, dataset_name)
        model = sem["model"]
        qwords = {w.lower() for w in re.findall(r"[A-Za-z0-9_]+", question) if len(w) > 2}
        candidates = []
        for table in model.get("tables", []):
            for m in table.get("measures", []):
                hay = " ".join([m.get("name") or "", m.get("description") or "", table.get("name") or ""]).lower()
                score = sum(1 for w in qwords if w in hay)
                if score:
                    candidates.append({"table": table["name"], "measure": m["name"],
                                       "score": score, "description": m.get("description")})
        candidates.sort(key=lambda x: x["score"], reverse=True)
        chosen = candidates[:5]
        if chosen:
            draft_dax = f'EVALUATE ROW("{chosen[0]["measure"]}", [{chosen[0]["measure"]}])'
        else:
            first = next((t for t in model["tables"] if not t.get("is_hidden")), None)
            draft_dax = f"EVALUATE TOPN({max_rows}, '{first['name']}')" if first else None
        plan = {
            "question": question,
            "candidate_measures": chosen,
            "draft_dax": draft_dax,
            "recommendation": "use_existing_measure" if chosen else "generate_exploratory_dax",
        }
        rows: list = []
        if execute and draft_dax:
            conn = _conn()
            wid, did = _resolve_ids(conn, workspace_name, dataset_name)
            rows = conn.execute_dax_query(wid, did, draft_dax)[:max_rows]
        return {"plan": plan, "rows": rows}
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
    """Execute a read-only DAX query through the Power BI REST Execute Queries API.

    Security policies are applied before and after execution (PII masking, row limits).

    Args:
        workspace_name: Workspace display name
        dataset_name: Dataset/semantic model display name
        dax_query: DAX query to execute (must start with EVALUATE or DEFINE)
        max_rows: Maximum rows to return (default 10 000, hard cap 100 000)
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
    """Validate a DAX query or measure expression without returning data.

    Args:
        workspace_name: Workspace display name
        dataset_name: Dataset/semantic model display name
        dax: The DAX query or scalar expression to validate
        as_measure: Wrap the expression in EVALUATE ROW(...) for scalar validation
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
) -> dict:
    """Run the Best Practice Analyzer over a live semantic model via INFO.VIEW.*.

    Args:
        workspace_name: Workspace display name
        dataset_name: Dataset/semantic model display name
        categories: Optional list of categories to filter (e.g. ["DAX", "Formatting"])
        min_severity: Minimum severity to include: info | warning | error (default: info)
    """
    try:
        model, err = await _gather_model(workspace_name, dataset_name)
        if err:
            raise ValueError(err)
        result = run_bpa_fn(model, categories=categories, min_severity=min_severity)
        return result
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def audit_ai_readiness(workspace_name: str, dataset_name: str) -> dict:
    """Audit a live model for AI-readiness: naming, documentation coverage, Copilot optimization.

    Args:
        workspace_name: Workspace display name
        dataset_name: Dataset/semantic model display name
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
) -> dict:
    """Static DAX anti-pattern linter. Lints a whole model, one named measure, or a raw expression.

    Args:
        workspace_name: Workspace display name (required unless expression is given)
        dataset_name: Dataset display name (required unless expression is given)
        measure_name: Optional – lint only this named measure
        expression: Optional – lint a raw DAX expression directly (skips live model fetch)
        min_severity: Minimum severity: info | warning | error (default: info)
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
        result["findings"] = [f for f in result["findings"]
                               if _dax_lint_mod.SEVERITY_RANK.get(f["severity"], 0) >= min_rank]
        return result
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def dax_suggest_rewrite(
    workspace_name: str,
    dataset_name: str,
    measure_name: str | None = None,
    expression: str | None = None,
) -> dict:
    """Concrete before/after rewrite hints for auto-fixable DAX anti-patterns.

    Args:
        workspace_name: Workspace display name
        dataset_name: Dataset display name
        measure_name: Optional – rewrite only this measure
        expression: Optional – rewrite a raw expression directly
    """
    try:
        rewrites: list[dict] = []
        if expression:
            rewrites = _dax_lint_mod.suggest_rewrites(measure_name or "(expression)", expression)
        else:
            model, err = await _gather_model(workspace_name, dataset_name)
            if err:
                raise ValueError(err)
            for m in _measures_from_model(model, measure_name):
                for h in _dax_lint_mod.suggest_rewrites(m["name"], m["expression"]):
                    h["object"] = m["name"]
                    rewrites.append(h)
        return {"rewrites": rewrites, "count": len(rewrites)}
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def analyze_model_storage(workspace_name: str, dataset_name: str) -> dict:
    """VertiPaq-style storage analysis: per-table row counts (via COUNTROWS DAX).

    Args:
        workspace_name: Workspace display name
        dataset_name: Dataset/semantic model display name
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
        return {
            "table_count": len(visible),
            "total_rows": sum(v for v in rows_by_table.values() if v),
            "tables": [
                {
                    "name": t["name"],
                    "row_count": rows_by_table.get(t["name"]),
                    "column_count": len(t.get("columns", [])),
                    "measure_count": len(t.get("measures", [])),
                }
                for t in ranked[:50]
            ],
        }
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def analyze_query_performance(
    workspace_name: str,
    dataset_name: str,
    dax: str,
) -> dict:
    """Time a DAX query and return duration, row count, and optimization hints.

    Args:
        workspace_name: Workspace display name
        dataset_name: Dataset/semantic model display name
        dax: The DAX query to benchmark
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

        return {"duration_ms": round(ms, 1), "row_count": row_count, "hints": hints}
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def model_diff(
    workspace_name: str,
    dataset_name: str,
    baseline_path: str,
) -> dict:
    """Semantic diff between a saved JSON baseline snapshot and the live model.

    Args:
        workspace_name: Workspace display name
        dataset_name: Dataset/semantic model display name
        baseline_path: Path to a previously saved JSON model snapshot
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
) -> dict:
    """Orphan-key scan across all active relationships via EXCEPT(DISTINCT(), DISTINCT()).

    Args:
        workspace_name: Workspace display name
        dataset_name: Dataset/semantic model display name
        max_samples: Number of example orphan keys to surface per violation (default: 5)
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
        return {"checked": checked, "violations": violations,
                "clean": len([v for v in violations if v.get("orphan_keys", 0) > 0]) == 0}
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
) -> dict:
    """CI quality gate: run BPA + AI-readiness on a live model and return a PASS/FAIL verdict.

    Args:
        workspace_name: Workspace display name
        dataset_name: Dataset/semantic model display name
        min_ai_score: Minimum AI-readiness score to pass (default: 60)
        block_on_warnings: Also block on BPA warnings, not just errors (default: false)
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
        return {
            "passed": passed,
            "bpa_errors": len(errors),
            "bpa_warnings": len(warnings),
            "ai_score": ai["score"],
            "blocking": [f"{f['rule_id']}: {f['object']}" for f in errors],
        }
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def bpa_validate_rules(
    rules: str,
    fix: bool = False,
) -> dict:
    """Validate a custom BPA rules JSON for structural correctness before using it.

    Args:
        rules: BPA rules as a JSON string (array of rule objects)
        fix: Attempt to auto-fix minor issues (default: false)
    """
    try:
        return _bpa_authoring_mod.validate_rules(rules, fix=fix)
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def verify_audit_integrity() -> dict:
    """Verify the tamper-evident SHA-256 hash chain of the security audit log."""
    try:
        if not _app_context or not _app_context.security:
            return {"valid": True, "checked": 0, "message": "Security layer not active."}
        return _app_context.security.verify_audit_integrity()
    except Exception as e:
        raise ValueError(str(handle_error(e)))


# ============================================================================
# Tools – diagnostics & ops
# ============================================================================

@mcp.tool()
async def refresh_doctor(workspace_name: str, dataset_name: str, history_count: int = 10) -> dict:
    """Diagnose dataset refresh failures from REST history with root-cause classification.

    Args:
        workspace_name: Workspace display name
        dataset_name: Dataset/semantic model display name
        history_count: Number of recent refreshes to examine (default: 10)
    """
    try:
        conn = _conn()
        loop = asyncio.get_event_loop()
        wid, did, err = await loop.run_in_executor(None, conn.resolve_dataset, workspace_name, dataset_name)
        if err:
            raise ValueError(err)
        history = await loop.run_in_executor(None, conn.get_refresh_history, wid, did, history_count)
        if not history:
            return {"history": 0, "message": "No refresh history found (dataset may never have refreshed, or history expired ~30 days)."}

        completed = sum(1 for h in history if str(h.get("status")) == "Completed")
        failed = [h for h in history if str(h.get("status")) == "Failed"]
        consecutive = 0
        for h in history:
            s = str(h.get("status"))
            if s == "Failed":
                consecutive += 1
            elif s in ("Completed", "Disabled"):
                break

        diagnosis = None
        if failed:
            err_text = failed[0].get("serviceExceptionJson") or ""
            diagnosis = _refresh_diag_mod.classify_refresh_error(err_text)

        return {
            "completed": completed,
            "failed": len(failed),
            "consecutive_failures": consecutive,
            "most_recent_status": history[0].get("status"),
            "most_recent_end": history[0].get("endTime"),
            "diagnosis": diagnosis,
            "warning": (
                f"{consecutive} consecutive failure(s). Power BI auto-disables a refresh schedule "
                f"after {_refresh_diag_mod.CONSECUTIVE_FAILURE_DISABLE_THRESHOLD} consecutive failures."
                if consecutive >= _refresh_diag_mod.CONSECUTIVE_FAILURE_DISABLE_THRESHOLD - 1 else None
            ),
        }
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def find_unused_objects(workspace_name: str, dataset_name: str) -> dict:
    """Find columns and measures not referenced by any other model object (INFO.CALCDEPENDENCY).

    NOTE: Report visual usage is not checked in REST-only mode; objects used only in visuals
    may be incorrectly listed as unused.

    Args:
        workspace_name: Workspace display name
        dataset_name: Dataset/semantic model display name
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
            return {
                "error": (
                    f"INFO.CALCDEPENDENCY unavailable: {e}. "
                    "This DMV needs write permission on the model (not available in REST read-only mode)."
                ),
                "unused_measures": None, "unused_columns": None,
            }
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
        return {
            "unused_measures": unused_cols[:200],
            "unused_columns": unused_measures[:200],
            "note": "Report visual usage is NOT checked in REST-only mode.",
        }
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def impact_analysis(
    workspace_name: str,
    dataset_name: str,
    object_name: str,
    table_name: str | None = None,
) -> dict:
    """Blast radius for a measure or column: which model objects depend on it (INFO.CALCDEPENDENCY).

    Args:
        workspace_name: Workspace display name
        dataset_name: Dataset/semantic model display name
        object_name: Measure or column name to analyze
        table_name: Optional table to narrow the search
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
            # INFO.CALCDEPENDENCY requires write permission; return a graceful error dict
            return {
                "object_name": object_name,
                "table_name": table_name,
                "error": (
                    f"INFO.CALCDEPENDENCY unavailable: {e}. "
                    "This DMV needs write permission on the model (not available in REST read-only mode)."
                ),
                "dependent_count": None,
                "dependents": None,
            }
        dependents = [
            {
                "type": _row_get(r, "OBJECT_TYPE"),
                "table": _row_get(r, "TABLE"),
                "object": _row_get(r, "OBJECT"),
            }
            for r in rows[:200]
        ]
        return {
            "object_name": object_name,
            "table_name": table_name,
            "dependent_count": len(dependents),
            "dependents": dependents,
            "safe_to_change": len(dependents) == 0,
        }
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def run_dax_tests(
    workspace_name: str,
    dataset_name: str,
    tests: list[dict],
) -> dict:
    """Run a suite of DAX regression tests and report pass/fail vs expected values.

    Each test: {"name": str, "dax": str, "expected": any, "tolerance": float (optional)}

    Args:
        workspace_name: Workspace display name
        dataset_name: Dataset/semantic model display name
        tests: List of test case objects
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
        return {
            "passed": passed,
            "total": total,
            "all_passed": total > 0 and passed == total,
            "results": results,
        }
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
) -> dict:
    """Tenant-wide inventory and lineage via the Admin Scanner API.

    Requires the Service Principal to be in an allowed security group with
    read-only admin APIs enabled.

    Args:
        workspace_ids: Optional list of workspace GUIDs to scan (auto-discovers if omitted)
        dataset_name: Optional – focus the output on this dataset name
        cache_path: Optional file path to cache/reload the scan result
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
async def fleet_refresh_monitor(workspace_ids: list[str]) -> dict:
    """Refresh health across many datasets: surfaces the most-recently-failed datasets.

    Args:
        workspace_ids: List of workspace GUIDs to check (from list_workspaces)
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
                    failures.append({"dataset": ds["name"], "end_time": hist[0].get("endTime"), "cause": diag["cause"]})
        return {"checked": checked, "failed_count": len(failures), "failures": failures}
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def usage_and_orphan_analytics(date: str | None = None, filter: str | None = None) -> dict:
    """Tenant usage analytics from the Admin Activity Events API for a single UTC day.

    Requires read-only admin APIs enabled. Events have ~28-day retention.

    Args:
        date: UTC date in YYYY-MM-DD format (default: yesterday)
        filter: Optional OData filter expression
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
    """Get the current security configuration (PII detection, audit, policy enforcement)."""
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
            active_policies=summary.get("tables_with_policies", []),
        )
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def security_audit_log(count: int = 10) -> list[dict]:
    """View recent entries from the tamper-evident security audit log.

    Args:
        count: Number of recent entries to return (default: 10, max: 100)
    """
    try:
        if not _app_context or not _app_context.security:
            return []
        sec = _app_context.security
        if not sec.audit_logger:
            return []
        return sec.audit_logger.get_recent_events(min(count, 100))
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
) -> list[dict]:
    """Generate a governed suite of DAX measures from a base measure or column.

    Kinds and required params:
    - time_intelligence: base_measure + date_column (e.g. "Date[Date]")
    - ratios: base_measure + dimension_columns (e.g. ["Product[Category]"])
    - ranking: base_measure + dimension_columns
    - column_stats: column (e.g. "Sales[Amount]")

    Every measure includes: name, expression, format_string, display_folder, description.

    Args:
        kind: time_intelligence | ratios | ranking | column_stats
        base_measure: Base measure name (for time_intelligence / ratios / ranking)
        date_column: Full date column ref e.g. "Date[Date]" (for time_intelligence)
        dimension_columns: Column refs for slicing e.g. ["Product[Category]"] (for ratios / ranking)
        column: Full column ref e.g. "Sales[Amount]" (for column_stats)
        variants: Optional subset of time-intelligence variants
        display_folder: Optional override for the display folder
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
async def summarize_security_scan(scan: dict, dataset_name: str | None = None) -> dict:
    """Summarize an Admin Scanner scan result for RLS gaps and sensitivity label coverage.

    Args:
        scan: Admin scanner result (from cross_workspace_lineage)
        dataset_name: Optional dataset name to focus the report
    """
    try:
        return summarize_scan(scan, dataset_name=dataset_name)
    except Exception as e:
        raise ValueError(str(handle_error(e)))


@mcp.tool()
async def aggregate_user_activity(events: list[dict]) -> dict:
    """Aggregate activity event objects into top-users, top-reports, and by-activity counts.

    Args:
        events: Activity event objects (from usage_and_orphan_analytics or admin API)
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
