"""
Power BI MCP Server V2
Supports both Power BI Service (Cloud) and Power BI Desktop (Local)
Features: PII Detection, Audit Logging, Access Policies
"""
import asyncio
import json
import logging
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from mcp.server import Server, NotificationOptions
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
import uvicorn
from mcp.types import (
    Tool, TextContent, ToolAnnotations,
    Resource, ResourceTemplate,
    Prompt, PromptArgument, PromptMessage, GetPromptResult,
    Completion,
    ListToolsResult, CallToolResult, ListResourcesResult, ListResourceTemplatesResult,
    ReadResourceResult, ListPromptsResult, CompleteResult, TextResourceContents,
    PaginatedRequestParams, CallToolRequestParams, ReadResourceRequestParams,
    GetPromptRequestParams, CompleteRequestParams,
)
from mcp.server.models import InitializationOptions
from urllib.parse import unquote

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO")),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger("powerbi-mcp-v2")


def redact_secrets(text: Any, extra_secrets: Optional[List[str]] = None) -> str:
    """Redact connection-string secrets and known secret values before logging or returning to the client.

    Power BI cloud connectors embed the service-principal client secret directly in the
    ADOMD/MSOLAP connection string (Password=...). Exception messages and verbose argument
    logs can therefore leak credentials. This masks the common vectors.
    """
    if text is None:
        return ""
    s = str(text)
    # Connection-string / URL style secrets
    s = re.sub(r"(?i)(password\s*=\s*)[^;]+", r"\1***", s)
    s = re.sub(r"(?i)(client_secret\s*=\s*)[^;&\s]+", r"\1***", s)
    s = re.sub(r"(?i)(\bsecret\s*=\s*)[^;&\s]+", r"\1***", s)
    # Known literal secret values (e.g. the configured client secret)
    for sec in (extra_secrets or []):
        if sec and len(sec) >= 6:
            s = s.replace(sec, "***")
    return s


def build_validation_probe(dax: str, as_measure: bool = False) -> str:
    """Wrap a DAX expression/query into an executable probe used to validate it.

    A full query (starts with EVALUATE/DEFINE) is run as-is; a scalar measure
    expression is wrapped in EVALUATE ROW(...) so the engine parses and evaluates it.
    Executing the probe with a tiny row cap surfaces syntax/semantic errors without
    materializing real data.
    """
    stripped = (dax or "").strip()
    upper = stripped.upper()
    if not as_measure and (upper.startswith("EVALUATE") or upper.startswith("DEFINE")):
        return stripped
    return f'EVALUATE ROW("validation", {stripped})'


# Real constraints on INFO.CALCDEPENDENCY (not "old engine"): it needs write permission on
# the model and cannot run over a live Power BI Desktop connection.
INFO_CALCDEP_NOTE = (
    "INFO.CALCDEPENDENCY needs write permission on the model and does not run over a live "
    "Power BI Desktop connection (it also requires a reasonably recent engine)."
)


# Import connectors
from powerbi_rest_connector import PowerBIRestConnector

# Pure-Python model analysis (BPA + AI-readiness), refresh diagnostics, governance
import model_analysis
import refresh_diagnostics
import governance
import dax_lint
import bpa_authoring
import dax_generator

# Import security layer
from security import SecurityLayer, get_security_layer
from security.access_policy import AccessPolicyEngine


class PowerBIMCPServer:
    """REST-only, read-only Power BI MCP Server."""

    _REST_READONLY_TOOLS = {
        "list_workspaces", "list_datasets", "list_tables", "list_columns",
        "execute_dax", "get_model_info", "describe_semantic_model",
        "answer_query_plan", "security_status", "security_audit_log",
        "validate_dax", "run_bpa", "audit_ai_readiness", "analyze_model_storage",
        "analyze_query_performance", "model_diff", "pre_deploy_gate",
        "refresh_doctor", "find_unused_objects", "impact_analysis", "run_dax_tests",
        "verify_audit_integrity", "cross_workspace_lineage", "fleet_refresh_monitor",
        "usage_and_orphan_analytics", "dax_lint", "dax_suggest_rewrite",
        "bpa_validate_rules",
        "bpa_audit_rule_sources", "scan_referential_integrity",
        "generate_measure_suite",
    }

    def __init__(self):
        self.server = Server("powerbi-mcp-rest-readonly")

        # Cloud credentials (optional for Desktop-only usage)
        self.tenant_id = os.getenv("TENANT_ID", "")
        self.client_id = os.getenv("CLIENT_ID", "")
        self.client_secret = os.getenv("CLIENT_SECRET", "")

        # Connector instances
        self.rest_connector: Optional[PowerBIRestConnector] = None

        # Initialize security layer
        config_path = Path(__file__).parent.parent / "config" / "policies.yaml"
        self.security = SecurityLayer(
            config_path=str(config_path) if config_path.exists() else None,
            enable_pii_detection=os.getenv("ENABLE_PII_DETECTION", "true").lower() == "true",
            enable_audit=os.getenv("ENABLE_AUDIT", "true").lower() == "true",
            enable_policies=os.getenv("ENABLE_POLICIES", "true").lower() == "true"
        )

        # Single source of truth for call routing and MCP safety hints. New tools
        # register here (dispatch + annotations) in addition to handle_list_tools.
        self._tool_dispatch = self._build_tool_dispatch()
        self._tool_annotations = self._build_tool_annotations()
        self._prompts = self._build_prompts()

        # REST-only build: write, Desktop, Desktop Bridge, XMLA, TOM, PBIP, and PBIR tools
        # are not exposed.
        self._read_only = True

        self._setup_handlers()

    def _build_prompts(self):
        """Reusable, user-invokable BI workflows exposed as MCP prompts. Each renders a
        guidance message that orchestrates the right tools in the right order."""
        return {
            "optimize_measure": {
                "title": "Optimize a DAX measure",
                "description": "Diagnose and optimize a DAX measure safely",
                "arguments": [PromptArgument(name="measure_name", description="Measure to optimize", required=True)],
                "render": lambda a: (
                    f"Optimize the DAX measure [{a.get('measure_name','<name>')}] in the connected model.\n"
                    "1) scan_measure_dependencies to understand what it uses and what depends on it.\n"
                    "2) analyze_query_performance on a query that exercises it to get a baseline.\n"
                    "3) Propose an improved expression; validate_dax it before changing anything.\n"
                    "4) Apply with create_measure/batch_update_measures (inside a tom transaction) and re-check."
                ),
            },
            "explain_measure": {
                "title": "Explain a measure",
                "description": "Explain what a measure computes in business terms",
                "arguments": [PromptArgument(name="measure_name", description="Measure to explain", required=True)],
                "render": lambda a: (
                    f"Explain the measure [{a.get('measure_name','<name>')}] in plain business language.\n"
                    "Use desktop_list_measures for its DAX and scan_measure_dependencies for context. "
                    "Describe inputs, the calculation, filter context, and a usage example."
                ),
            },
            "audit_model": {
                "title": "Audit the model",
                "description": "Full quality + AI-readiness audit of the connected model",
                "arguments": [],
                "render": lambda a: (
                    "Audit the connected Power BI model end to end:\n"
                    "1) run_bpa (note errors/warnings by category).\n"
                    "2) audit_ai_readiness (descriptions/format coverage).\n"
                    "3) analyze_model_storage (largest tables).\n"
                    "Then summarize the top issues and a prioritized remediation plan."
                ),
            },
            "document_model": {
                "title": "Document the model",
                "description": "Generate human-readable documentation for the connected model",
                "arguments": [],
                "render": lambda a: (
                    "Generate documentation for the connected model.\n"
                    "Use get_model_info / desktop_get_model_info and the powerbi://desktop/schema resource. "
                    "Produce: overview, table-by-table (purpose, key columns), key measures (with descriptions), "
                    "relationships, and any best-practice issues from run_bpa."
                ),
            },
            "pre_deploy_review": {
                "title": "Pre-deploy quality gate",
                "description": "Run a full quality gate before shipping a model/report",
                "arguments": [],
                "render": lambda a: (
                    "Run a pre-deployment quality gate on the connected model and report the verdict:\n"
                    "1) run_bpa (fail the gate on any error-severity findings).\n"
                    "2) audit_ai_readiness (warn if score < 70).\n"
                    "3) export_data_dictionary (so docs ship with the release).\n"
                    "4) If a .pbip project is loaded: pbip_validate + pbip_scan_broken_refs.\n"
                    "Summarize PASS/FAIL with the blocking issues and a remediation checklist."
                ),
            },
            "plan_safe_rename": {
                "title": "Plan a safe rename",
                "description": "Plan a rename that won't break visuals or downstream measures",
                "arguments": [
                    PromptArgument(name="old_name", description="Current name", required=True),
                    PromptArgument(name="new_name", description="New name", required=True),
                ],
                "render": lambda a: (
                    f"Plan a SAFE rename from [{a.get('old_name','<old>')}] to [{a.get('new_name','<new>')}].\n"
                    "1) scan_measure_dependencies (downstream) and pbip_scan_broken_refs to see impact.\n"
                    "2) Use the PBIP tools (pbip_rename_tables/columns/measures) which update model AND report visuals - "
                    "do NOT use the deprecated TOM batch_rename_* tools (they break visuals).\n"
                    "3) After renaming, run pbip_validate and pbip_scan_broken_refs to confirm nothing is broken."
                ),
            },
        }

    def _build_tool_dispatch(self):
        """Map tool name -> coroutine handler. Every entry accepts the args dict
        (handlers that take no arguments simply ignore it). Replaces the former
        34-branch if/elif chain so list_tools and call_tool cannot drift apart."""
        dispatch = {
            # Cloud REST API
            "list_workspaces": lambda a: self._handle_list_workspaces(),
            "list_datasets": lambda a: self._handle_list_datasets(a),
            "list_tables": lambda a: self._handle_list_tables(a),
            "list_columns": lambda a: self._handle_list_columns(a),
            "execute_dax": lambda a: self._handle_execute_dax(a),
            "get_model_info": lambda a: self._handle_get_model_info(a),
            "describe_semantic_model": lambda a: self._handle_describe_semantic_model(a),
            "answer_query_plan": lambda a: self._handle_answer_query_plan(a),
            # Security
            "security_status": lambda a: self._handle_security_status(),
            "security_audit_log": lambda a: self._handle_security_audit_log(a),
            # DAX safety loop
            "validate_dax": lambda a: self._handle_validate_dax(a),
            # Model quality & performance (Bundle B)
            "run_bpa": lambda a: self._handle_run_bpa(a),
            "audit_ai_readiness": lambda a: self._handle_audit_ai_readiness(a),
            "analyze_model_storage": lambda a: self._handle_analyze_model_storage(a),
            "analyze_query_performance": lambda a: self._handle_analyze_query_performance(a),
            "model_diff": lambda a: self._handle_model_diff(a),
            "pre_deploy_gate": lambda a: self._handle_pre_deploy_gate(a),
            # Diagnostics & ops (Wave 2)
            "refresh_doctor": lambda a: self._handle_refresh_doctor(a),
            "find_unused_objects": lambda a: self._handle_find_unused_objects(a),
            "impact_analysis": lambda a: self._handle_impact_analysis(a),
            "run_dax_tests": lambda a: self._handle_run_dax_tests(a),
            "verify_audit_integrity": lambda a: self._handle_verify_audit_integrity(),
            # Governance-ops fleet (Wave 3, admin-gated)
            "cross_workspace_lineage": lambda a: self._handle_cross_workspace_lineage(a),
            "fleet_refresh_monitor": lambda a: self._handle_fleet_refresh_monitor(a),
            "usage_and_orphan_analytics": lambda a: self._handle_usage_and_orphan_analytics(a),
            # DAX quality (Wave 4: reach + quality)
            "dax_lint": lambda a: self._handle_dax_lint(a),
            "dax_suggest_rewrite": lambda a: self._handle_dax_suggest_rewrite(a),
            # Custom BPA governance (Wave 4)
            "bpa_validate_rules": lambda a: self._handle_bpa_validate_rules(a),
            "bpa_audit_rule_sources": lambda a: self._handle_bpa_audit_rule_sources(a),
            # Data modelling / warehousing
            "scan_referential_integrity": lambda a: self._handle_scan_referential_integrity(a),
            # Measure generation (read-only preview)
            "generate_measure_suite": lambda a: self._handle_generate_measure_suite(a),
        }
        return dispatch

    def _build_tool_annotations(self):
        """Map tool name -> ToolAnnotations. Hints let MCP clients auto-approve safe
        reads and require confirmation for destructive writes (the spec's primary safe-agent
        lever, since destructive-op guards are not otherwise standardized)."""
        def ann(read_only, destructive=False, idempotent=False, open_world=False):
            return ToolAnnotations(
                readOnlyHint=read_only,
                destructiveHint=destructive,
                idempotentHint=idempotent,
                openWorldHint=open_world,
            )

        local_read = ann(True, open_world=False)
        cloud_read = ann(True, open_world=True)
        annotations = {
            # Cloud reads (open world / network)
            "list_workspaces": cloud_read,
            "list_datasets": cloud_read,
            "list_tables": cloud_read,
            "list_columns": cloud_read,
            "execute_dax": cloud_read,
            "get_model_info": cloud_read,
            "describe_semantic_model": cloud_read,
            "answer_query_plan": cloud_read,
            # Security (local reads)
            "security_status": local_read,
            "security_audit_log": local_read,
            # DAX safety loop
            "validate_dax": ann(True, open_world=False),
            # Model quality & performance (Bundle B) - all read-only analysis
            "run_bpa": local_read,
            "audit_ai_readiness": local_read,
            "analyze_model_storage": local_read,
            "analyze_query_performance": local_read,
            "model_diff": local_read,
            "pre_deploy_gate": local_read,
            # Diagnostics & ops (Wave 2)
            "refresh_doctor": cloud_read,
            "find_unused_objects": local_read,
            "impact_analysis": local_read,
            "run_dax_tests": local_read,
            "verify_audit_integrity": local_read,
            # Governance-ops fleet (Wave 3) - read-only, cloud/admin
            "cross_workspace_lineage": cloud_read,
            "fleet_refresh_monitor": cloud_read,
            "usage_and_orphan_analytics": cloud_read,
            # DAX quality (Wave 4) - read-only static analysis
            "dax_lint": local_read,
            "dax_suggest_rewrite": local_read,
            # Custom BPA governance (Wave 4) - read-only validation/discovery
            "bpa_validate_rules": local_read,
            "bpa_audit_rule_sources": local_read,
            # Data modelling / warehousing
            "scan_referential_integrity": local_read,
            # Measure generation (read-only preview)
            "generate_measure_suite": local_read,
        }
        return annotations


    def _semantic_agent_tools(self) -> List[Tool]:
        """Additional REST-only tools that help autonomous agents understand a model."""
        common = {
            "workspace_name": {"type": "string", "description": "Power BI workspace name"},
            "dataset_name": {"type": "string", "description": "Semantic model/dataset name"},
        }
        return [
            Tool(
                name="describe_semantic_model",
                description=(
                    "Build an agent-ready semantic map of a Power BI model using REST Execute Queries: "
                    "visible tables, columns, measures, relationships, hidden flags, descriptions, "
                    "and suggested queryable entities. Use this before answering business questions."
                ),
                inputSchema={"type": "object", "properties": common, "required": ["workspace_name", "dataset_name"]},
                outputSchema={"type": "object", "properties": {"model": {"type": "object"}, "guidance": {"type": "array"}}},
            ),
            Tool(
                name="answer_query_plan",
                description=(
                    "Given a natural-language user question and a semantic model, suggest whether existing "
                    "measures can answer it or whether to generate a read-only DAX query on the fly. "
                    "Returns candidate measures/tables and a draft DAX query; it does not execute unless execute=true."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        **common,
                        "question": {"type": "string"},
                        "execute": {"type": "boolean", "default": False},
                        "max_rows": {"type": "integer", "default": 100},
                    },
                    "required": ["workspace_name", "dataset_name", "question"],
                },
                outputSchema={"type": "object", "properties": {"plan": {"type": "object"}, "rows": {"type": "array"}}},
            ),
            Tool(
                name="generate_measure_suite",
                description="Generate a suite of related measures for a table based on a pattern (time intelligence, ratios, ranking, column stats). Returns the generated measures as DAX; use target='none' to preview without writing. This is a read-only preview tool - actual measure creation requires write tools not available in REST-only mode.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "kind": {"type": "string", "enum": ["time_intelligence", "ratios", "ranking", "column_stats"], "description": "Pattern preset"},
                        "table_name": {"type": "string", "description": "Table to generate measures for"},
                        "base_column": {"type": "string", "description": "Base column for aggregations (for time_intelligence, ratios, column_stats)"},
                        "base_measure": {"type": "string", "description": "Base measure for ratios/ranking"},
                        "target": {"type": "string", "enum": ["none", "pbip", "live"], "default": "none", "description": "Write target: none=preview only (REST-only mode), pbip=offline TMDL, live=TOM (not available in REST-only mode)"},
                        "skip_validation": {"type": "boolean", "default": False, "description": "Skip DAX linting (default: false)"},
                    },
                    "required": ["kind"],
                },
                outputSchema={"type": "object", "properties": {"measures": {"type": "array"}, "written": {"type": "boolean"}, "target": {"type": "string"}}},
            ),
        ]

    def _semantic_model_from_rest_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        g = self._row_get
        tables = {g(r, "Name"): {"name": g(r, "Name"), "is_hidden": bool(g(r, "IsHidden")),
                 "description": g(r, "Description") or "", "columns": [], "measures": []}
                  for r in metadata.get("tables", []) if g(r, "Name")}
        for r in metadata.get("columns", []):
            table = g(r, "Table") or g(r, "TableName")
            if not table:
                continue
            tables.setdefault(table, {"name": table, "is_hidden": False, "description": "", "columns": [], "measures": []})
            tables[table]["columns"].append({"name": g(r, "Name"), "data_type": g(r, "DataType"),
                "is_hidden": bool(g(r, "IsHidden")), "description": g(r, "Description") or "",
                "summarize_by": g(r, "SummarizeBy"), "data_category": g(r, "DataCategory")})
        for r in metadata.get("measures", []):
            table = g(r, "Table") or g(r, "TableName")
            tables.setdefault(table, {"name": table, "is_hidden": False, "description": "", "columns": [], "measures": []})
            tables[table]["measures"].append({"name": g(r, "Name"), "expression": g(r, "Expression"),
                "format_string": g(r, "FormatString"), "description": g(r, "Description") or "",
                "is_hidden": bool(g(r, "IsHidden"))})
        relationships = [{"from_table": g(r, "FromTable"), "from_column": g(r, "FromColumn"),
            "to_table": g(r, "ToTable"), "to_column": g(r, "ToColumn"), "is_active": g(r, "IsActive")}
            for r in metadata.get("relationships", [])]
        return {"dataset": metadata.get("dataset", {}), "tables": list(tables.values()), "relationships": relationships}

    async def _handle_describe_semantic_model(self, args: Dict[str, Any]):
        workspace = args.get("workspace_name")
        dataset = args.get("dataset_name")
        if not workspace or not dataset:
            return ("Error: workspace_name and dataset_name are required", {"error": "missing_arguments"})
        connector, workspace_id, dataset_id, err = await self._resolve_rest_dataset(workspace, dataset)
        if err:
            return (f"Error: {err}", {"error": err})
        metadata = await asyncio.get_event_loop().run_in_executor(None, connector.get_semantic_model_metadata, workspace_id, dataset_id)
        model = self._semantic_model_from_rest_metadata(metadata)
        visible_tables = [t for t in model["tables"] if not t.get("is_hidden")]
        measures = [m for t in visible_tables for m in t.get("measures", []) if not m.get("is_hidden")]
        guidance = [
            "Use visible measures first for business metrics; only generate DAX when no suitable measure exists.",
            "Use table/column descriptions and relationships to choose dimensions and filters.",
            "All query execution is read-only through the Power BI REST Execute Queries API.",
        ]
        text = f"Semantic model '{dataset}' has {len(visible_tables)} visible table(s), {len(measures)} visible measure(s), and {len(model['relationships'])} relationship(s)."
        return (text + "\n\n" + json.dumps({"model": model, "guidance": guidance}, indent=2, default=str), {"model": model, "guidance": guidance})

    async def _handle_answer_query_plan(self, args: Dict[str, Any]):
        question = (args.get("question") or "").strip()
        if not question:
            return ("Error: question is required", {"error": "question is required"})
        desc_text, desc = await self._handle_describe_semantic_model(args)
        if "error" in desc:
            return (desc_text, desc)
        model = desc["model"]
        qwords = {w.lower() for w in re.findall(r"[A-Za-z0-9_]+", question) if len(w) > 2}
        candidates = []
        for table in model.get("tables", []):
            for measure in table.get("measures", []):
                hay = " ".join([measure.get("name") or "", measure.get("description") or "", table.get("name") or ""]).lower()
                score = sum(1 for w in qwords if w in hay)
                if score:
                    candidates.append({"table": table.get("name"), "measure": measure.get("name"), "score": score, "description": measure.get("description")})
        candidates.sort(key=lambda x: x["score"], reverse=True)
        chosen = candidates[:5]
        draft_dax = None
        if chosen:
            measure = chosen[0]["measure"]
            draft_dax = f'EVALUATE ROW("{measure}", [{measure}])'
        else:
            first_table = next((t for t in model.get("tables", []) if not t.get("is_hidden")), None)
            if first_table:
                draft_dax = f"EVALUATE TOPN({int(args.get('max_rows', 100))}, '{first_table['name']}')"
        plan = {"question": question, "candidate_measures": chosen, "draft_dax": draft_dax,
                "recommendation": "use_existing_measure" if chosen else "generate_exploratory_dax"}
        rows = []
        if args.get("execute") and draft_dax:
            connector, workspace_id, dataset_id, err = await self._resolve_rest_dataset(args.get("workspace_name"), args.get("dataset_name"))
            if err:
                plan["execution_error"] = err
            else:
                rows = await asyncio.get_event_loop().run_in_executor(None, connector.execute_dax_query, workspace_id, dataset_id, draft_dax)
        text = json.dumps({"plan": plan, "rows": rows}, indent=2, default=str)
        return (text, {"plan": plan, "rows": rows})

    def _setup_handlers(self):
        """Set up MCP tool handlers"""

        if not hasattr(self.server, "list_tools"):
            async def list_tools_v2(ctx, params: PaginatedRequestParams | None = None):
                tools = self._semantic_agent_tools() + [
                    Tool(name="list_workspaces", description="List Power BI Service workspaces accessible to the service principal", inputSchema={"type": "object", "properties": {}, "required": []}),
                    Tool(name="list_datasets", description="List datasets in a workspace", inputSchema={"type": "object", "properties": {"workspace_id": {"type": "string"}}, "required": ["workspace_id"]}),
                    Tool(name="list_tables", description="List visible tables in a semantic model using REST Execute Queries", inputSchema={"type": "object", "properties": {"workspace_name": {"type": "string"}, "dataset_name": {"type": "string"}}, "required": ["workspace_name", "dataset_name"]}),
                    Tool(name="list_columns", description="List columns for a table using REST Execute Queries", inputSchema={"type": "object", "properties": {"workspace_name": {"type": "string"}, "dataset_name": {"type": "string"}, "table_name": {"type": "string"}}, "required": ["workspace_name", "dataset_name", "table_name"]}),
                    Tool(name="execute_dax", description="Execute a read-only DAX query through the Power BI REST Execute Queries API", inputSchema={"type": "object", "properties": {"workspace_name": {"type": "string"}, "dataset_name": {"type": "string"}, "dax_query": {"type": "string"}, "max_rows": {"type": "integer", "default": 100}}, "required": ["workspace_name", "dataset_name", "dax_query"]}),
                    Tool(name="get_model_info", description="Summarize a semantic model through REST metadata", inputSchema={"type": "object", "properties": {"workspace_name": {"type": "string"}, "dataset_name": {"type": "string"}}, "required": ["workspace_name", "dataset_name"]}),
                    Tool(name="security_status", description="Get security settings", inputSchema={"type": "object", "properties": {}, "required": []}),
                    Tool(name="security_audit_log", description="Read recent audit log entries", inputSchema={"type": "object", "properties": {"count": {"type": "integer", "default": 10}}, "required": []}),
                    Tool(name="validate_dax", description="Validate read-only DAX through REST Execute Queries", inputSchema={"type": "object", "properties": {"workspace_name": {"type": "string"}, "dataset_name": {"type": "string"}, "dax": {"type": "string"}, "as_measure": {"type": "boolean", "default": False}}, "required": ["workspace_name", "dataset_name", "dax"]}),
                ]
                for t in tools:
                    annotations = self._tool_annotations.get(t.name)
                    if annotations is not None:
                        t.annotations = annotations
                return ListToolsResult(tools=tools)

            async def call_tool_v2(ctx, params: CallToolRequestParams):
                name = params.name
                args = params.arguments or {}
                handler = self._tool_dispatch.get(name)
                if handler is None:
                    return CallToolResult(content=[TextContent(type="text", text=f"Unknown tool: {name}")], isError=True)
                result = await handler(args)
                if isinstance(result, tuple) and len(result) == 2:
                    text, structured = result
                    return CallToolResult(content=[TextContent(type="text", text=redact_secrets(text, [self.client_secret]))], structuredContent=structured)
                return CallToolResult(content=[TextContent(type="text", text=redact_secrets(result, [self.client_secret]))])

            async def list_resources_v2(ctx, params: PaginatedRequestParams | None = None):
                return ListResourcesResult(resources=[
                    Resource(uri="powerbi://reference/bpa-rules", name="bpa_rules", title="Best Practice Analyzer rules", description="Built-in BPA rule catalog", mimeType="application/json"),
                    Resource(uri="powerbi://reference/refresh-errors", name="refresh_errors", title="Refresh error remediation map", description="Known refresh failure causes and fixes", mimeType="application/json"),
                ])

            async def list_resource_templates_v2(ctx, params: PaginatedRequestParams | None = None):
                return ListResourceTemplatesResult(resourceTemplates=[
                    ResourceTemplate(uriTemplate="powerbi://cloud/{workspace}/{dataset}/schema", name="cloud_schema", title="Cloud model schema", description="Semantic model schema through REST", mimeType="application/json"),
                ])

            async def read_resource_v2(ctx, params: ReadResourceRequestParams):
                text = await self._read_resource(str(params.uri))
                return ReadResourceResult(contents=[TextResourceContents(uri=params.uri, mimeType="application/json", text=text)])

            async def list_prompts_v2(ctx, params: PaginatedRequestParams | None = None):
                return ListPromptsResult(prompts=[Prompt(name=n, title=p.get("title", n), description=p["description"], arguments=p.get("arguments", [])) for n, p in self._prompts.items()])

            async def get_prompt_v2(ctx, params: GetPromptRequestParams):
                p = self._prompts.get(params.name)
                if not p:
                    raise ValueError(f"Unknown prompt: {params.name}")
                text = p["render"](params.arguments or {})
                return GetPromptResult(description=p["description"], messages=[PromptMessage(role="user", content=TextContent(type="text", text=text))])

            async def complete_v2(ctx, params: CompleteRequestParams):
                completion = await self._complete_argument(params.argument)
                return CompleteResult(completion=completion)

            self.server.add_request_handler("tools/list", PaginatedRequestParams, list_tools_v2)
            self.server.add_request_handler("tools/call", CallToolRequestParams, call_tool_v2)
            self.server.add_request_handler("resources/list", PaginatedRequestParams, list_resources_v2)
            self.server.add_request_handler("resources/templates/list", PaginatedRequestParams, list_resource_templates_v2)
            self.server.add_request_handler("resources/read", ReadResourceRequestParams, read_resource_v2)
            self.server.add_request_handler("prompts/list", PaginatedRequestParams, list_prompts_v2)
            self.server.add_request_handler("prompts/get", GetPromptRequestParams, get_prompt_v2)
            self.server.add_request_handler("completion/complete", CompleteRequestParams, complete_v2)
            return

        @self.server.list_tools()
        async def handle_list_tools() -> List[Tool]:
            """Return list of available tools"""
            tools = []
            tools = [t for t in tools if t.name in self._REST_READONLY_TOOLS]
            tools.extend(self._semantic_agent_tools())
            # Attach MCP safety/behavior hints from the annotations registry.
            for t in tools:
                annotations = self._tool_annotations.get(t.name)
                if annotations is not None:
                    t.annotations = annotations
            return tools

        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: Optional[Dict[str, Any]]) -> List[TextContent]:
            """Handle tool calls"""
            try:
                args = arguments or {}
                logger.info(f"Tool called: {name}")
                # Arguments can carry DAX (with PII literals) or secrets; only log at DEBUG, redacted.
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(
                        f"Tool args ({name}): "
                        f"{redact_secrets(json.dumps(args, default=str), [self.client_secret])}"
                    )

                handler = self._tool_dispatch.get(name)
                if handler is None:
                    return [TextContent(type="text", text=f"Unknown tool: {name}")]

                result = await handler(args)
                # Handlers return either a plain string (text only) or a
                # (text, structured_dict) tuple for tools that declare an outputSchema.
                # The MCP SDK puts the dict in structuredContent for typed, chainable results.
                # Defense in depth: redact connection-string secrets from the text at the
                # boundary, so a handler that swallows an exception and returns its raw message
                # cannot leak the service-principal secret to the model.
                if isinstance(result, tuple) and len(result) == 2:
                    text, structured = result
                    if isinstance(text, str):
                        text = redact_secrets(text, [self.client_secret])
                    return [TextContent(type="text", text=text)], structured
                if isinstance(result, str):
                    result = redact_secrets(result, [self.client_secret])
                return [TextContent(type="text", text=result)]

            except Exception as e:
                safe_err = redact_secrets(str(e), [self.client_secret])
                logger.error(f"Error executing {name}: {safe_err}", exc_info=True)
                return [TextContent(type="text", text=f"Error executing {name}: {safe_err}")]

        # ---------- MCP Resources: model context without spending a tool call ----------
        @self.server.list_resources()
        async def handle_list_resources():
            return [
                Resource(uri="powerbi://reference/bpa-rules", name="bpa_rules",
                         title="Best Practice Analyzer rules",
                         description="The built-in BPA rule catalog (id, category, severity, name)",
                         mimeType="application/json"),
                Resource(uri="powerbi://reference/refresh-errors", name="refresh_errors",
                         title="Refresh error remediation map",
                         description="Known refresh failure causes and their fixes (used by refresh_doctor)",
                         mimeType="application/json"),
            ]

        @self.server.list_resource_templates()
        async def handle_list_resource_templates():
            return [
                ResourceTemplate(uriTemplate="powerbi://cloud/{workspace}/{dataset}/schema",
                                 name="cloud_schema", title="Cloud model schema",
                                 description="Schema of a published semantic model via the XMLA endpoint",
                                 mimeType="application/json"),
            ]

        @self.server.read_resource()
        async def handle_read_resource(uri):
            return await self._read_resource(str(uri))

        # ---------- MCP Prompts: reusable guided BI workflows ----------
        @self.server.list_prompts()
        async def handle_list_prompts():
            return [
                Prompt(name=n, title=p.get("title", n), description=p["description"],
                       arguments=p.get("arguments", []))
                for n, p in self._prompts.items()
            ]

        @self.server.get_prompt()
        async def handle_get_prompt(name, arguments):
            p = self._prompts.get(name)
            if not p:
                raise ValueError(f"Unknown prompt: {name}")
            text = p["render"](arguments or {})
            return GetPromptResult(
                description=p["description"],
                messages=[PromptMessage(role="user", content=TextContent(type="text", text=text))],
            )

        # ---------- MCP Completion: ground arguments in real model object names ----------
        @self.server.completion()
        async def handle_completion(ref, argument, context):
            return await self._complete_argument(argument)

    # ==================== DESKTOP HANDLERS ====================


    # ==================== CLOUD HANDLERS ====================

    def _get_rest_connector(self) -> Optional[PowerBIRestConnector]:
        """Get or create REST connector"""
        if not self.tenant_id or not self.client_id or not self.client_secret:
            logger.warning("Cloud credentials not configured")
            return None

        if not self.rest_connector:
            self.rest_connector = PowerBIRestConnector(
                self.tenant_id, self.client_id, self.client_secret
            )
        return self.rest_connector

    async def _handle_list_workspaces(self) -> str:
        """List Power BI Service workspaces"""
        try:
            connector = self._get_rest_connector()
            if not connector:
                return "Error: Cloud credentials not configured. Set TENANT_ID, CLIENT_ID, CLIENT_SECRET in .env"

            workspaces = await asyncio.get_event_loop().run_in_executor(
                None, connector.list_workspaces
            )

            if not workspaces:
                return "No workspaces found or authentication failed."

            result = f"Power BI Workspaces ({len(workspaces)}):\n\n"
            for ws in workspaces:
                result += f"  - {ws['name']}\n"
                result += f"    ID: {ws['id']}\n\n"

            return result

        except Exception as e:
            logger.error(f"List workspaces error: {e}")
            return f"Error listing workspaces: {str(e)}"

    async def _handle_list_datasets(self, args: Dict[str, Any]) -> str:
        """List datasets in a workspace"""
        try:
            connector = self._get_rest_connector()
            workspace_id = args.get("workspace_id")

            if not connector:
                return "Error: Cloud credentials not configured."

            if not workspace_id:
                return "Error: workspace_id is required"

            datasets = await asyncio.get_event_loop().run_in_executor(
                None, connector.list_datasets, workspace_id
            )

            if not datasets:
                return "No datasets found in this workspace."

            result = f"Datasets ({len(datasets)}):\n\n"
            for ds in datasets:
                result += f"  - {ds['name']}\n"
                result += f"    ID: {ds['id']}\n"
                result += f"    Configured by: {ds.get('configuredBy', 'Unknown')}\n\n"

            return result

        except Exception as e:
            logger.error(f"List datasets error: {e}")
            return f"Error listing datasets: {str(e)}"


    async def _resolve_rest_dataset(self, workspace_name: str, dataset_name: str):
        connector = self._get_rest_connector()
        if not connector:
            return None, None, None, "Error: Cloud credentials not configured."
        loop = asyncio.get_event_loop()
        ws_id, ds_id, err = await loop.run_in_executor(None, connector.resolve_dataset, workspace_name, dataset_name)
        return connector, ws_id, ds_id, err

    @staticmethod
    def _normalize_info_rows(rows):
        normalized = []
        for row in rows or []:
            normalized.append({str(k).strip("[]"): v for k, v in row.items()})
        return normalized

    async def _handle_list_tables(self, args: Dict[str, Any]) -> str:
        """List tables in a Cloud dataset"""
        try:
            workspace_name = args.get("workspace_name")
            dataset_name = args.get("dataset_name")

            if not workspace_name or not dataset_name:
                return "Error: workspace_name and dataset_name are required"

            connector, workspace_id, dataset_id, err = await self._resolve_rest_dataset(workspace_name, dataset_name)
            if err:
                return f"Error: {err}"
            rows = await asyncio.get_event_loop().run_in_executor(
                None, connector.execute_dax_query, workspace_id, dataset_id, "EVALUATE INFO.VIEW.TABLES()"
            )
            tables = self._normalize_info_rows(rows)

            result = f"Tables in '{dataset_name}' ({len(tables)}):\n\n"
            for table in tables:
                if not table.get("IsHidden", False):
                    result += f"  - {table.get('Name', 'Unknown')}\n"

            return result

        except Exception as e:
            logger.error(f"List tables error: {e}")
            return f"Error listing tables: {str(e)}"

    async def _handle_list_columns(self, args: Dict[str, Any]) -> str:
        """List columns for a table in Cloud dataset"""
        try:
            workspace_name = args.get("workspace_name")
            dataset_name = args.get("dataset_name")
            table_name = args.get("table_name")

            if not all([workspace_name, dataset_name, table_name]):
                return "Error: workspace_name, dataset_name, and table_name are required"

            connector, workspace_id, dataset_id, err = await self._resolve_rest_dataset(workspace_name, dataset_name)
            if err:
                return f"Error: {err}"
            query = f'EVALUATE FILTER(INFO.VIEW.COLUMNS(), [Table] = "{str(table_name).replace(chr(34), chr(34)+chr(34))}")'
            rows = await asyncio.get_event_loop().run_in_executor(
                None, connector.execute_dax_query, workspace_id, dataset_id, query
            )
            columns = self._normalize_info_rows(rows)
            result = f"Columns in '{table_name}' ({len(columns)}):\n\n"
            for col in columns:
                result += f"  - {col.get('Name', 'Unknown')} ({col.get('DataType', 'Unknown')})\n"

            return result

        except Exception as e:
            logger.error(f"List columns error: {e}")
            return f"Error listing columns: {str(e)}"

    async def _handle_execute_dax(self, args: Dict[str, Any]) -> str:
        """Execute DAX on Cloud dataset with security processing"""
        try:
            workspace_name = args.get("workspace_name")
            dataset_name = args.get("dataset_name")
            dax_query = args.get("dax_query")

            if not all([workspace_name, dataset_name, dax_query]):
                return "Error: workspace_name, dataset_name, and dax_query are required"

            # Pre-query security check (resolve referenced tables/columns so column policies fire)
            ref_tables, ref_columns = AccessPolicyEngine.extract_references(dax_query)
            policy_check = self.security.pre_query_check(
                dax_query, tables=ref_tables, columns=ref_columns
            )
            if not policy_check.allowed:
                self.security.log_policy_violation(
                    policy_name="query_policy",
                    violation_type=policy_check.reason,
                    query=dax_query
                )
                return f"Query blocked by security policy: {policy_check.reason}"

            # Determine a row cap (cloud execute_dax is otherwise unbounded). Honor an explicit
            # max_rows, clamp to policy, and enforce an absolute ceiling to protect memory.
            cap = policy_check.max_rows or 10000
            requested = args.get("max_rows")
            max_rows = min(requested, cap) if requested else cap
            max_rows = min(max_rows, 100000)

            connector, workspace_id, dataset_id, err = await self._resolve_rest_dataset(workspace_name, dataset_name)
            if err:
                return f"Error: {err}"

            # Execute query with timing via REST Execute Queries API
            start_time = time.time()
            rows = await asyncio.get_event_loop().run_in_executor(
                None, connector.execute_dax_query, workspace_id, dataset_id, dax_query
            )
            duration_ms = (time.time() - start_time) * 1000

            # Enforce the row cap (XMLA connector does not cap internally)
            truncated = False
            if isinstance(rows, list) and len(rows) > max_rows:
                rows = rows[:max_rows]
                truncated = True

            # Process results through security layer
            safe_rows, security_report = self.security.process_results(
                results=rows,
                query=dax_query,
                source="cloud",
                model_name=dataset_name,
                duration_ms=duration_ms,
                success=True
            )

            # Build response
            result = f"Query returned {len(safe_rows)} row(s)"

            # Add security notices
            if security_report.get('pii_detected'):
                result += f"\n⚠️ PII detected and masked: {security_report['pii_count']} instance(s) of {', '.join(security_report['pii_types'])}"

            if security_report.get('columns_blocked'):
                result += f"\n🚫 Blocked columns: {', '.join(security_report['columns_blocked'])}"

            if truncated:
                result += f"\n(Note: result truncated to the first {max_rows} rows)"

            result += "\n\n"
            result += json.dumps(safe_rows, indent=2, default=str)

            return result

        except Exception as e:
            safe = redact_secrets(str(e), [self.client_secret])
            logger.error(f"Execute DAX error: {safe}")
            # Log failed query to audit (redacted: a connection-string error can carry the secret)
            self.security.process_results(
                results=[],
                query=args.get("dax_query", ""),
                source="cloud",
                success=False,
                error_message=safe
            )
            return f"Error executing DAX: {safe}"

    async def _handle_get_model_info(self, args: Dict[str, Any]) -> str:
        """Get model info from a Power BI semantic model through REST only."""
        text, structured = await self._handle_describe_semantic_model(args)
        if structured.get("error"):
            return text
        model = structured["model"]
        result = f"=== Semantic Model Info: {args.get('dataset_name')} ===\n\n"
        for table in model.get("tables", []):
            if table.get("is_hidden"):
                continue
            result += f"- {table['name']}: {len(table.get('columns', []))} columns, {len(table.get('measures', []))} measures\n"
            for measure in table.get("measures", [])[:10]:
                result += f"  measure: [{measure.get('name')}]\n"
        result += f"\nRelationships: {len(model.get('relationships', []))}\n"
        return result

    # ==================== SECURITY HANDLERS ====================

    async def _handle_security_status(self) -> str:
        """Get security layer status"""
        try:
            status = self.security.get_status()
            policy_summary = self.security.get_policy_summary()

            result = "=== Power BI MCP Security Status ===\n\n"

            # Enabled features
            result += "--- Features ---\n"
            enabled = status.get('enabled', {})
            result += f"  PII Detection:    {'✅ Enabled' if enabled.get('pii_detection') else '❌ Disabled'}\n"
            result += f"  Audit Logging:    {'✅ Enabled' if enabled.get('audit_logging') else '❌ Disabled'}\n"
            result += f"  Access Policies:  {'✅ Enabled' if enabled.get('access_policies') else '❌ Disabled'}\n\n"

            # PII Detection settings
            if enabled.get('pii_detection'):
                pii = status.get('pii_detector', {})
                result += "--- PII Detection ---\n"
                result += f"  Strategy: {pii.get('strategy', 'N/A')}\n"
                result += f"  Types: {', '.join(pii.get('enabled_types', []))}\n\n"

            # Policy settings
            if enabled.get('access_policies'):
                result += "--- Access Policies ---\n"
                result += f"  Enabled: {policy_summary.get('enabled', False)}\n"
                result += f"  Max rows per query: {policy_summary.get('max_rows', 'N/A')}\n"
                result += f"  Tables with policies: {len(policy_summary.get('tables_with_policies', []))}\n\n"

            # Audit log info
            if enabled.get('audit_logging'):
                audit = status.get('audit', {})
                result += "--- Audit Log ---\n"
                result += f"  Session ID: {audit.get('session_id', 'N/A')}\n"
                result += f"  Queries logged: {audit.get('query_count', 0)}\n"
                result += f"  Log file: {audit.get('log_file', 'N/A')}\n"

            return result

        except Exception as e:
            logger.error(f"Security status error: {e}")
            return f"Error getting security status: {str(e)}"

    async def _handle_security_audit_log(self, args: Dict[str, Any]) -> str:
        """View recent audit log entries"""
        try:
            count = args.get("count", 10)

            if not self.security.enable_audit or not self.security.audit_logger:
                return "Audit logging is not enabled."

            events = self.security.audit_logger.get_recent_events(count)

            if not events:
                return "No audit log entries found."

            result = f"=== Recent Audit Log ({len(events)} entries) ===\n\n"

            for event in events[-count:]:
                timestamp = event.get('timestamp', 'N/A')
                event_type = event.get('event_type', 'unknown')
                severity = event.get('severity', 'info')

                result += f"[{timestamp}] [{severity.upper()}] {event_type}\n"

                # Show details based on event type
                if event_type in ('query_success', 'query_failure'):
                    query_info = event.get('query', {})
                    result_info = event.get('result', {})
                    pii_info = event.get('pii', {})

                    result += f"  Query: {query_info.get('fingerprint', 'N/A')}\n"
                    result += f"  Rows: {result_info.get('row_count', 0)}, Duration: {result_info.get('duration_ms', 0):.0f}ms\n"

                    if pii_info.get('detected'):
                        result += f"  ⚠️ PII: {pii_info.get('count', 0)} instances\n"

                elif event_type == 'policy_violation':
                    details = event.get('details', {})
                    result += f"  Policy: {details.get('policy', 'N/A')}\n"
                    result += f"  Violation: {details.get('violation', 'N/A')}\n"

                result += "\n"

            return result

        except Exception as e:
            logger.error(f"Audit log error: {e}")
            return f"Error reading audit log: {str(e)}"

    # ==================== DAX SAFETY LOOP (Bundle A) ====================

    async def _handle_validate_dax(self, args: Dict[str, Any]):
        """Validate DAX (query or scalar measure expression) without committing.

        Returns (text, {valid, error, probe}) so agents get a typed result.
        """
        dax = args.get("dax")
        probe = build_validation_probe(dax or "", bool(args.get("as_measure", False)))
        if not dax:
            return ("Error: dax is required", {"valid": False, "error": "dax is required", "probe": probe})
        source = "cloud"
        loop = asyncio.get_event_loop()
        try:
            workspace = args.get("workspace_name")
            dataset = args.get("dataset_name")
            if not (workspace and dataset):
                msg = "Error: workspace_name and dataset_name are required for REST validation"
                return (msg, {"valid": False, "error": msg, "probe": probe})
            connector, workspace_id, dataset_id, err = await self._resolve_rest_dataset(workspace, dataset)
            if err:
                return (f"Error: {err}", {"valid": False, "error": err, "probe": probe})
            await loop.run_in_executor(None, connector.execute_dax_query, workspace_id, dataset_id, probe)
            return (
                f"[VALID] DAX validated successfully against the model.\n\nProbe executed:\n{probe}",
                {"valid": True, "error": None, "probe": probe},
            )
        except Exception as e:
            msg = redact_secrets(str(e), [self.client_secret])
            return (
                f"[INVALID] DAX failed validation.\n\nError:\n{msg}\n\nProbe:\n{probe}",
                {"valid": False, "error": msg, "probe": probe},
            )

    @staticmethod
    def _row_get(row: Dict[str, Any], *names):
        """Read a field from an INFO.* result row tolerating bracketed/cased key variants."""
        for n in names:
            for k in (n, f"[{n}]", n.lower(), f"[{n.lower()}]", n.upper(), f"[{n.upper()}]"):
                if k in row:
                    return row[k]
        return None

    # ==================== MODEL ANALYSIS (Bundle B) ====================

    async def _get_query_runner(self, source: str, workspace=None, dataset=None):
        """Return (run, error): a synchronous DAX executor for the chosen source.

        run(query_str) -> list[dict]. Used by analysis tools that issue INFO/DMV/DAX queries.
        """
        if not (workspace and dataset):
            return None, "workspace_name and dataset_name are required"
        connector, workspace_id, dataset_id, err = await self._resolve_rest_dataset(workspace, dataset)
        if err:
            return None, err
        return (lambda q: connector.execute_dax_query(workspace_id, dataset_id, q)), None

    async def _gather_model_metadata(self, source: str, workspace=None, dataset=None):
        """Build a normalized model dict (for BPA / AI-readiness) via INFO.VIEW.* DAX.

        Returns (model_dict, error).
        """
        run, err = await self._get_query_runner(source, workspace, dataset)
        if err:
            return None, err
        loop = asyncio.get_event_loop()
        g = self._row_get

        async def q(query):
            return await loop.run_in_executor(None, run, query)

        try:
            tables_rows = await q("EVALUATE INFO.VIEW.TABLES()")
            cols_rows = await q("EVALUATE INFO.VIEW.COLUMNS()")
            meas_rows = await q("EVALUATE INFO.VIEW.MEASURES()")
        except Exception as e:
            return None, (f"could not read model metadata via INFO.VIEW: {e}. "
                          "INFO.VIEW.* requires a recent Analysis Services engine.")
        try:
            rel_rows = await q("EVALUATE INFO.VIEW.RELATIONSHIPS()")
        except Exception:
            rel_rows = []

        tmap: Dict[str, Any] = {}
        for r in tables_rows:
            nm = g(r, "Name")
            if nm is None:
                continue
            tmap[nm] = {"name": nm, "is_hidden": g(r, "IsHidden"),
                        "description": g(r, "Description") or "", "columns": [], "measures": []}
        for r in cols_rows:
            tn = g(r, "Table")
            tmap.setdefault(tn, {"name": tn, "is_hidden": False, "description": "", "columns": [], "measures": []})
            ctype = str(g(r, "ColumnType") or "").lower()
            tmap[tn]["columns"].append({
                "name": g(r, "Name"), "table": tn, "data_type": g(r, "DataType"),
                "is_hidden": g(r, "IsHidden"), "is_key": g(r, "IsKey"),
                "summarize_by": g(r, "SummarizeBy"), "sort_by": g(r, "SortByColumn"),
                "description": g(r, "Description") or "", "display_folder": g(r, "DisplayFolder"),
                "data_category": g(r, "DataCategory"), "is_calculated": ctype == "calculated",
                "expression": g(r, "Expression"),
            })
        for r in meas_rows:
            tn = g(r, "Table")
            tmap.setdefault(tn, {"name": tn, "is_hidden": False, "description": "", "columns": [], "measures": []})
            tmap[tn]["measures"].append({
                "name": g(r, "Name"), "table": tn, "expression": g(r, "Expression"),
                "format_string": g(r, "FormatString"), "description": g(r, "Description") or "",
                "display_folder": g(r, "DisplayFolder"), "is_hidden": g(r, "IsHidden"),
                "data_type": g(r, "DataType"),
            })
        rels = []
        for r in rel_rows:
            rels.append({
                "from_table": g(r, "FromTable"), "from_column": g(r, "FromColumn"),
                "to_table": g(r, "ToTable"), "to_column": g(r, "ToColumn"),
                "is_active": g(r, "IsActive"),
                "cross_filter": g(r, "CrossFilteringBehavior", "CrossFilterDirection"),
                "from_cardinality": g(r, "FromCardinality"), "to_cardinality": g(r, "ToCardinality"),
            })
        return {"tables": list(tmap.values()), "relationships": rels}, None

    async def _handle_run_bpa(self, args: Dict[str, Any]):
        """Run the Best Practice Analyzer over the connected model. Returns (text, result)."""
        try:
            model, err = await self._gather_model_metadata(
                "cloud", args.get("workspace_name"), args.get("dataset_name")
            )
            if err:
                return (f"Error: {err}", {"error": err, "summary": {"total": 0}, "findings": []})
            result = model_analysis.run_bpa(
                model, categories=args.get("categories"),
                min_severity=(args.get("min_severity") or "info"),
            )
            s = result["summary"]
            out = "=== Best Practice Analyzer ===\n\n"
            out += f"Findings: {s['total']}  (errors: {s['by_severity'].get('error', 0)}, "
            out += f"warnings: {s['by_severity'].get('warning', 0)}, info: {s['by_severity'].get('info', 0)})\n"
            if s["by_category"]:
                out += "By category: " + ", ".join(f"{k}={v}" for k, v in s["by_category"].items()) + "\n"
            out += "\n"
            current_rule = None
            for f in result["findings"][:200]:
                if f["rule_id"] != current_rule:
                    current_rule = f["rule_id"]
                    out += f"--- [{f['severity'].upper()}] {f['name']} ({f['category']}) ---\n"
                out += f"  - {f['object']}: {f['detail']}\n"
            if s["total"] > 200:
                out += f"\n... and {s['total'] - 200} more findings (filter by category or min_severity).\n"
            if s["total"] == 0:
                out += "No issues found for the selected rules.\n"
            return (out, result)
        except Exception as e:
            msg = redact_secrets(str(e), [self.client_secret])
            return (f"Error running BPA: {msg}", {"error": msg, "summary": {"total": 0}, "findings": []})

    async def _handle_audit_ai_readiness(self, args: Dict[str, Any]):
        """Score how AI-ready (Copilot/agent-ready) the connected model is. Returns (text, result)."""
        try:
            model, err = await self._gather_model_metadata(
                "cloud", args.get("workspace_name"), args.get("dataset_name")
            )
            if err:
                return (f"Error: {err}", {"error": err, "score": 0})
            r = model_analysis.audit_ai_readiness(model)
            m = r["metrics"]
            out = "=== AI-Readiness Audit ===\n\n"
            out += f"Score: {r['score']}/100  (Grade {r['grade']})\n\n"
            out += "--- Metrics ---\n"
            out += f"  Measures with descriptions: {m['measures_with_description_pct']}% of {m['measures_total']}\n"
            out += f"  Measures with format string: {m['measures_with_format_pct']}%\n"
            out += f"  Visible columns with descriptions: {m['columns_with_description_pct']}% of {m['visible_columns_total']}\n"
            out += f"  Tables with descriptions: {m['tables_with_description_pct']}% of {m['tables_total']}\n\n"
            out += "--- Recommendations ---\n"
            for rec in r["recommendations"]:
                out += f"  - {rec}\n"
            return (out, r)
        except Exception as e:
            msg = redact_secrets(str(e), [self.client_secret])
            return (f"Error auditing AI-readiness: {msg}", {"error": msg, "score": 0})

    def _measures_from_model(self, model: Dict[str, Any], measure_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Flatten {name, expression} for every measure in a gathered model, optionally filtered."""
        out: List[Dict[str, Any]] = []
        for t in model.get("tables", []):
            for m in t.get("measures", []):
                if measure_name and m.get("name") != measure_name:
                    continue
                out.append({"name": m.get("name"), "expression": m.get("expression") or ""})
        return out

    async def _handle_dax_lint(self, args: Dict[str, Any]):
        """Static DAX anti-pattern linter (raw expression, one measure, or whole model).
        Returns (text, result)."""
        try:
            min_rank = dax_lint.SEVERITY_RANK.get((args.get("min_severity") or "info").lower(), 1)
            expr = args.get("expression")
            if expr:
                measures = [{"name": args.get("name") or "(expression)", "expression": expr}]
            else:
                model, err = await self._gather_model_metadata(
                    "cloud", args.get("workspace_name"), args.get("dataset_name"))
                if err:
                    return (f"Error: {err}", {"error": err, "summary": {"total": 0}, "findings": []})
                measures = self._measures_from_model(model, args.get("measure_name"))
                if args.get("measure_name") and not measures:
                    return (f"Measure '{args.get('measure_name')}' not found in the model.",
                            {"error": "measure_not_found", "summary": {"total": 0}, "findings": []})
            result = dax_lint.lint_measures(measures)
            result["findings"] = [f for f in result["findings"]
                                  if dax_lint.SEVERITY_RANK.get(f["severity"], 0) >= min_rank]
            s = result["summary"]
            out = "=== DAX Lint ===\n\n"
            out += f"Scanned {s['measures_scanned']} expression(s); {len(result['findings'])} finding(s)"
            if s.get("by_severity"):
                out += "  (" + ", ".join(f"{k}: {v}" for k, v in s["by_severity"].items()) + ")"
            out += "\n\n"
            cur = None
            for f in result["findings"][:200]:
                if f.get("object") != cur:
                    cur = f.get("object")
                    out += f"--- {cur} ---\n"
                out += f"  [{f['severity'].upper()}] {f['rule_id']} (line {f['line']}): {f['message']}\n"
                out += f"      fix: {f['suggestion']}\n"
            if not result["findings"]:
                out += "No issues found.\n"
            return (out, result)
        except Exception as e:
            msg = redact_secrets(str(e), [self.client_secret])
            return (f"Error linting DAX: {msg}", {"error": msg, "summary": {"total": 0}, "findings": []})

    async def _handle_dax_suggest_rewrite(self, args: Dict[str, Any]):
        """Concrete before/after rewrite hints for auto-fixable DAX anti-patterns.
        Returns (text, result)."""
        try:
            expr = args.get("expression")
            rewrites: List[Dict[str, Any]] = []
            if expr:
                rewrites = dax_lint.suggest_rewrites(args.get("name") or "(expression)", expr)
            else:
                model, err = await self._gather_model_metadata(
                    "cloud", args.get("workspace_name"), args.get("dataset_name"))
                if err:
                    return (f"Error: {err}", {"error": err, "rewrites": []})
                for m in self._measures_from_model(model, args.get("measure_name")):
                    for h in dax_lint.suggest_rewrites(m["name"], m["expression"]):
                        h["object"] = m["name"]
                        rewrites.append(h)
            out = "=== DAX Rewrite Suggestions ===\n\n"
            if not rewrites:
                out += "No auto-fixable anti-patterns detected.\n"
            for h in rewrites[:100]:
                label = (h.get("object") + ": ") if h.get("object") else ""
                out += f"--- {label}{h['rule_id']} (line {h['line']}) ---\n"
                out += f"  before: {h['before']}\n  after:  {h['after']}\n  note:   {h['note']}\n\n"
            return (out, {"rewrites": rewrites})
        except Exception as e:
            msg = redact_secrets(str(e), [self.client_secret])
            return (f"Error suggesting rewrites: {msg}", {"error": msg, "rewrites": []})

    _SVG_PARAMS = {
        "progress": ["value_measure", "max_value", "min_value", "fill", "track", "width", "height"],
        "bullet": ["value_measure", "target_measure", "max_value", "fill", "target", "track", "width", "height"],
        "status_pill": ["value_measure", "thresholds", "width", "height"],
        "sparkline": ["axis_column", "value_measure", "sort_column", "stroke", "width", "height"],
    }

    async def _handle_bpa_validate_rules(self, args: Dict[str, Any]):
        """Validate a custom BPA rules JSON. Returns (text, result)."""
        try:
            rules = args.get("rules")
            path = args.get("rules_path")
            if rules is None and path:
                with open(path, "r", encoding="utf-8-sig") as f:
                    rules = f.read()
            if rules is None:
                return ("Error: provide 'rules' (JSON) or 'rules_path'.", {"error": "rules_required"})
            result = bpa_authoring.validate_rules(rules, fix=bool(args.get("fix")))
            out = "=== BPA Rules Validation ===\n\n"
            out += f"Rules: {result['rule_count']}  |  Valid: {result['valid']}  |  "
            out += f"Errors: {len(result['errors'])}  Warnings: {len(result['warnings'])}\n\n"
            for e in result["errors"][:100]:
                out += f"  [ERROR] {e.get('rule_id') or '(rule #' + str(e.get('index')) + ')'}: {e['message']}\n"
            for w in result["warnings"][:100]:
                out += f"  [WARN]  {w.get('rule_id') or '(rule #' + str(w.get('index')) + ')'}: {w['message']}\n"
            if result["valid"] and not result["warnings"]:
                out += "All rules conform.\n"
            return (out, result)
        except Exception as e:
            msg = redact_secrets(str(e), [self.client_secret])
            return (f"Error validating BPA rules: {msg}", {"error": msg, "valid": False})

    @staticmethod
    def _bpa_local_rule_paths() -> Dict[str, str]:
        paths: Dict[str, str] = {}
        la = os.environ.get("LOCALAPPDATA")
        pd = os.environ.get("PROGRAMDATA")
        if la:
            paths["user (TE2)"] = os.path.join(la, "TabularEditor", "BPARules.json")
            paths["user (TE3)"] = os.path.join(la, "TabularEditor3", "BPARules.json")
        if pd:
            paths["machine"] = os.path.join(pd, "TabularEditor", "BPARules.json")
        return paths

    async def _handle_bpa_audit_rule_sources(self, args: Dict[str, Any]):
        """Audit where BPA rules live for the loaded project. Returns (text, result)."""
        try:
            model_text = args.get("model_text")
            if not model_text:
                return ("No 'model_text' provided. PBIP functionality is not available in REST-only mode.",
                        {"error": "no_model_text"})
            local: Dict[str, str] = {}
            for label, p in self._bpa_local_rule_paths().items():
                try:
                    with open(p, "r", encoding="utf-8-sig") as fh:
                        local[label] = fh.read()
                except Exception:
                    continue
            result = bpa_authoring.audit_rule_sources(model_text, local_rule_files=local or None)
            out = "=== BPA Rule Sources ===\n\n"
            out += f"Embedded in model: {result['embedded_rule_count']} rule(s)\n"
            out += f"External rule files: {len(result['external_rule_files'])}\n"
            for u in result["external_rule_files"][:20]:
                out += f"  - {u}\n"
            out += f"Ignored rule IDs: {len(result['ignored_rule_ids'])}"
            if result["ignored_rule_ids"]:
                out += " (" + ", ".join(result["ignored_rule_ids"][:20]) + ")"
            out += "\n"
            for lf in result.get("local_rule_files", []):
                out += f"  local {lf.get('source')}: {lf.get('rule_count', lf.get('error'))}\n"
            return (out, result)
        except Exception as e:
            msg = redact_secrets(str(e), [self.client_secret])
            return (f"Error auditing BPA rule sources: {msg}", {"error": msg})

    # ==================== Wave 5: data modelling / warehousing / bulk DAX ====================

    @staticmethod
    def _render_measure_list(measures: List[Dict[str, Any]]) -> str:
        out = ""
        for m in measures:
            out += f"--- {m['name']} ---\n"
            if m.get("format_string"):
                out += f"  format: {m['format_string']}\n"
            if m.get("display_folder"):
                out += f"  folder: {m['display_folder']}\n"
            out += f"  {m['expression']}\n\n".replace("\n", "\n  ").rstrip() + "\n\n"
        return out

    def _suite_kwargs(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Map tool args onto dax_generator.generate_suite kwargs by kind."""
        kind = (args.get("kind") or "").lower()
        if kind in ("time_intelligence", "time", "ti"):
            kw = {"base_measure": args.get("base_measure"), "date_column": args.get("date_column"),
                  "variants": args.get("variants"), "display_folder": args.get("display_folder"),
                  "base_format": args.get("base_format")}
            if not kw["base_measure"] or not kw["date_column"]:
                raise ValueError("time_intelligence needs base_measure and date_column")
        elif kind in ("ratios", "ratio", "share"):
            kw = {"base_measure": args.get("base_measure"),
                  "dimension_columns": args.get("dimension_columns"),
                  "display_folder": args.get("display_folder")}
            if not kw["base_measure"] or not kw["dimension_columns"]:
                raise ValueError("ratios needs base_measure and dimension_columns")
        elif kind in ("ranking", "rank"):
            kw = {"base_measure": args.get("base_measure"),
                  "dimension_columns": args.get("dimension_columns"),
                  "display_folder": args.get("display_folder")}
            if not kw["base_measure"] or not kw["dimension_columns"]:
                raise ValueError("ranking needs base_measure and dimension_columns")
        elif kind in ("column_stats", "stats"):
            kw = {"column": args.get("column"), "stats": args.get("stats"),
                  "display_folder": args.get("display_folder")}
            if not kw["column"]:
                raise ValueError("column_stats needs column")
        else:
            raise ValueError(f"Unknown kind '{args.get('kind')}'")
        return {k: v for k, v in kw.items() if v is not None}

    async def _handle_generate_measure_suite(self, args: Dict[str, Any]):
        """Bulk-generate a measure suite as a read-only preview. Returns (text, result)."""
        try:
            target = (args.get("target") or "none").lower()
            if target not in ("none", "pbip", "live"):
                return (f"Error: unknown target '{target}'.", {"error": "bad_target", "measures": []})
            if target != "none":
                return ("Refused: writing a measure suite is a write operation and this server is REST-only and read-only. Use target='none' to generate a preview without writing.",
                        {"error": "read_only", "measures": []})
            measures = dax_generator.generate_suite(args.get("kind"), **self._suite_kwargs(args))
            result = {"measures": measures, "written": False, "target": target}
            out = f"=== Measure suite: {args.get('kind')} ({len(measures)} measures) ===\n\n"
            out += self._render_measure_list(measures)
            out += "\nNot written (target='none'). This is a read-only preview - actual measure creation requires write tools not available in REST-only mode."
            return (out, result)
        except ValueError as e:
            return (f"Error: {e}", {"error": str(e), "measures": []})
        except Exception as e:
            msg = redact_secrets(str(e), [self.client_secret])
            return (f"Error generating measure suite: {msg}", {"error": msg, "measures": []})

    @staticmethod
    def _dax_col(table: str, column: str) -> str:
        return ("'" + str(table).replace("'", "''") + "'["
                + str(column).replace("]", "]]") + "]")

    async def _handle_scan_referential_integrity(self, args: Dict[str, Any]):
        """Orphan-key scan across active relationships. Returns (text, result)."""
        try:
            source = "cloud"
            model, err = await self._gather_model_metadata(source, args.get("workspace_name"), args.get("dataset_name"))
            if err:
                return (f"Error: {err}", {"error": err, "checked": 0, "violations": []})
            run, err = await self._get_query_runner(source, args.get("workspace_name"), args.get("dataset_name"))
            if err:
                return (f"Error: {err}", {"error": err, "checked": 0, "violations": []})
            loop = asyncio.get_event_loop()
            try:
                max_samples = max(1, min(100, int(args.get("max_samples", 5) or 5)))
            except (TypeError, ValueError):
                max_samples = 5
            checked, violations = 0, []
            for r in model.get("relationships", []):
                if not (r.get("from_table") and r.get("from_column") and r.get("to_table") and r.get("to_column")):
                    continue
                active = r.get("is_active", True)
                if isinstance(active, str):
                    active = active.strip().lower() in ("true", "1", "yes")
                if not active:
                    continue
                fcol = self._dax_col(r["from_table"], r["from_column"])
                tcol = self._dax_col(r["to_table"], r["to_column"])
                q = (f"EVALUATE ROW(\"Orphans\", COUNTROWS(EXCEPT(DISTINCT({fcol}), DISTINCT({tcol}))))")
                try:
                    rows = await loop.run_in_executor(None, run, q)
                    count = int(list(rows[0].values())[0] or 0) if rows else 0
                except Exception as qe:
                    violations.append({"relationship": f"{r['from_table']}[{r['from_column']}] -> {r['to_table']}[{r['to_column']}]",
                                       "error": redact_secrets(str(qe), [self.client_secret])})
                    continue
                checked += 1
                if count > 0:
                    samples = []
                    try:
                        sq = f"EVALUATE TOPN({max_samples}, EXCEPT(DISTINCT({fcol}), DISTINCT({tcol})))"
                        srows = await loop.run_in_executor(None, run, sq)
                        samples = [list(x.values())[0] for x in (srows or [])]
                    except Exception:
                        pass
                    violations.append({
                        "relationship": f"{r['from_table']}[{r['from_column']}] -> {r['to_table']}[{r['to_column']}]",
                        "orphan_keys": count,
                        "samples": samples,
                    })
            result = {"checked": checked, "violations": violations}
            out = "=== Referential Integrity Scan ===\n\n"
            out += f"Relationships checked: {checked}   Violations: {len([v for v in violations if v.get('orphan_keys')])}\n\n"
            for v in violations:
                if v.get("error"):
                    out += f"  [SKIPPED] {v['relationship']}: {v['error']}\n"
                else:
                    out += f"  [ORPHANS] {v['relationship']}: {v['orphan_keys']} key(s) missing on the one side"
                    if v.get("samples"):
                        out += f"  e.g. {', '.join(str(s) for s in v['samples'])}"
                    out += "\n"
            if not violations:
                out += "  No orphan keys. Every fact key has a matching dimension row.\n"
            else:
                out += ("\nOrphan keys land in the hidden blank row and silently distort totals; fix the "
                        "source join or add the missing dimension rows.\n")
            return (out, result)
        except Exception as e:
            msg = redact_secrets(str(e), [self.client_secret])
            return (f"Error scanning referential integrity: {msg}", {"error": msg, "checked": 0, "violations": []})

    async def _handle_analyze_model_storage(self, args: Dict[str, Any]) -> str:
        """VertiPaq-style storage analysis: per-table row counts (reliable via DAX) plus
        best-effort sizes, to find the biggest/most expensive tables."""
        try:
            source = "cloud"
            run, err = await self._get_query_runner(source, args.get("workspace_name"), args.get("dataset_name"))
            if err:
                return f"Error: {err}"
            loop = asyncio.get_event_loop()

            # Table list (+ column counts) from metadata
            model, merr = await self._gather_model_metadata(source, args.get("workspace_name"), args.get("dataset_name"))
            if merr:
                return f"Error: {merr}"
            tables = [t for t in model["tables"] if not model_analysis._truthy(t.get("is_hidden"))]

            # Reliable row counts via DAX COUNTROWS per table
            rows_by_table = {}
            for t in tables:
                name = t["name"]
                q = f"EVALUATE ROW(\"r\", COUNTROWS('{name}'))"
                try:
                    res = await loop.run_in_executor(None, run, q)
                    val = None
                    if res:
                        val = next(iter(res[0].values()), None)
                    rows_by_table[name] = int(val) if val is not None else None
                except Exception:
                    rows_by_table[name] = None

            # VertiPaq sizes not available in REST-only mode
            sizes = {}

            ranked = sorted(
                tables, key=lambda t: (rows_by_table.get(t["name"]) or 0), reverse=True
            )
            out = "=== Model Storage Analysis ===\n\n"
            total_rows = sum(v for v in rows_by_table.values() if v)
            out += f"Tables: {len(tables)}   Total rows (visible tables): {total_rows:,}\n\n"
            out += f"{'Table':<35} {'Rows':>14} {'Cols':>6} {'Size(KB)':>10}\n"
            out += "-" * 68 + "\n"
            for t in ranked[:50]:
                nm = t["name"]
                rc = rows_by_table.get(nm)
                rc_s = f"{rc:,}" if rc is not None else "n/a"
                sz = sizes.get(nm)
                sz_s = f"{round(sz/1024):,}" if sz else "-"
                out += f"{nm[:34]:<35} {rc_s:>14} {len(t.get('columns', [])):>6} {sz_s:>10}\n"
            out += "\nNotes: row counts via DAX COUNTROWS (exact). VertiPaq sizes not available in REST-only mode.\n"
            return out
        except Exception as e:
            return f"Error analyzing storage: {redact_secrets(str(e), [self.client_secret])}"

    async def _handle_analyze_query_performance(self, args: Dict[str, Any]) -> str:
        """Time a DAX query and return duration, row count, and heuristic optimization hints."""
        try:
            dax = args.get("dax")
            if not dax:
                return "Error: dax is required"
            source = "cloud"
            run, err = await self._get_query_runner(source, args.get("workspace_name"), args.get("dataset_name"))
            if err:
                return f"Error: {err}"
            loop = asyncio.get_event_loop()
            start = time.time()
            rows = await loop.run_in_executor(None, run, dax)
            duration_ms = (time.time() - start) * 1000
            row_count = len(rows) if isinstance(rows, list) else 0

            hints = []
            up = dax.upper()
            if duration_ms > 2000:
                hints.append(f"Slow ({duration_ms:.0f} ms). Check relationship cardinality and avoid row-by-row iterators over large fact tables.")
            if row_count > 10000:
                hints.append(f"Large result ({row_count:,} rows). Add TOPN / SUMMARIZECOLUMNS filters.")
            if up.count("FILTER(") >= 3:
                hints.append("Multiple FILTER() calls; prefer CALCULATE with boolean filters or KEEPFILTERS where possible.")
            if "ADDCOLUMNS(" in up and "SUMMARIZE(" in up:
                hints.append("SUMMARIZE+ADDCOLUMNS pattern; SUMMARIZECOLUMNS is usually faster and safer.")
            if not hints:
                hints.append("No obvious red flags. For storage-engine vs formula-engine timings, use DAX Studio Server Timings.")

            out = "=== Query Performance ===\n\n"
            out += f"Duration: {duration_ms:.0f} ms\n"
            out += f"Rows returned: {row_count:,}\n\n"
            out += "--- Hints ---\n"
            for h in hints:
                out += f"  - {h}\n"
            return out
        except Exception as e:
            return f"Error analyzing query performance: {redact_secrets(str(e), [self.client_secret])}"

    async def _handle_model_diff(self, args: Dict[str, Any]) -> str:
        """Semantic diff between a baseline snapshot and another snapshot or the live model."""
        try:
            baseline_path = args.get("baseline_path")
            if not baseline_path:
                return "Error: baseline_path is required (a JSON snapshot from model_snapshot)"
            try:
                with open(baseline_path, "r", encoding="utf-8") as f:
                    before = json.load(f)
            except Exception as e:
                return f"Error reading baseline snapshot: {e}"

            compare_path = args.get("compare_path")
            if compare_path:
                try:
                    with open(compare_path, "r", encoding="utf-8") as f:
                        after = json.load(f)
                except Exception as e:
                    return f"Error reading compare snapshot: {e}"
            else:
                after, err = await self._gather_model_metadata(
                    "cloud", args.get("workspace_name"), args.get("dataset_name")
                )
                if err:
                    return f"Error reading live model to compare: {err}"

            return model_analysis.diff_models(before, after)["markdown"]
        except Exception as e:
            return f"Error diffing models: {redact_secrets(str(e), [self.client_secret])}"

    async def _handle_pre_deploy_gate(self, args: Dict[str, Any]):
        """CI quality gate: run BPA + AI-readiness and return a machine PASS/FAIL verdict."""
        try:
            model, err = await self._gather_model_metadata(
                "cloud", args.get("workspace_name"), args.get("dataset_name")
            )
            if err:
                return (f"Error: {err}", {"passed": False, "error": err})
            bpa = model_analysis.run_bpa(model)
            ai = model_analysis.audit_ai_readiness(model)
            errors = [f for f in bpa["findings"] if f["severity"] == "error"]
            warnings = [f for f in bpa["findings"] if f["severity"] == "warning"]
            min_ai = args.get("min_ai_score", 60)
            block_on_warnings = bool(args.get("block_on_warnings", False))
            passed = (len(errors) == 0 and ai["score"] >= min_ai
                      and (not block_on_warnings or len(warnings) == 0))

            structured = {
                "passed": passed,
                "bpa_errors": len(errors),
                "bpa_warnings": len(warnings),
                "ai_score": ai["score"],
                "blocking": [f"{f['rule_id']}: {f['object']}" for f in errors],
            }
            verdict = "PASS" if passed else "FAIL"
            text = f"[{verdict}] Pre-deploy quality gate\n\n"
            text += f"  BPA errors: {len(errors)}  warnings: {len(warnings)}\n"
            text += f"  AI-readiness: {ai['score']}/100 (min {min_ai})\n"
            if errors:
                text += "\nBlocking errors:\n"
                for f in errors[:50]:
                    text += f"  - {f['rule_id']}: {f['object']} ({f['detail']})\n"
            return (text, structured)
        except Exception as e:
            msg = redact_secrets(str(e), [self.client_secret])
            return (f"Error running pre-deploy gate: {msg}", {"passed": False, "error": msg})

    # ==================== DIAGNOSTICS & OPS (Wave 2) ====================

    async def _handle_refresh_doctor(self, args: Dict[str, Any]):
        """Diagnose dataset refresh failures (root cause + remediation) from REST history."""
        try:
            workspace = args.get("workspace_name")
            dataset = args.get("dataset_name")
            if not (workspace and dataset):
                return ("Error: workspace_name and dataset_name are required",
                        {"error": "missing workspace_name/dataset_name"})
            rest = self._get_rest_connector()
            if not rest:
                return ("Error: cloud credentials not configured (TENANT_ID / CLIENT_ID / CLIENT_SECRET).",
                        {"error": "no cloud credentials"})
            loop = asyncio.get_event_loop()
            wid, did, err = await loop.run_in_executor(None, rest.resolve_dataset, workspace, dataset)
            if err:
                return (f"Error: {err}", {"error": err})
            top = int(args.get("history_count", 10))
            history = await loop.run_in_executor(None, rest.get_refresh_history, wid, did, top)
            if not history:
                return ("No refresh history found (dataset may never have refreshed, or history expired ~30 days).",
                        {"history": 0})

            completed = sum(1 for h in history if str(h.get("status")) == "Completed")
            failed = [h for h in history if str(h.get("status")) == "Failed"]
            # Consecutive leading failures (history is most-recent-first). The status enum is
            # Unknown | Completed | Failed | Disabled: count Failed, stop at any non-Failed
            # terminal (Completed/Disabled), and skip Unknown (in-progress) without resetting.
            consecutive = 0
            for h in history:
                s = str(h.get("status"))
                if s == "Failed":
                    consecutive += 1
                elif s in ("Completed", "Disabled"):
                    break
                # Unknown / in-progress: skip

            out = f"=== Refresh Doctor: {dataset} ===\n\n"
            out += f"Last {len(history)} refreshes: {completed} completed, {len(failed)} failed\n"
            recent = history[0]
            out += f"Most recent: {recent.get('status')} ({recent.get('refreshType','?')}) ended {recent.get('endTime','?')}\n\n"

            diagnosis = None
            if failed:
                err_text = failed[0].get("serviceExceptionJson") or ""
                diag = refresh_diagnostics.classify_refresh_error(err_text)
                diagnosis = diag
                out += f"Most recent failure:\n  Cause: {diag['cause']}\n  Fix: {diag['remediation']}\n"
                if err_text:
                    out += f"  Raw: {redact_secrets(err_text, [self.client_secret])[:300]}\n"
                out += "\n"
            thr = refresh_diagnostics.CONSECUTIVE_FAILURE_DISABLE_THRESHOLD
            if consecutive >= thr - 1:
                out += (f"WARNING: {consecutive} consecutive failure(s). Power BI auto-disables a "
                        f"refresh schedule after {thr} consecutive failures.\n")

            structured = {
                "completed": completed, "failed": len(failed),
                "consecutive_failures": consecutive,
                "most_recent_status": recent.get("status"),
                "diagnosis": diagnosis,
            }
            return (out, structured)
        except Exception as e:
            msg = redact_secrets(str(e), [self.client_secret])
            return (f"Error diagnosing refresh: {msg}", {"error": msg})

    async def _handle_find_unused_objects(self, args: Dict[str, Any]) -> str:
        """Find columns/measures not referenced by any other model object nor any report visual."""
        try:
            source = "cloud"
            model, err = await self._gather_model_metadata(source, args.get("workspace_name"), args.get("dataset_name"))
            if err:
                return f"Error: {err}"
            run, rerr = await self._get_query_runner(source, args.get("workspace_name"), args.get("dataset_name"))
            if rerr:
                return f"Error: {rerr}"
            loop = asyncio.get_event_loop()
            try:
                dep_rows = await loop.run_in_executor(None, run, "EVALUATE INFO.CALCDEPENDENCY()")
            except Exception as e:
                return (f"Error reading INFO.CALCDEPENDENCY: {redact_secrets(str(e), [self.client_secret])}. "
                        + INFO_CALCDEP_NOTE)

            used = set()
            for r in dep_rows:
                rt = self._row_get(r, "REFERENCED_TABLE")
                ro = self._row_get(r, "REFERENCED_OBJECT")
                if rt and ro:
                    used.add((str(rt), str(ro)))
            # columns used in relationships are not 'unused'
            for rel in model.get("relationships", []):
                if rel.get("from_table") and rel.get("from_column"):
                    used.add((str(rel["from_table"]), str(rel["from_column"])))
                if rel.get("to_table") and rel.get("to_column"):
                    used.add((str(rel["to_table"]), str(rel["to_column"])))

            report_scanned = False
            pbip = self.pbip_connector
            if pbip and pbip.current_project:
                used |= pbip.collect_report_references()
                report_scanned = True

            unused_cols, unused_measures = [], []
            for t in model.get("tables", []):
                tn = t.get("name")
                for c in t.get("columns", []):
                    if (tn, c.get("name")) not in used:
                        unused_cols.append(f"{tn}[{c.get('name')}]")
                for m in t.get("measures", []):
                    if (tn, m.get("name")) not in used:
                        unused_measures.append(f"{tn}[{m.get('name')}]")

            out = "=== Unused Object Scan ===\n\n"
            if not report_scanned:
                out += ("WARNING: no PBIP project loaded, so REPORT usage was NOT checked - objects used only "
                        "in reports may be wrongly listed. Load the .pbip with pbip_load_project for an accurate scan.\n\n")
            out += f"Unused measures ({len(unused_measures)}):\n"
            out += ("\n".join(f"  - {m}" for m in unused_measures[:100]) or "  (none)") + "\n\n"
            out += f"Unused columns ({len(unused_cols)}):\n"
            out += ("\n".join(f"  - {c}" for c in unused_cols[:100]) or "  (none)") + "\n"
            out += ("\nNote: dependency graph includes measures, calc columns, RLS, calc groups and "
                    "field parameters (via INFO.CALCDEPENDENCY) plus relationships; review before deleting.")
            return out
        except Exception as e:
            return f"Error finding unused objects: {redact_secrets(str(e), [self.client_secret])}"

    async def _handle_impact_analysis(self, args: Dict[str, Any]) -> str:
        """Blast radius for an object: model dependents (INFO.CALCDEPENDENCY) + report visuals using it."""
        try:
            name = args.get("object_name") or args.get("measure_name") or args.get("column_name")
            if not name:
                return "Error: object_name is required (a measure or column name)"
            table = args.get("table_name")
            source = "cloud"
            run, rerr = await self._get_query_runner(source, args.get("workspace_name"), args.get("dataset_name"))
            if rerr:
                return f"Error: {rerr}"
            loop = asyncio.get_event_loop()
            esc = str(name).replace('"', '""')
            filt = f'[REFERENCED_OBJECT] = "{esc}"'
            if table:
                et = str(table).replace('"', '""')
                filt = f'[REFERENCED_TABLE] = "{et}" && {filt}'
            try:
                q = f'EVALUATE FILTER(INFO.CALCDEPENDENCY(), {filt})'
                rows = await loop.run_in_executor(None, run, q)
            except Exception as e:
                return (f"Error reading INFO.CALCDEPENDENCY: {redact_secrets(str(e), [self.client_secret])}. "
                        + INFO_CALCDEP_NOTE)

            out = f"=== Impact Analysis: {name}{(' in ' + table) if table else ''} ===\n\n"
            out += f"--- Model objects that depend on it ({len(rows)}) ---\n"
            if not rows:
                out += "  (none at the model level)\n"
            for r in rows[:100]:
                otype = self._row_get(r, "OBJECT_TYPE") or "?"
                otable = self._row_get(r, "TABLE") or ""
                oobj = self._row_get(r, "OBJECT") or ""
                out += f"  <- [{otype}] {otable}{('[' + oobj + ']') if oobj else ''}\n"

            # Report-layer usage from a loaded PBIP project
            pbip = self.pbip_connector
            if pbip and pbip.current_project:
                by_file = pbip.collect_report_references_by_file()
                hit_files = [fp for fp, refs in by_file.items()
                             if any(fld == name and (not table or tbl == table) for (tbl, fld) in refs)]
                out += f"\n--- Report files that reference it ({len(hit_files)}) ---\n"
                if not hit_files:
                    out += "  (none in the loaded report)\n"
                for fp in hit_files[:100]:
                    out += f"  * {fp}\n"
            else:
                out += "\n(No PBIP project loaded - report-layer usage not checked. Use pbip_load_project.)\n"

            if not rows:
                out += "\nSafe to change from a model-dependency standpoint (verify report usage above)."
            return out
        except Exception as e:
            return f"Error in impact analysis: {redact_secrets(str(e), [self.client_secret])}"

    async def _handle_run_dax_tests(self, args: Dict[str, Any]):
        """Run a suite of DAX test cases and report pass/fail vs expected results (regression testing)."""
        try:
            tests = args.get("tests")
            tests_path = args.get("tests_path")
            if not tests and tests_path:
                try:
                    with open(tests_path, "r", encoding="utf-8") as f:
                        tests = json.load(f)
                except Exception as e:
                    return (f"Error reading tests_path: {e}", {"passed": 0, "total": 0, "error": str(e)})
            if not tests or not isinstance(tests, list):
                return ("Error: provide 'tests' (array of {name, dax, expected, tolerance?}) or 'tests_path'.",
                        {"passed": 0, "total": 0})
            run, rerr = await self._get_query_runner("cloud",
                                                     args.get("workspace_name"), args.get("dataset_name"))
            if rerr:
                return (f"Error: {rerr}", {"passed": 0, "total": len(tests), "error": rerr})
            loop = asyncio.get_event_loop()

            results = []
            passed = 0
            for t in tests:
                name = t.get("name", t.get("dax", "test")[:40])
                dax = t.get("dax")
                if not dax:
                    results.append({"name": name, "status": "ERROR", "detail": "no dax"})
                    continue
                try:
                    rows = await loop.run_in_executor(None, run, dax)
                    actual = next(iter(rows[0].values()), None) if rows else None
                except Exception as e:
                    results.append({"name": name, "status": "ERROR", "detail": redact_secrets(str(e), [self.client_secret])[:200]})
                    continue
                if "expected" not in t:
                    results.append({"name": name, "status": "INFO", "detail": f"actual={actual} (no expected given)"})
                    continue
                ok, detail = model_analysis.dax_test_verdict(actual, t.get("expected"), t.get("tolerance", 0))
                results.append({"name": name, "status": "PASS" if ok else "FAIL", "detail": detail})
                if ok:
                    passed += 1

            graded = [r for r in results if r["status"] in ("PASS", "FAIL")]
            total = len(graded)
            all_passed = total > 0 and passed == total
            out = f"[{'PASS' if all_passed else 'FAIL'}] DAX tests: {passed}/{total} passed\n\n"
            for r in results:
                out += f"  [{r['status']}] {r['name']}: {r['detail']}\n"
            return (out, {"passed": passed, "total": total, "all_passed": all_passed, "results": results})
        except Exception as e:
            msg = redact_secrets(str(e), [self.client_secret])
            return (f"Error running DAX tests: {msg}", {"passed": 0, "total": 0, "error": msg})

    async def _handle_cross_workspace_lineage(self, args: Dict[str, Any]) -> str:
        """Tenant-wide inventory + lineage via the Admin Scanner API (admin-gated)."""
        try:
            rest = self._get_rest_connector()
            if not rest:
                return "Error: cloud credentials not configured (TENANT_ID / CLIENT_ID / CLIENT_SECRET)."
            loop = asyncio.get_event_loop()

            # Reuse a cached scanResult if provided (Scanner API is rate-limited).
            cache_path = args.get("cache_path")
            scan = None
            if cache_path and args.get("use_cache", True):
                try:
                    with open(cache_path, "r", encoding="utf-8") as f:
                        scan = json.load(f)
                except Exception:
                    scan = None

            if scan is None:
                ids = args.get("workspace_ids")
                if not ids:
                    try:
                        ws = await loop.run_in_executor(None, rest.admin_list_workspaces, 100)
                        ids = [w.get("id") for w in ws if w.get("id")]
                    except Exception as e:
                        return (f"Error listing workspaces (needs admin / read-only admin APIs enabled): "
                                f"{redact_secrets(str(e), [self.client_secret])}")
                ids = [i for i in (ids or [])][:100]  # Scanner caps at 100 workspaces/call
                if not ids:
                    return "No workspaces found to scan."
                started = await loop.run_in_executor(None, rest.admin_post_workspace_info, ids, True)
                scan_id = started.get("id")
                if not scan_id:
                    return f"Error: scan did not start ({started})."
                status = ""
                last_st = {}
                for _ in range(20):  # ~5 min budget (Microsoft suggests 30-60s polling for big scans)
                    last_st = await loop.run_in_executor(None, rest.admin_get_scan_status, scan_id)
                    status = str(last_st.get("status", "")).lower()
                    if status == "succeeded":
                        break
                    if status == "failed":
                        return f"Scan failed: {last_st.get('error') or last_st}"
                    await asyncio.sleep(15)
                if status != "succeeded":
                    return (f"Scan still running after the wait (status={status}). Re-run with the same "
                            "cache_path to resume later, or scan fewer workspace_ids.")
                scan = await loop.run_in_executor(None, rest.admin_get_scan_result, scan_id)
                if cache_path:
                    try:
                        with open(cache_path, "w", encoding="utf-8") as f:
                            json.dump(scan, f)
                    except Exception:
                        pass

            s = governance.summarize_scan(scan, dataset_name=args.get("dataset_name"))
            out = "=== Cross-Workspace Lineage / Inventory ===\n\n"
            out += f"Workspaces: {s['workspaces']}  Datasets: {s['datasets']}  Reports: {s['reports']}\n\n"
            if s.get("focus_dataset"):
                out += f"Dataset '{s['focus_dataset']}' found in: {', '.join(s['focus_found_in']) or '(not found)'}\n"
                out += f"Downstream reports ({len(s['downstream_reports'])}):\n"
                out += ("\n".join(f"  - {r}" for r in s['downstream_reports']) or "  (none)") + "\n\n"
            out += f"Datasets WITHOUT RLS roles ({len(s['datasets_without_rls'])}):\n"
            out += ("\n".join(f"  - {d}" for d in s['datasets_without_rls'][:50]) or "  (none)") + "\n\n"
            out += f"Datasets WITHOUT a sensitivity label ({len(s['datasets_without_sensitivity_label'])}):\n"
            out += ("\n".join(f"  - {d}" for d in s['datasets_without_sensitivity_label'][:50]) or "  (none)") + "\n"
            return out
        except Exception as e:
            return f"Error in cross-workspace lineage: {redact_secrets(str(e), [self.client_secret])}"

    async def _handle_fleet_refresh_monitor(self, args: Dict[str, Any]) -> str:
        """Refresh health across many datasets/workspaces, classifying failures (admin or workspace access)."""
        try:
            rest = self._get_rest_connector()
            if not rest:
                return "Error: cloud credentials not configured (TENANT_ID / CLIENT_ID / CLIENT_SECRET)."
            loop = asyncio.get_event_loop()
            workspace_ids = args.get("workspace_ids")
            if not workspace_ids:
                return ("Error: workspace_ids is required (a list of workspace GUIDs) to bound the scan. "
                        "Use list_workspaces or cross_workspace_lineage to discover them.")

            failures = []
            checked = 0
            for wid in workspace_ids:
                try:
                    datasets = await loop.run_in_executor(None, rest.list_datasets, wid)
                except Exception:
                    continue
                for ds in datasets:
                    if not ds.get("isRefreshable"):
                        continue
                    checked += 1
                    try:
                        hist = await loop.run_in_executor(None, rest.get_refresh_history, wid, ds["id"], 1)
                    except Exception:
                        continue
                    if not hist:
                        continue
                    last = hist[0]
                    if str(last.get("status")) == "Failed":
                        diag = refresh_diagnostics.classify_refresh_error(last.get("serviceExceptionJson") or "")
                        failures.append((ds.get("name"), last.get("endTime"), diag["cause"]))

            out = "=== Fleet Refresh Monitor ===\n\n"
            out += f"Refreshable datasets checked: {checked}\n"
            out += f"Most-recent-refresh FAILURES: {len(failures)}\n\n"
            for name, when, cause in failures[:100]:
                out += f"  [FAILED] {name} ({when}): {cause}\n"
            if not failures:
                out += "  All checked datasets' most recent refresh succeeded.\n"
            return out
        except Exception as e:
            return f"Error in fleet refresh monitor: {redact_secrets(str(e), [self.client_secret])}"

    async def _handle_usage_and_orphan_analytics(self, args: Dict[str, Any]) -> str:
        """Tenant usage analytics from the Admin Activity Events API for a single UTC day."""
        try:
            rest = self._get_rest_connector()
            if not rest:
                return "Error: cloud credentials not configured (TENANT_ID / CLIENT_ID / CLIENT_SECRET)."
            date = args.get("date")
            if not date:
                from datetime import datetime, timezone, timedelta
                # default to yesterday UTC (today is incomplete; events lag up to ~60 min)
                date = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
            loop = asyncio.get_event_loop()
            try:
                events = await loop.run_in_executor(
                    None, rest.admin_get_activity_events_for_day, date, args.get("filter")
                )
            except Exception as e:
                return (f"Error reading activity events (needs admin / read-only admin APIs; 28-day "
                        f"retention): {redact_secrets(str(e), [self.client_secret])}")
            agg = governance.aggregate_activity(events)
            out = f"=== Usage Analytics ({date} UTC) ===\n\n"
            out += f"Total events: {agg['total_events']}   Distinct users: {agg['distinct_users']}\n\n"
            out += "Top activities:\n"
            out += ("\n".join(f"  {n}  {a}" for a, n in agg["by_activity"][:15]) or "  (none)") + "\n\n"
            out += "Top viewed reports:\n"
            out += ("\n".join(f"  {n}  {r}" for r, n in agg["top_reports_by_views"][:15]) or "  (none)") + "\n\n"
            out += "Top users:\n"
            out += ("\n".join(f"  {n}  {u}" for u, n in agg["top_users"][:15]) or "  (none)") + "\n"
            out += ("\nNote: 28-day retention; pull a fully-past day for completeness. For orphan "
                    "(zero-view) detection, correlate cross_workspace_lineage inventory with a longer "
                    "activity window persisted over time.")
            return out
        except Exception as e:
            return f"Error in usage analytics: {redact_secrets(str(e), [self.client_secret])}"

    async def _handle_verify_audit_integrity(self):
        """Verify the tamper-evident hash chain of the audit log."""
        res = self.security.verify_audit_integrity()
        status = "INTACT" if res.get("valid") else "TAMPERED"
        text = f"[{status}] Audit log integrity: {res.get('message', '')}\n  Entries checked: {res.get('checked', 0)}"
        if not res.get("valid") and res.get("broken_line"):
            text += f"\n  First problem at line {res['broken_line']}"
        return (text, res)

    # ==================== MCP RESOURCES & COMPLETION (Bundle C) ====================

    async def _read_resource(self, uri: str) -> str:
        """Resolve a powerbi:// resource URI to a JSON document (read-only model context)."""
        try:
            rest = uri.split("://", 1)[1] if "://" in uri else uri
            parts = [unquote(p) for p in rest.split("/") if p != ""]
            if not parts:
                return json.dumps({"error": f"unrecognized resource uri: {uri}"})

            if parts[0] == "reference":
                what = parts[1] if len(parts) > 1 else ""
                if what == "bpa-rules":
                    rules = [{"id": r["id"], "category": r["category"], "severity": r["severity"], "name": r["name"]}
                             for r in model_analysis.DEFAULT_BPA_RULES]
                    return json.dumps(rules, indent=2)
                if what == "refresh-errors":
                    return json.dumps({
                        "consecutive_failure_disable_threshold": refresh_diagnostics.CONSECUTIVE_FAILURE_DISABLE_THRESHOLD,
                        "rules": refresh_diagnostics.REFRESH_ERROR_RULES,
                    }, indent=2)
                return json.dumps({"error": f"unknown reference resource '{what}'"})

            if parts[0] == "desktop":
                kind = parts[1] if len(parts) > 1 else "schema"
                model, err = await self._gather_model_metadata("desktop")
                if err:
                    return json.dumps({"error": err})
                if kind == "schema":
                    return json.dumps(model, default=str, indent=2)
                if kind == "measures":
                    measures = [m for t in model["tables"] for m in t.get("measures", [])]
                    return json.dumps(measures, default=str, indent=2)
                if kind == "bpa":
                    return json.dumps(model_analysis.run_bpa(model), default=str, indent=2)
                if kind in ("ai-readiness", "ai_readiness"):
                    return json.dumps(model_analysis.audit_ai_readiness(model), default=str, indent=2)
                return json.dumps({"error": f"unknown desktop resource '{kind}'"})

            if parts[0] == "cloud" and len(parts) >= 3:
                workspace, dataset = parts[1], parts[2]
                model, err = await self._gather_model_metadata("cloud", workspace, dataset)
                if err:
                    return json.dumps({"error": err})
                return json.dumps(model, default=str, indent=2)

            return json.dumps({"error": f"unrecognized resource uri: {uri}"})
        except Exception as e:
            return json.dumps({"error": redact_secrets(str(e), [self.client_secret])})

    async def _complete_argument(self, argument) -> Completion:
        """Completion for prompt/resource-template arguments: real table/measure names
        from the connected Desktop model when available."""
        try:
            name = getattr(argument, "name", "") or ""
            value = (getattr(argument, "value", "") or "").lower()
            candidates = []
            desktop = self.desktop_connector
            if desktop is not None and getattr(desktop, "current_port", None):
                model, err = await self._gather_model_metadata("desktop")
                if not err and model:
                    measures = [m["name"] for t in model["tables"] for m in t.get("measures", []) if m.get("name")]
                    tables = [t["name"] for t in model["tables"] if t.get("name")]
                    if name in ("measure_name", "old_name", "new_name"):
                        candidates = measures + tables
                    elif name in ("table", "dataset", "table_name"):
                        candidates = tables
                    else:
                        candidates = tables + measures
            filtered = [c for c in candidates if value in c.lower()][:100]
            return Completion(values=filtered, total=len(filtered), hasMore=False)
        except Exception:
            return Completion(values=[], total=0, hasMore=False)

    # ==================== PBIP HANDLERS (File-based editing) ====================


    async def run(self):
        """Run the MCP server over HTTP/SSE."""
        host = os.getenv("POWERBI_MCP_HOST", "0.0.0.0")
        port = int(os.getenv("POWERBI_MCP_PORT", "8000"))
        sse_path = os.getenv("POWERBI_MCP_SSE_PATH", "/sse")
        messages_path = os.getenv("POWERBI_MCP_MESSAGES_PATH", "/messages/")
        transport = SseServerTransport(messages_path)

        async def handle_sse(request: Request):
            async with transport.connect_sse(request.scope, request.receive, request._send) as streams:
                await self.server.run(
                    streams[0], streams[1],
                    InitializationOptions(
                        server_name="powerbi-mcp-rest-readonly",
                        server_version="3.0.0",
                        capabilities=self.server.get_capabilities(
                            notification_options=NotificationOptions(),
                            experimental_capabilities={}
                        )
                    )
                )

        async def health(request: Request):
            return JSONResponse({"status": "ok", "transport": "sse", "mode": "rest-readonly"})

        app = Starlette(routes=[
            Route("/health", endpoint=health, methods=["GET"]),
            Route(sse_path, endpoint=handle_sse, methods=["GET"]),
            Mount(messages_path, app=transport.handle_post_message),
        ])
        logger.info("Power BI MCP REST read-only server starting on http://%s:%s%s", host, port, sse_path)
        config = uvicorn.Config(app, host=host, port=port, log_level=os.getenv("LOG_LEVEL", "info").lower())
        await uvicorn.Server(config).serve()


def main():
    """Main entry point"""
    server = PowerBIMCPServer()
    asyncio.run(server.run())


if __name__ == "__main__":
    main()
