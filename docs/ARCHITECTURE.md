# Architecture

## Overview

A Python **HTTP/SSE MCP server** (`src/server.py`) that routes REST-only, read-only tools to the Power BI Service, wrapped by a security layer, with pure-Python modules for model analysis, diagnostics, and governance.

```
        MCP client (Claude / Copilot / VS Code)
                      |  HTTP/SSE (JSON-RPC)
        +-------------v---------------------------------------------+
        |  server.py (PowerBIMCPServer)                             |
        |  - tool registry: dispatch + annotations + list (parity)  |
        |  - resources / prompts / completion                       |
        |  - read-only lockdown gate + response-boundary redaction  |
        +------------------+------------------+----------------------+
           |                 |                 |
       REST API      Pure-Python      Security
       (Power BI     analysis &      layer
       Service)      governance       (PII/audit/
           |        modules)          policy)
           |
     Power BI
     Service
```

## Integration path

|| Path | Transport | What it does |
||------|-----------|--------------|
|| **Cloud (REST)** | MSAL service-principal REST API | Workspace/dataset discovery, metadata, read-only DAX execution, refresh diagnostics, admin APIs |

This server is **REST-only and read-only**. It does not support Desktop, TOM writes, PBIP/PBIR file editing, or any create/update/delete/rename operations.

## Components

### `server.py`
- **Tool registry.** `_build_tool_dispatch()` (name to handler) and `_build_tool_annotations()`
  (name to `ToolAnnotations`) are the single source of truth; `handle_list_tools` and
  `handle_call_tool` derive from them. A parity test enforces that the tool list, the dispatch
  map, and the annotation map contain exactly the same names.
- **Read-only lockdown gate.** The server only exposes tools in `_REST_READONLY_TOOLS`, which are
  all read-only operations. No destructive or write operations are available.
- **Response-boundary redaction.** Every text response passes through `redact_secrets` at the
  dispatch boundary, so a handler that swallows an exception cannot leak a connection-string
  secret to the model.
- **Structured output.** Handlers return a string or a `(text, dict)` tuple; tools with an
  `outputSchema` return the tuple so clients get typed `structuredContent`.
- **Resources / prompts / completion.** Model context (`powerbi://...`), reusable BI prompts,
  and argument completion grounded in the connected model.

### Connectors
- **`powerbi_rest_connector.py`** - cloud datasets and the admin Scanner/Activity APIs. The client
  secret is redacted from any provider error. Uses `requests.Session` for connection management.

### Analysis and audit (pure Python, unit-tested)
- **`model_analysis.py`** - INFO.VIEW-based model metadata extraction, data dictionary rendering,
  and query guidance (table/column/measure selection for a business question).
- **`refresh_diagnostics.py`** - refresh failure classification, eviction detection, capacity
  throttling, gateway errors, and remediation suggestions.
- **`governance.py`** - audit chain (tamper-evident JSON with line-by-line hashes), cross-workspace
  lineage, fleet refresh monitoring, and usage/orphan analytics.
- **`dax_lint.py`** - DAX linting against a rule catalog (unused variables, DIVIDE safety, variable
  naming, etc.).
- **`bpa_authoring.py`** - Best Practice Analyzer rule authoring (custom rules in JSON, rule
  source audit).

### Security layer (`src/security/`)
- **`security_layer.py`** - orchestrates PII detection, audit logging, and access policy enforcement.
- **`pii_detector.py`** - regex-based PII detection (email, phone, SSN, credit card, IP address) with
  configurable patterns.
- **`audit_logger.py`** - structured audit log (tool calls, arguments, results, PII findings, policy
  decisions) with rotation and retention.
- **`access_policy.py`** - column-level access policies (allow/deny/mask), row-level filters, and
  query-time enforcement.

## Tool categories

### Cloud discovery and metadata
- `list_workspaces`, `list_datasets`, `list_tables`, `list_columns`, `get_model_info`, `describe_semantic_model`

### DAX (read-only)
- `execute_dax`, `validate_dax`, `answer_query_plan`

### Diagnostics and ops
- `refresh_doctor`, `analyze_query_performance`, `analyze_model_storage`

### Quality and governance
- `run_bpa`, `audit_ai_readiness`, `dax_lint`, `dax_suggest_rewrite`, `pre_deploy_gate`

### Impact analysis
- `find_unused_objects`, `impact_analysis`, `scan_referential_integrity`

### Audit and testing
- `model_diff`, `run_dax_tests`, `verify_audit_integrity`, `cross_workspace_lineage`, `fleet_refresh_monitor`, `usage_and_orphan_analytics`

### Security
- `security_status`, `security_audit_log`

## Resources

- `powerbi://reference/bpa-rules` - Built-in BPA rule catalog
- `powerbi://reference/refresh-errors` - Known refresh failure causes and fixes
- `powerbi://cloud/{workspace}/{dataset}/schema` - Semantic model schema through REST

## Prompts

- `optimize_measure` - DAX optimization workflow
- `explain_measure` - Measure explanation workflow
- `audit_model` - Model audit workflow
- `document_model` - Documentation generation workflow
- `plan_safe_rename` - Safe rename planning workflow
- `pre_deploy_review` - Pre-deployment gate workflow
