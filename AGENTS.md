# Power BI MCP Server - Agent Guide

This file orients AI agents (Claude, Copilot, etc.) working through this MCP server.
Read it before driving Power BI tasks.

## What this server does

A Model Context Protocol server that lets an agent inspect, query, validate, optimize,
and govern Power BI semantic models through a REST-only, read-only interface. It connects to:

- **Power BI Service** (REST API) - cloud datasets, metadata, read-only DAX execution, refresh diagnostics

This server is designed for autonomous BI agents that need to understand a published semantic model, identify existing measures and dimensions, generate safe read-only DAX on the fly, and answer business questions without mutating Power BI content.

## Golden rules

1. **Read-only operations only.** This server does not support any write, create, update, delete, or rename operations.
2. **Validate DAX before execution.** Call `validate_dax` on any generated DAX before calling `execute_dax`.
3. **Respect the safety hints.** Every tool is annotated (`readOnlyHint`). No destructive operations are available.
4. **Use cloud credentials.** All operations require Power BI Service credentials (TENANT_ID, CLIENT_ID, CLIENT_SECRET).

## Recommended workflows

- **Understand a model:** `describe_semantic_model` -> `get_model_info` -> review tables, measures, relationships.
- **Answer a business question:** `answer_query_plan` (maps question to measures/tables) -> `execute_dax` (run the query).
- **Validate generated DAX:** `validate_dax` (checks syntax/semantics without executing) -> `execute_dax` (if valid).
- **Optimize a model:** `run_bpa` -> `audit_ai_readiness` -> `analyze_model_storage` -> remediate top issues -> re-run.
- **Improve DAX:** `dax_lint` (whole model or one measure) -> `dax_suggest_rewrite` -> apply suggestions manually (no write tools available).
- **Generate measure previews:** `generate_measure_suite` (target='none' to preview DAX) -> review manually (no write tools available). This tool generates measure suites (time intelligence, ratios, ranking, column stats) as a read-only preview.
- **Diagnostics:** `refresh_doctor` (refresh failures) -> `analyze_query_performance` (slow queries) -> `find_unused_objects` (cleanup opportunities).
- **Pre-deployment checks:** `pre_deploy_gate` -> `verify_audit_integrity` -> `run_dax_tests`.

## Prompts (guided workflows)

`optimize_measure`, `explain_measure`, `audit_model`, `document_model`, `pre_deploy_review` - invoke these for ready-made, tool-orchestrated playbooks.

## Resources

`powerbi://cloud/{workspace}/{dataset}/schema` exposes model context as a read-only resource (no tool call needed). Reference resources `powerbi://reference/bpa-rules` and `powerbi://reference/refresh-errors` provide BPA rules and refresh error remediation guidance.

## DAX patterns the agent should prefer

- Use `DIVIDE(n, d)` instead of `n / d` (safe divide-by-zero).
- Use `SUMMARIZECOLUMNS(...)` instead of `SUMMARIZE` + `ADDCOLUMNS`.
- Use variables (`VAR`/`RETURN`) to avoid recomputing sub-expressions.
- Filter with boolean predicates inside `CALCULATE` rather than wrapping whole tables in `FILTER` when possible.
- Always set a `FormatString` and a `Description` on measures (helps Copilot too).

## Governance

A security layer can mask/block PII and sensitive columns and audit every query
(see `config/policies.yaml`, tools `security_status` / `security_audit_log`).
Column policies are enforced on `execute_dax` results.

## Positioning vs Microsoft's official Power BI MCP

Microsoft's official **remote** server is best for cloud chat-with-data, and the
official **local modeling** MCP for raw model authoring. This server is
complementary and differentiates on: a governance/PII layer, REST-only read-only access,
and a focus on autonomous BI agents that need to understand and query published models
without making changes.
