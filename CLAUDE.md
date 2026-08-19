# CLAUDE.md

Agent guidance for this repository lives in [AGENTS.md](AGENTS.md). Read it before
driving Power BI tasks through this MCP server.

Quick reminders:
- This server is REST-only and read-only. No write, create, update, delete, or rename operations are available.
- `validate_dax` before executing DAX queries.
- Read the `powerbi://cloud/{workspace}/{dataset}/schema` resource to ground DAX in real object names.
- All operations require Power BI Service credentials (TENANT_ID, CLIENT_ID, CLIENT_SECRET).

## Developer notes

- Source: `src/` (server.py + connectors + `security/` + model_analysis.py + refresh_diagnostics.py + governance.py + dax_lint.py + bpa_authoring.py + dax_generator.py).
- Tests: `tests/test_*.py` are assert-based and run without Power BI (pure-Python paths). Run them after changes: `python run_tests.py` (or `python tests/test_<name>.py`).
- Every tool registers in one place (`_build_tool_dispatch` + `_build_tool_annotations` + `handle_list_tools` in `src/server.py`); keep the three in sync (a parity test guards this).
