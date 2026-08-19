# Power BI MCP Server

<p align="center">
  <strong>A REST-only, read-only Model Context Protocol server for Power BI Service.</strong>
</p>

<p align="center">
  <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-compatible-blue?style=flat-square" alt="MCP compatible"></a>
  <a href="https://www.python.org"><img src="https://img.shields.io/badge/Python-3.10%2B-green?style=flat-square" alt="Python 3.10+"></a>
  <a href="#"><img src="https://img.shields.io/badge/Tools-REST--only-purple?style=flat-square" alt="REST-only"></a>
  <a href="#"><img src="https://img.shields.io/badge/Read--only-success?style=flat-square" alt="Read-only"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow?style=flat-square" alt="MIT license"></a>
</p>

<p align="center">
  <em>Let AI assistants inspect, query, validate, optimize, and govern Power BI
  semantic models through a REST-only, read-only interface.</em>
</p>

> **Disclaimer:** This is an independent, community project. It is not affiliated with, endorsed
> by, or connected to Microsoft Corporation or Anthropic.

---

## What it is

Power BI MCP Server connects an AI assistant (Claude, GitHub Copilot, any MCP client) to Power BI Service through a REST-only, read-only MCP interface. It is designed for autonomous BI agents that need to understand a published semantic model, identify existing measures and dimensions, generate safe read-only DAX on the fly, and answer business questions without mutating Power BI content.

It exposes cloud/API analysis tools plus MCP **resources**, **prompts**, and **completion**, and wraps every operation in a security and governance layer.

|| Capability | What you get |
||------------|--------------|
|| **REST-only Power BI Service access** | Workspace/dataset discovery, metadata, refresh diagnostics, admin reads |
|| **Semantic model understanding** | Agent-ready map of tables, columns, measures, relationships, and query guidance |
|| **Read-only DAX** | Execute and validate DAX through the Power BI REST Execute Queries API |
|| **Governance and safety** | PII masking, access policies, audit logging, and no exposed write/delete/update tools |
|| **Modern MCP over SSE** | HTTP/SSE transport for remote MCP clients |

## Tool surface

The server intentionally exposes only read-only API tools. All write, create, update, delete, and rename operations are removed from the public MCP surface.

Key autonomous-agent tools:

- `describe_semantic_model`: returns an agent-ready semantic map of a published model.
- `answer_query_plan`: maps a user question to candidate measures/tables and a draft read-only DAX query.
- `execute_dax`: executes read-only DAX through REST after security checks.
- `validate_dax`: validates generated DAX through REST without committing anything.
- `run_bpa`, `audit_ai_readiness`, `dax_lint`, and `dax_suggest_rewrite`: model understanding and quality diagnostics.
- `refresh_doctor`: diagnoses dataset refresh failures from REST history.
- `analyze_query_performance`: times DAX queries and returns optimization hints.
- `find_unused_objects`: identifies unused measures/columns for cleanup planning.
- `impact_analysis`: shows model and report dependents before changes.
- `pre_deploy_gate`: runs a pre-deployment validation checklist.

## Security and governance

- **PII detection and masking** before results reach the AI (SSN, credit card, email, phone, IP).
- **Enforced column and table policies** from `config/policies.yaml`: `block`, `mask`, `hash`,
  `redact`, and `numeric_mask` (session-randomized scaling that hides values but preserves ratios).
- **Audit logging** with a tamper-evident hash chain; verify it with `verify_audit_integrity`.
  Set `POWERBI_MCP_AUDIT_KEY` to switch the chain to HMAC-SHA256 (cryptographically strong against
  tampering).
- **Access control** at the column level (allow/deny/mask/hash/redact) and row-level filters.

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

Set environment variables:

```bash
# Power BI Service credentials (required)
export TENANT_ID="your-tenant-id"
export CLIENT_ID="your-client-id"
export CLIENT_SECRET="your-client-secret"

# Optional: Security configuration
export ENABLE_PII_DETECTION="true"
export ENABLE_AUDIT="true"
export ENABLE_POLICIES="true"

# Optional: Server configuration
export POWERBI_MCP_HOST="0.0.0.0"
export POWERBI_MCP_PORT="8000"
export POWERBI_MCP_SSE_PATH="/sse"
export POWERBI_MCP_MESSAGES_PATH="/messages/"
```

## Running the server

```bash
python -m src.server
```

The server starts an HTTP/SSE endpoint on `http://0.0.0.0:8000/sse`.

## Development

Run tests:

```bash
python run_tests.py
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) - Component overview and data flow
- [Agent Guide](AGENTS.md) - How AI agents should use this server
- [Testing](docs/TESTING.md) - Test structure and conventions

## License

MIT
