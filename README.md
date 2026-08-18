# Power BI MCP Server

<p align="center">
  <strong>An enterprise-grade Model Context Protocol server for Power BI and Microsoft Fabric.</strong>
</p>

<p align="center">
  <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-compatible-blue?style=flat-square" alt="MCP compatible"></a>
  <a href="https://www.python.org"><img src="https://img.shields.io/badge/Python-3.10%2B-green?style=flat-square" alt="Python 3.10+"></a>
  <a href="#"><img src="https://img.shields.io/badge/Tools-82-purple?style=flat-square" alt="82 tools"></a>
  <a href="#"><img src="https://img.shields.io/badge/Live-Windows-lightgrey?style=flat-square" alt="Windows for live connectivity"></a>
  <a href="#"><img src="https://img.shields.io/badge/Offline-cross--platform-success?style=flat-square" alt="Offline cross-platform"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow?style=flat-square" alt="MIT license"></a>
</p>

<p align="center">
  <em>Let AI assistants inspect, query, validate, optimize, govern, and safely refactor Power BI
  semantic models and reports, through natural language.</em>
</p>

> **Disclaimer:** This is an independent, community project. It is not affiliated with, endorsed
> by, or connected to Microsoft Corporation or Anthropic.

---

## What it is

Power BI MCP Server connects an AI assistant (Claude, GitHub Copilot, any MCP client) to Power BI Service through a REST-only, read-only MCP interface. It is designed for autonomous BI agents that need to understand a published semantic model, identify existing measures and dimensions, generate safe read-only DAX on the fly, and answer business questions without mutating Power BI content.

It exposes cloud/API analysis tools plus MCP **resources**, **prompts**, and **completion**, and wraps every operation in a security and governance layer.

| Capability | What you get |
|------------|--------------|
| **REST-only Power BI Service access** | Workspace/dataset discovery, metadata, refresh diagnostics, admin reads |
| **Semantic model understanding** | Agent-ready map of tables, columns, measures, relationships, and query guidance |
| **Read-only DAX** | Execute and validate DAX through the Power BI REST Execute Queries API |
| **Governance and safety** | PII masking, access policies, audit logging, and no exposed write/delete/update tools |
| **Modern MCP over SSE** | HTTP/SSE transport for remote MCP clients |

## Tool surface

The server intentionally exposes only read-only API tools. Desktop, Desktop Bridge, TOM writes, PBIP/PBIR file editing, extraction, snapshots, and all create/update/delete/rename operations are removed from the public MCP surface.

Key autonomous-agent tools:

- `describe_semantic_model`: returns an agent-ready semantic map of a published model.
- `answer_query_plan`: maps a user question to candidate measures/tables and a draft read-only DAX query.
- `execute_dax`: executes read-only DAX through REST after security checks.
- `validate_dax`: validates generated DAX through REST without committing anything.
- `run_bpa`, `audit_ai_readiness`, `audit_star_schema`, `dax_lint`, and `dax_suggest_rewrite`: model understanding and quality diagnostics.

## Removed local/write workflows

Power BI stores a model layer and a report layer separately. TOM (and the official modeling MCP)
can edit the model, but cannot update report visuals, so a TOM rename leaves visuals pointing at
the old name. This server solves it with **PBIP file editing**: it rewrites the TMDL model files
and the PBIR report files (visual bindings, cultures, diagram) together, so nothing breaks.

```
User: "Load PBIP project from C:/Projects/SalesReport"
User: "Rename table Salesforce_Data to Sales Force Data"
```

The rename cascade is transactional (it rolls every file back on failure) and writes atomically
(temp file plus `os.replace`), preserving encoding and line endings.

> **Always** use the `pbip_rename_*` tools for renames, not the deprecated TOM `batch_rename_*`
> tools. Close Power BI Desktop before PBIP edits, or keep it open and hot-reload afterwards
> with `bridge_reload`.

---

## The edit-and-verify loop (Desktop Bridge)

With Power BI Desktop June 2026+ the agent can drive a complete authoring loop against the
RUNNING app, with the files on disk as the source of truth:

```
bridge_status          which file is open, unsaved-change state, pages, and the AS port
   |
pbip_* / pbir_* tools  author offline: measures, date table, calc groups, pages, visuals
   |
bridge_reload          hot-reload the open file from disk - no close/reopen
   |
bridge_screenshot      PNG of each page so the agent can SEE and fix its own work
```

`bridge_reload` refuses to run over unsaved Desktop changes (pass `force=true` to override),
and `bridge_status` reports the matching Analysis Services port so the same window is one
`desktop_connect` away from live DAX and TOM.

---

## Security and governance

- **PII detection and masking** before results reach the AI (SSN, credit card, email, phone, IP).
- **Enforced column and table policies** from `config/policies.yaml`: `block`, `mask`, `hash`,
  `redact`, and `numeric_mask` (session-randomized scaling that hides values but preserves ratios).
- **Audit logging** with a tamper-evident hash chain; verify it with `verify_audit_integrity`.
  Set `POWERBI_MCP_AUDIT_KEY` to switch the chain to HMAC-SHA256 (cryptographically strong against
  an attacker who edits the log); without a key it is a plain SHA-256 chain that still catches
  accidental edits and naive tampering.
- **Read-only / lockdown mode:** set `POWERBI_MCP_READONLY=true` to refuse every write tool
  (model/report mutations **and** file-writing tools like snapshots, dictionaries, and PBIX
  extraction) while reads and diagnostics keep working. Ideal for shared or autonomous agent use.
- Connection-string secrets and PII are redacted from logs, error messages, the audit log, and
  every tool response (redaction is applied at the response boundary, not just per-handler).

```yaml
# config/policies.yaml (excerpt)
tables:
  - name: "*"
    columns:
      - name: ssn
        action: block
      - name: card_number
        action: mask
```

### Environment variables

| Variable | Purpose |
|----------|---------|
| `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET` | Azure AD service principal (cloud, REST, admin) |
| `ADOMD_DLL_PATH` | Folder (or full path) of `Microsoft.AnalysisServices.AdomdClient.dll`, if auto-discovery misses it |
| `TOM_DLL_PATH` | Folder (or full path) of `Microsoft.AnalysisServices.Tabular.dll` for live writes (`ADOMD_DLL_PATH` is also searched) |
| `POWERBI_MCP_READONLY` | `true` refuses all write tools (lockdown mode) |
| `POWERBI_MCP_AUDIT_KEY` | Secret key that switches the audit hash chain to HMAC-SHA256 (stronger tamper-resistance) |
| `ENABLE_PII_DETECTION`, `ENABLE_AUDIT`, `ENABLE_POLICIES` | Toggle security subsystems (default true) |
| `LOG_LEVEL` | `DEBUG` enables redacted argument logging |

---

## Documentation

| Doc | Contents |
|-----|----------|
| [docs/TOOLS.md](docs/TOOLS.md) | Complete reference of all 82 tools, resources, prompts, env vars |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, security layer, registry pattern, verification methodology, file map |
| [docs/TESTING.md](docs/TESTING.md) | How to run the suites and what each covers |
| [CHANGELOG.md](CHANGELOG.md) | Everything that changed, by milestone |
| [AGENTS.md](AGENTS.md) | Agent playbook: golden rules, workflows, DAX patterns |

---

## Testing and verification

The 25 suites in `tests/` are assert-based scripts that run without Power BI (pure logic is
tested directly; live connectors are mocked).

```bash
python run_tests.py
```

Verification goes four layers deep, using the strongest check available per surface:

1. **Assert suites** for all pure logic (emitters, linters, auditors, security, parsers).
2. **Adversarial doc-verification**: API contracts (PBIR schemas, TMDL shapes, REST/INFO
   surfaces, the Desktop Bridge protocol) fact-checked against Microsoft Learn and real
   exports before implementation.
3. **Engine-level validation**: generated TMDL parses under Microsoft's own `TmdlSerializer`,
   the code path Power BI Desktop runs when opening a PBIP.
4. **Live testing** against a running Power BI Desktop: ADOMD queries, validated TOM batch
   writes with rollback, the star-schema audit on a real model, and the Desktop Bridge
   (discovery, manifest, state, hot-reload).

Cloud XMLA/REST/admin paths are doc-verified and mock-tested; their end-to-end verification
needs a real tenant. Details in [docs/TESTING.md](docs/TESTING.md).

---

## Project structure

```
powerbi-mcp/
├── src/
│   ├── server.py                    # MCP server: 82 tools + resources/prompts/completion
│   ├── powerbi_desktop_connector.py # Desktop (ADOMD) + RLS + VertiPaq DMVs
│   ├── powerbi_xmla_connector.py    # Cloud XMLA
│   ├── powerbi_rest_connector.py    # REST: discovery, refresh, admin Scanner/Activity
│   ├── powerbi_tom_connector.py     # TOM writes: measures, relationships, transactions
│   ├── powerbi_pbip_connector.py    # PBIP/TMDL/PBIR offline editing (transactional)
│   ├── pbir_authoring.py            # PBIR emitters: pages, visuals, field projections
│   ├── adomd_loader.py             # Shared ADOMD.NET discovery (Desktop + XMLA)
│   ├── model_analysis.py            # BPA, AI-readiness, data dictionary, diff, DAX tests
│   ├── dax_lint.py                  # DAX anti-pattern linter + rewrite hints (tokenizer)
│   ├── svg_measures.py             # SVG micro-visual DAX measure generators
│   ├── naming_audit.py             # Naming-convention audit -> rename plan
│   ├── pbix_tools.py               # PBIX (.pbix ZIP) inspect/extract + layout decode
│   ├── bpa_authoring.py            # Custom BPA rule validation + rule-source audit
│   ├── dax_generator.py            # Bulk measure-suite generation (time intel, ratios, ranks)
│   ├── star_schema.py              # Star-schema classification + warehouse audit
│   ├── tmdl_authoring.py           # TMDL emitters: measures, date table, calc groups, hierarchies
│   ├── desktop_bridge.py           # Power BI Desktop Bridge client (JSON-RPC over named pipe)
│   ├── refresh_diagnostics.py       # Refresh error classification
│   ├── governance.py                # Scanner summary + activity aggregation
│   └── security/                    # security_layer, access_policy, pii_detector, audit_logger
├── config/policies.yaml
├── tests/                           # Assert-based suites
├── docs/                            # TOOLS, ARCHITECTURE, TESTING
├── run_tests.py
├── pbip_diagnostic_tool.py            # Standalone PBIP diagnostic utility
├── AGENTS.md, CLAUDE.md
├── Dockerfile, requirements-core.txt
├── pyproject.toml, .editorconfig
├── CHANGELOG.md, requirements.txt
└── README.md
```

---

## Limitations

| Limitation | Notes |
|------------|-------|
| Live connectivity is Windows only | ADOMD.NET, TOM, and the Desktop Bridge named pipe require Windows. The offline subset runs cross-platform via Docker. |
| TOM renames break visuals | Use the PBIP tools for safe renames (they update the report layer too). |
| `bridge_screenshot` depends on a Desktop preview fix | On current Desktop builds `report.snapshot.capture` can return an internal error for any input (a Desktop-side preview defect; verified independent of this client). Status, manifest, and hot-reload work. |
| Cloud paths are doc-verified, not live-verified | XMLA/REST/admin tools are mock-tested and fact-checked against Microsoft Learn; they have not yet been exercised against a production tenant. |
| Cloud enhanced refresh needs Premium | XMLA and enhanced refresh need PPU / Premium / Fabric capacity. Basic refresh and history work on Pro. |
| Fleet governance is admin-gated | Scanner and Activity tools need Fabric admin, or a service principal allowed to use read-only admin APIs. |
| Deep server timings | `analyze_query_performance` gives duration and hints; use DAX Studio for storage-vs-formula-engine timings (a trace-based loop is on the roadmap). |

---

## Roadmap

### Done

- Power BI Desktop and Service connectivity, RLS testing, TOM writes, PBIP safe editing.
- DAX validate-before-commit loop, atomic transactions, dependency and impact analysis.
- Best Practice Analyzer, AI-readiness scoring, VertiPaq-style storage and query analysis.
- Transactional, atomic, encoding-faithful PBIP renames (model + report + hierarchies + sort wiring).
- Enforced column policies, PII masking, numeric masking, HMAC-capable tamper-evident audit,
  read-only mode, response-boundary secret redaction.
- Documentation export, model snapshot and diff, pre-deploy gate, DAX regression runner.
- Refresh doctor, unused-object detection, RLS test matrix.
- Cross-workspace lineage, fleet refresh monitor, usage analytics.
- Modern MCP surface: annotations, structured output, resources, prompts, completion.
- Docker image for the cross-platform offline subset.
- PBIR report authoring (pages, visuals, field bindings) with schema-verified output.
- DAX anti-pattern linter with rewrite hints; SVG micro-visual measure generators.
- Naming audit with rename plans; PBIX inspection/extraction; custom BPA rule governance.
- Bulk DAX creation (time intelligence, ratios, ranks) written offline into TMDL or live via
  validated TOM batches with intra-batch references and rollback.
- Offline data modelling: generated date dimensions, calculation groups, hierarchies,
  engine-verified against Microsoft's TmdlSerializer and a live Desktop.
- Star-schema audit and referential-integrity orphan scanning.
- Power BI Desktop Bridge integration: status, manifest, hot-reload, screenshots.

### Planned

- Trace-based DAX optimization loop (formula-engine vs storage-engine timings) and an
  EVALUATEANDLOG debugger.
- Refresh trigger/monitor/cancel (Enhanced Refresh API + Desktop TMSL).
- PyPI packaging, CI pipeline, and tagged releases.
- Live validation of the cloud XMLA/REST/admin paths against a production tenant.
- Best Practice Analyzer auto-fix; field parameters, object-level security, translations.
- Remote HTTP transport with Microsoft Entra OAuth (today, use the official remote Power BI MCP
  server for cloud auth).

---

## Contributing

1. Fork the repository.
2. Create a feature branch.
3. Keep the tool registry in sync (a tool lives in `handle_list_tools`, `_build_tool_dispatch`,
   and `_build_tool_annotations` in `src/server.py`; a parity check enforces this).
4. Run `python run_tests.py` and keep all suites green.
5. Open a pull request.

Formatting conventions are in `pyproject.toml` and `.editorconfig`.

---

## Author

**Sulaiman Ahmed**, Data Analytics Engineer and Microsoft Certified Professional.

[![GitHub](https://img.shields.io/badge/GitHub-sulaiman013-181717?style=flat-square&logo=github)](https://github.com/sulaiman013)
[![Portfolio](https://img.shields.io/badge/Portfolio-sulaiman--ahmed-blue?style=flat-square&logo=google-chrome)](https://sulaiman-ahmed.lovable.app)

---

## License

MIT. See [LICENSE](LICENSE).

## Acknowledgments

- [Model Context Protocol](https://modelcontextprotocol.io) by Anthropic.
- Microsoft's TOM, TMDL, and PBIR documentation.
- The Power BI community for insights on the PBIP format and semantic-model best practices.
