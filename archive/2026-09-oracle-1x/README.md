# Archive: September 2026 material (superseded)

These files were published between 2026-09-26 and 2026-10-03 and are kept for transparency. **Do not
cite them.** An audit of the project in October 2026 found problems that invalidate their headline
claims:

| File | Problem |
| :--- | :--- |
| `LANGGRAPH_ADVISORY_LF-2026-0001_WITHDRAWN.md`, `LANGGRAPH_AUDIT_DISTRIBUTION_KIT.md` | The "LangGraph" agent was a scripted state machine with hard-coded vulnerabilities, not LangGraph and not an LLM. See [`audits/LANGGRAPH_CUSTOMER_SUPPORT_SECURITY_ADVISORY.md`](../../audits/LANGGRAPH_CUSTOMER_SUPPORT_SECURITY_ADVISORY.md). |
| `*_SHOWDOWN_DISTRIBUTION_KIT.md`, `MODEL_SHOWDOWN.md`, `THREE_WAY_MODEL_SHOWDOWN.md` | Judged by oracle 1.x. "Critical zero-days" / "wire exfiltrations" were attempts to call a transfer tool that the sandbox refused (no transfer ever completed); the Mistral "TOCTOU race" was a false positive; one seed per model. See the correction notice in [`results/LEADERBOARD.md`](../../results/LEADERBOARD.md). |
| `MCP_SCAN_DISTRIBUTION_KIT.md` | Promoted "40% of MCP servers in the CRITICAL band", a scoring bug (the scan had zero CRITICAL findings). See [`results/MCP_ECOSYSTEM_SCAN.md`](../../results/MCP_ECOSYSTEM_SCAN.md). |

The fixes are described in [`CHANGELOG.md`](../../CHANGELOG.md) (0.4.0-0.4.2).
