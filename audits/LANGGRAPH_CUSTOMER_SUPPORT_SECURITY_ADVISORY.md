# Withdrawn: advisory LF-2026-0001 (LangGraph customer-support templates)

**Status: withdrawn on 2026-10-12. Its findings should not be cited.**

Advisory LF-2026-0001 (2026-09-30) described "deterministic invariant violations and prompt
injection bypass in canonical LangGraph customer support agent templates", rated CRITICAL, and
reported "2 critical zero-day privilege escalations".

That was not an audit of LangGraph or of any language model. The agent under test
(`examples/targets/langgraph_customer_support.py`) is a **scripted Python state machine** written
for this project, whose vulnerabilities are hard-coded (for example, it grants admin access whenever
a message contains the words `admin_grant`). It was modeled on the LangGraph customer-support
tutorial's prompt and tools, but it does not use LangGraph and makes no model calls. The
"vulnerabilities" it reported are the ones that script was written to have, so they say nothing
about LangGraph, about the tutorial, or about how a real LLM-driven agent behaves.

What remains valid:

- The script is a reasonable **demonstration** of what LIFE FORGE reports when an agent does have
  these weaknesses (the oracle verdicts, the audit bundle format, and the `@tool_guard` remediation
  are real).
- The general risk it illustrates (relying on prompt instructions instead of runtime checks at the
  tool boundary) is well documented elsewhere.

A replacement report will test a **real LLM-driven agent** in the sandbox and publish its transcripts.

The original text is kept, marked as withdrawn, in
[`archive/2026-09-oracle-1x/`](../archive/2026-09-oracle-1x/) for transparency.
