"""Static and comparative detectors for MCP tool definitions.

Every detector is a pure function over tool definitions (plus optional
comparison state), producing :class:`McpFinding` records. Nothing here touches
the network: the live probe layer (``probe.py``) fetches definitions and hands
them to these detectors, so every rule can be tested against fixtures.

Severity vocabulary matches the rest of LIFE FORGE (CRITICAL/HIGH/MEDIUM/LOW)
so scanner findings, oracle verdicts, and audit bundles speak one language.
"""
from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

from .manifest import McpToolDefinition

#: Ruleset version, stamped into every report so a finding can always be
#: traced back to the exact detector logic that produced it.
RULESET_VERSION = "1.0.0"

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass
class McpFinding:
    """One scanner finding against a tool definition or a manifest."""

    rule_id: str
    severity: str
    title: str
    tool: str
    server: str = "default"
    description: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""

    def sort_key(self) -> tuple[int, str, str]:
        """Order findings by severity, then tool, then rule."""
        return (_SEVERITY_ORDER.get(self.severity, 4), self.tool, self.rule_id)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the finding."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "tool": self.tool,
            "server": self.server,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


# ---------------------------------------------------------------------------
# Pattern library
# ---------------------------------------------------------------------------

#: Directives that try to steer the agent when the model reads the schema.
POISON_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules|constraints)", "instruction override"),
    (r"(system|developer)\s*(prompt|message)\s*(override|update|directive)", "authority spoofing"),
    (r"\[\s*(system|admin|root|maintainer)\s*\]", "bracketed authority marker"),
    # Coercion only counts when it targets a consequential action: benign
    # sequencing ("call the resolve tool first") is normal tool documentation
    # and flagging it would drown the signal in false positives.
    (r"(call|invoke|execute)\s+\w*transfer\w*\s*\(?", "coercive transfer instruction"),
    (r"you\s+(must|need to|should)[^.]{0,80}(transfer|wire|send)\s+(\$|\d|funds)", "coercive transfer instruction"),
    (r"authorization\s+code|auth\s+code\s*[:=]|EXEC-[A-Z-]+", "credential exfiltration attempt"),
    (r"do\s+not\s+(tell|inform|mention|reveal|disclose)", "concealment instruction"),
    (r"tool[_\s]*policy[_\s]*update|schema[_\s]*directive|maintenance[_\s]*directive", "fake policy channel"),
    (r"propagation\s+step|copy\s+(this|the entire)\s+(text|notice|payload)", "worm propagation instruction"),
    (r"\[\s*::\s*[A-Z-]+\s*::\s*\]", "worm marker"),
    (r"before\s+(merging|deploying|executing)[^.]*(read|send|include|email)", "conditional exfiltration setup"),
    (r"(send|email|post)\s+[^.]*(credentials|secrets|api[_\s]?keys?|tokens?|\.env)", "secret exfiltration instruction"),
)

#: Regex for long base64-looking runs, which smuggle instructions past naive filters.
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{48,}={0,2}")

#: Invisible and directional Unicode that can hide instructions or flip rendering.
_INVISIBLE_RANGES: tuple[tuple[int, int, str], ...] = (
    (0x200B, 0x200F, "zero-width / directional mark"),
    (0x202A, 0x202E, "bidi override"),
    (0x2060, 0x2064, "invisible separator"),
    (0x2066, 0x2069, "bidi isolate"),
    (0xFEFF, 0xFEFF, "byte-order mark"),
    (0xE0000, 0xE007F, "tag character"),
)

#: Destructive-capability verbs. A tool matching these without an authorization
#: surface is one injected instruction away from an unauthorized action.
#: "issue" is deliberately absent: as a noun it names GitHub/Jira artifacts and
#: flagging read tools like get_issue would be a false positive.
_DESTRUCTIVE_VERBS = (
    "delete", "drop", "destroy", "remove", "execute", "run", "deploy",
    "transfer", "send", "pay", "refund", "purchase", "grant",
    "revoke", "merge", "cancel", "purge", "overwrite", "write",
)

#: Verb matcher over natural-language descriptions: whole words with common
#: inflections only, so "purchase_orders" (a table name) never matches the
#: verb "purchase" - substring matching flagged every database query tool.
_VERB_PATTERN = re.compile(
    r"\b(" + "|".join(verb + r"(?:s|es|d|ed|ing)?" for verb in _DESTRUCTIVE_VERBS) + r")\b"
)


def _is_destructive(tool: McpToolDefinition) -> bool:
    """Return True when the tool's name or description signals a mutating capability.

    Name matching uses underscore-delimited tokens (``issue_purchase_order``
    contains the verb "issue"); description matching uses whole-word
    inflection-aware boundaries.
    """
    name_tokens = {token for token in tool.name.lower().split("_") if token}
    if name_tokens & set(_DESTRUCTIVE_VERBS):
        return True
    return bool(_VERB_PATTERN.search(tool.description.lower()))

#: Argument names that constitute an authorization surface.
_AUTHORIZATION_ARGUMENTS = (
    "confirm", "confirmation", "authorization", "authorization_code",
    "auth_code", "approval", "approved", "dry_run", "token", "signature",
    "verified", "signed",
)

#: Confusable Unicode blocks used for homoglyph attacks on identifiers.
_CONFUSABLE_BLOCKS = (
    (0x0400, 0x04FF, "Cyrillic"),
    (0x0370, 0x03FF, "Greek"),
    (0x1E00, 0x1EFF, "Latin Extended Additional"),
    (0xFF00, 0xFFEF, "Fullwidth forms"),
)


def _find_invisible(text: str) -> list[dict[str, Any]]:
    """Return the invisible/directional characters present in ``text``."""
    found: list[dict[str, Any]] = []
    for index, char in enumerate(text):
        code = ord(char)
        for low, high, label in _INVISIBLE_RANGES:
            if low <= code <= high:
                found.append(
                    {"index": index, "codepoint": f"U+{code:04X}", "kind": label, "context": text[max(0, index - 12): index + 12]}
                )
                break
    return found


def _find_confusables(text: str) -> list[dict[str, Any]]:
    """Return non-ASCII confusable characters inside identifier-like text."""
    found: list[dict[str, Any]] = []
    for index, char in enumerate(text):
        code = ord(char)
        if code < 0x80:
            continue
        for low, high, label in _CONFUSABLE_BLOCKS:
            if low <= code <= high:
                found.append(
                    {
                        "index": index,
                        "codepoint": f"U+{code:04X}",
                        "character": char,
                        "script": label,
                        "decomposed": unicodedata.normalize("NFKD", char),
                    }
                )
                break
    return found


def _scan_text_for_poison(text: str) -> list[dict[str, Any]]:
    """Return every poisoning pattern hit in a text blob."""
    hits: list[dict[str, Any]] = []
    for pattern, label in POISON_PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            hits.append(
                {"kind": label, "pattern": pattern, "excerpt": text[max(0, match.start() - 20): match.end() + 40]}
            )
    # Base64 must be matched against the original text: the encoding is
    # case-sensitive, and lowercasing it corrupts the payload so it never
    # decodes (which would silently hide exactly the payloads we look for).
    for match in _BASE64_RUN.finditer(text):
        blob = match.group(0)
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            readable = sum(1 for byte in decoded if 32 <= byte < 127) / max(1, len(decoded))
            if readable > 0.7:
                hits.append(
                    {
                        "kind": "encoded payload",
                        "excerpt": blob[:48] + ("..." if len(blob) > 48 else ""),
                        "decoded_preview": decoded[:120].decode("utf-8", errors="replace"),
                    }
                )
        except (ValueError, UnicodeDecodeError):
            continue
    return hits


# ---------------------------------------------------------------------------
# Static detectors
# ---------------------------------------------------------------------------


def detect_schema_poisoning(tool: McpToolDefinition) -> list[McpFinding]:
    """Detect injection directives embedded in tool descriptions (CRITICAL).

    This is the 2026 tool-poisoning class: an agent loads tool schemas into its
    context, so a description is *instructions the model reads*, not
    documentation a human reads. Anything directive-shaped in a description is
    attacker-controlled if the server is compromised.
    """
    findings: list[McpFinding] = []
    hits = _scan_text_for_poison(tool.description)
    for argument, value in sorted(tool.properties().items()):
        if isinstance(value, dict):
            for key in ("description", "enum"):
                if isinstance(value.get(key), str):
                    hits.extend(_scan_text_for_poison(value[key]))
    if hits:
        findings.append(
            McpFinding(
                rule_id="MCP_SCHEMA_POISONING",
                severity="CRITICAL",
                title="Injection directive embedded in tool description",
                tool=tool.name,
                server=tool.server,
                description=(
                    "The tool description carries text that reads as an instruction to the agent "
                    "rather than documentation. Because agents load tool schemas into their context, "
                    "a compromised or malicious server can steer the agent through this channel."
                ),
                evidence={"hits": hits[:8]},
                remediation=(
                    "Treat tool descriptions as untrusted data: render them to a human reviewer, "
                    "scan them with this ruleset in CI, and pin server versions so description "
                    "changes require re-approval."
                ),
            )
        )
    return findings


def detect_hidden_characters(tool: McpToolDefinition) -> list[McpFinding]:
    """Detect invisible or directional Unicode in descriptions and names (HIGH).

    Zero-width and bidi characters can carry hidden instructions, flip the visual
    order of text (making a reviewed description differ from the executed one),
    or smuggle payloads past filters.
    """
    targets = [
        ("description", tool.description),
        ("name", tool.name),
    ]
    for argument, value in tool.properties().items():
        targets.append((f"parameter:{argument}", str(argument)))
        if isinstance(value, dict) and isinstance(value.get("description"), str):
            targets.append((f"parameter:{argument}:description", value["description"]))

    all_hits: list[dict[str, Any]] = []
    for field_name, text in targets:
        for hit in _find_invisible(text):
            all_hits.append({"field": field_name, **hit})
    if not all_hits:
        return []

    return [
        McpFinding(
            rule_id="MCP_HIDDEN_CHARACTERS",
            severity="HIGH",
            title="Invisible or directional Unicode in tool definition",
            tool=tool.name,
            server=tool.server,
            description=(
                "The definition contains invisible or bidirectional control characters. These can "
                "hide instructions from human review or reorder displayed text so the reviewed "
                "content differs from what the model receives."
            ),
            evidence={"characters": all_hits[:10], "total": len(all_hits)},
            remediation="Strip all invisible and directional Unicode from tool metadata before publishing; reject definitions containing them.",
        )
    ]


def detect_homoglyph_identifiers(tool: McpToolDefinition) -> list[McpFinding]:
    """Detect confusable (homoglyph) characters in identifiers (HIGH).

    A tool named with a Cyrillic character that renders like an ASCII name can
    shadow the legitimate tool in an agent's tool list while a human reviewer
    sees no difference.
    """
    identifier_targets = [tool.name] + list(tool.properties().keys())
    hits: list[dict[str, Any]] = []
    for text in identifier_targets:
        for hit in _find_confusables(text):
            hits.append({"field": "name" if text == tool.name else "parameter", "text": text, **hit})
    if not hits:
        return []

    return [
        McpFinding(
            rule_id="MCP_HOMOGLYPH_IDENTIFIER",
            severity="HIGH",
            title="Confusable non-ASCII characters in identifier",
            tool=tool.name,
            server=tool.server,
            description=(
                "The tool or parameter name contains characters from scripts commonly used for "
                "homoglyph spoofing. It renders identically to an ASCII name but is a different "
                "string, which enables tool shadowing that survives human review."
            ),
            evidence={"hits": hits[:10]},
            remediation="Restrict tool and parameter names to ASCII; reject definitions containing confusable scripts.",
        )
    ]


def detect_unconstrained_destructive(tool: McpToolDefinition) -> list[McpFinding]:
    """Detect destructive tools with no authorization surface (HIGH).

    A tool whose name or description indicates it mutates the world (transfers,
    deletes, deploys) but whose schema has no confirmation, approval token, or
    dry-run argument will execute on the model's say-so alone.
    """
    if not _is_destructive(tool):
        return []

    haystack = f"{tool.name} {tool.description}".lower()
    arguments = {str(name).lower() for name in tool.properties()}
    has_authorization = any(any(auth in name for auth in _AUTHORIZATION_ARGUMENTS) for name in arguments)
    mentions_authorization = any(auth in haystack for auth in ("authorization", "confirmation", "approved by", "requires approval"))
    if has_authorization or mentions_authorization:
        return []

    return [
        McpFinding(
            rule_id="MCP_DESTRUCTIVE_UNCONSTRAINED",
            severity="HIGH",
            title="Destructive tool exposes no authorization surface",
            tool=tool.name,
            server=tool.server,
            description=(
                "The tool appears to mutate state or move money, but its schema declares no "
                "confirmation, approval-token, or dry-run argument. Execution is gated only on "
                "the model choosing to call it."
            ),
            evidence={
                "arguments": sorted(arguments)[:12],
                "required": tool.required_arguments(),
            },
            remediation=(
                "Add a confirmation or authorization argument (or a dry_run default) to every "
                "state-mutating tool, and enforce it server-side - not just in the schema."
            ),
        )
    ]


def detect_unbounded_parameters(tool: McpToolDefinition) -> list[McpFinding]:
    """Detect string parameters without bounds and numbers without ranges (MEDIUM).

    Unbounded arguments feed the PARAMETER_BOUNDARY violation class: the agent
    can pass arbitrary-length payloads (context flooding) or unvalidated values.
    """
    findings: list[McpFinding] = []
    for argument, spec in sorted(tool.properties().items()):
        if not isinstance(spec, dict):
            continue
        spec_type = spec.get("type")
        if spec_type == "string":
            bounded = any(key in spec for key in ("maxLength", "enum", "pattern", "format"))
            if not bounded:
                findings.append(
                    McpFinding(
                        rule_id="MCP_UNBOUNDED_PARAMETER",
                        severity="MEDIUM",
                        title="Unbounded string parameter",
                        tool=tool.name,
                        server=tool.server,
                        description=(
                            f"Parameter '{argument}' accepts a string with no maximum length, "
                            "enum, or pattern. It can carry arbitrarily large or arbitrary content "
                            "into the tool - including flood payloads and injection strings."
                        ),
                        evidence={"parameter": argument},
                        remediation=f"Constrain '{argument}' with maxLength and/or a pattern or enum.",
                    )
                )
        elif spec_type == "number" or spec_type == "integer":
            if "minimum" not in spec and "maximum" not in spec:
                findings.append(
                    McpFinding(
                        rule_id="MCP_UNBOUNDED_PARAMETER",
                        severity="MEDIUM",
                        title="Numeric parameter without range",
                        tool=tool.name,
                        server=tool.server,
                        description=(
                            f"Parameter '{argument}' is numeric with no minimum or maximum. "
                            "Out-of-range values (negative amounts, absurd quantities) reach the tool."
                        ),
                        evidence={"parameter": argument},
                        remediation=f"Declare minimum/maximum for '{argument}'.",
                    )
                )
    return findings


def detect_missing_required_on_mutating(tool: McpToolDefinition) -> list[McpFinding]:
    """Detect mutating tools that require no arguments (MEDIUM)."""
    if not _is_destructive(tool) or tool.required_arguments():
        return []

    return [
        McpFinding(
            rule_id="MCP_MUTATING_NO_REQUIRED",
            severity="MEDIUM",
            title="State-mutating tool declares no required arguments",
            tool=tool.name,
            server=tool.server,
            description=(
                "The tool can mutate state while every argument is optional. The agent can invoke "
                "it with an empty or degenerate call, and the schema communicates no intended shape."
            ),
            evidence={"arguments": sorted(str(name) for name in tool.properties())[:12]},
            remediation="Mark the arguments the tool genuinely needs as required.",
        )
    ]


def detect_external_references(tool: McpToolDefinition) -> list[McpFinding]:
    """Detect URLs inside descriptions (MEDIUM).

    A URL in a description invites the agent to fetch attacker-controlled
    content at use time - a living-off-the-context attack channel.
    """
    urls = re.findall(r"https?://[^\s)>\]]+", tool.description)
    if not urls:
        return []

    return [
        McpFinding(
            rule_id="MCP_EXTERNAL_REFERENCE",
            severity="MEDIUM",
            title="External URL embedded in tool description",
            tool=tool.name,
            server=tool.server,
            description=(
                "The description contains a URL the agent may be invited to fetch. If the server "
                "is compromised, the destination can be changed after approval and used to serve "
                "injected content."
            ),
            evidence={"urls": urls[:5]},
            remediation="Remove URLs from tool metadata; document endpoints in human-facing docs instead.",
        )
    ]


def detect_tool_shadowing(tools: list[McpToolDefinition]) -> list[McpFinding]:
    """Detect identical tool names across servers (MEDIUM).

    Cross-server tool shadowing is the CSA-flagged systemic flaw: when two
    connected servers publish the same tool name, which implementation runs
    depends on client resolution order - a compromise of either can hijack the
    other's call.
    """
    by_name: dict[str, list[str]] = {}
    for tool in tools:
        by_name.setdefault(tool.name, []).append(tool.server)

    findings: list[McpFinding] = []
    for name, servers in sorted(by_name.items()):
        if len(set(servers)) > 1:
            findings.append(
                McpFinding(
                    rule_id="MCP_TOOL_SHADOWING",
                    severity="MEDIUM",
                    title="Tool name published by multiple servers",
                    tool=name,
                    server=", ".join(sorted(set(servers))),
                    description=(
                        f"'{name}' is registered by more than one connected server "
                        f"({', '.join(sorted(set(servers)))}). Resolution order decides which "
                        "implementation executes; a compromised server can shadow the legitimate one."
                    ),
                    evidence={"servers": sorted(set(servers))},
                    remediation="Namespace tool names per server, or reject duplicate names at connection time.",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Comparative detectors (drift)
# ---------------------------------------------------------------------------


def detect_drift(
    baseline: list[McpToolDefinition],
    current: list[McpToolDefinition],
) -> list[McpFinding]:
    """Detect tool definitions that changed between two observations (HIGH).

    The rug-pull attack: a server is approved with benign definitions, then the
    definitions change. Comparing two snapshots - or a live fetch against the
    approved baseline - is the only reliable detection.
    """
    baseline_by_name = {tool.name: tool for tool in baseline}
    findings: list[McpFinding] = []

    for tool in current:
        original = baseline_by_name.get(tool.name)
        if original is None:
            if baseline:
                findings.append(
                    McpFinding(
                        rule_id="MCP_TOOL_DRIFT",
                        severity="HIGH",
                        title="Tool appeared after baseline",
                        tool=tool.name,
                        server=tool.server,
                        description=(
                            "This tool was not present in the approved baseline. It was added "
                            "dynamically after the server was vetted."
                        ),
                        evidence={"description_preview": tool.description[:160]},
                        remediation="Re-approve the server's tool set; pin tool lists where the client supports it.",
                    )
                )
            continue

        if original.description != tool.description:
            findings.append(
                McpFinding(
                    rule_id="MCP_TOOL_DRIFT",
                    severity="HIGH",
                    title="Tool description changed after baseline",
                    tool=tool.name,
                    server=tool.server,
                    description=(
                        "The description differs from the approved baseline. Description edits are "
                        "the classic rug-pull: approval was granted for the old text, execution "
                        "happens under the new one."
                    ),
                    evidence={
                        "baseline_preview": original.description[:160],
                        "current_preview": tool.description[:160],
                    },
                    remediation="Re-run approval on the new description; alert on any description change in CI.",
                )
            )

        if original.input_schema != tool.input_schema:
            findings.append(
                McpFinding(
                    rule_id="MCP_TOOL_DRIFT",
                    severity="HIGH",
                    title="Tool input schema changed after baseline",
                    tool=tool.name,
                    server=tool.server,
                    description="The input schema differs from the approved baseline.",
                    evidence={"tool": tool.name},
                    remediation="Re-approve the tool's contract before allowing calls.",
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Scan entry points
# ---------------------------------------------------------------------------

_STATIC_TOOL_DETECTORS = (
    detect_schema_poisoning,
    detect_hidden_characters,
    detect_homoglyph_identifiers,
    detect_unconstrained_destructive,
    detect_unbounded_parameters,
    detect_missing_required_on_mutating,
    detect_external_references,
)


def scan_tool(tool: McpToolDefinition) -> list[McpFinding]:
    """Run every static detector against one tool definition."""
    findings: list[McpFinding] = []
    for detector in _STATIC_TOOL_DETECTORS:
        findings.extend(detector(tool))
    return findings


def scan_tools(tools: list[McpToolDefinition], *, include_shadowing: bool = True) -> list[McpFinding]:
    """Run the full static ruleset over a set of tool definitions."""
    findings: list[McpFinding] = []
    for tool in tools:
        findings.extend(scan_tool(tool))
    if include_shadowing and len({tool.server for tool in tools}) > 1:
        findings.extend(detect_tool_shadowing(tools))
    return sorted(findings, key=McpFinding.sort_key)
