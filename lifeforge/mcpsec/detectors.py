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
#: 1.1.0: NFKC-normalized, whole-schema poisoning/hidden-character scans;
#: category-based invisible detection; any non-ASCII identifier flagged;
#: token-exact authorization arguments; camelCase/kebab destructive names.
RULESET_VERSION = "1.1.0"

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

#: Paths and artifacts whose contents an injected instruction tries to steal.
_SENSITIVE_TARGET = (
    r"(?:~|\$home|%userprofile%)?[/\\]?\.ssh\b|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|\.aws[/\\]credentials"
    r"|(?<![\w-])\.env\b|\bmcp\.json\b|claude_desktop_config|\.npmrc\b|\.netrc\b|\.git-credentials"
    r"|\.kube[/\\]config|/etc/(?:passwd|shadow)\b|\.bash_history|\bprivate[\s_-]?keys?\b|\bwallet\.dat\b"
)

#: Secret-bearing material an injected instruction asks the agent to smuggle
#: out through a tool argument. Plain "contents" is deliberately absent:
#: "pass the file contents as the 'content' parameter" is ordinary write-tool
#: documentation.
_SMUGGLED_MATERIAL = (
    r"credentials|secrets?|private[\s_-]?keys?|api[\s_-]?keys?|passwords?|access[\s_-]?tokens?"
    r"|ssh[\s_-]?keys?|conversation(?:\s+history)?|chat\s+history|system\s+prompt|previous\s+messages"
    r"|environment\s+variables"
)

#: Optional filler words between a verb and its object ("ignore *all the* previous ...").
_FILLER = r"(?:(?:all|any|the|your|of|these|those|every|earlier|other)\s+)*"

#: Directives that try to steer the agent when the model reads the schema.
#: Patterns run against NFKC-normalized text with invisible characters
#: removed, so fullwidth letters and zero-width splits cannot dodge them.
POISON_PATTERNS: tuple[tuple[str, str], ...] = (
    (
        r"\b(?:ignore|disregard|forget|override|bypass|discard|skip)\s+" + _FILLER
        + r"(?:previous|prior|above|earlier|preceding|original|system|existing)\s+"
        r"(?:instructions?|prompts?|rules|constraints|guidelines|directives|guidance)",
        "instruction override",
    ),
    (r"(system|developer)\s*(prompt|message)\s*(override|update|directive)", "authority spoofing"),
    (r"\[\s*(system|admin|root|maintainer)\s*\]", "bracketed authority marker"),
    (r"<\s*/?\s*(important|system|instructions?|admin|secret|hidden)\s*>", "tagged authority marker"),
    (
        r"\b(?:read|cat|include|send|pass|attach|upload|copy|provide|append|forward|share)\b[^.\n]{0,80}(?:"
        + _SENSITIVE_TARGET + r")",
        "sensitive file access instruction",
    ),
    (
        r"\b(?:pass|put|include|insert|embed|place|provide|send|add)\b[^.\n]{0,60}\b(?:" + _SMUGGLED_MATERIAL
        + r")\b[^.\n]{0,60}\b(?:as|in|into|inside|via)\b[^.\n]{0,40}\b(?:parameter|argument|field|arg)\b",
        "argument exfiltration instruction",
    ),
    (r"\bwithout\s+(?:telling|informing|notifying|alerting|asking)\s+(?:the\s+)?(?:user|human|operator)", "concealment instruction"),
    (r"\b(?:don'?t|never)\s+(?:tell|inform|mention|reveal|disclose|show)\s+(?:this\s+)?(?:to\s+)?(?:the\s+)?(?:user|human)", "concealment instruction"),
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

#: Invisible characters that are not format controls (category Cf) but still
#: render as nothing: variation selectors (the "emoji smuggling" channel),
#: the combining grapheme joiner, and the Hangul fillers.
_INVISIBLE_EXTRA_RANGES: tuple[tuple[int, int, str], ...] = (
    (0x034F, 0x034F, "combining grapheme joiner"),
    (0x115F, 0x1160, "Hangul filler"),
    (0x3164, 0x3164, "Hangul filler"),
    (0xFFA0, 0xFFA0, "Hangul filler"),
    (0xFE00, 0xFE0F, "variation selector"),
    (0xE0100, 0xE01EF, "variation selector supplement"),
    (0x2800, 0x2800, "braille blank"),
)

#: Unicode general categories that never belong in tool metadata text:
#: format controls (zero-width, bidi, soft hyphen, tag characters, BOM...),
#: private-use, unassigned, and surrogate code points.
_INVISIBLE_CATEGORIES = {"Cf": "format control", "Co": "private use", "Cn": "unassigned", "Cs": "surrogate"}


def _invisible_kind(char: str) -> str | None:
    """Return a label when ``char`` is invisible/directional, else None."""
    code = ord(char)
    for low, high, label in _INVISIBLE_EXTRA_RANGES:
        if low <= code <= high:
            return label
    category = unicodedata.category(char)
    if category in _INVISIBLE_CATEGORIES:
        for low, high, label in _INVISIBLE_LABELS:
            if low <= code <= high:
                return label
        return _INVISIBLE_CATEGORIES[category]
    return None


#: Specific labels for well-known Cf ranges (kept stable for report readers).
_INVISIBLE_LABELS: tuple[tuple[int, int, str], ...] = (
    (0x200B, 0x200F, "zero-width / directional mark"),
    (0x202A, 0x202E, "bidi override"),
    (0x2060, 0x2064, "invisible separator"),
    (0x2066, 0x2069, "bidi isolate"),
    (0xFEFF, 0xFEFF, "byte-order mark"),
    (0xE0000, 0xE007F, "tag character"),
    (0x00AD, 0x00AD, "soft hyphen"),
)


def _strip_invisible(text: str) -> str:
    """Remove every character :func:`_invisible_kind` flags."""
    return "".join(char for char in text if _invisible_kind(char) is None)


def _normalize_for_matching(text: str) -> str:
    """NFKC-fold, drop invisible characters, and collapse whitespace.

    Fullwidth/compatibility letters fold to ASCII, and zero-width splits
    ("ig\\u200bnore") rejoin, so neither can dodge the directive patterns.
    """
    folded = unicodedata.normalize("NFKC", _strip_invisible(text))
    return re.sub(r"\s+", " ", folded)


def _iter_schema_strings(node: Any, path: str = "inputSchema", depth: int = 0):
    """Yield ``(path, text)`` for every string anywhere in a JSON-schema tree.

    Covers descriptions, titles, defaults, examples, enum items, const values,
    nested ``properties``/``items``/``anyOf``/``$defs``, and property names
    (dictionary keys under ``properties``) - everything a client hands the
    model. Depth is bounded so a pathological schema cannot recurse forever.
    """
    if depth > 32:
        return
    if isinstance(node, str):
        yield path, node
    elif isinstance(node, dict):
        for key, value in node.items():
            key_text = str(key)
            if path.endswith(".properties") or path.endswith(".patternProperties"):
                yield f"{path}.<name:{key_text}>", key_text
            yield from _iter_schema_strings(value, f"{path}.{key_text}", depth + 1)
    elif isinstance(node, (list, tuple)):
        for index, item in enumerate(node):
            yield from _iter_schema_strings(item, f"{path}[{index}]", depth + 1)


def _tool_text_fields(tool: McpToolDefinition) -> list[tuple[str, str]]:
    """Every model-visible text field of a tool definition, with its location."""
    fields: list[tuple[str, str]] = [("name", tool.name), ("description", tool.description)]
    fields.extend(_iter_schema_strings(tool.input_schema or {}))
    fields.extend(_iter_schema_strings(tool.annotations or {}, "annotations"))
    return fields


def _iter_property_names(schema: Any, depth: int = 0):
    """Yield every property name declared anywhere in a JSON-schema tree."""
    if depth > 32 or not isinstance(schema, dict):
        return
    for key, value in schema.items():
        if key in ("properties", "patternProperties", "$defs", "definitions") and isinstance(value, dict):
            for name, sub in value.items():
                if key in ("properties", "patternProperties"):
                    yield str(name)
                yield from _iter_property_names(sub, depth + 1)
        elif isinstance(value, dict):
            yield from _iter_property_names(value, depth + 1)
        elif isinstance(value, list):
            for item in value:
                yield from _iter_property_names(item, depth + 1)

#: Destructive-capability verbs. A tool matching these without an authorization
#: surface is one injected instruction away from an unauthorized action.
#: "issue" is deliberately absent: as a noun it names GitHub/Jira artifacts and
#: flagging read tools like get_issue would be a false positive.
_DESTRUCTIVE_VERBS = (
    "delete", "drop", "destroy", "remove", "execute", "run", "deploy",
    "transfer", "send", "pay", "refund", "purchase", "grant",
    "revoke", "merge", "cancel", "purge", "overwrite", "write",
    "erase", "wipe", "kill", "terminate", "truncate",
)


def _identifier_token_list(name: str) -> list[str]:
    """Split an identifier on ``_``, ``-``, ``.``, spaces, and camelCase humps."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    spaced = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", spaced)
    return [token for token in re.split(r"[\s_\-./:]+", spaced.lower()) if token]


def _identifier_tokens(name: str) -> set[str]:
    """Set form of :func:`_identifier_token_list`."""
    return set(_identifier_token_list(name))

#: Verb matcher over natural-language descriptions: whole words with common
#: inflections only, so "purchase_orders" (a table name) never matches the
#: verb "purchase" - substring matching flagged every database query tool.
_VERB_PATTERN = re.compile(
    r"\b(" + "|".join(verb + r"(?:s|es|d|ed|ing)?" for verb in _DESTRUCTIVE_VERBS) + r")\b"
)


def _is_destructive(tool: McpToolDefinition) -> bool:
    """Return True when the tool's name or description signals a mutating capability.

    Name matching uses identifier tokens split on ``_``/``-``/``.`` and
    camelCase (``deleteRepository`` contains "delete"); description matching
    uses whole-word inflection-aware boundaries.
    """
    if _identifier_tokens(tool.name) & set(_DESTRUCTIVE_VERBS):
        return True
    return bool(_VERB_PATTERN.search(_normalize_for_matching(tool.description).lower()))

#: Argument-name tokens that constitute an authorization surface. Matching is
#: token-exact: ``page_token`` or ``max_tokens`` are pagination/limits, not an
#: approval gate, and substring matching let them silence the rule.
_AUTHORIZATION_TOKENS = frozenset({
    "confirm", "confirmation", "confirmed", "authorization", "approval",
    "approved", "approve", "signature", "verified", "signed",
})

#: Whole argument names that constitute an authorization surface.
_AUTHORIZATION_NAMES = frozenset({
    "auth_code", "authorization_code", "dry_run", "dryrun", "approval_token",
    "confirmation_token", "confirm_token", "auth_token", "otp", "mfa_code",
})


def _is_authorization_argument(name: str) -> bool:
    """True when an argument name is an approval/confirmation/dry-run gate."""
    token_list = _identifier_token_list(name)
    if "_".join(token_list) in _AUTHORIZATION_NAMES:
        return True
    tokens = set(token_list)
    if {"dry", "run"} <= tokens:
        return True
    return bool(tokens & _AUTHORIZATION_TOKENS)


def _is_emoji_presentation_selector(text: str, index: int) -> bool:
    """True for a single VS15/VS16 (or ZWJ) inside an ordinary emoji sequence.

    ``⚠️`` is U+26A0 followed by U+FE0F; flagging it would make every
    description with an emoji a HIGH finding. Smuggling uses *runs* of
    selectors, selectors after ASCII, or the supplement range - all still
    flagged.
    """
    char = text[index]
    if char not in "︎️‍":
        return False
    if index == 0:
        return False
    previous = text[index - 1]
    if char == "‍":
        # ZWJ joins two pictographs: symbol (+ optional VS16) ZWJ symbol.
        before = text[index - 2] if previous == "️" and index >= 2 else previous
        after = text[index + 1] if index + 1 < len(text) else ""
        return _is_pictograph(before) and _is_pictograph(after)
    return _is_pictograph(previous)


def _is_pictograph(char: str) -> bool:
    """Rough emoji-base test: a non-ASCII symbol or a supplementary-plane pictograph."""
    if not char or ord(char) < 0x80:
        return False
    return unicodedata.category(char) == "So" or 0x1F000 <= ord(char) <= 0x1FAFF


def _find_invisible(text: str) -> list[dict[str, Any]]:
    """Return the invisible/directional characters present in ``text``.

    Detection is by Unicode category (Cf, Co, Cn, Cs) plus the renders-as-
    nothing characters outside Cf (variation selectors, Hangul fillers, CGJ),
    so newly assigned format characters are covered without a list update.
    """
    found: list[dict[str, Any]] = []
    for index, char in enumerate(text):
        kind = _invisible_kind(char)
        if kind is not None and _is_emoji_presentation_selector(text, index):
            continue
        if kind is not None:
            found.append(
                {
                    "index": index,
                    "codepoint": f"U+{ord(char):04X}",
                    "kind": kind,
                    "context": _strip_invisible(text[max(0, index - 12): index + 12]),
                }
            )
    return found


def _script_label(char: str) -> str:
    """Best-effort script/block label for a character, from its Unicode name."""
    try:
        return unicodedata.name(char).split(" ")[0].title()
    except ValueError:
        return "Unnamed"


def _find_confusables(text: str) -> list[dict[str, Any]]:
    """Return every non-ASCII character inside identifier text.

    Identifiers (tool and parameter names) have no legitimate need for
    non-ASCII: any of it - Cyrillic, Greek, Latin Extended (dotless i), IPA,
    mathematical alphanumerics, Armenian, Cherokee - can render like ASCII
    and shadow another tool, so the rule no longer relies on a block list.
    """
    found: list[dict[str, Any]] = []
    for index, char in enumerate(text):
        code = ord(char)
        if code < 0x80:
            continue
        found.append(
            {
                "index": index,
                "codepoint": f"U+{code:04X}",
                "character": char,
                "script": _script_label(char),
                "decomposed": unicodedata.normalize("NFKD", char),
            }
        )
    return found


def _scan_text_for_poison(text: str) -> list[dict[str, Any]]:
    """Return every poisoning pattern hit in a text blob.

    Directive patterns run on the NFKC-normalized, invisible-stripped text.
    """
    hits: list[dict[str, Any]] = []
    normalized = _normalize_for_matching(text)
    for pattern, label in POISON_PATTERNS:
        match = re.search(pattern, normalized, re.IGNORECASE)
        if match:
            hits.append(
                {"kind": label, "pattern": pattern, "excerpt": normalized[max(0, match.start() - 20): match.end() + 40]}
            )
    # Base64 must be matched against the original text: the encoding is
    # case-sensitive, and lowercasing it corrupts the payload so it never
    # decodes (which would silently hide exactly the payloads we look for).
    for match in _BASE64_RUN.finditer(_strip_invisible(text)):
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
    hits: list[dict[str, Any]] = []
    # Every model-visible string: description, and the whole input schema
    # (nested properties, items, enum items, defaults, titles, examples) plus
    # annotations - an enum value is read by the model just like a description.
    for field_name, text in _tool_text_fields(tool):
        for hit in _scan_text_for_poison(text):
            hits.append({"field": field_name, **hit})
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
    all_hits: list[dict[str, Any]] = []
    for field_name, text in _tool_text_fields(tool):
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
    identifier_targets = [("name", tool.name)] + [
        ("parameter", name) for name in _iter_property_names(tool.input_schema or {})
    ]
    hits: list[dict[str, Any]] = []
    for field_name, text in identifier_targets:
        for hit in _find_confusables(text):
            hits.append({"field": field_name, "text": text, **hit})
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

    haystack = f"{tool.name} {_normalize_for_matching(tool.description)}".lower()
    raw_arguments = [str(name) for name in tool.properties()]
    arguments = {name.lower() for name in raw_arguments}
    has_authorization = any(_is_authorization_argument(name) for name in raw_arguments)
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
