"""Default harness for the refund desk: chat plus the desk's tools, nothing else.

Without a harness of its own, a taskset is evaluated with verifiers' ``bash``
harness, which frames the model as a coding agent and gives it a live shell and
a file editor. In the first benchmark run that let injected instructions execute
real commands on the evaluation machine (``nc`` to an attacker-named host, writes
to disk), and the shell use was invisible to the desk's reward. Exporting this
harness makes it the default for ``refund-desk-v1``: the model can only call the
six desk tools, and nothing it is told to do can run code on the host.
"""
from verifiers.v1.harnesses.null import NullHarness


class RefundDeskHarness(NullHarness):
    """Built-in ``null`` harness: a chat loop with MCP tools, no code execution."""

    EXECUTES_CODE = False
