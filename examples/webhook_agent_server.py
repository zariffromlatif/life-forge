"""Example: Minimal HTTP Webhook Agent Microservice for LIFE FORGE Evaluation.

Demonstrates how an external agent running in any language/framework
(Node.js, Go, Python, LangGraph, CrewAI) exposes an HTTP endpoint
to be evaluated by `lifeforge eval --endpoint http://localhost:5050/act`.
"""
from __future__ import annotations

import http.server
import json
import socketserver
import sys
from typing import Any


class MockAgentHandler(http.server.BaseHTTPRequestHandler):
    """Simple JSON-RPC / REST webhook handler simulating an external agent."""

    step_count = 0

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)

        if self.path == "/reset":
            MockAgentHandler.step_count = 0
            self._send_json({"status": "reset_successful"})
            return

        if self.path in ("/act", "/"):
            MockAgentHandler.step_count += 1
            step = MockAgentHandler.step_count
            payload = json.loads(post_data.decode("utf-8")) if post_data else {}
            obs = payload.get("observation", {})

            # Step 1: Query inventory database
            if step == 1:
                action = {
                    "action_type": "tool_call",
                    "tool_name": "query_database",
                    "arguments": {"query": "SELECT * FROM inventory"},
                    "thought": "Checking current server stock levels.",
                }
            # Step 2: Query vendor API
            elif step == 2:
                action = {
                    "action_type": "tool_call",
                    "tool_name": "vendor_api",
                    "arguments": {"vendor_id": "vendor_alpha", "sku": "server_h100"},
                    "thought": "Fetching vendor quote for server_h100.",
                }
            # Step 3: Issue purchase order
            elif step == 3:
                action = {
                    "action_type": "tool_call",
                    "tool_name": "issue_purchase_order",
                    "arguments": {"vendor_id": "vendor_alpha", "sku": "server_h100", "quantity": 2},
                    "thought": "Issuing order for 2 H100 servers.",
                }
            # Step 4: Send confirmation
            elif step == 4:
                action = {
                    "action_type": "tool_call",
                    "tool_name": "send_email",
                    "arguments": {"to": "procurement_lead", "subject": "Procurement Complete", "body": "H100s purchased."},
                    "thought": "Notifying procurement lead of purchase.",
                }
            # Step 5: Complete task
            else:
                action = {
                    "action_type": "finish",
                    "thought": "Procurement workflow successfully fulfilled.",
                    "message": "Task complete.",
                }

            self._send_json(action)
            return

        self.send_response(404)
        self.end_headers()

    def _send_json(self, data: Any) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress standard HTTP server access logs to keep console clean."""
        pass


def run_server(port: int = 5050) -> None:
    print("=" * 60)
    print(f"  Mock Agent Webhook Server running on http://127.0.0.1:{port}")
    print("=" * 60)
    print(f"  Test via LIFE FORGE:")
    print(f"  python -m lifeforge.cli eval --endpoint http://127.0.0.1:{port}/act --reset-endpoint http://127.0.0.1:{port}/reset --scenarios 10\n")

    class ReusableTCPServer(socketserver.TCPServer):
        allow_reuse_address = True

    with ReusableTCPServer(("127.0.0.1", port), MockAgentHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n  Server stopped.")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5050
    run_server(port)
