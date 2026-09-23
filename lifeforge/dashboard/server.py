"""HTTP server and REST backend for the LIFE FORGE Visual Flight Simulator Dashboard."""
from __future__ import annotations

import http.server
import json
import socketserver
import sys
import threading
import urllib.parse
import webbrowser
from pathlib import Path
from typing import Any


STATIC_DIR = Path(__file__).parent / "static"


def find_results_dir(preferred_dir: str | Path = "results") -> Path:
    """Locate the results directory relative to current working dir or project root."""
    p = Path(preferred_dir)
    if p.exists() and p.is_dir():
        return p.resolve()
    # Check parent directory
    parent_p = Path(__file__).resolve().parent.parent.parent / "results"
    if parent_p.exists() and parent_p.is_dir():
        return parent_p
    p.mkdir(parents=True, exist_ok=True)
    return p.resolve()


def get_all_reports(
    results_dir: str | Path = "results",
    agent_filter: str | None = None,
) -> list[dict[str, Any]]:
    """Scan and parse all JSON reports in the results directory."""
    target_dir = find_results_dir(results_dir)
    reports: list[dict[str, Any]] = []

    # Recursively look for JSON reports
    for json_file in sorted(target_dir.rglob("*.json")):
        try:
            with json_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict) and "agent_name" in data:
                    name = data["agent_name"]
                    if agent_filter and agent_filter.lower() not in name.lower():
                        continue
                    data["_file_name"] = json_file.name
                    data["_file_path"] = str(json_file)
                    reports.append(data)
        except Exception:
            continue

    return reports


def get_aggregate_summary(reports: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute aggregate executive metrics across all evaluated agents."""
    total_evals = sum(r.get("total_evaluations", 0) for r in reports)
    total_crit = sum(r.get("critical_failures", 0) for r in reports)
    total_scenarios = sum(r.get("scenarios_generated", 0) for r in reports)

    categories: dict[str, int] = {}
    for r in reports:
        for cat, count in r.get("failure_mode_breakdown", {}).items():
            categories[cat] = categories.get(cat, 0) + count

    avg_failure_rate = (
        sum(r.get("failure_rate", 0.0) for r in reports) / len(reports)
        if reports
        else 0.0
    )

    return {
        "total_models_audited": len(reports),
        "total_evaluations": total_evals,
        "total_scenarios_explored": total_scenarios,
        "total_critical_vulnerabilities": total_crit,
        "average_adversarial_failure_rate": round(avg_failure_rate, 1),
        "failure_categories": categories,
        "models": [r.get("agent_name", "Unknown") for r in reports],
    }


def get_map_elites_grid_data(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Generate behavior space grid points populated by discovered failure modes."""
    cells = []
    # Grid of Adversarial Intensity (0..4) x Price Volatility (0..4)
    for adv in range(5):
        for vol in range(5):
            cell_type = "unexplored"
            findings_in_cell = []

            # Match findings by causal triggers
            for r in reports:
                for f in r.get("findings", []):
                    triggers = f.get("minimal_causal_trigger", [])
                    matches_adv = any("injection" in t or "spoofed" in t for t in triggers)
                    matches_vol = any("volatility" in t or "scarcity" in t for t in triggers)

                    if (matches_adv and adv >= 2) or (matches_vol and vol >= 2):
                        findings_in_cell.append({
                            "agent": r.get("agent_name"),
                            "severity": f.get("severity"),
                            "category": f.get("category"),
                            "title": f.get("title"),
                        })

            if findings_in_cell:
                has_crit = any(f["severity"] == "CRITICAL" for f in findings_in_cell)
                has_high = any(f["severity"] == "HIGH" for f in findings_in_cell)
                cell_type = "critical" if has_crit else ("high" if has_high else "medium")
            elif (adv + vol) <= 2:
                cell_type = "pass"

            cells.append({
                "adversarial_intensity": adv,
                "volatility_index": vol,
                "status": cell_type,
                "count": len(findings_in_cell),
                "findings": findings_in_cell,
            })
    return cells


class LifeForgeDashboardHandler(http.server.BaseHTTPRequestHandler):
    """Custom request handler serving REST endpoints and the UI single-page application."""

    results_dir: str | Path = "results"

    def do_GET(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query = urllib.parse.parse_qs(parsed_url.query)
        agent_filter = query.get("agent", [None])[0]

        if path == "/api/reports":
            reports = get_all_reports(self.results_dir, agent_filter=agent_filter)
            self.send_json_response(reports)
        elif path == "/api/summary":
            reports = get_all_reports(self.results_dir, agent_filter=agent_filter)
            self.send_json_response(get_aggregate_summary(reports))
        elif path == "/api/showdown":
            reports = get_all_reports(self.results_dir)
            self.send_json_response({
                "reports": reports,
                "summary": get_aggregate_summary(reports),
            })
        elif path == "/api/map_elites":
            reports = get_all_reports(self.results_dir, agent_filter=agent_filter)
            self.send_json_response(get_map_elites_grid_data(reports))
        elif path == "/api/modes/simulate":
            # Real-time CA MODES simulation
            rule = int(query.get("rule", [110])[0])
            steps = min(int(query.get("steps", [50])[0]), 100)
            self.handle_modes_simulation(rule, steps)
        elif path == "/api/export":
            filename = query.get("file", ["MODEL_SHOWDOWN.md"])[0]
            target_file = find_results_dir(self.results_dir) / filename
            if target_file.exists() and target_file.is_file():
                content = target_file.read_bytes()
                mime = "application/json" if target_file.suffix == ".json" else "text/markdown"
                self.send_response(200)
                self.send_header("Content-Type", f"{mime}; charset=utf-8")
                self.send_header("Content-Disposition", f"attachment; filename=\"{target_file.name}\"")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_error(404, "Report file not found")
        elif path in ("/", "/index.html"):
            self.serve_static_file(STATIC_DIR / "index.html", "text/html")
        else:
            # Attempt static file resolution
            static_file = STATIC_DIR / path.lstrip("/")
            if static_file.exists() and static_file.is_file():
                content_type = "text/plain"
                if static_file.suffix == ".html":
                    content_type = "text/html"
                elif static_file.suffix == ".css":
                    content_type = "text/css"
                elif static_file.suffix == ".js":
                    content_type = "application/javascript"
                elif static_file.suffix == ".json":
                    content_type = "application/json"
                self.serve_static_file(static_file, content_type)
            else:
                self.send_error(404, f"Path not found: {path}")

    def handle_modes_simulation(self, rule: int, steps: int) -> None:
        """Run a lightweight CA simulation and return JSON trajectory + MODES profile."""
        try:
            from lifeforge.metrics.modes import analyze_modes
            from lifeforge.substrates.ca.elementary import ElementaryCA

            ca = ElementaryCA(rule)
            state = ElementaryCA.seed_center(width=61)
            traj = ca.rollout(state, steps=steps)
            modes = analyze_modes(traj)

            response_data = {
                "rule": rule,
                "steps": steps,
                "wolfram_class": modes.wolfram_class,
                "complexity_gap": round(modes.complexity_gap, 4),
                "shannon_entropy": round(modes.shannon_entropy, 4),
                "compressibility": round(modes.compressibility_ratio, 4),
                "cumulative_activity": float(modes.cumulative_activity),
                "grid": [step.tolist() for step in traj],
            }
            self.send_json_response(response_data)
        except Exception as exc:
            self.send_json_response({"error": str(exc)}, status=500)

    def serve_static_file(self, file_path: Path, content_type: str) -> None:
        """Serve a static file from disk."""
        if not file_path.exists():
            self.send_error(404, "File not found")
            return
        content = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(content)

    def send_json_response(self, data: Any, status: int = 200) -> None:
        """Send JSON encoded response with appropriate CORS headers."""
        body = json.dumps(data, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        """Quiet default console logging to keep terminal clean."""
        pass


def create_server(
    port: int = 8000,
    host: str = "127.0.0.1",
    results_dir: str | Path = "results",
) -> http.server.HTTPServer:
    """Create and return a configured HTTPServer instance."""
    LifeForgeDashboardHandler.results_dir = results_dir

    class ReusableTCPServer(socketserver.TCPServer):
        allow_reuse_address = True

    server = ReusableTCPServer((host, port), LifeForgeDashboardHandler)
    return server


def start_dashboard(
    port: int = 8000,
    host: str = "127.0.0.1",
    open_browser: bool = True,
    results_dir: str | Path = "results",
) -> None:
    """Start the dashboard HTTP server and block until interrupted."""
    # Ensure static directory exists
    STATIC_DIR.mkdir(parents=True, exist_ok=True)

    server = create_server(port=port, host=host, results_dir=results_dir)
    url = f"http://{host}:{port}"

    print("=" * 60)
    print("  LIFE FORGE -- Visual Flight Simulator Command Center")
    print("=" * 60)
    print(f"\n  [OK] Dashboard Server running at: {url}")
    print(f"  [OK] Monitoring reports in:       {find_results_dir(results_dir)}")
    print("  [OK] Press Ctrl+C to stop.\n")

    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Dashboard stopped.")
    finally:
        server.server_close()
