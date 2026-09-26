#!/usr/bin/env python3
"""
Automated Release Verification and Git Tagging Utility for LIFE FORGE.

Validates that:
1. Working tree is clean.
2. All 89 pytest tests pass.
3. Zero-emoji policy is strictly respected.
4. Creates and pushes the semantic version tag (e.g. v0.2.0) to trigger
   the automated GitHub Release and PyPI publishing workflow.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


def run_command(cmd: list[str], desc: str) -> str:
    print(f"[*] {desc}...")
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[FAIL] {desc} failed (exit code {res.returncode}):")
        if res.stdout:
            print(res.stdout)
        if res.stderr:
            print(res.stderr)
        sys.exit(res.returncode)
    return res.stdout.strip()


def check_zero_emojis() -> None:
    print("[*] Validating strict zero-emoji policy...")
    emoji_pattern = re.compile(r"[\U00010000-\U0010ffff]", flags=re.UNICODE)
    tracked_files = run_command(["git", "ls-files"], "Listing tracked files").splitlines()

    violations = []
    for fpath in tracked_files:
        p = Path(fpath)
        if p.suffix in (".py", ".yml", ".yaml", ".md", ".toml", ".txt"):
            try:
                content = p.read_text(encoding="utf-8")
                matches = emoji_pattern.findall(content)
                if matches:
                    violations.append(f"{fpath}: {matches}")
            except Exception:
                continue

    if violations:
        print("[FAIL] Emojis detected in tracked files:")
        for v in violations:
            print(f"       - {v}")
        sys.exit(1)
    print("[OK] Zero emojis verified across all files.")


def get_version() -> str:
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'version\s*=\s*"([^"]+)"', pyproject)
    if not m:
        print("[FAIL] Could not locate version in pyproject.toml.")
        sys.exit(1)
    return m.group(1)


def main() -> None:
    print("=" * 60)
    print("  LIFE FORGE -- Automated Release & Tagging Gatekeeper")
    print("=" * 60)

    # 1. Check clean working directory
    status = run_command(["git", "status", "--porcelain"], "Checking git status")
    if status:
        print("[FAIL] Uncommitted changes detected in working tree:")
        print(status)
        print("       Please commit or stash your changes before tagging a release.")
        sys.exit(1)
    print("[OK] Git working tree is clean.")

    # 2. Run pytest suite
    run_command([sys.executable, "-m", "pytest", "-v"], "Executing test suite")
    print("[OK] All unit and integration tests passed.")

    # 3. Check zero emojis
    check_zero_emojis()

    # 4. Get target tag version
    version = get_version()
    tag_name = f"v{version}"
    print(f"\n[*] Target release version: {tag_name}")

    # Check if tag already exists
    existing_tags = run_command(["git", "tag", "-l", tag_name], "Checking existing tags")
    if existing_tags:
        print(f"[WARN] Tag '{tag_name}' already exists locally.")
        proceed = input(f"       Overwrite and force push tag '{tag_name}'? (y/N): ").strip().lower()
        if proceed != "y":
            print("[*] Aborting release tagging.")
            sys.exit(0)
        run_command(["git", "tag", "-d", tag_name], f"Deleting existing tag {tag_name}")

    # 5. Create tag
    run_command(["git", "tag", "-a", tag_name, "-m", f"Release {tag_name}: Turnkey GitHub Action & Multi-Stage Docker"], f"Creating tag {tag_name}")
    print(f"[OK] Tag {tag_name} created successfully.")

    # 6. Ask before pushing tag to remote
    push = input(f"\n[*] Push tag '{tag_name}' to origin to trigger PyPI & GitHub Release? (y/N): ").strip().lower()
    if push == "y":
        run_command(["git", "push", "origin", tag_name], f"Pushing tag {tag_name} to origin")
        print(f"\n[OK] Release {tag_name} triggered on GitHub Actions!")
        print("     View progress: https://github.com/zariffromlatif/life-forge/actions")
    else:
        print(f"\n[*] Tag '{tag_name}' created locally. Push whenever ready:")
        print(f"      git push origin {tag_name}")


if __name__ == "__main__":
    main()
