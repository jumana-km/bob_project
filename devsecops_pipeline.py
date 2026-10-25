# =============================================================================
# Project  : DevSecOps CI/CD Pipeline Demo
# Author   : Jumana
# Date     : 2025-07-10
# Purpose  : Demonstrates intentional vulnerabilities, secure remediation,
#            automated security gates, and a generated GitHub Actions workflow.
# =============================================================================

from __future__ import annotations

import os
import re
import sqlite3
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Optional FastAPI / uvicorn import (not required for scan / write-workflow)
# ---------------------------------------------------------------------------
try:
    from fastapi import FastAPI, HTTPException
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:  # pragma: no cover
    FASTAPI_AVAILABLE = False

# ===========================================================================
# SECTION 1 – SAMPLE WEB APPLICATION
# ===========================================================================

SECURE_MODE: bool = os.environ.get("SECURE_MODE", "0") == "1"

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

DB_PATH = ":memory:"


def _get_db() -> sqlite3.Connection:
    """Return an in-memory SQLite connection seeded with demo data."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username TEXT, email TEXT)"
    )
    conn.execute(
        "INSERT OR IGNORE INTO users VALUES (1, 'alice', 'alice@example.com')"
    )
    conn.execute(
        "INSERT OR IGNORE INTO users VALUES (2, 'bob', 'bob@example.com')"
    )
    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# Build the FastAPI application
# ---------------------------------------------------------------------------

def create_app() -> "FastAPI":  # type: ignore[name-defined]
    if not FASTAPI_AVAILABLE:
        raise RuntimeError("fastapi is not installed. Run: pip install fastapi uvicorn")

    app = FastAPI(title="DevSecOps Demo App")

    if SECURE_MODE:
        _register_secure_routes(app)
    else:
        _register_vulnerable_routes(app)

    return app


# ---------------------------------------------------------------------------
# VULNERABLE routes (intentional – for demonstration only)
# ---------------------------------------------------------------------------

def _register_vulnerable_routes(app: "FastAPI") -> None:  # type: ignore[name-defined]
    # CWE-798: Hardcoded secret key
    SECRET_KEY = "super_secret_hardcoded_key_12345"  # noqa: S105  # CWE-798

    @app.get("/")
    def index() -> dict[str, str]:
        return {"message": "Welcome to the Vulnerable Demo App", "secret_hint": SECRET_KEY[:4]}

    @app.post("/login")
    def login(username: str, password: str) -> dict[str, Any]:
        # CWE-798: compares against hardcoded credential
        if username == "admin" and password == SECRET_KEY:  # CWE-798
            return {"status": "ok", "token": SECRET_KEY}
        raise HTTPException(status_code=401, detail="Unauthorized")

    @app.get("/users/{user_id}")
    def get_user(user_id: str) -> dict[str, Any]:
        conn = _get_db()
        # CWE-89: SQL injection via string formatting
        query = f"SELECT * FROM users WHERE id = {user_id}"  # CWE-89
        try:
            row = conn.execute(query).fetchone()
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if row is None:
            raise HTTPException(status_code=404, detail="User not found")
        return {"id": row[0], "username": row[1], "email": row[2]}

    @app.get("/search")
    def search_users(q: str) -> dict[str, Any]:
        conn = _get_db()
        # CWE-89: SQL injection via string formatting
        query = f"SELECT * FROM users WHERE username LIKE '%{q}%'"  # CWE-89
        try:
            rows = conn.execute(query).fetchall()
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"results": [{"id": r[0], "username": r[1]} for r in rows]}

    @app.get("/ping")
    def ping(host: str) -> dict[str, str]:
        # CWE-78: Command injection via os.system
        os.system(f"ping -c 1 {host}")  # CWE-78  # noqa: S605
        return {"status": "pinged", "host": host}

    # CWE-489: Debug mode / bind to 0.0.0.0 is set in run_app() below


# ---------------------------------------------------------------------------
# SECURE routes (SECURE_MODE=1)
# ---------------------------------------------------------------------------

def _register_secure_routes(app: "FastAPI") -> None:  # type: ignore[name-defined]
    # Secrets loaded from environment variables – no hardcoded value
    secret_key = os.environ.get("APP_SECRET_KEY", "")

    @app.get("/")
    def index() -> dict[str, str]:
        return {"message": "Welcome to the Secure Demo App"}

    @app.post("/login")
    def login(username: str, password: str) -> dict[str, Any]:
        if not secret_key:
            raise HTTPException(status_code=500, detail="APP_SECRET_KEY not configured")
        if username == "admin" and password == secret_key:
            return {"status": "ok"}
        raise HTTPException(status_code=401, detail="Unauthorized")

    @app.get("/users/{user_id}")
    def get_user(user_id: str) -> dict[str, Any]:
        if not user_id.isdigit():
            raise HTTPException(status_code=400, detail="Invalid user_id")
        conn = _get_db()
        # Parameterized query – no SQL injection
        row = conn.execute("SELECT * FROM users WHERE id = ?", (int(user_id),)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="User not found")
        return {"id": row[0], "username": row[1], "email": row[2]}

    @app.get("/search")
    def search_users(q: str) -> dict[str, Any]:
        conn = _get_db()
        # Parameterized query – no SQL injection
        rows = conn.execute(
            "SELECT * FROM users WHERE username LIKE ?", (f"%{q}%",)
        ).fetchall()
        return {"results": [{"id": r[0], "username": r[1]} for r in rows]}

    @app.get("/ping")
    def ping(host: str) -> dict[str, str]:
        allowed = re.fullmatch(r"[a-zA-Z0-9.\-]+", host)
        if not allowed:
            raise HTTPException(status_code=400, detail="Invalid host")
        # subprocess with argument list – no shell injection
        result = subprocess.run(  # noqa: S603
            ["ping", "-c", "1", host],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return {"status": "ok" if result.returncode == 0 else "unreachable", "host": host}


# ---------------------------------------------------------------------------
# App runner
# ---------------------------------------------------------------------------

def run_app() -> None:
    app = create_app()
    if SECURE_MODE:
        # Secure: bind to localhost only, debug off
        uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")
    else:
        # CWE-489: debug mode + 0.0.0.0 binding
        uvicorn.run(app, host="0.0.0.0", port=8000, log_level="debug")  # CWE-489  # noqa: S104


# ===========================================================================
# SECTION 2 – SECURITY GATE RUNNER
# ===========================================================================

# Patterns for the regex-based secret scanner
_SECRET_PATTERNS: list[tuple[str, str]] = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("Generic API Key", r"(?i)api[_\-]?key\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}['\"]?"),
    ("Private Key Header", r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
]


def _run_subprocess(cmd: list[str]) -> tuple[int, str]:
    """Run a command and return (returncode, combined output)."""
    proc = subprocess.run(  # noqa: S603
        cmd,
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout + proc.stderr


def _scan_bandit(target: str) -> tuple[bool, str]:
    """Run Bandit SAST; fail on HIGH severity findings."""
    print("  [*] Running Bandit (SAST)…")
    code, output = _run_subprocess(
        [sys.executable, "-m", "bandit", "-r", target, "--severity-level", "high", "-f", "txt"]
    )
    passed = code == 0
    # Bandit returns 1 when issues found
    summary_lines = [l for l in output.splitlines() if l.strip().startswith(("Total issues", "Run metrics", "Issue"))]
    summary = " | ".join(summary_lines[:4]) if summary_lines else output.strip()[-200:]
    if not summary_lines:
        # fallback: grab last non-empty lines
        non_empty = [l for l in output.splitlines() if l.strip()]
        summary = non_empty[-1][-200:] if non_empty else "no output"
    return passed, summary


def _scan_pip_audit() -> tuple[bool, str]:
    """Run pip-audit; fail on any known CVE."""
    print("  [*] Running pip-audit (dependency CVEs)…")
    code, output = _run_subprocess([sys.executable, "-m", "pip_audit", "-r", "requirements.txt", "--format", "columns"])
    passed = code == 0
    lines = [l for l in output.splitlines() if l.strip()]
    summary = lines[-1] if lines else "no output"
    return passed, summary


def _scan_secrets(target: str) -> tuple[bool, str]:
    """Regex-based secret scanner over all .py and config files."""
    print("  [*] Running secret scanner (regex)…")
    findings: list[str] = []
    base = Path(target)
    files = list(base.rglob("*.py")) + list(base.rglob("*.env")) + list(base.rglob("*.cfg"))
    for fpath in files:
        try:
            text = fpath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for name, pattern in _SECRET_PATTERNS:
            for match in re.finditer(pattern, text):
                findings.append(f"{fpath}:{name}: …{match.group()[:40]}…")

    passed = len(findings) == 0
    if findings:
        summary = f"{len(findings)} secret(s) found: " + "; ".join(findings[:3])
    else:
        summary = "No secrets detected"
    return passed, summary


def run_security_gates(target: str = ".") -> int:
    """
    Run all security gates and print a PASS/FAIL table.
    Returns 0 if all gates pass, 1 if any gate fails.
    """
    print("\n" + "=" * 60)
    print("  DEVSECOPS SECURITY GATE RUNNER")
    print("=" * 60)

    results: list[tuple[str, bool, str]] = []

    bandit_ok, bandit_msg = _scan_bandit(target)
    results.append(("Bandit SAST (HIGH)", bandit_ok, bandit_msg))

    audit_ok, audit_msg = _scan_pip_audit()
    results.append(("pip-audit (CVEs)", audit_ok, audit_msg))

    secrets_ok, secrets_msg = _scan_secrets(target)
    results.append(("Secret Scan (regex)", secrets_ok, secrets_msg))

    print("\n" + "-" * 60)
    print(f"{'Gate':<28} {'Status':<8} Summary")
    print("-" * 60)
    for gate_name, passed, msg in results:
        status = "PASS" if passed else "FAIL"
        short_msg = msg[:55] + "…" if len(msg) > 55 else msg
        print(f"{gate_name:<28} {status:<8} {short_msg}")
    print("-" * 60)

    overall_pass = all(p for _, p, _ in results)
    print(f"\nOverall result: {'PASS [OK]' if overall_pass else 'FAIL [!!]'}")
    print("=" * 60 + "\n")

    return 0 if overall_pass else 1


# ===========================================================================
# SECTION 3 – GITHUB ACTIONS WORKFLOW WRITER
# ===========================================================================

WORKFLOW_YAML = textwrap.dedent("""\
    # GitHub Actions – DevSecOps Security Pipeline
    # Generated by devsecops_pipeline.py

    name: DevSecOps Pipeline

    on:
      push:
        branches: ["main", "develop"]
      pull_request:
        branches: ["main"]

    jobs:
      # ------------------------------------------------------------------
      # Job 1 – Lint and Unit Tests
      # ------------------------------------------------------------------
      lint-and-test:
        name: Lint & Unit Tests
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4

          - name: Set up Python 3.11
            uses: actions/setup-python@v5
            with:
              python-version: "3.11"

          - name: Install dependencies
            run: |
              python -m pip install --upgrade pip
              pip install -r requirements.txt

          - name: Lint with flake8
            run: |
              pip install flake8
              flake8 devsecops_pipeline.py --max-line-length=100 --count

          - name: Run unit tests
            run: pytest devsecops_pipeline.py -v --tb=short

      # ------------------------------------------------------------------
      # Job 2 – SAST (Bandit)
      # ------------------------------------------------------------------
      sast:
        name: SAST – Bandit
        runs-on: ubuntu-latest
        needs: lint-and-test
        steps:
          - uses: actions/checkout@v4

          - name: Set up Python 3.11
            uses: actions/setup-python@v5
            with:
              python-version: "3.11"

          - name: Install Bandit
            run: pip install bandit

          - name: Run Bandit
            run: bandit -r . --severity-level high -f json -o bandit-report.json || true

          - name: Upload Bandit report
            uses: actions/upload-artifact@v4
            with:
              name: bandit-report
              path: bandit-report.json

          - name: Fail on HIGH findings
            run: bandit -r . --severity-level high

      # ------------------------------------------------------------------
      # Job 3 – Secrets Scan (Gitleaks)
      # ------------------------------------------------------------------
      secrets-scan:
        name: Secrets Scan – Gitleaks
        runs-on: ubuntu-latest
        needs: lint-and-test
        steps:
          - uses: actions/checkout@v4
            with:
              fetch-depth: 0

          - name: Run Gitleaks
            uses: gitleaks/gitleaks-action@v2
            env:
              GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      # ------------------------------------------------------------------
      # Job 4 – Dependency Scan (pip-audit)
      # ------------------------------------------------------------------
      dependency-scan:
        name: Dependency Scan – pip-audit
        runs-on: ubuntu-latest
        needs: lint-and-test
        steps:
          - uses: actions/checkout@v4

          - name: Set up Python 3.11
            uses: actions/setup-python@v5
            with:
              python-version: "3.11"

          - name: Install pip-audit
            run: pip install pip-audit

          - name: Install project dependencies
            run: pip install -r requirements.txt

          - name: Run pip-audit
            run: pip-audit --format columns

      # ------------------------------------------------------------------
      # Job 5 – Container Build + Trivy Image Scan
      # ------------------------------------------------------------------
      container-scan:
        name: Container Build & Trivy Scan
        runs-on: ubuntu-latest
        needs: lint-and-test
        steps:
          - uses: actions/checkout@v4

          - name: Build Docker image
            run: docker build -t devsecops-demo:${{ github.sha }} .

          - name: Run Trivy image scan
            uses: aquasecurity/trivy-action@master
            with:
              image-ref: "devsecops-demo:${{ github.sha }}"
              format: "table"
              exit-code: "1"
              severity: "CRITICAL,HIGH"
              ignore-unfixed: true

      # ------------------------------------------------------------------
      # Job 6 – Final Security Gate
      # ------------------------------------------------------------------
      security-gate:
        name: Final Security Gate
        runs-on: ubuntu-latest
        needs:
          - sast
          - secrets-scan
          - dependency-scan
          - container-scan
        steps:
          - uses: actions/checkout@v4

          - name: Set up Python 3.11
            uses: actions/setup-python@v5
            with:
              python-version: "3.11"

          - name: Install dependencies
            run: pip install -r requirements.txt

          - name: Run security gates
            run: python devsecops_pipeline.py scan

          - name: Gate passed
            run: echo "All security gates passed. Pipeline approved for deployment."
""")


def write_workflow() -> None:
    """Write the GitHub Actions workflow YAML to .github/workflows/."""
    workflow_dir = Path(".github") / "workflows"
    workflow_dir.mkdir(parents=True, exist_ok=True)
    workflow_path = workflow_dir / "security-pipeline.yml"
    workflow_path.write_text(WORKFLOW_YAML, encoding="utf-8")
    print(f"Workflow written to: {workflow_path}")


# ===========================================================================
# SECTION 4 – PYTEST TEST SUITE
# ===========================================================================
# Tests are collected by pytest when this file is run with:
#   pytest devsecops_pipeline.py -v

import pytest  # noqa: E402  (placed here to keep the file self-contained)


@pytest.fixture(scope="module")
def secure_client():
    """TestClient for the secure version of the app."""
    # Import here so pytest collection works even without fastapi installed
    try:
        from fastapi.testclient import TestClient  # type: ignore
    except ImportError:
        pytest.skip("fastapi not installed")

    os.environ["SECURE_MODE"] = "1"
    os.environ["APP_SECRET_KEY"] = "test_secret_key_for_pytest_only"

    # Reload SECURE_MODE global after env change
    import importlib
    import devsecops_pipeline as _mod
    _mod.SECURE_MODE = True

    original_secure = _mod.SECURE_MODE
    app = _mod.create_app()
    client = TestClient(app)

    yield client

    # Teardown
    _mod.SECURE_MODE = original_secure
    os.environ.pop("SECURE_MODE", None)
    os.environ.pop("APP_SECRET_KEY", None)


def test_secure_index(secure_client):
    """GET / returns 200 and a welcome message."""
    response = secure_client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert "Secure" in data["message"]


def test_secure_get_user_valid(secure_client):
    """GET /users/1 returns user alice."""
    response = secure_client.get("/users/1")
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "alice"


def test_secure_get_user_invalid_id(secure_client):
    """GET /users/bad returns 400 for non-numeric user_id."""
    response = secure_client.get("/users/bad")
    assert response.status_code == 400


def test_secure_get_user_not_found(secure_client):
    """GET /users/999 returns 404."""
    response = secure_client.get("/users/999")
    assert response.status_code == 404


def test_secure_search_users(secure_client):
    """GET /search?q=alice returns results list."""
    response = secure_client.get("/search?q=alice")
    assert response.status_code == 200
    data = response.json()
    assert "results" in data
    assert len(data["results"]) >= 1
    assert data["results"][0]["username"] == "alice"


def test_secure_search_empty(secure_client):
    """GET /search?q=zzz returns empty results list."""
    response = secure_client.get("/search?q=zzz")
    assert response.status_code == 200
    assert response.json()["results"] == []


def test_secure_login_no_secret_configured():
    """POST /login returns 500 when APP_SECRET_KEY is not set."""
    try:
        from fastapi.testclient import TestClient
    except ImportError:
        pytest.skip("fastapi not installed")

    import devsecops_pipeline as _mod
    _mod.SECURE_MODE = True
    os.environ.pop("APP_SECRET_KEY", None)
    app = _mod.create_app()
    client = TestClient(app, raise_server_exceptions=False)
    response = client.post("/login?username=admin&password=anything")
    assert response.status_code == 500


def test_secure_ping_invalid_host(secure_client):
    """GET /ping with shell-injection payload returns 400."""
    response = secure_client.get("/ping?host=google.com;rm+-rf+/")
    assert response.status_code == 400


# ===========================================================================
# SECTION 5 – ENTRY POINT
# ===========================================================================

def _print_usage() -> None:
    print(
        textwrap.dedent("""
        Usage: python devsecops_pipeline.py <command>

        Commands:
          run             Start the FastAPI app (set SECURE_MODE=1 for secure version)
          scan            Run all security gates (Bandit, pip-audit, secret scan)
          write-workflow  Write .github/workflows/security-pipeline.yml
          test            Run the pytest test suite
        """).strip()
    )


if __name__ == "__main__":
    if len(sys.argv) < 2:
        _print_usage()
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "run":
        run_app()

    elif command == "scan":
        target_dir = sys.argv[2] if len(sys.argv) > 2 else "."
        exit_code = run_security_gates(target_dir)
        sys.exit(exit_code)

    elif command == "write-workflow":
        write_workflow()

    elif command == "test":
        raise SystemExit(
            subprocess.call(
                [sys.executable, "-m", "pytest", __file__, "-v", "--tb=short"],
            )
        )

    else:
        print(f"Unknown command: {command!r}\n")
        _print_usage()
        sys.exit(1)
