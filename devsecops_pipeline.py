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
    from fastapi.responses import HTMLResponse
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

_FRONTEND_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>DevSecOps Demo</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, "Segoe UI", system-ui, sans-serif; background: #f0f2f5; color: #1f2328; min-height: 100vh; }
    header { background: #1f2328; color: #fff; padding: 18px 32px; display: flex; align-items: center; gap: 14px; }
    header h1 { font-size: 1.2rem; font-weight: 600; }
    .badge { font-size: 0.7rem; padding: 3px 10px; border-radius: 20px; font-weight: 700; letter-spacing: 0.05em; }
    .badge-vuln { background: #f87171; color: #fff; }
    .badge-secure { background: #34d399; color: #1f2328; }
    main { max-width: 860px; margin: 32px auto; padding: 0 16px 40px; }
    .info-bar { background: #fff3cd; border: 1px solid #ffc107; border-radius: 8px; padding: 12px 16px; margin-bottom: 24px; font-size: 0.85rem; color: #856404; }
    .info-bar.secure { background: #d1fae5; border-color: #34d399; color: #065f46; }
    h2 { font-size: 1rem; font-weight: 600; color: #57606a; text-transform: uppercase; letter-spacing: 0.06em; margin: 28px 0 12px; }
    .card { background: #fff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 20px; margin-bottom: 16px; }
    .card-title { font-weight: 600; font-size: 0.95rem; margin-bottom: 4px; }
    .card-desc { font-size: 0.82rem; color: #57606a; margin-bottom: 14px; }
    .row { display: flex; gap: 8px; flex-wrap: wrap; align-items: flex-end; margin-bottom: 10px; }
    label { font-size: 0.8rem; color: #57606a; display: block; margin-bottom: 3px; }
    input { border: 1px solid #d1d5db; border-radius: 6px; padding: 7px 10px; font-size: 0.88rem; width: 180px; outline: none; }
    input:focus { border-color: #3b82d4; }
    button { background: #1f2328; color: #fff; border: none; border-radius: 6px; padding: 8px 18px; font-size: 0.88rem; cursor: pointer; white-space: nowrap; }
    button:hover { background: #3b82d4; }
    .cwe-tag { font-size: 0.72rem; background: #fee2e2; color: #b91c1c; border-radius: 4px; padding: 2px 7px; font-weight: 600; margin-left: 6px; }
    .secure-tag { font-size: 0.72rem; background: #d1fae5; color: #065f46; border-radius: 4px; padding: 2px 7px; font-weight: 600; margin-left: 6px; }
    pre { background: #f7f8fa; border: 1px solid #e5e7eb; border-radius: 6px; padding: 12px; font-size: 0.82rem; white-space: pre-wrap; word-break: break-all; min-height: 36px; color: #1f2328; }
    pre.ok { border-color: #34d399; background: #f0fdf4; }
    pre.err { border-color: #f87171; background: #fff5f5; }
    footer { text-align: center; font-size: 0.75rem; color: #57606a; margin-top: 40px; border-top: 1px solid #e5e7eb; padding-top: 16px; }
  </style>
</head>
<body>
<header>
  <h1>DevSecOps Demo App</h1>
  <span class="badge {BADGE_CLASS}">{MODE_LABEL}</span>
</header>
<main>
  <div class="info-bar {INFO_CLASS}">
    {INFO_MSG}
  </div>

  <h2>Endpoints</h2>

  <!-- GET / -->
  <div class="card">
    <div class="card-title">GET &nbsp;/</div>
    <div class="card-desc">Welcome message. In vulnerable mode also returns a secret hint.</div>
    <div class="row"><button onclick="call('GET','/')">Send</button></div>
    <pre id="out-root">—</pre>
  </div>

  <!-- POST /login -->
  <div class="card">
    <div class="card-title">POST &nbsp;/login {LOGIN_TAG}</div>
    <div class="card-desc">Login with username and password.</div>
    <div class="row">
      <div><label>Username</label><input id="login-user" value="admin"/></div>
      <div><label>Password</label><input id="login-pass" type="password" value=""/></div>
      <button onclick="login()">Send</button>
    </div>
    <pre id="out-login">—</pre>
  </div>

  <!-- GET /users/{id} -->
  <div class="card">
    <div class="card-title">GET &nbsp;/users/&#123;user_id&#125; {SQLI_TAG}</div>
    <div class="card-desc">Fetch a user by ID.</div>
    <div class="row">
      <div><label>user_id</label><input id="uid" value="1"/></div>
      <button onclick="call('GET','/users/'+document.getElementById('uid').value)">Send</button>
    </div>
    <pre id="out-user">—</pre>
  </div>

  <!-- GET /search -->
  <div class="card">
    <div class="card-title">GET &nbsp;/search {SQLI_TAG}</div>
    <div class="card-desc">Search users by name.</div>
    <div class="row">
      <div><label>q</label><input id="sq" value="alice"/></div>
      <button onclick="call('GET','/search?q='+encodeURIComponent(document.getElementById('sq').value))">Send</button>
    </div>
    <pre id="out-search">—</pre>
  </div>

  <!-- GET /ping -->
  <div class="card">
    <div class="card-title">GET &nbsp;/ping {PING_TAG}</div>
    <div class="card-desc">Ping a host.</div>
    <div class="row">
      <div><label>host</label><input id="ph" value="127.0.0.1"/></div>
      <button onclick="call('GET','/ping?host='+encodeURIComponent(document.getElementById('ph').value))">Send</button>
    </div>
    <pre id="out-ping">—</pre>
  </div>

  <footer>DevSecOps Demo &mdash; For educational use only. Do not deploy vulnerable mode to production.</footer>
</main>

<script>
const outMap = {
  '/': 'out-root',
  '/login': 'out-login',
  '/search': 'out-search',
  '/ping': 'out-ping',
};

function getOutId(path) {
  if (path.startsWith('/users/')) return 'out-user';
  if (path.startsWith('/search')) return 'out-search';
  if (path.startsWith('/ping')) return 'out-ping';
  return outMap[path] || 'out-root';
}

async function call(method, path, body) {
  const el = document.getElementById(getOutId(path));
  el.textContent = 'Loading...';
  el.className = '';
  try {
    const opts = { method, headers: { 'Content-Type': 'application/json' } };
    if (body) opts.body = JSON.stringify(body);
    const r = await fetch(path, opts);
    const data = await r.json();
    el.textContent = JSON.stringify(data, null, 2);
    el.className = r.ok ? 'ok' : 'err';
  } catch(e) {
    el.textContent = 'Error: ' + e.message;
    el.className = 'err';
  }
}

async function login() {
  const u = document.getElementById('login-user').value;
  const p = document.getElementById('login-pass').value;
  const el = document.getElementById('out-login');
  el.textContent = 'Loading...';
  el.className = '';
  try {
    const r = await fetch('/login?username=' + encodeURIComponent(u) + '&password=' + encodeURIComponent(p), { method: 'POST' });
    const data = await r.json();
    el.textContent = JSON.stringify(data, null, 2);
    el.className = r.ok ? 'ok' : 'err';
  } catch(e) {
    el.textContent = 'Error: ' + e.message;
    el.className = 'err';
  }
}
</script>
</body>
</html>"""


def _build_frontend(secure: bool) -> str:
    if secure:
        badge_class = "badge-secure"
        mode_label = "SECURE MODE"
        info_class = "secure"
        info_msg = "Running in <strong>Secure Mode</strong>. All routes use parameterised queries, env-based secrets, input validation, and localhost-only binding."
        login_tag = '<span class="secure-tag">Env secret</span>'
        sqli_tag = '<span class="secure-tag">Parameterised</span>'
        ping_tag = '<span class="secure-tag">Validated</span>'
    else:
        badge_class = "badge-vuln"
        mode_label = "VULNERABLE MODE"
        info_class = ""
        info_msg = "&#9888; Running in <strong>Vulnerable Mode</strong>. This app contains intentional security flaws for demonstration. Never deploy this to production."
        login_tag = '<span class="cwe-tag">CWE-798</span>'
        sqli_tag = '<span class="cwe-tag">CWE-89</span>'
        ping_tag = '<span class="cwe-tag">CWE-78</span>'

    return (
        _FRONTEND_HTML
        .replace("{BADGE_CLASS}", badge_class)
        .replace("{MODE_LABEL}", mode_label)
        .replace("{INFO_CLASS}", info_class)
        .replace("{INFO_MSG}", info_msg)
        .replace("{LOGIN_TAG}", login_tag)
        .replace("{SQLI_TAG}", sqli_tag)
        .replace("{PING_TAG}", ping_tag)
    )


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

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        return HTMLResponse(_build_frontend(secure=False))

    @app.get("/api/info")
    def info() -> dict[str, str]:
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

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        return HTMLResponse(_build_frontend(secure=True))

    @app.get("/api/info")
    def info() -> dict[str, str]:
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
