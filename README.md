# DevSecOps CI/CD Pipeline Demo

A self-contained Python project that demonstrates a complete DevSecOps pipeline: a FastAPI web application with intentional, CWE-documented vulnerabilities, a secure remediation mode, automated security gate scanning (SAST, dependency audit, secret detection), and a generated GitHub Actions workflow covering lint, SAST, secrets scan, dependency scan, container scan, and a final gate job.

---

## Architecture

```
Developer (local)
       │
       │  git push
       ▼
  GitHub Repository
       │
       ├──────────────────────────────────────────────────────────┐
       │                   CI Pipeline Stages                     │
       │                                                          │
       │  ┌─────────────┐   ┌──────────┐   ┌──────────────────┐  │
       │  │  Lint &     │   │  SAST    │   │ Secrets Scan     │  │
       │  │  Unit Tests │   │ (Bandit) │   │ (Gitleaks)       │  │
       │  │  (pytest)   │   │          │   │                  │  │
       │  └──────┬──────┘   └────┬─────┘   └────────┬─────────┘  │
       │         │               │                   │            │
       │         └───────────────┴─────┬─────────────┘            │
       │                               │                          │
       │  ┌────────────────────┐   ┌───┴──────────────────────┐   │
       │  │ Dependency Scan    │   │ Container Build & Trivy  │   │
       │  │ (pip-audit)        │   │ Image Scan               │   │
       │  └──────────┬─────────┘   └────────────┬─────────────┘   │
       │             └──────────────┬────────────┘                │
       │                            ▼                             │
       │                  ┌─────────────────────┐                 │
       │                  │   Final Security    │                 │
       │                  │   Gate (all must    │                 │
       │                  │   pass)             │                 │
       │                  └──────────┬──────────┘                 │
       └─────────────────────────────┼──────────────────────────-─┘
                                     │
                                     ▼
                               Deploy  ✓
                         (only if gate passes)
```

---

## Setup

### Prerequisites

- Python 3.11 or higher
- pip

### Install dependencies

```bash
pip install -r requirements.txt
```

---

## Running the commands

### 1 – Start the web application

**Vulnerable mode (default):**
```bash
python devsecops_pipeline.py run
```

**Secure mode:**
```bash
# Linux / macOS
SECURE_MODE=1 APP_SECRET_KEY=my_strong_secret python devsecops_pipeline.py run

# Windows PowerShell
$env:SECURE_MODE="1"; $env:APP_SECRET_KEY="my_strong_secret"; python devsecops_pipeline.py run
```

The app starts on `http://127.0.0.1:8000` (secure) or `http://0.0.0.0:8000` (vulnerable).

### 2 – Run security gates

```bash
python devsecops_pipeline.py scan
```

Runs Bandit (SAST), pip-audit (dependency CVEs), and a regex secret scanner.  
Prints a PASS/FAIL table. Exits with code 1 if any gate fails.

### 3 – Generate the GitHub Actions workflow

```bash
python devsecops_pipeline.py write-workflow
```

Writes `.github/workflows/security-pipeline.yml`.

### 4 – Run the test suite

```bash
python devsecops_pipeline.py test
# or directly:
pytest devsecops_pipeline.py -v
```

---

## API Endpoints

| Method | Path              | Description                  |
|--------|-------------------|------------------------------|
| GET    | `/`               | Welcome message              |
| POST   | `/login`          | Login (username + password)  |
| GET    | `/users/{user_id}`| Fetch user by ID             |
| GET    | `/search`         | Search users by name         |
| GET    | `/ping`           | Ping a host                  |

---

## Pipeline stages → OWASP Top 10 & NIST SSDF mapping

| CI Stage            | Tool / Action     | OWASP Top 10 (2021)              | NIST SSDF Practice (SP 800-218)    |
|---------------------|-------------------|----------------------------------|------------------------------------|
| Lint & Unit Tests   | flake8, pytest    | A04 Insecure Design              | PW.1 – Implement Secure Coding     |
| SAST                | Bandit            | A03 Injection, A05 Misconfiguration | PW.7 – Review & Analyse Code    |
| Secrets Scan        | Gitleaks          | A02 Cryptographic Failures       | PW.8 – Archive & Protect Code     |
| Dependency Scan     | pip-audit         | A06 Vulnerable Components        | PW.4 – Reuse Existing Software     |
| Container Scan      | Trivy             | A05 Security Misconfiguration    | RV.1 – Identify Vulnerabilities    |
| Final Gate          | Custom runner     | All (blocks promotion)           | RV.3 – Respond to Vulnerabilities  |

---

## Vulnerability reference

| CWE   | Location in code               | Description                           |
|-------|--------------------------------|---------------------------------------|
| CWE-798 | `_register_vulnerable_routes` | Hardcoded secret key                |
| CWE-89  | `/users/{user_id}`, `/search` | SQL injection via string formatting |
| CWE-78  | `/ping`                        | Command injection via os.system     |
| CWE-489 | `run_app()`                    | Debug mode + 0.0.0.0 binding        |

---

## Screenshots

> **Note:** Replace the placeholders below with actual screenshots after running the project.

### Security gate output (vulnerable mode)
```
[ Screenshot: terminal showing FAIL rows for Bandit and secret scan ]
```

### Security gate output (secure mode)
```
[ Screenshot: terminal showing all PASS rows ]
```

### GitHub Actions pipeline run
```
[ Screenshot: GitHub Actions UI showing all 6 jobs green ]
```

---

## Project structure

```
.
├── devsecops_pipeline.py        # All code: app, gates, tests, entry point
├── requirements.txt             # Pinned dependencies
├── README.md                    # This file
└── PROJECT_REPORT.md            # Academic/professional report
```

---

## License

MIT – for demonstration and educational use only.  
**Do not deploy the vulnerable mode to a production or public-facing server.**
