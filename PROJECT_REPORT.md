# PROJECT REPORT

**Project Title:** DevSecOps CI/CD Pipeline Demo  
**Author:** Jumana  
**Date:** July 2025

---

## Abstract

This project delivers a self-contained DevSecOps demonstration system implemented in Python 3.11. It combines a FastAPI web application that deliberately embeds four documented vulnerability classes (CWE-798, CWE-89, CWE-78, CWE-489) with an environment-variable-toggled secure remediation, a multi-gate automated security runner covering static analysis, dependency auditing, and secret detection, and a generated GitHub Actions workflow that orchestrates all scanning stages inside a CI/CD pipeline. The objective is to provide a runnable, end-to-end reference for integrating security checks at every stage of the software delivery lifecycle, aligned with OWASP Top 10 (2021) and NIST Secure Software Development Framework (SP 800-218) practices.

---

## Introduction

The convergence of development, security, and operations — commonly abbreviated DevSecOps — represents a fundamental shift in how software organisations manage risk. Rather than treating security as a phase that follows development, the DevSecOps model embeds security controls directly into the CI/CD pipeline so that every code change is automatically evaluated against a defined security policy before it can progress toward production. This "shift-left" philosophy means that vulnerabilities are discovered and remediated when they are cheapest to fix: at code-review time, not post-deployment.

This project provides a complete, runnable implementation of a DevSecOps pipeline on a single Python file and a minimal supporting configuration. It is intentionally kept small enough to serve as a teaching tool, while being comprehensive enough to demonstrate every major stage of a real pipeline: lint and unit testing, static application security testing (SAST), secret detection, dependency auditing, container image scanning, and a blocking final security gate.

---

## Objectives

1. Implement a minimal but realistic web application that contains well-documented, intentional vulnerabilities useful for training and demonstration.
2. Provide a side-by-side secure remediation of the same application, selectable without code changes via an environment variable.
3. Automate security gate execution so that a single command surfaces all issues and exits with a machine-readable status code suitable for use in CI.
4. Generate a production-grade GitHub Actions workflow file from code, establishing the link between local tooling and cloud CI/CD.
5. Align every pipeline stage with a published security standard (OWASP Top 10, NIST SP 800-218) to demonstrate practical compliance.

---

## Literature and Background

### DevSecOps and Shift-Left Security

The term "DevSecOps" emerged from the broader DevOps movement as organisations recognised that velocity gains from continuous integration were being undermined by late-stage security reviews. Forrester Research and Gartner both documented industry adoption of the shift-left principle in the early 2010s, with the Cloud Security Alliance formalising a DevSecOps manifesto in 2015. The model is now endorsed by government bodies: the U.S. National Institute of Standards and Technology published SP 800-218 (the Secure Software Development Framework, SSDF) in 2022, explicitly calling for security activities to be integrated throughout the SDLC rather than appended at the end.

Academic literature supports the economic argument: IBM's *Cost of a Data Breach* reports consistently show that vulnerabilities found in the design and development phases cost 4–6× less to fix than those found in production. Automated tooling — SAST, SCA (software composition analysis), secret scanning, and DAST — enables organisations to scale these checks across hundreds of daily commits without proportionally increasing security headcount.

---

## System Architecture

The project is structured as a single Python module (`devsecops_pipeline.py`) partitioned into five logical sections:

1. **Web Application** — A FastAPI application factory that builds either a vulnerable or a secure variant depending on the `SECURE_MODE` environment variable.
2. **Security Gate Runner** — An orchestration function that invokes Bandit, pip-audit, and an inline regex secret scanner, collects results, and prints a structured PASS/FAIL table.
3. **Workflow Writer** — A function that materialises a multi-job GitHub Actions YAML file from an embedded string constant, creating the `.github/workflows/` directory tree as needed.
4. **Test Suite** — Pytest test functions at the bottom of the same file that verify secure-mode endpoint behaviour through FastAPI's built-in TestClient.
5. **Entry Point** — An `if __name__ == "__main__"` dispatcher that routes the `run`, `scan`, `write-workflow`, and `test` commands.

The GitHub Actions workflow defines six jobs in dependency order:

```
lint-and-test  ──►  sast ──────────────────────────────────┐
               ──►  secrets-scan ─────────────────────────►  security-gate
               ──►  dependency-scan ──────────────────────►
               ──►  container-scan ───────────────────────►
```

The `security-gate` job depends on all four parallel scanning jobs. If any one of them fails, the gate is never reached and the pipeline is blocked.

---

## Tools and Technologies

| Tool / Library | Role | Justification |
|---|---|---|
| **FastAPI** | Web framework | High-performance ASGI framework; type-annotated routes make vulnerability insertion and remediation explicit. |
| **SQLite3** (stdlib) | Database | No external server needed; sufficient to demonstrate SQL injection with real queries. |
| **Bandit** | SAST | The de facto Python SAST tool; maps findings to CWE/CVE; integrates cleanly with CI via exit codes. |
| **pip-audit** | Dependency CVE scan | Queries the OSV database; supports pip constraints; exits non-zero on any known vulnerability. |
| **Gitleaks** (GitHub Action) | Secret detection | Git-history-aware; regex + entropy analysis; widely used in open-source and enterprise pipelines. |
| **Trivy** (GitHub Action) | Container image scan | Multi-target scanner (OS packages, language dependencies); fail-on-severity flag maps directly to pipeline policy. |
| **pytest + httpx** | Unit testing | FastAPI's TestClient uses httpx under the hood; allows full request/response testing without a live server. |
| **GitHub Actions** | CI/CD orchestration | Native to GitHub; YAML-defined jobs; matrix builds and reusable actions ecosystem. |

---

## Implementation

### Vulnerable Application

The vulnerable variant of the application (`SECURE_MODE=0`, the default) intentionally introduces four weakness classes:

- **CWE-798 (Hardcoded Credentials):** The secret key is defined as a Python string literal `"super_secret_hardcoded_key_12345"` and returned in API responses, making it trivially extractable by any Bandit scan or log inspection.
- **CWE-89 (SQL Injection):** Both `/users/{user_id}` and `/search` construct SQL queries by f-string interpolation of unvalidated user input. An attacker can supply `1 OR 1=1` or `' UNION SELECT ...` payloads.
- **CWE-78 (OS Command Injection):** The `/ping` endpoint passes user-controlled input directly to `os.system()`. A payload such as `127.0.0.1; cat /etc/passwd` executes arbitrary shell commands with the server process's privileges.
- **CWE-489 (Active Debug Code):** The server starts with `log_level="debug"` and binds to `0.0.0.0`, exposing the application on all network interfaces with verbose logging that may leak internal stack traces.

### Secure Application

When `SECURE_MODE=1` is set, the application factory registers an entirely different set of route handlers:

- The secret key is read from `os.environ.get("APP_SECRET_KEY")` and an HTTP 500 is returned if it is absent, forcing operators to configure the secret explicitly.
- All SQL queries use parameterised placeholders (`?` with a tuple argument), eliminating injection regardless of input content.
- The `/ping` endpoint validates the host with `re.fullmatch(r"[a-zA-Z0-9.\-]+", host)` and invokes `subprocess.run(["ping", "-c", "1", host], ...)` with a list argument and no shell expansion.
- The server binds to `127.0.0.1` with `log_level="warning"`.

### Security Gate Runner

The `run_security_gates()` function calls three sub-scanners in sequence and collects their boolean pass/fail results and textual summaries into a list. After all scans complete, it prints a fixed-width table with one row per gate. The function returns exit code `0` only when all three gates pass, enabling shell-level composition (`python devsecops_pipeline.py scan || exit 1`).

### GitHub Actions Workflow

The `write_workflow()` function writes a 130-line YAML document embedded in the `WORKFLOW_YAML` constant. The workflow triggers on pushes to `main` and `develop` and on pull requests to `main`. All scanning jobs (`sast`, `secrets-scan`, `dependency-scan`, `container-scan`) are listed as `needs` of the `security-gate` job, ensuring that a failure in any scan prevents deployment approval.

---

## Results

The table below lists expected findings for each scan in both modes. **These are expected results; replace with actual run output after executing the commands.**

| Scan | Tool | Findings — Vulnerable Mode | Findings — Secure Mode (`SECURE_MODE=1`) |
|---|---|---|---|
| SAST — HIGH severity | Bandit | ~4 HIGH issues (B105, B106, B602, B608) | 0 HIGH issues |
| SAST — MEDIUM severity | Bandit | ~2 MEDIUM issues | 0 MEDIUM issues |
| Dependency CVEs | pip-audit | 0 CVEs (pinned recent versions) | 0 CVEs |
| Secret detection | Regex scanner | 1 secret found (hardcoded key) | 0 secrets |
| Container scan | Trivy | Varies by base image (expected ≥1 CRITICAL in old images) | Same (image is independent of app mode) |
| **Overall gate** | — | **FAIL** | **PASS** |

> All numbers above are indicative based on tool behaviour at the time of writing. Actual CVE counts depend on the installed package versions and the current state of the OSV vulnerability database.

---

## Limitations

- **No real database:** SQLite operates in-memory (`:memory:`), so the SQL injection demonstrations do not persist data across requests and cannot demonstrate multi-request attack sequences such as blind injection.
- **No DAST:** The pipeline does not include dynamic application security testing. A deployed application would require OWASP ZAP or a similar tool to test running endpoints for injection, authentication bypass, and SSRF.
- **Container stage requires Docker:** The `container-scan` job in the generated workflow requires a `Dockerfile` that is not part of this project. The CI job will fail until a `Dockerfile` is added.
- **Regex secret scanner has limited coverage:** The three patterns (AWS key, generic API key, private key header) cover only common cases. A production deployment should use a dedicated tool such as Gitleaks, TruffleHog, or detect-secrets.
- **Single-file structure limits scalability:** Keeping all code in one file aids portability and demonstration but would not scale to a production application.

---

## Future Work

- **SonarQube integration:** Replace or supplement Bandit with a SonarQube server scan step for richer code-quality metrics, technical debt tracking, and persistent historical trending across branches.
- **DAST with OWASP ZAP:** Add a job after container build that starts the container and runs `zap-baseline.py` against `http://localhost:8000`, surfacing runtime vulnerabilities such as missing security headers and open redirects.
- **Cloud deployment gate:** Extend the final gate job to conditionally trigger a deployment to AWS ECS, Azure Container Apps, or Google Cloud Run only when all scans pass, using OIDC-based keyless authentication.
- **SBOM generation:** Use Syft or cyclonedx-python to generate a Software Bill of Materials artifact on every build, satisfying executive-order-level supply-chain transparency requirements.
- **Policy as code:** Encode organisational security policies (e.g., "no CVEs with CVSS ≥ 7 in production dependencies") as OPA/Rego rules evaluated by the gate job, replacing hard-coded severity thresholds.

---

## Conclusion

This project demonstrates that a practical DevSecOps pipeline can be fully specified and executed from a single Python source file without external infrastructure. By deliberately introducing and then remediating four CWE-classified vulnerabilities, the codebase serves as a side-by-side comparison of insecure and secure patterns. The automated gate runner and generated GitHub Actions workflow provide a concrete bridge between local developer tooling and cloud CI/CD enforcement, aligning each stage with OWASP Top 10 and NIST SSDF controls. The result is a reproducible, runnable, and extensible foundation for teaching and prototyping DevSecOps practices.

---

## References

1. OWASP Foundation. *OWASP Top 10 — 2021*. https://owasp.org/www-project-top-ten/
2. NIST. *Secure Software Development Framework (SSDF), SP 800-218*. February 2022. https://csrc.nist.gov/publications/detail/sp/800-218/final
3. MITRE Corporation. *Common Weakness Enumeration (CWE)*. https://cwe.mitre.org/
4. PyCQA. *Bandit — Security linter for Python*. https://bandit.readthedocs.io/
5. Aqua Security. *Trivy — Vulnerability scanner for containers*. https://trivy.dev/
6. Gitleaks. *Gitleaks — Detect secrets in git repositories*. https://gitleaks.io/
7. IBM Security. *Cost of a Data Breach Report 2023*. https://www.ibm.com/security/data-breach
8. pypa. *pip-audit — Audit Python environments for known vulnerabilities*. https://github.com/pypa/pip-audit
9. Tiangolo, S. *FastAPI Documentation*. https://fastapi.tiangolo.com/
10. Cloud Security Alliance. *DevSecOps — Manifesto and Practices*. https://cloudsecurityalliance.org/
