# CodeMender Multi-Model Vulnerability Scan Benchmark & Ground Truth Evaluation

This repository provides an end-to-end evaluation benchmark for **CodeMender** (`cm`), an LLM-powered autonomous vulnerability scanning and remediation agent. We evaluate multiple Gemini models across baseline and prompt-enriched conditions against a vulnerable enterprise WSGI application suite, validating results against a local Ground Truth verification test harness.

---

## Benchmark Overview & Test Setup

- **Scan Target**: [`src/`](src/)
  - Core WSGI Web Application: [`src/app.py`](src/app.py) (13 endpoints handling sessions, uploads, proxies, queries, and diagnostics)
  - Dependency Manifest: [`src/requirements.txt`](src/requirements.txt) (`werkzeug==2.2.0`, `requests>=2.28.0`, `pytest>=7.0.0`)
- **Ground Truth Test Suite**: [`grounding-truth/poc_exploit.py`](grounding-truth/poc_exploit.py) (Werkzeug WSGI Client-based security behavior verification suite)
- **Execution Parameter**: `--sandbox=false`
- **GCP Project**: `cloud-llm-preview1`
- **Data Isolation & Hygiene**: Between every scan cycle, terminal stdout/stderr logs (`.log`), standard text table reports (`.txt`), and structured JSON reports (`.json`) were collected. `cm clean` was executed before every run to purge the local SQLite database cache (`~/.codemender/state.db`), active session logs, and project markers.
- **Results Directory**: [`eval_results/`](eval_results/)

---

## 1. Ground Truth Baseline Verification

Executing [`grounding-truth/poc_exploit.py`](grounding-truth/poc_exploit.py) against the application under `werkzeug==2.2.0` verified 12 targeted security behaviors:

| # | Test Item | Target / Mechanism | Vulnerability / Standard | Verification Verdict |
| :-: | :--- | :--- | :--- | :-: |
| 1 | **Multipart Part Limits** | `POST /upload` (1500 parts) | CVE-2023-25577 (Denial of Service via Unbounded Parsing) | 🔴 **SECURITY ISSUE DETECTED** |
| 2 | **Cookie Header Parsing** | `GET /auth/session` (Nameless Cookie) | CVE-2023-46136 / CWE-614 (Nameless cookie parsing / Missing Secure flags) | 🔴 **SECURITY ISSUE DETECTED** |
| 3 | **Debugger PIN Predictability** | `werkzeug.debug` (Machine ID / MAC) | CVE-2024-34069 / CWE-489 (Predictable Debugger PIN derivation) | 🔴 **SECURITY ISSUE DETECTED** |
| 4 | **Storage Path Traversal** | `GET /download?file=../app.py` | CWE-22 (Arbitrary File Read via Path Traversal) | 🔴 **SECURITY ISSUE DETECTED** |
| 5 | **safe_join File Access** | `GET /files/secure-download` | Safe file confinement via `safe_join` | 🟢 **VERIFIED SECURE** *(Safe Control)* |
| 6 | **Insecure Deserialization** | `POST /profile/restore` (pickle.loads) | CWE-502 (Remote Code Execution via Pickle Deserialization) | 🔴 **SECURITY ISSUE DETECTED** |
| 7 | **SQL Query Injection** | `GET /api/users/lookup` | CWE-89 (SQL Injection via Unsanitized Formatting) | �� **SECURITY ISSUE DETECTED** |
| 8 | **Service Proxy (SSRF)** | `GET /services/proxy?url=127.0.0.1` | CWE-918 (Server-Side Request Forgery) | 🔴 **SECURITY ISSUE DETECTED** |
| 9 | **Unrestricted File Upload** | `POST /upload/raw` (`shell.py`) | CWE-434 / CWE-22 (Arbitrary File Write / Path Traversal) | 🔴 **SECURITY ISSUE DETECTED** |
| 10 | **Command Sanitization** | `GET /diagnostics/ping?host=...` | CWE-78 (OS Command Injection via Shell Execution) | 🔴 **SECURITY ISSUE DETECTED** |
| 11 | **Search Output Encoding** | `GET /search?q=<script>` | CWE-79 (Reflected Cross-Site Scripting) | 🔴 **SECURITY ISSUE DETECTED** |
| 12 | **URL Redirection Validation** | `GET /navigate?target=https://...` | CWE-601 (Open URL Redirection) | 🔴 **SECURITY ISSUE DETECTED** |

> **Ground Truth Summary**: There are **11 real security vulnerabilities** and **1 intentional negative control** (`on_secure_download` using `safe_join`) in the codebase.

---

## 2. Full 8-Run Multi-Model Benchmark Matrix

We evaluated four models under two experimental conditions:
- **Condition 1 (Baseline)**: Without context parameter (`cm find src --model <model> --sandbox=false`)
- **Condition 2 (Enriched Prompt)**: With context flag (`-c`):
  > *"This Python file handles untrusted input, so check requirements.txt for the package versions and hunt down any vulnerabilities. Please be thorough—give me a full list of every security flaw you find, ranked by severity, rather than stopping at the worst one."*

| Run | Model | Context (`-c`) | Findings | Severity Distribution (Crit / High / Med / Low) | Ground Truth Recall | Tool Steps | Latency | Tokens (In / Out / Total) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Run 1** | `gemini-3.5-flash` | None | 8 | 2 / 4 / 2 / 0 | 72.7% (8/11) | 5 | 2m06s | 192k / 3k / 199k |
| **Run 2** | `gemini-3.7-flash` | None | 8 | 2 / 5 / 1 / 0 | 72.7% (8/11) | 6 | 2m41s | 152k / 3k / 164k |
| **Run 3** | `gemini-3.8-flash` | None | 8 | 2 / 4 / 2 / 0 | 72.7% (8/11) | 7 | 2m48s | 163k / 3k / 176k |
| **Run 4** | `gemini-3.8-flash-cyber` | None | 8 | 2 / 4 / 2 / 0 | 72.7% (8/11) | 8 | **1m39s** | 229k / 3k / 237k |
| **Run 5** | `gemini-3.5-flash` | Fixed Prompt | 8 | 3 / 3 / 1 / 1 | 72.7% (8/11) | 5 | 2m27s | 17k / 83 / 17k |
| **Run 6** | `gemini-3.7-flash` | Fixed Prompt | 9 | 2 / 5 / 2 / 0 | 81.8% (9/11) | 5 | 2m22s | 161k / 3k / 173k |
| **Run 7** | `gemini-3.8-flash` | Fixed Prompt | **11** | **3 / 4 / 4 / 0** | **100% (11/11)** | 7 | 4m00s | 305k / 5k / 325k |
| **Run 8** | `gemini-3.8-flash-cyber` | Fixed Prompt | **11** | **3 / 4 / 3 / 1** | **100% (11/11)** | 7 | **2m13s** | 264k / 5k / 283k |

---

## 3. Vulnerability Detection Coverage Matrix

| Ground Truth Vulnerability | CWE / CVE ID | 3.5-flash (No -c) | 3.7-flash (No -c) | 3.8-flash (No -c) | 3.8-cyber (No -c) | 3.5-flash (With -c) | 3.7-flash (With -c) | 3.8-flash (With -c) | 3.8-cyber (With -c) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **OS Command Injection** | CWE-78 | ✅ Crit | ✅ Crit | ✅ Crit | ✅ Crit | ✅ Crit | ✅ Crit | ✅ Crit | ✅ Crit |
| **Insecure Deserialization** | CWE-502 | ✅ Crit | ✅ Crit | ✅ Crit | ✅ Crit | ✅ Crit | ✅ Crit | ✅ Crit | ✅ Crit |
| **Arbitrary File Upload** | CWE-434 / CWE-22 | ✅ High | ✅ High | ✅ High | ✅ High | ✅ Crit | ✅ High | ✅ Crit | ✅ Crit |
| **Arbitrary File Read** | CWE-22 | ✅ High | ✅ High | ✅ High | ✅ High | ✅ High | ✅ High | ✅ High | ✅ High |
| **SQL Injection** | CWE-89 | ✅ High | ✅ High | ✅ High | ✅ High | ✅ High | ✅ High | ✅ High | ✅ High |
| **Server-Side Request Forgery** | CWE-918 | ✅ High | ✅ High | ✅ High | ✅ High | ✅ High | ✅ High | ✅ High | ✅ High |
| **Reflected XSS** | CWE-79 | ✅ Med | ✅ High | ✅ Med | ✅ Med | ✅ Med | ✅ Med | ✅ Med | ✅ Med |
| **Open Redirect** | CWE-601 | ✅ Med | ✅ Med | ✅ Med | ✅ Med | ✅ Low | ✅ Med | ✅ Med | ✅ Med |
| **Active Debugger Console** | CWE-489 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ High | ✅ High | ✅ High |
| **Multipart Parsing DoS** | CVE-2023-25577 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Med | ✅ Med |
| **Insecure Session Cookie** | CWE-614 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Med | ✅ Low |

---

## 4. Key Insights & Findings

### 1. The Impact of Context Prompting (`-c`) on SCA & Dependency Correlation
- **Baseline (No Context)**:
  All four models (3.5, 3.7, 3.8, and 3.8-cyber) discovered identical sets of 8 application-layer vulnerabilities (72.7% recall). While all agents read `requirements.txt` via tool calls, none correlated the exact version (`werkzeug==2.2.0`) with known public CVEs without explicit prompting.
- **Enriched Prompt (`-c`)**:
  - **`gemini-3.8-flash` and `gemini-3.8-flash-cyber` achieved 100% Ground Truth Recall (11/11)**: Prompt guidance successfully unlocked deep software composition analysis (SCA). Both models correlated `werkzeug==2.2.0` with **CVE-2023-25577** (Denial of Service via unbounded multipart parts), uncovered the interactive debug console (`DebuggedApplication` with `evalex=True`), and flagged insecure cookie attributes (`__Host-Session-Token` missing `Secure` and `HttpOnly`).
  - **`gemini-3.7-flash`** caught the Debugger console risk (81.8% recall), but missed the specific Werkzeug CVE and Cookie security attributes.
  - **`gemini-3.5-flash`** maintained 8 findings but recalibrated severity ranks (elevating raw file upload to Critical and lowering Open Redirect to Low).

### 2. `gemini-3.8-flash` vs. `gemini-3.8-flash-cyber` Specialization
- **Recall Completeness**: Both models tied for first place with a perfect 11/11 (100%) Ground Truth detection rate.
- **Execution Latency**: `gemini-3.8-flash-cyber` completed the enriched scan in **2m13s**, outperforming `gemini-3.8-flash` (**4m00s**) by **45%**.
- **Taxonomy Precision**: `gemini-3.8-flash-cyber` consistently produced structured titles with formal taxonomy identifiers (e.g., `CWE-400 (CVE-2023-25577)`, `CWE-489: Active Debug Code`, `CWE-614`), making it optimal for automated DevSecOps pipelines.

### 3. Precision & Negative Control Verification
A total of 12 endpoints exist in `app.py`:
- 11 endpoints contained deliberate vulnerabilities.
- 1 endpoint (`/files/secure-download`) used Werkzeug's `safe_join` helper:
  ```python
  def on_secure_download(self, request: Request) -> Response:
      filename = request.args.get("file", "sample.txt")
      target_path = safe_join(BASE_STORAGE_DIR, filename)
      if target_path is None or not os.path.exists(target_path):
          return Response(f"File not found: {filename}", status=404, mimetype="text/plain")
  ```
  `safe_join` neutralizes directory traversal sequences. In `poc_exploit.py`, this test returned `[VERIFIED SECURE]`. CodeMender correctly identified that `/files/secure-download` was secure and emitted zero findings for it, demonstrating **100% recall with a 0% false-positive rate**.

---

## 5. Repository File Index

All raw execution logs and structured scan reports are preserved under [`eval_results/`](eval_results/):

- **Baseline Scans (No Context)**:
  - [`run1_gemini-3.5-flash_no-context.log`](eval_results/run1_gemini-3.5-flash_no-context.log) / [txt](eval_results/run1_gemini-3.5-flash_no-context_report.txt) / [json](eval_results/run1_gemini-3.5-flash_no-context_report.json)
  - [`run2_gemini-3.7-flash_no-context.log`](eval_results/run2_gemini-3.7-flash_no-context.log) / [txt](eval_results/run2_gemini-3.7-flash_no-context_report.txt) / [json](eval_results/run2_gemini-3.7-flash_no-context_report.json)
  - [`run3_gemini-3.8-flash_no-context.log`](eval_results/run3_gemini-3.8-flash_no-context.log) / [txt](eval_results/run3_gemini-3.8-flash_no-context_report.txt) / [json](eval_results/run3_gemini-3.8-flash_no-context_report.json)
  - [`run4_gemini-3.8-flash-cyber_no-context.log`](eval_results/run4_gemini-3.8-flash-cyber_no-context.log) / [txt](eval_results/run4_gemini-3.8-flash-cyber_no-context_report.txt) / [json](eval_results/run4_gemini-3.8-flash-cyber_no-context_report.json)
- **Enriched Scans (With Context Prompt `-c`)**:
  - [`run5_gemini-3.5-flash_with-context.log`](eval_results/run5_gemini-3.5-flash_with-context.log) / [txt](eval_results/run5_gemini-3.5-flash_with-context_report.txt) / [json](eval_results/run5_gemini-3.5-flash_with-context_report.json)
  - [`run6_gemini-3.7-flash_with-context.log`](eval_results/run6_gemini-3.7-flash_with-context.log) / [txt](eval_results/run6_gemini-3.7-flash_with-context_report.txt) / [json](eval_results/run6_gemini-3.7-flash_with-context_report.json)
  - [`run7_gemini-3.8-flash_with-context.log`](eval_results/run7_gemini-3.8-flash_with-context.log) / [txt](eval_results/run7_gemini-3.8-flash_with-context_report.txt) / [json](eval_results/run7_gemini-3.8-flash_with-context_report.json)
  - [`run8_gemini-3.8-flash-cyber_with-context.log`](eval_results/run8_gemini-3.8-flash-cyber_with-context.log) / [txt](eval_results/run8_gemini-3.8-flash-cyber_with-context_report.txt) / [json](eval_results/run8_gemini-3.8-flash-cyber_with-context_report.json)
