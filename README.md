# CodeMender (`cm v0.14.0`) Cross-Stack Security Benchmark, Ground Truth Coverage Analysis & Universal Pipeline Guide

> **Evaluation Scale**: **43 Controlled Ablation Runs** across **Python WSGI**, **Node.js/TypeScript**, and **Java/Spring Boot** (**1,654+** total findings) + **C/C++ & Go Live Multi-Stack Verification Scans** + **8 Legacy Baseline Runs**
> **Execution Environment**: `cm v0.14.0` (`--sandbox=false`)
> **Quick Navigation**:
> - 🛡️ **Stage 3 & 4 Automated Vulnerability Verification (`cm verify`) & Remediation (`cm fix`) Report (`fix` branch)**: [`docs/VERIFY_AND_FIX_REPORT.md`](./docs/VERIFY_AND_FIX_REPORT.md)
> - 🏛️ **Universal Two-Stage Architecture Review & 4 Trap Mitigations**: [`docs/UNIVERSAL_PIPELINE_REVIEW.md`](./docs/UNIVERSAL_PIPELINE_REVIEW.md)
> - 📊 **Full 43-Run Ablation Matrix**: [`docs/BENCHMARK_RESULTS.md`](./docs/BENCHMARK_RESULTS.md) | ☕ **`macrozheng/mall` Code Audit Reference (Non-Official Ground Truth)**: [`docs/MALL_AUDIT_REFERENCE.md`](./docs/MALL_AUDIT_REFERENCE.md) | 🇨🇳 **中文主报告与实战指南**: [`README_CN.md`](./README_CN.md)
> - ⚙️ **End-to-End Pipeline (Profile $\rightarrow$ Scan $\rightarrow$ Verify $\rightarrow$ Fix)**: [`pipeline/pipeline.py`](./pipeline/pipeline.py), [`pipeline/run_verify_and_fix.py`](./pipeline/run_verify_and_fix.py), [`pipeline/test_universal_pipeline.py`](./pipeline/test_universal_pipeline.py), [`pipeline/run_python_benchmarks.py`](./pipeline/run_python_benchmarks.py), [`pipeline/run_all_benchmarks.py`](./pipeline/run_all_benchmarks.py), [`pipeline/generate_report.py`](./pipeline/generate_report.py)

---

## 0. Glossary of Abbreviations, Target Scopes & Experiment Codes

To ensure clarity across all benchmark tables and reports, the following terms, scopes, and abbreviations are defined below:

### 1. Target Repository Scopes (`Bench` vs. `High-Risk` vs. `Full Core`)
For large multi-module repositories (`juice-shop` and `macrozheng/mall`), we evaluate three progressive directory scopes:
- **`Bench` (Core Benchmark Subset, e.g., `juice-shop-bench` / `mall-bench`)**: A curated subset of the most representative vulnerable & negative-control files (`19` files for Juice Shop, `20` files for `mall`) used for controlled model and prompt ablation.
- **`High-Risk` (formerly abbreviated `HR`, High-Risk Attack-Surface Subset, e.g., `juice-shop-high-risk` / `mall-high-risk`)**: Medium-scale subset (`48` files for Juice Shop, `57` files for `mall`) containing all HTTP route handlers/controllers, authentication middlewares, security configurations, and view templates.
- **`Full Core` (Full Backend Core Scope, e.g., `juice-shop-core` / `mall-core`)**: Complete backend source code (`138` files for Juice Shop, `297–335` files for `mall`) after excluding static frontend assets (`frontend/`), unit tests (`test/`), and auto-generated ORM boilerplate (`mall-mbg`).

### 2. CodeMender Execution Modes & Internal Concepts
- **`Quick` Mode (Single-Agent Mode)**: Default `cm find` mode without `--deep`. A single primary agent reads files and reports vulnerabilities directly; ideal for micro-repositories ($\le 5$ active files).
- **`Parallel Deep` Mode (`--deep`)**: Invoked with `--deep --deep-workers 16 --deep-max-turns 8`. CodeMender indexes the repository and spawns 16 concurrent worker sub-agents to trace cross-file call chains and verify exploitability; ideal for multi-file repositories ($> 5$ active files).
- **`Tier 0 Pruner`**: CodeMender's built-in pre-filter during `--deep` initialization that skips files it considers non-code (which can inadvertently prune `requirements.txt` or `package.json` on small targets unless mitigated).
- **`Thin Wrapper`**: A lightweight entrypoint or interface file that contains no direct vulnerability sink itself but imports and delegates requests to an underlying implementation file (e.g., `app.ts` delegating to `server.ts`, or `http.py` delegating to `sansio/http.py`).

### 3. Security & Evaluation Metrics
- **`Ground Truth` (formerly `GT`)**: The verified set of real vulnerabilities present in a target repository, used as the denominator for **Recall** ($\text{Recall} = \text{Detected Real Vulnerabilities} / \text{Total Ground Truth Vulnerabilities}$).
- **`False Positive` (formerly `FP`)**: Incorrectly flagging a secure implementation as vulnerable. Evaluated using dedicated **Negative Controls** (such as `/files/secure-download` guarded by `safe_join`, or MyBatis XML mappers using 100% parameterized `#{}` bindings).
- **Severity Breakdown (`Critical / High / Medium / Low`)**: Shown in tables as `5 Critical / 5 High / 2 Medium` (formerly `5C / 5H / 2M`).
- **`SAST` vs. `SCA`**:
  - **`SAST` (Static Application Security Testing)**: Analyzing first-party source code for taint flows from untrusted **Sources** (HTTP parameters, headers, uploads) to dangerous **Sinks** (SQL queries, command execution, file writes) lacking a proper **Guard / Sanitizer** (`safe_join`, `realpath`, parameterized queries).
  - **`SCA` (Software Composition Analysis)**: Auditing dependency manifests (`requirements.txt`, `package.json`, `pom.xml`, `go.mod`) for pinned third-party library versions with known CVEs and correlating them with reachable application code.
- **Vulnerability Class Abbreviations**:
  - **`RCE`**: Remote Code Execution | **`SQLi` / `NoSQLi`**: SQL / NoSQL Injection | **`SSRF`**: Server-Side Request Forgery
  - **`XSS`**: Cross-Site Scripting | **`SSTI`**: Server-Side Template Injection | **`XXE`**: XML External Entity Injection
  - **`LFI`**: Local File Inclusion | **`IDOR`**: Insecure Direct Object Reference (horizontal privilege escalation, e.g., accessing another user's order by ID)

### 4. Experiment Run Identifiers (`py_01..13`, `js_01..15`, `mall_01..15`)
- Prefixes `py_`, `js_`, and `mall_` denote the **Python WSGI**, **Node.js Juice Shop**, and **Java `macrozheng/mall`** experiment series (full 43-run table in [`docs/BENCHMARK_RESULTS.md`](./docs/BENCHMARK_RESULTS.md)).
- Context prompt tiers: `c0_none` (no `-c` prompt), `c1_sca` (dependency CVE prompt only), `c2_arch` (architecture/route prompt only), and **`c3_hybrid` (5-Pillar Hybrid Prompt combining file index navigation, SCA version correlation, SAST route/sink tracing, configuration/secret audit, and security guard verification)**.

---

## 1. Executive Summary & Five-Stack Benchmark Results

This repository provides a **zero-hardcoded-repo-name, two-stage universal security scanning pipeline** (**Stage 1 Static Auto-Profiler $\rightarrow$ Stage 2 Adaptive Concurrent Scanner**) for CodeMender (`cm v0.14.0`), validated across **5 distinct language ecosystems** (**Python**, **Node.js/TypeScript**, **Java/Spring Boot**, **C/C++**, and **Go**):

| Dimension | 🐍 Python / Werkzeug WSGI ([`src/`](./src)) | 🟢 Node.js / Express / TS ([`juice-shop`](./benchmarks/juice-shop-bench)) | ☕ Java / Spring Boot + MyBatis ([`mall`](./benchmarks/mall-bench)) | ⚙️ C / C++ HTTP Gateway (`c-gateway`) | 🐹 Go Microservice (`go-microservice`) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Target Profile & Scale** | Micro-service (`app.py` + `requirements.txt`, 2 files) with **11 Ground Truth vulns + 1 `safe_join` negative control** | Full-stack web app (Express + Sequelize + MarsDB + Pug/HBS templates; `19` Bench / `48` High-Risk / `138` Full Core files) | Enterprise multi-module e-commerce system (6 Maven modules, MyBatis XML, MinIO/OSS/Alipay; `20` Bench / `335` Full Core files) | Multi-file C HTTP gateway (`CMakeLists.txt` + `.h/.c` thin wrappers & `sansio` parser, 8 files) | Multi-file Go service (`go.mod` + Gorilla Mux + SQLite + JWT, 6 files) |
| **Auto-Selected Mode** | **Quick Mode** (`deep=False`, active files $\le 5$) | **Parallel Deep Mode** (`--deep --deep-workers 16 --deep-max-turns 8`) | **Parallel Deep Mode** (`--deep --deep-workers 16 --deep-max-turns 8`) | **Parallel Deep Mode** (`--deep --deep-workers 16 --deep-max-turns 8`) | **Parallel Deep Mode** (`--deep --deep-workers 16 --deep-max-turns 8`) |
| **Peak Single-Run Findings** | **12** (`5 Critical / 5 High / 2 Medium`) | Bench: **49** (`js_05`)<br>High-Risk Subset: **91** (`js_15`) | Bench: **29** (`mall_12`)<br>Deep Mode: **35** (`mall_05`) | **6** (`4 Critical / 2 High`) | **10** (`5 Critical / 4 High / 1 Medium`) |
| **Ground Truth / Audit Recall** | **11 / 11 (`100.0%`)** | Bench: **26 / 26 (`100.0%`)**<br>Backend Coding Challenges: **18 / 18 (`100.0%`)**<br>High-Risk Subset Files: **38 / 39 (`97.4%`)** | Audit Reference ([`MALL_AUDIT_REFERENCE.md`](./docs/MALL_AUDIT_REFERENCE.md)):<br>**17 / 17 (`100.0%`)** vulnerable files (**21 / 22 = `95.5%`** single-run, `22 / 22 = 100%` union) | **100%** (Stack/Heap Buffer Overflows `CWE-120/190`, Format String `CWE-134`, Command Injection `CWE-78`) | **100%** (SQL Injection `CWE-89`, JWT `alg:none` `CWE-347`, Hardcoded Secrets `CWE-798`, SSRF) |
| **False Positive Rate (Negative Controls)** | **`0.0%`** (`safe_join` not flagged) | **`0.0%`** (all findings map to real sinks) | **`0.0%`** (`0` false positives on 3 parameterized `#{}` XML / POJO controls) | **`0.0%`** (`realpath` safe static handler not flagged) | **`0.0%`** (`filepath.Clean` safe handler not flagged) |
| **Wall-Clock Duration** | **213s – 226s** (`~3.6 min`) | **206s – 373s** (`3.4 – 6.2 min`) | **236s – 376s** (`3.9 – 6.3 min`) | **188s** (`~3.1 min`) | **174s** (`~2.9 min`) |

---

## 2. Deep-Dive Ground Truth Coverage Analysis (Python WSGI & OWASP Juice Shop)

### 2.1 Python WSGI Benchmark (`src/` — 11 Ground Truth Vulnerabilities + 1 Negative Control) & 13-Run `-c` Ablation Matrix

[`src/app.py`](./src/app.py) and [`src/requirements.txt`](./src/requirements.txt) contain **11 real-world vulnerabilities** (dynamically verified by [`grounding-truth/poc_exploit.py`](./grounding-truth/poc_exploit.py)) plus **1 secure negative-control endpoint** (`/files/secure-download` guarded by `werkzeug.security.safe_join`):

#### (1) Impact of `-c` (`--context`) Strategies on Ground Truth Recall

| Ground Truth ID & Vulnerability Class | Sink / Root Cause | No-`-c` Baseline (`c0_none`: `py_01`/`py_03`) | `-c` with Literal Filenames (`c_legacy_literal`: `py_13` Trap) | Sanitized 5-Pillar `-c` (`c3_hybrid_max`: `py_02`/`py_06`/`py_08`/`py_12`) |
| :--- | :--- | :---: | :---: | :---: |
| **GT01–GT08** (8 SAST flaws: OS Command Injection `CWE-78`, Pickle Deserialization `CWE-502`, Arbitrary File Upload `CWE-434` / Read `CWE-22`, SQL Injection `CWE-89`, SSRF `CWE-918`, Reflected XSS `CWE-79`, Open Redirect `CWE-601`) | `src/app.py` route handlers | 8 / 8 (100%) | **0 / 8 (0%)** *(skipped)* | **8 / 8 (100%)** |
| **GT09**: Interactive Debugger RCE & Predictable PIN (`CWE-489` / `CVE-2024-34069`) | `DebuggedApplication(app, evalex=True)` + `Werkzeug==2.2.0` | ❌ Missed (except `4-argon`) | ❌ Missed | **✅ Found** |
| **GT10**: Unbounded Multipart Parsing DoS (`CWE-400` / `CVE-2023-25577`) | `request.files` / `request.form` + `Werkzeug==2.2.0` | ❌ Missed | ❌ Missed | **✅ Found** |
| **GT11**: Insecure Session Cookie Flags, `__Host-` Prefix Violation & Cookie Shadowing (`CWE-614` / `CVE-2023-46136`) | `set_cookie` / `request.cookies` + `Werkzeug==2.2.0` | ❌ Missed (except `4-argon`) | ❌ Missed | **✅ Found** |
| **Negative Control**: `/files/secure-download` (`safe_join` confinement) | `on_secure_download()` checking `target_path is None` | 🟢 `0%` False Positive | — | 🟢 **`0%` False Positive (`fp_safe_join: False`)** |
| **Total Ground Truth Recall** | **11 Ground Truth Vulnerabilities** | **8 / 11 (`72.7%`)** | **0 / 11 (`0.0%`)** | **11 / 11 (`100.0%`)** |

#### (2) Complete 13-Run Python WSGI `-c` Parameter & Model Ablation Matrix (`eval_results/python_wsgi/`)

| Run ID | Model | Scan Mode | Context Prompt (`-c`) Strategy | Findings | Severity (`Critical / High / Medium / Low`) | Ground Truth Recall (`11` Vulns) | `safe_join` Control FP | Wall Time |
| :--- | :--- | :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| [`py_01_quick_35flash_c0`](./eval_results/python_wsgi/py_01_quick_35flash_c0_report.json) | `gemini-3.5-flash` | Quick (Single-Agent) | `c0_none` (No `-c` flag) | 8 | 2 Critical / 4 High / 2 Medium / 0 Low | 8 / 11 (`72.7%`) | 🟢 `0%` | 169.7s |
| [`py_02_quick_35flash_c3`](./eval_results/python_wsgi/py_02_quick_35flash_c3_report.json) | `gemini-3.5-flash` | Quick (Single-Agent) | `c3_hybrid_max` (5-Pillar Hybrid Prompt) | **12** | 3 Critical / 5 High / 4 Medium / 0 Low | **11 / 11 (`100.0%`)** | 🟢 `0%` | 202.7s |
| [`py_03_quick_38flash_c0`](./eval_results/python_wsgi/py_03_quick_38flash_c0_report.json) | `gemini-3.8-flash` | Quick (Single-Agent) | `c0_none` (No `-c` flag) | 8 | 4 Critical / 3 High / 1 Medium / 0 Low | 8 / 11 (`72.7%`) | 🟢 `0%` | 296.7s |
| [`py_04_quick_38flash_c1_sca`](./eval_results/python_wsgi/py_04_quick_38flash_c1_sca_report.json) | `gemini-3.8-flash` | Quick (Single-Agent) | `c1_sca` (Dependency Version & CVE Only) | **11** | 2 Critical / 7 High / 2 Medium / 0 Low | **11 / 11 (`100.0%`)** | 🟢 `0%` | 330.6s |
| [`py_05_quick_38flash_c2_sast`](./eval_results/python_wsgi/py_05_quick_38flash_c2_sast_report.json) | `gemini-3.8-flash` | Quick (Single-Agent) | `c2_sast_framework` (Framework & Sinks Only) | 10 | 3 Critical / 4 High / 3 Medium / 0 Low | 10 / 11 (`90.9%`) | 🟢 `0%` | 163.7s |
| [`py_06_quick_38flash_c3_hybrid`](./eval_results/python_wsgi/py_06_quick_38flash_c3_hybrid_report.json) | `gemini-3.8-flash` | Quick (Single-Agent) | `c3_hybrid_max` (5-Pillar Hybrid Prompt) | **13** | 4 Critical / 6 High / 3 Medium / 0 Low | **11 / 11 (`100.0%`)** | 🟢 `0%` | 230.9s |
| [`py_07_quick_4argon_c0`](./eval_results/python_wsgi/py_07_quick_4argon_c0_report.json) | `gemini-4-argon` | Quick (Single-Agent) | `c0_none` (No `-c` flag) | 10 | 3 Critical / 5 High / 2 Medium / 0 Low | **10 / 11 (`90.9%`)** | 🟢 `0%` | 307.2s |
| [`py_08_quick_4argon_c3`](./eval_results/python_wsgi/py_08_quick_4argon_c3_report.json) | `gemini-4-argon` | Quick (Single-Agent) | `c3_hybrid_max` (5-Pillar Hybrid Prompt) | **13** | 4 Critical / 7 High / 2 Medium / 0 Low | **11 / 11 (`100.0%`)** | 🟢 `0%` | 206.3s |
| [`py_09_deep_35flash_c3`](./eval_results/python_wsgi/py_09_deep_35flash_c3_report.json) | `gemini-3.5-flash` | **Parallel Deep** (`--deep`) | `c3_hybrid_max` (5-Pillar Hybrid Prompt) | 9 | 2 Critical / 6 High / 1 Medium / 0 Low | 9 / 11 (`81.8%`) | 🟢 `0%` | 132.7s |
| [`py_10_deep_38flash_c0`](./eval_results/python_wsgi/py_10_deep_38flash_c0_report.json) | `gemini-3.8-flash` | **Parallel Deep** (`--deep`) | `c0_none` (No `-c` flag) | 8 | 2 Critical / 4 High / 2 Medium / 0 Low | 8 / 11 (`72.7%`) | 🟢 `0%` | **78.1s** |
| [`py_11_deep_38flash_c3_hybrid`](./eval_results/python_wsgi/py_11_deep_38flash_c3_hybrid_report.json) | `gemini-3.8-flash` | **Parallel Deep** (`--deep`) | `c3_hybrid_max` (5-Pillar Hybrid Prompt) | 10 | 3 Critical / 4 High / 3 Medium / 0 Low | 10 / 11 (`90.9%`) | 🟢 `0%` | 175.2s |
| [`py_12_deep_4argon_c3`](./eval_results/python_wsgi/py_12_deep_4argon_c3_report.json) | `gemini-4-argon` | **Parallel Deep** (`--deep`) | `c3_hybrid_max` (5-Pillar Hybrid Prompt) | **11** | 4 Critical / 4 High / 3 Medium / 0 Low | **11 / 11 (`100.0%`)** | 🟢 `0%` | **76.3s** |
| [`py_13_deep_38flash_literal_trap`](./eval_results/python_wsgi/py_13_deep_38flash_literal_trap_meta.json) | `gemini-3.8-flash` | **Parallel Deep** (`--deep`) | `c_legacy_literal` *(contains literal `requirements.txt` in `-c`)* | **0** | 0 / 0 / 0 / 0 | **0 / 11 (`0.0%`)** *(filtered + pruned)* | 🟢 `0%` | 0.5s |

---

### 2.2 OWASP Juice Shop Three-Tier Ground Truth Comparison & Pipeline Optimizations

We evaluated all 15 Juice Shop runs ([`eval_results/nodejs_juiceshop/`](./eval_results/nodejs_juiceshop)) against OWASP Juice Shop's official Ground Truth definitions (`data/static/challenges.yml` with **116** CTF challenges, and `data/static/codefixes/` with **35** official Coding Challenges):

#### (1) Why Raw 116 CTF Challenges Cannot Be Used Directly as a Backend SAST Denominator
- **Many-to-One Challenge Mapping (1 Code Vulnerability = Multiple CTF Challenges)**: For example, the **single SQL Injection** at `routes/login.ts:34` solves `loginAdmin`, `loginJim`, `loginBender`, `ghostLogin`, and `ephemeralAccountant` (**5 CTF challenges = 1 code flaw**); the single SQL Injection at `routes/search.ts:23` solves both `unionSqlInjection` and `dbSchema`.
- **Pure OSINT / Guessing / Trivia Challenges (Non-Code Flaws)**: 6 password-reset challenges in `routes/resetPassword.ts` test whether a player can guess static security-question answers in `data/static/users.yml` (e.g., Bjoern's cat `'Zaya'` or Jim's brother's middle name `'Samuel'`) from photo EXIF metadata or public trivia.
- **Frontend Angular & On-Chain Solidity Smart Contract Challenges**: 7 Coding Challenges reside in `frontend/src/app/` and 3 reside in testnet `.sol` smart contracts outside backend Node.js/Express SAST scope.

#### (2) Three-Tier Ground Truth Coverage Summary (Including No-`-c` vs. 5-Pillar `-c`)

> **Key Experiment Codes in Table**:
> - `js_01` / `js_09`: `gemini-3.8-flash` / `gemini-3.5-flash` in `Quick` mode + **No `-c` (`c0_none`)** on `juice-shop-bench` (`0` / `6` findings, 480s timeout)
> - `js_08`: `gemini-3.8-flash` in `--deep` mode + **No `-c` (`c0_none`)** on `juice-shop-bench` (`19` findings, 600s timeout)
> - `js_10`: `gemini-4-argon` in `Quick` mode + **No `-c` (`c0_none`)** on `juice-shop-bench` (`20` findings)
> - `js_03`: `gemini-3.8-flash` in `--deep` mode + **With `-c` (`c3_hybrid_max`)** on `juice-shop-bench`
> - `js_05`: `gemini-4-argon` in `--deep` mode + **With `-c` (`c3_hybrid_max`)** on `juice-shop-bench`
> - `js_12`: `gemini-4-argon` in `Quick` mode + **With `-c` (`c3_hybrid_max`)** on `juice-shop-bench`
> - `js_13` / `js_14`: `gemini-3.8-flash` in `--deep` mode + **With `-c` (`c3_hybrid_max`)** on `juice-shop-high-risk` (`48` High-Risk files) and `juice-shop-core` (`138` Full Core backend files)
> - `js_15` / `js_16`: `gemini-4-argon` in `--deep` mode + **With `-c` (`c3_hybrid_max`)** on `juice-shop-high-risk` (`48` High-Risk files) and `juice-shop-core` (Full Core backend files, logging **94** findings and hitting **27 / 28 = 96.4%** in `js_16` single-run and **28 / 28 = 100.0%** across `js_15`+`js_16` on the unified 28-file denominator)

| Ground Truth Evaluation Tier | Denominator (Unified) | `js_08` (`3.8F` Deep **No `-c`**) | `js_10` (`4-argon` Quick **No `-c`**) | `js_03` (`3.8F` Deep **With `-c`**) | `js_13`/`14` (`3.8F` High-Risk/Core **With `-c`**) | `js_05` (`4-argon` Deep **With `-c`**) | `js_12` (`4-argon` Quick **With `-c`**) | `js_15`/`16` (`4-argon` High-Risk/Core **With `-c`**) | Union Across Runs |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Tier 1: `juice-shop-bench` Core Code Vulnerabilities** | **26 distinct code vulns** | 14 / 26 (**53.8%**) | 20 / 26 (**76.9%**) | 20 / 26 (**76.9%**) | 22 / 26 (**84.6%**) | 24 / 26 (**92.3%**) | 24 / 26 (**92.3%**) | **26 / 26 (100.0%)** | **26 / 26 (100.0%)** |
| **Tier 2A: Official 35 Coding Challenges (Backend TS Subset)** | **18 backend coding challenges** | 11 / 18 (**61.1%**) | 15 / 18 (**83.3%**) | 15 / 18 (**83.3%**) | **18 / 18 (100.0%)** | 16 / 18 (**88.9%**) | 16 / 18 (**88.9%**) | **18 / 18 (100.0%)** | **18 / 18 (100.0%)** |
| **Tier 2B: `juice-shop-high-risk` Vulnerable Backend Files** | **39 vulnerable source files** | — *(Bench only)* | — *(Bench only)* | — *(Bench only)* | 33 / 39 (**84.6%**) | — *(Bench only)* | — *(Bench only)* | **39 / 39 (100.0%)** | **39 / 39 (100.0%)** |
| **Tier 3: Full Backend `solveIf` Vulnerable Route/Model Files** | **28 backend vuln files** | — *(Bench only)* | — *(Bench only)* | — *(Bench only)* | 26 / 28 (**92.9%**) | — *(Bench only)* | — *(Bench only)* | **27 / 28 (96.4%)** *(`js_16` single)*<br/>**28 / 28 (100.0%)** *(`js_15`+`16`)* | **28 / 28 (100.0%)** |

#### (3) Tier 1 Itemized Breakdown (26 Core Code Vulnerabilities in `juice-shop-bench`, No-`-c` vs. With-`-c`)

| ID | Target File | Ground Truth Vulnerability | `js_08` (`3.8F` Deep **No `-c`**) | `js_10` (`4-argon` Quick **No `-c`**) | `js_03` (`3.8F` Deep **With `-c`**) | `js_05` (`4-argon` Deep **With `-c`**) | `js_12` (`4-argon` Quick **With `-c`**) | `js_13`/`14` (`3.8F` High-Risk/Core **With `-c`**) | `js_15` (`4-argon` High-Risk **With `-c`**) |
| :---: | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **V01** | `routes/login.ts:34` | SQL Injection Authentication Bypass (`loginAdmin`, etc.) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **V02** | `routes/search.ts:23` | UNION SQL Injection / DB Schema Extraction (`unionSqlInjection`, `dbSchema`) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **V03** | `routes/b2bOrder.ts:22` | `safeEval` (`vm`) Sandbox Escape RCE & ReDoS (`rceChallenge`) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **V04** | `routes/userProfile.ts:57` | `pug.compile()` Template Concatenation SSTI / RCE (`usernameXss`) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **V05** | `routes/profileImageUrlUpload.ts:23` | Arbitrary Image URL Fetch SSRF (`ssrfChallenge`) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **V06** | `routes/profileImageUrlUpload.ts:29` | Unsanitized URL Pathname Extension in `createWriteStream` (Path Traversal Write) | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ (`js_13`) | ✅ |
| **V07** | `routes/fileUpload.ts:39` | Zip Slip Arbitrary File Overwrite (`fileWriteChallenge`) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **V08** | `routes/fileUpload.ts:81` | `libxmljs.parseXml` with `noent:true` XXE Injection (`xxeFileDisclosure`) | ❌ | ✅ | ❌ | ✅ | ✅ | ✅ (`js_14`) | ✅ |
| **V09** | `routes/fileUpload.ts:113` | `yaml.load()` Insecure Deserialization / YAML Bomb DoS (`yamlBomb`) | ❌ | ✅ | ❌ | ✅ | ✅ | ✅ (`js_14`) | ✅ |
| **V10** | `routes/fileUpload.ts:62` | Unrestricted File Upload Missing Server-Side Type/Size Enforcement | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **V11** | `routes/fileServer.ts:33` | `%2500` Poison Null Byte Path Traversal Arbitrary File Read | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **V12** | `routes/dataErasure.ts:68` | `res.render` Request Spread `layout` Local File Inclusion (LFI) & SSTI | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **V13** | `routes/redirect.ts:19` | `includes()` Substring Bypass Open Redirect (`redirectChallenge`) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **V14** | `routes/showProductReviews.ts:34` | MarsDB `$where` NoSQL Injection / DoS (`noSqlCommand`) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **V15** | `routes/updateProductReviews.ts:21` | NoSQL Injection (`multi:true`) + IDOR Forged Review Author (`forgedReview`) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **V16** | `routes/trackOrder.ts:20` | `$where` NoSQL Injection Order Disclosure + Reflected XSS (`noSqlOrders`) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **V17** | `lib/insecurity.ts:21` | Hardcoded RSA Private/Public Keys & Weak HMAC Secret (`jwtForged`) | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **V18** | `lib/insecurity.ts:57` | JWT Algorithm Confusion (RS256 Public Key as HS256 Secret / `unsignedJwt`) | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **V19** | `lib/insecurity.ts:26` | Unsalted MD5 Weak Password Hashing (`hash()`) | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **V20** | `lib/insecurity.ts:168` | Legacy `sanitize-html` Recursive XSS Bypass & Weak Redirect Allowlist | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **V21** | `models/user.ts:81` | Mass Assignment Privilege Escalation (`role: 'admin'`) + Plaintext/MD5 Setter | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **V22** | `server.ts:661` | Verbose Stack Trace Exposure via `errorhandler()` (`errorHandlingChallenge`) | ❌ | ❌ | ✅ | ✅ | ❌ | ✅ (`js_13`) | ✅ |
| **V23** | `server.ts:172` | Permissive Global CORS Policy (`origin: '*'`) | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ✅ |
| **V24** | `server.ts:368` | Spoofable `X-Forwarded-For` Rate-Limit Bypass + Unauthenticated Route Access | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **V25** | `views/promotionVideo.pug:70` | Unescaped Pug Interpolation `!=subs` XSS (`videoXssChallenge`) | ❌ | ✅ | ❌ | ❌ | ✅ | ✅ (`videoHandler.ts`) | ✅ (`videoHandler.ts`) |
| **V26** | `package.json` | Vulnerable Outdated Dependencies (`express-jwt 0.1.3`, `sanitize-html 1.4.2`, `marsdb`) | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ✅ |
| **Total** | **26 Core Vulnerabilities** | **Bench Ground Truth Recall** | **14/26 (`53.8%`)** | **20/26 (`76.9%`)** | **20/26 (`76.9%`)** | **24/26 (`92.3%`)** | **24/26 (`92.3%`)** | **22/26 (`84.6%`)** | **26/26 (`100.0%`)** |

#### (4) Four Closed-Loop Pipeline Optimizations Implemented from Ground Truth Gap Analysis
1. **Cross-File Controller ↔ View Template Co-Location (`_trace_thin_wrappers` & `materialize_isolated_scan_target`)**:
   - **Root Cause**: Earlier `juice-shop-bench` included `views/promotionVideo.pug` without its rendering controller `routes/videoHandler.ts`. In `--deep` mode, the verification agent dropped `!=subs` in `promotionVideo.pug` when it could not see how `subs` was populated in `videoHandler.ts`.
   - **Fix**: `RepoProfiler._trace_thin_wrappers()` now automatically detects template references (`views/`, `templates/`, `res.render()`, `render_template()`), records controller-to-view pairs (`routes/videoHandler.ts -> views/promotionVideo.pug`, `routes/userProfile.ts -> views/userProfile.pug`, `routes/dataErasure.ts -> views/dataErasureForm.hbs`) in `PROJECT_FILE_INDEX.md`, and guarantees bidirectional co-location when scoping repositories.
2. **Weak Password Recovery Mechanism (`CWE-640`) Signal Extraction (`routes/resetPassword.ts`)**:
   - **Root Cause**: `routes/resetPassword.ts` was the only vulnerable route file in `juice-shop-high-risk` (`38/39 = 97.4%`) not flagged separately because it uses parameterized Sequelize queries (`SecurityAnswerModel.findOne`) while allowing direct password resets solely via static security answers without an email token (`CWE-640`).
   - **Fix**: Added `password_recovery` (`resetPassword`, `SecurityAnswerModel`, `forgot_password`) to `SINK_PATTERNS` and `SINK_AUDIT_DIRECTIVES`, and updated Pillar 3 to explicitly audit weak security-question password recovery flows.
3. **Multi-Sink Exhaustive Enumeration in Dense Route Files (`routes/fileUpload.ts` & `routes/profileImageUrlUpload.ts`)**:
   - **Root Cause**: When 3–4 vulnerabilities co-exist in a single file (`fileUpload.ts` has Zip Slip, unrestricted upload, XXE, and YAML deserialization; `profileImageUrlUpload.ts` has SSRF + `createWriteStream` path traversal), `3.8-flash` occasionally stopped after reporting the primary sink.
   - **Fix**: Added `createWriteStream` to `file_upload`, `!=` to `xss`, and `res.render` to `template_injection`, and updated Pillar 5 to require reporting every distinct sink separately even within the same file.
4. **Tier-S Dependency Manifest Co-Location (`package.json`)**:
   - **Fix**: Assigned `+1000` priority to all dependency manifests in `score_file_security_signal()` and linked `package.json` in delegation maps so `--deep` workers consistently correlate vulnerable packages with reachable sinks.

---

## 3. Deep-Dive on the `-c` (`--context`) Parameter: 5-Pillar Prompt Engineering, Ablation Matrix & Literal Filename Trap

In `cm find -c "<context_prompt>"`, the **`-c` (`--context`) parameter is the single most impactful lever controlling both vulnerability recall and `--deep` file-scoping behavior**.

### 3.1 Controlled Comparison Across All Three Stacks: No-`-c` (`c0_none`) vs. 5-Pillar `-c` (`c3_hybrid_max`)

| Stack & Controlled Pair (Fixed Model & Mode, Varying Only `-c`) | Without `-c` (`c0_none` Baseline) | With 5-Pillar `-c` (`c3_hybrid_max`) | Net Uplift from `-c` |
| :--- | :--- | :--- | :--- |
| **🐍 Python (`src/`) — `gemini-3.5-flash` Quick** | [`py_01`](./eval_results/python_wsgi/py_01_quick_35flash_c0_report.json): 8 findings, **`72.7%` (8/11) recall** | [`py_02`](./eval_results/python_wsgi/py_02_quick_35flash_c3_report.json): 12 findings, **`100.0%` (11/11) recall** | **`+27.3%` recall** (unlocks Debugger RCE, Multipart DoS, Cookie flags) |
| **🐍 Python (`src/`) — `gemini-3.8-flash` Quick** | [`py_03`](./eval_results/python_wsgi/py_03_quick_38flash_c0_report.json): 8 findings, **`72.7%` (8/11) recall** | [`py_06`](./eval_results/python_wsgi/py_06_quick_38flash_c3_hybrid_report.json): 13 findings, **`100.0%` (11/11) recall** | **`+27.3%` recall**, **`+62.5%` findings** |
| **🟢 Node.js (`juice-shop-bench`) — `gemini-3.8-flash` Deep** | [`js_08`](./eval_results/nodejs_juiceshop/js_08_3.8-flash_deep_c0_none_report.json): 19 findings, **`53.8%` (14/26) recall** (600s timeout; missed `insecurity.ts`, `dataErasure.ts`, `package.json`) | [`js_03`](./eval_results/nodejs_juiceshop/js_03_3.8-flash_deep_c3_hybrid_report.json): 25 findings, **`76.9%` (20/26) recall** in **201.7s** | **`+23.1%` recall**, **`3.0x` faster** |
| **🟢 Node.js (`juice-shop-bench`) — `gemini-3.5-flash` Quick** | [`js_09`](./eval_results/nodejs_juiceshop/js_09_3.5-flash_quick_c0_none_report.json): 6 findings across 5 files | [`js_11`](./eval_results/nodejs_juiceshop/js_11_3.5-flash_quick_c3_hybrid_report.json): 13 findings across 11 files | **`+116.7%` (`2.17x`) findings** |
| **🟢 Node.js (`juice-shop-bench`) — `gemini-4-argon` Quick** | [`js_10`](./eval_results/nodejs_juiceshop/js_10_4-argon_quick_c0_none_report.json): 20 findings, **`76.9%` (20/26) recall** (missed `package.json` SCA, CORS, etc.) | [`js_12`](./eval_results/nodejs_juiceshop/js_12_4-argon_quick_c3_hybrid_report.json): 35 findings, **`92.3%` (24/26) recall** (`100%` 26/26 in `js_15` Deep) | **`+15.4%` recall**, **`+75.0%` findings** |
| **☕ Java (`mall-bench`) — `gemini-3.8-flash` Deep** | [`mall_08`](./eval_results/java_mall/mall_08_3.8-flash_deep_c0_none_report.json): **7 findings**, **6/17 (`35.3%`)** vulnerable files, **7/22 (`31.8%`)** audited flaws | [`mall_03`](./eval_results/java_mall/mall_03_3.8-flash_deep_c3_hybrid_report.json): **13 findings**, **10/17 (`58.8%`)** vulnerable files, **13/22 (`59.1%`)** flaws | **`+85.7%` findings**, **`+27.3%` flaw recall** |
| **☕ Java (`mall-bench`) — `gemini-4-argon` Quick** | [`mall_10`](./eval_results/java_mall/mall_10_4-argon_quick_c0_none_report.json): **10 findings**, **8/17 (`47.1%`)** vulnerable files, **10/22 (`45.5%`)** flaws (missed `pom.xml`, `OssController`, `SecurityConfig`) | [`mall_12`](./eval_results/java_mall/mall_12_4-argon_quick_c3_hybrid_report.json): **29 findings**, **17/17 (`100.0%`)** vulnerable files, **21/22 (`95.5%`)** flaws | **`+190.0%` (`2.9x`) findings**, vulnerable file recall jumps from `47.1%` to **`100.0%`**! |

#### Summary of the Five `-c` Context Prompt Strategies:
1. **`c0_none` (No `-c` flag — Zero-Context Baseline)**: Inspects only surface-level single-file functions and misses third-party dependency CVEs (SCA), framework debugger configurations (`evalex=True`), missing cookie security attributes, and cross-file XML/template sinks.
2. **`c1_sca` (Dependency Versions & CVE Correlation in `-c` Only)**: Injecting extracted package versions (`Werkzeug 2.2.0`, `fastjson 1.2.75`) into `-c` unlocks `CVE-2023-25577` (`100.0%` Python recall in [`py_04`](./eval_results/python_wsgi/py_04_quick_38flash_c1_sca_report.json)).
3. **`c2_sast_framework` (Framework Routes & Sink Directives in `-c` Only)**: Guides the agent toward framework-specific sinks, outperforming `c0_none` on SAST depth while missing pure dependency CVEs.
4. **`c3_hybrid_max` (5-Pillar Hybrid Semantic Prompt — Pipeline Default)**: Combines **Architecture Navigation + SCA Dependency Versions + SAST Route Sink Directives + Guard False-Positive Controls + Multi-Sink Exhaustive Enumeration**, achieving peak recall across all three stacks with **`0.0%` false positives**.
5. **`c_legacy_literal` (Anti-Pattern: Literal `<name>.<ext>` Filenames Inside `-c`)**: In [`py_13_deep_38flash_literal_trap`](./eval_results/python_wsgi/py_13_deep_38flash_literal_trap_meta.json), passing a prompt mentioning `requirements.txt` to `cm find --deep` caused `cm` to exit in **0.5 seconds with `0` findings (`0.0%` recall)**!

---

### 3.2 How `--deep` Mode's `-c` Literal Filename Regex + Tier 0 Pruner Causes `0%` Recall
Reverse-engineering `/usr/local/google/home/hongbocheng/bin/cm` (offset `0x241d120`) revealed a two-step interaction whenever `-c` is used with `--deep`:
1. **Step 1 (`-c` Regex File Scoping)**: `cm v0.14.0 --deep` scans the `-c` string using:
   ```regex
   (?:^|[\s"'`(])([a-zA-Z0-9_./-]+\.[a-zA-Z0-9]+)(?:$|[\s"'`),:;])
   ```
   If **any** token in `-c` matches `<name>.<ext>` (such as `requirements.txt`, `package.json`, `pom.xml`, `server.ts`, or even version strings with alphabetic suffixes like `2.0.53.Final` or `Hoxton.SR9`), `--deep` restricts the entire repository scan **exclusively to those matched filenames**, discarding `app.py` and all other source files!
2. **Step 2 (`Tier 0 Pruner` Lockfile Elimination)**: Next, `--deep`'s built-in **Tier 0 Pruner** classifies `requirements.txt` / `package.json` as a non-code manifest/lockfile and prunes it (`Tier 0 Pruner: 2 safe files pruned at 0 token cost`).
3. **Net Result**: `1 matched file - 1 pruned file = 0 files scanned`!

> **Hard Sanitization Gate ([`sanitize_context_prompt()`](./pipeline/pipeline.py))**:
> [`pipeline/pipeline.py`](./pipeline/pipeline.py) automatically rewrites all literal filenames into semantic descriptions (*"the root dependency manifest"*), normalizes `.ALL`/`.RELEASE`/`.Final` version suffixes to hyphens, strips prompt-injection strings from untrusted repo identifiers, and asserts `len(FILE_SCOPING_REGEX.findall(prompt)) == 0` before invoking `cm`.

---

### 3.3 The 5-Pillar `-c` Prompt Automatically Synthesized by `pipeline.py`
Stage 1 (`RepoProfiler.synthesize_context_prompt`) automatically constructs a repository-specific `-c` prompt across **5 Pillars**:
1. **Pillar 1 (Architecture & Entrypoints)**: Directs the agent to read `PROJECT_FILE_INDEX` first and highlights entrypoints, thin-wrapper delegation chains, and Controller ↔ View template pairs.
2. **Pillar 2 (Dependency & SCA CVE Correlation)**: Injects exact package names and versions extracted from `requirements.txt`, `package.json`, `pom.xml` (with `${}` property interpolation), `go.mod`, or `CMakeLists.txt` directly into the `-c` prompt text.
3. **Pillar 3 (Route & Taint Sink Analysis)**: Lists discovered route counts and active sink categories across 17 vulnerability classes (`command_injection`, `deserialization`, `sql_injection`, `nosql_injection`, `ssrf`, `xxe`, `ssti`, `xss`, `file_upload`, `path_traversal`, `open_redirect`, `jwt_crypto`, `debug_config`, `cookie_security`, `mass_assignment`, `idor_business_logic`, `password_recovery`).
4. **Pillar 4 (Sanitizer & False-Positive Control)**: Explicitly names detected security guards (`safe_join`, `realpath`, `filepath.Clean`, parameterized queries) and instructs the agent to verify whether they neutralize the taint flow before reporting (`0.0%` false positives).
5. **Pillar 5 (Full-Scope Multi-Sink Exhaustive Coverage)**: Instructs the agent to audit all language components and report every distinct vulnerability sink independently even when multiple flaws reside in the same file.

---

### 3.4 Five Golden Rules for CodeMender Teams
1. **Rule 1 (Choose `Quick` vs `--deep` by Active File Count)**: Use `Quick + c3_hybrid_max` for micro-services ($\le 5$ active files) so Tier 0 Pruner does not drop dependency manifests; use `--deep --deep-workers 16 --deep-max-turns 8 + c3_hybrid_max` for multi-file repos ($> 5$ files).
2. **Rule 2 (Never Put Literal `<name>.<ext>` Tokens in `-c` Under `--deep`)**: Always pass `-c` prompts through `sanitize_context_prompt()` (`0` matches on `FILE_SCOPING_REGEX`) and inject extracted dependency versions directly into the prompt text.
3. **Rule 3 (Expand `CM_HOME/config.yaml` Extensions)**: Include `.json`, `.xml`, `.yml`, `.yaml`, `.properties`, `.pug`, `.hbs`, `.ejs`, `.txt`, `.gradle` in `scan.extensions.include` to cover MyBatis `*Dao.xml`, Spring `application.yml`, and view templates.
4. **Rule 4 (Prune Non-Attack-Surface Noise & Co-Locate Controllers with Views in `PROJECT_FILE_INDEX.md`)**: Exclude SPA `frontend/` and generated ORM boilerplate (`mall-mbg`), co-locate controllers with rendered view templates, and generate `PROJECT_FILE_INDEX.md`.
5. **Rule 5 (Use the 5-Pillar Hybrid `-c` Prompt & Keep `--enable-bash` Off in `--deep`)**: Combine all 5 pillars in `-c` while leaving `--enable-bash` disabled in `--deep` mode (**1.87x** faster execution).

---

## 4. Four Critical `cm v0.14.0` `--deep` Failure Traps & Architectural Defenses

Reverse-engineering the `/usr/local/google/home/hongbocheng/bin/cm` binary and analyzing our 43 runs revealed **4 critical failure traps** that our pipeline automatically prevents (see [`docs/UNIVERSAL_PIPELINE_REVIEW.md`](./docs/UNIVERSAL_PIPELINE_REVIEW.md)):

| Trap | Internal `cm v0.14.0` Mechanism | Empirical Failure Impact | Automated Defense in `pipeline/pipeline.py` |
| :--- | :--- | :--- | :--- |
| **Trap 1: `-c` Filename Regex Scoping in `--deep`** | `cm` binary (`0x241d120`) parses `-c` with `([a-zA-Z0-9_./-]+\.[a-zA-Z0-9]+)`. Any matching token locks `--deep` to ONLY those matched filenames | `py_13` (mentioning `requirements.txt`) skipped `app.py` and yielded **`0` findings (`0%` recall)**; early `mall` (`.ALL` version suffix) yielded **`0` findings** | **`sanitize_context_prompt()` Hard Regex Gate**: Rewrites all literal filenames into semantic descriptions, normalizes `.ALL`/`.RELEASE` version suffixes, neutralizes prompt injections, and enforces `0` `FILE_SCOPING_REGEX` matches |
| **Trap 2: Single-Worker Deep Starvation** | Default `--deep-workers 1` and `--deep-max-turns 50` causes single-worker starvation on multi-file repositories | Single-worker `--deep` runs hit the **900s hard timeout** with **`0` findings** | **Adaptive Concurrency (`select_execution_profile`)**: Automatically configures `--deep --deep-workers 16 --deep-max-turns 8` when `active_files_count > 5` |
| **Trap 3: Tier 0 Pruner on Micro-Targets** | On micro-targets ($\le 5$ files), `--deep`'s Tier 0 Pruner skips `requirements.txt` as a non-code manifest | Misses dependency CVE correlation on 2-file services | **Adaptive Mode Threshold**: Selects **Quick Mode (`deep=False`)** when `active_files_count <= 5` and **Parallel Deep Mode** when `> 5` |
| **Trap 4: State DB Bleed & Generated ORM Noise** | Shared `~/.codemender/state.db` leaks prior findings; hundreds of generated MyBatis `*Example.java` files exhaust worker budgets | Polluted reports or worker exhaustion on generated boilerplate | **Isolated `.cm_home` + Smart ORM/SPA Filtering**: Creates a fresh `.cm_home` and `.git` boundary per scan; excludes SPA `frontend/` and generated `mall-mbg` while preserving custom `dao/*Dao.xml` |

---

## 5. Operational Guide: How to Scan Any New Repository

Because [`pipeline/pipeline.py`](./pipeline/pipeline.py) uses **zero hardcoded repository names** (enforced by AST unit test `test_pipeline_ast_has_zero_hardcoded_repo_branching`), you can scan any new local repository (`Python`, `Node.js/TypeScript`, `Java/Spring Boot`, `C/C++`, `Go`, `Ruby`, `PHP`) without modifying any code or writing custom prompts:

### Option A: One-Command End-to-End Automated Scan (Recommended)
```bash
# Automatically runs Stage 1 Auto-Profiling + Stage 2 Isolated cm Scan and generates report.json & report.md
python3 pipeline/pipeline.py scan /path/to/your-new-repo

# Optional flags: custom output directory, model (gemini-3.8-flash or gemini-4-argon), and timeout (capped at 900s)
python3 pipeline/pipeline.py scan /path/to/your-new-repo \
  --output-dir ./scan_outputs/your-new-repo \
  --model gemini-3.8-flash \
  --timeout 600
```

### Option B: Two-Step Workflow (Inspect Stage 1 Dry-Run Profile First, Then Scan)
For large or unfamiliar monorepos, run the **Stage 1 Dry-Run Profiler** (`< 3 seconds`, `0` LLM tokens) to inspect the generated profile before launching `cm`:
```bash
# Step 1: Run Stage 1 static profiler only (supports 'profile' subcommand or '--dry-run' flag)
python3 pipeline/pipeline.py profile /path/to/your-new-repo --output-dir ./scan_outputs/your-new-repo

# Inspect generated Stage 1 artifacts:
# 1. ./scan_outputs/your-new-repo/profile.json          -> Detected languages, active files, dependencies, sanitized -c prompt, CLI flags
# 2. ./scan_outputs/your-new-repo/config.yaml           -> Tailored scan.extensions.include & exclude directories
# 3. ./scan_outputs/your-new-repo/PROJECT_FILE_INDEX.md -> Entrypoints, thin-wrapper chains & controller-to-view template map

# Step 2: Run full scan (supports manual override via --deep or --quick)
python3 pipeline/pipeline.py scan /path/to/your-new-repo --output-dir ./scan_outputs/your-new-repo
```

---

## 6. Stage 3 & Stage 4: End-to-End Automated Vulnerability Verification (`cm verify`) & Remediation (`cm fix`) (`fix` Branch)

Building on Stage 2 `cm find` (`100%` recall across all **11 Ground Truth vulnerabilities / 12 distinct findings** in [`src/app.py`](./src/app.py) and [`src/requirements.txt`](./src/requirements.txt) with `0%` false positives on `/files/secure-download`), we implemented [`pipeline/run_verify_and_fix.py`](./pipeline/run_verify_and_fix.py) on the `fix` branch to run **12 parallel isolated workers executing `cm verify` $\rightarrow$ `cm fix`** (full report in [`docs/VERIFY_AND_FIX_REPORT.md`](./docs/VERIFY_AND_FIX_REPORT.md), raw JSON telemetry in [`eval_results/python_wsgi/py_16_verify_and_fix_summary.json`](./eval_results/python_wsgi/py_16_verify_and_fix_summary.json)):

### 6.1 End-to-End `cm verify` $\rightarrow$ `cm fix` Benchmark Results

| Pipeline Stage & Metric | Empirical Result (`cm v0.14.0`, `gemini-3.8-flash`) | Notes |
| :--- | :---: | :--- |
| **Stage 3: `cm verify` Verification Rate (`status=VERIFIED`)** | **12 / 12 (`100.0%`)** | All 12 findings generated complete `.exploit/exploit.sh`, `PLAN.md`, `LOG.md`, `REPORT.md`, and `info.yaml` artifacts |
| **Stage 3: Generated PoC Exploit Success on Unpatched Code** | **12 / 12 (`100.0%`)** | All 12 `.exploit/exploit.sh` scripts reproduced the vulnerability via `werkzeug.test.Client` (`EXPLOIT SUCCESSFUL`, `rc=0`) |
| **Stage 4: `cm fix` Automated Patch Generation Rate (`status=FIXED`)** | **12 / 12 (`100.0%`)** | All 12 findings produced verified patches in `state.db` (`patches` table) and modified the target source files |
| **Stage 4: Post-Fix Regression Verification (Exploits Blocked)** | **12 / 12 (`100.0%`)** | After merging all 12 patches into [`src/app.py`](./src/app.py) and [`src/requirements.txt`](./src/requirements.txt), all 12 `exploit.sh` scripts were blocked (`rc=1`) |
| **Total 12-Way Parallel Wall-Clock Duration (12 `verify` + 12 `fix`)** | **`665.09s` (`~11.1 min`)** | **8.1× speedup** over sequential single-threaded execution (`~90 min`) |

### 6.2 Four Key Engineering Requirements for Unattended `cm verify` & `cm fix`
1. **Pass `--bypass-warning` in Non-Interactive Mode**: Unattended `cm verify` and `cm fix` invocations that execute `run_command` must pass `cm -y --bypass-warning --sandbox=false ...` to avoid immediate exit (`rc=1`) on the responsibility warning prompt.
2. **Pre-Populate Target Runtime Virtualenv on `PATH` + `PYTHONDONTWRITEBYTECODE=1`**: Prepending a virtualenv containing the target's dependencies (`/tmp/cm_py_venv/bin`) prevents verification agents from running slow `find / -name werkzeug` full-filesystem scans when `import werkzeug` fails on system Python.
3. **Per-Finding Isolated `.cm_home` & Target Workspaces (`worker_cm_XX` / `worker_tgt_XX`)**: Cloning isolated workspaces and rewriting `state.db` paths prevents concurrent `cm verify` / `cm fix` workers from overwriting `.exploit/exploit.sh` or contending on SQLite locks.
4. **3-Way Patch Merging (`git apply --3way --recount`)**: Because each route handler flaw in `src/app.py` occupies a distinct line range, 3-way git patch application cleanly merges all 12 generated fixes into the unified codebase.

---

## 7. Verification Suite & Repository Structure

```bash
# 1. Run the 20-test Unit & Integration Suite (hard regex sanitizer, manifest parsers, ORM filtering, controller-view co-location, AST zero-hardcoding check)
python3 -m unittest -v pipeline/test_universal_pipeline.py

# 2. Run the 12-worker parallel cm verify -> cm fix automated verification & remediation pipeline
python3 -u pipeline/run_verify_and_fix.py
```

```text
codemender-test/
├── README.md                          # English Flagship Report, Glossary & Universal Pipeline Guide (this file)
├── README_CN.md                       # Chinese Flagship Report, Glossary, Ground Truth Analysis & Guide (中文主报告)
├── docs/
│   ├── VERIFY_AND_FIX_REPORT.md       # Stage 3 & 4 Automated Vulnerability Verification (cm verify) & Fix (cm fix) Report
│   ├── UNIVERSAL_PIPELINE_REVIEW.md   # Deep Technical Review & 4 Failure Trap Mitigations
│   ├── BENCHMARK_RESULTS.md           # Full 43-run ablation tables & CWE/Ground-Truth breakdown
│   ├── MALL_AUDIT_REFERENCE.md        # macrozheng/mall Curated Code Audit Reference (Non-Official Ground Truth)
│   └── CODEMENDER_SHARE_SUMMARY_CN.md # Archived Chinese executive briefing
├── pipeline/                          # Universal CodeMender v0.14.0 Profile, Scan, Verify & Fix Pipeline
│   ├── pipeline.py                    # Universal Stage 1 Auto-Profiler & Stage 2 Runner (zero hardcoded repo names)
│   ├── run_verify_and_fix.py          # Parallel 12-worker Stage 3 (cm verify) & Stage 4 (cm fix) Runner
│   ├── test_universal_pipeline.py     # 20-test unit & integration test suite
│   ├── run_python_benchmarks.py       # Python WSGI benchmark + strict Ground Truth (11/11) & safe_join (0% FP) evaluator
│   ├── run_all_benchmarks.py          # Node.js (juice-shop) & Java (macrozheng/mall) ablation suite
│   └── generate_report.py             # Automated Markdown report generator
├── src/                               # Target 1: Python Werkzeug WSGI Application (11 GT vulnerabilities + 1 safe_join negative control on main; remediated on fix branch)
│   ├── app.py
│   └── requirements.txt
├── grounding-truth/                   # Ground Truth PoC Exploit & Verification Suite for Python WSGI
│   └── poc_exploit.py
├── benchmarks/                        # Curated Benchmark Target Scopes (with PROJECT_FILE_INDEX.md)
│   ├── ref-codemender-bench/          # Python WSGI isolated benchmark scope (2 files)
│   ├── juice-shop-bench/              # Node.js / TypeScript core benchmark scope (co-located routes + views)
│   └── mall-bench/                    # Java / Spring Boot + MyBatis core benchmark scope (20 files)
└── eval_results/                      # Complete Evaluation Artifacts (.log, _report.txt, _report.json, _meta.json)
    ├── python_wsgi/                   # Python WSGI scan & verify/fix results (py_01..py_16_verify_and_fix_summary.json)
    ├── nodejs_juiceshop/              # 16-run cm v0.14.0 Node.js/TS OWASP Juice Shop matrix (js_01..js_16)
    ├── java_mall/                     # 15-run cm v0.14.0 Java/Spring Boot macrozheng/mall matrix (mall_01..mall_15)
    └── legacy_v0.7_python/            # Original 8-run quick-mode baseline (run1..run8)
```
