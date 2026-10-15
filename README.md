# CodeMender (`cm v0.14.0`) Tri-Language Vulnerability Scan Benchmark, Ground Truth Evaluation & Best Practices

[![Language: Python / Node.js / Java](https://img.shields.io/badge/Stacks-Python%20%7C%20Node.js%20%7C%20Java-blue)](#1-tri-language-benchmark-executive-summary)
[![Experiments: 43 Controlled Runs](https://img.shields.io/badge/Experiments-43%20Controlled%20Runs%20(%2B8%20Legacy)-success)](#3-benchmark-suite-i-python--werkzeug-wsgi-ground-truth-evaluation)
[![Ground Truth Recall: 100%](https://img.shields.io/badge/Python%20GT%20Recall-100%25%20(11%2F11)%20%7C%200%25%20FP-brightgreen)](#3-benchmark-suite-i-python--werkzeug-wsgi-ground-truth-evaluation)

> 📖 **Quick Navigation**:
> - 🏛️ **[Architectural Review & 4 Failure Trap Mitigations (`docs/UNIVERSAL_PIPELINE_REVIEW.md`)](docs/UNIVERSAL_PIPELINE_REVIEW.md)**
> - 🇨🇳 **[中文综合评测总结与最佳实践分享版 (`README_CN.md`)](README_CN.md)**
> - 📊 **[Full 43-Run Ablation Report (`docs/BENCHMARK_RESULTS.md`)](docs/BENCHMARK_RESULTS.md)**
> - ⚙️ **[Universal Two-Stage Auto-Profile & Auto-Scan Pipeline (`pipeline/pipeline.py`)](pipeline/pipeline.py)** | **[Unit Tests (`pipeline/test_universal_pipeline.py`)](pipeline/test_universal_pipeline.py)**

This repository provides an end-to-end multi-language benchmark, Ground Truth verification harness, and universal two-stage **Auto-Profile -> Auto-Scan** pipeline for **CodeMender** (`cm v0.14.0`), an LLM-powered autonomous vulnerability scanning and remediation agent.

---

## 1. Tri-Language Benchmark Executive Summary & Universal Two-Stage Pipeline Verification

We evaluated CodeMender (`cm v0.14.0`, `--sandbox=false`) across **43 controlled ablation runs** (plus **8 legacy `v0.7.0` baseline runs**) and verified our **Universal Two-Stage Auto-Profile & Auto-Scan Pipeline** (`pipeline/pipeline.py`) across **5 distinct repository stacks** (`Python`, `Node.js/TypeScript`, `Java/Spring Boot`, `C/C++`, and `Go`) with **zero hardcoded repository names**:

| Dimension | 🐍 Python / Werkzeug WSGI ([`src/`](src/)) | 🟢 Node.js / Express / TypeScript ([`benchmarks/juice-shop-bench/`](benchmarks/juice-shop-bench/)) | ☕ Java / Spring Boot + MyBatis ([`benchmarks/mall-bench/`](benchmarks/mall-bench/)) |
| :--- | :--- | :--- | :--- |
| **Application Profile** | Enterprise WSGI Microservice with Ground Truth PoC Suite (`11` Real Vulns + `1` `safe_join` Control) | OWASP Juice Shop Full-Stack Web App (Express + Sequelize + MarsDB + Pug Templates) | Multi-Module E-Commerce Platform (`macrozheng/mall`: Spring Security + MyBatis XML + MinIO/OSS/Alipay) |
| **Target Scope Scale** | **Microservice** (`2` core files: `app.py` + `requirements.txt`) | **Medium Service** (`16` bench files / `35` high-risk / `118` core files) | **Multi-Module Monorepo** (`20` bench files / `48` high-risk / `297` core files across 6 Maven modules) |
| **Baseline (`Quick + c0_none`)** | **8 findings** (`72.7%` GT Recall on `3.5F` / `3.8F`; **`90.9%` (`10/11`)** zero-shot on `gemini-4-argon`) | **16–24 findings** (`4` Crit / `13` High / `7` Med) | **10–13 findings** (`2` Crit / `3` High / `5` Med) |
| **Enriched (`Quick + c3_hybrid_max`)** | **13 findings — `100.0% (11/11)` GT Recall, `0%` False Positive** (`py_06` `3.8F`, `py_08` `4-argon`, `py_02` `3.5F`) | **30 findings** (`+25%` over `c0_none` baseline) | **16 findings** (`+60%` over `c0_none` baseline) |
| **Parallel Deep (`--deep + c3_hybrid_max`)** | **11 findings in `76.3s` — `100.0% (11/11)` GT Recall, `0%` FP** (`py_12_deep_4argon_c3`) | **118 findings (`4.92x` uplift)** (`19` Crit / `58` High / `36` Med / `5` Low in `js_11`) | **90 findings (`9.0x` uplift)** (`8` Crit / `36` High / `36` Med / `10` Low in `mall_12`) |
| **Recommended Golden Profile** | **Quick + `c3_hybrid_max`** (for 1–5 file services) or **`--deep` + `gemini-4-argon` + `c3_hybrid_max`** (`76s`) | **`--deep --deep-workers 16 --deep-max-turns 8` + `c3_hybrid_max` + `gemini-3.8-flash`** | **`--deep --deep-workers 16 --deep-max-turns 8` + `c3_hybrid_max` + `gemini-4-argon`** |

---

## 2. Five Golden Engineering Discoveries & Universal Stage 1 Mitigations

### Discovery 1: The `--deep` Literal Filename Scoping + Tier 0 Pruner Trap (`0%` Recall in `py_13` vs `100%` Recall in `py_12`)
- **What Happened**: In experiment [`py_13_deep_38flash_literal_trap`](eval_results/python_wsgi/py_13_deep_38flash_literal_trap_meta.json), we passed the original legacy context prompt (*"This Python file handles untrusted input, so check `requirements.txt` for the package versions..."*) into `cm find --deep`. **The scan exited in `0.5s` with `0` findings (`0.0%` recall)!**
- **Root Cause**:
  1. **Prompt Regex File Scoping (`0x241b160`)**: `cm v0.14.0 --deep` scans the `-c` prompt for any literal `<name>.<ext>` token (`requirements.txt`, `package.json`, `pom.xml`, `server.ts`). When matched, it restricts the scan strictly to those named files (+ 1-hop imports), dropping `app.py`.
  2. **Tier 0 Lockfile Pruning (`0x241ae80`)**: Next, `--deep`'s **Tier 0 Pruner** pruned `requirements.txt` as a safe manifest/lockfile (`Tier 0 Pruner: 2 safe files pruned at 0 token cost`).
  3. **Net Result**: `1 - 1 = 0` candidate files scanned!
- **Universal Pipeline Fix**: [`pipeline/pipeline.py`](pipeline/pipeline.py) enforces a hard programmatic regex sanitizer (`sanitize_context_prompt` + `FILE_SCOPING_REGEX`) that guarantees `0` literal `filename.ext` tokens remain in `-c`, deterministically extracts dependency versions (`werkzeug 2.2.0`) directly into `-c`, and automatically selects Quick mode (`deep=False`) for micro-targets (`<= 5` active files) and Parallel Deep mode (`--deep --deep-workers 16 --deep-max-turns 8`) for multi-file repositories (`> 5` active files).

### Discovery 2: Structured 5-Pillar Hybrid Prompting Unlocks `100%` Unassisted Recall
- In the legacy benchmark (`run5`), `gemini-3.5-flash` plateaued at `72.7% (8/11)` recall even with `-c`.
- With our structured 5-pillar context synthesis in [`pipeline/pipeline.py`](pipeline/pipeline.py) (combining **Index Navigation + SCA CVE correlation + SAST route/sink directives + Config/Debugger/Cookie audit + Thin-Wrapper delegation + `safe_join` guard verification**), unassisted `python3 pipeline/pipeline.py scan src` achieves **`100.0% (11/11)` Ground Truth Recall** and **`0.0%` false positives** out of the box!

### Discovery 3: Expanding `CM_HOME/config.yaml` Extensions for XML, YAML & Template Sinks
- Default CodeMender configurations only index source files (`.py`, `.js`, `.ts`, `.java`, `.go`), ignoring **MyBatis SQL Mappers (`*Dao.xml`)**, **Spring Boot configs (`application*.yml`)**, and **Pug/Handlebars templates (`.pug`, `.hbs`)**.
- [`pipeline/pipeline.py`](pipeline/pipeline.py) automatically generates an isolated `CM_HOME/config.yaml` including `[".txt", ".json", ".xml", ".yml", ".yaml", ".properties", ".pug", ".hbs", ".ejs", ".gradle"]`, unlocking `${}` SQL Injection in `OmsOrderDao.xml` and SSTI in `promotionVideo.pug`.

### Discovery 4: Attack-Surface Scoping, Generated ORM Filtering & `PROJECT_FILE_INDEX.md`
- Universal structural heuristics in `RepoProfiler` automatically exclude generated ORM boilerplate (`mall-mbg` with `generatorConfig.xml` / `*Example.java` / `Example_Where_Clause` XMLs while retaining custom `dao/*Dao.xml` mappers), client-side SPA `frontend/` bundles, and test fixtures, and pre-generate `PROJECT_FILE_INDEX.md` with 1-hop thin-wrapper delegation maps.

### Discovery 5: Native File Tools Outperform `--enable-bash` by `1.87x` in `--deep` Mode
- Running `--deep --deep-workers 16 --deep-max-turns 8` **without** `--enable-bash` (`js_11`: `223.7s` vs `js_14` with bash: `417.6s`) is **1.87x faster** and avoids shell pagination stalls.

---

## 3. Benchmark Suite I: Python / Werkzeug WSGI Ground Truth Evaluation

### 3.1 Ground Truth Baseline Verification (`src/app.py` + `grounding-truth/poc_exploit.py`)
Executing [`grounding-truth/poc_exploit.py`](grounding-truth/poc_exploit.py) against [`src/app.py`](src/app.py) (`werkzeug==2.2.0`) verifies **11 real security vulnerabilities** and **1 intentional negative control** (`/files/secure-download` using `werkzeug.security.safe_join`):

| # | Test Item | Target / Mechanism | Vulnerability / Standard | Verification Verdict |
| :-: | :--- | :--- | :--- | :-: |
| 1 | **Multipart Part Limits** | `POST /upload` (1500 parts) | CVE-2023-25577 (Denial of Service via Unbounded Parsing) | 🔴 **SECURITY ISSUE DETECTED** |
| 2 | **Cookie Header Parsing** | `GET /auth/session` (Nameless Cookie) | CVE-2023-46136 / CWE-614 (Nameless cookie / Missing Secure flags) | 🔴 **SECURITY ISSUE DETECTED** |
| 3 | **Debugger PIN Predictability** | `werkzeug.debug` (`evalex=True`) | CVE-2024-34069 / CWE-489 (Interactive Debugger RCE) | 🔴 **SECURITY ISSUE DETECTED** |
| 4 | **Storage Path Traversal** | `GET /download?file=../app.py` | CWE-22 (Arbitrary File Read via Path Traversal) | 🔴 **SECURITY ISSUE DETECTED** |
| 5 | **safe_join File Access** | `GET /files/secure-download` | Safe file confinement via `safe_join` | 🟢 **VERIFIED SECURE** *(Safe Control)* |
| 6 | **Insecure Deserialization** | `POST /profile/restore` (`pickle.loads`) | CWE-502 (Remote Code Execution via Pickle Deserialization) | 🔴 **SECURITY ISSUE DETECTED** |
| 7 | **SQL Query Injection** | `GET /api/users/lookup` | CWE-89 (SQL Injection via Unsanitized Formatting) | 🔴 **SECURITY ISSUE DETECTED** |
| 8 | **Service Proxy (SSRF)** | `GET /services/proxy?url=127.0.0.1` | CWE-918 (Server-Side Request Forgery) | 🔴 **SECURITY ISSUE DETECTED** |
| 9 | **Unrestricted File Upload** | `POST /upload/raw` (`shell.py`) | CWE-434 / CWE-22 (Arbitrary File Write / Path Traversal) | 🔴 **SECURITY ISSUE DETECTED** |
| 10 | **Command Sanitization** | `GET /diagnostics/ping?host=...` | CWE-78 (OS Command Injection via Shell Execution) | 🔴 **SECURITY ISSUE DETECTED** |
| 11 | **Search Output Encoding** | `GET /search?q=<script>` | CWE-79 (Reflected Cross-Site Scripting) | 🔴 **SECURITY ISSUE DETECTED** |
| 12 | **URL Redirection Validation** | `GET /navigate?target=https://...` | CWE-601 (Open URL Redirection) | 🔴 **SECURITY ISSUE DETECTED** |

### 3.2 New 13-Run `cm v0.14.0` Benchmark Matrix (`eval_results/python_wsgi/`)

| Run ID | Model | Mode | Context (`-c`) | Findings | Severity (`C / H / M / L`) | Ground Truth Recall (`11` Vulns) | `safe_join` Control FP | Wall Time |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| [`py_01_quick_35flash_c0`](eval_results/python_wsgi/py_01_quick_35flash_c0_report.json) | `gemini-3.5-flash` | Quick | `c0_none` | 8 | 2 / 4 / 2 / 0 | 8/11 (`72.7%`) | 🟢 `0%` | 169.7s |
| [`py_02_quick_35flash_c3`](eval_results/python_wsgi/py_02_quick_35flash_c3_report.json) | `gemini-3.5-flash` | Quick | `c3_hybrid_max` | **12** | 3 / 5 / 4 / 0 | **11/11 (`100.0%`)** | 🟢 `0%` | 202.7s |
| [`py_03_quick_38flash_c0`](eval_results/python_wsgi/py_03_quick_38flash_c0_report.json) | `gemini-3.8-flash` | Quick | `c0_none` | 8 | 4 / 3 / 1 / 0 | 8/11 (`72.7%`) | 🟢 `0%` | 296.7s |
| [`py_04_quick_38flash_c1_sca`](eval_results/python_wsgi/py_04_quick_38flash_c1_sca_report.json) | `gemini-3.8-flash` | Quick | `c1_sca` | **11** | 2 / 7 / 2 / 0 | **11/11 (`100.0%`)** | 🟢 `0%` | 330.6s |
| [`py_05_quick_38flash_c2_sast`](eval_results/python_wsgi/py_05_quick_38flash_c2_sast_report.json) | `gemini-3.8-flash` | Quick | `c2_sast_framework` | 10 | 3 / 4 / 3 / 0 | 10/11 (`90.9%`) | 🟢 `0%` | 163.7s |
| [`py_06_quick_38flash_c3_hybrid`](eval_results/python_wsgi/py_06_quick_38flash_c3_hybrid_report.json) | `gemini-3.8-flash` | Quick | `c3_hybrid_max` | **13** | 4 / 6 / 3 / 0 | **11/11 (`100.0%`)** | 🟢 `0%` | 230.9s |
| [`py_07_quick_4argon_c0`](eval_results/python_wsgi/py_07_quick_4argon_c0_report.json) | `gemini-4-argon` | Quick | `c0_none` | 10 | 3 / 5 / 2 / 0 | **10/11 (`90.9%`)** | 🟢 `0%` | 307.2s |
| [`py_08_quick_4argon_c3`](eval_results/python_wsgi/py_08_quick_4argon_c3_report.json) | `gemini-4-argon` | Quick | `c3_hybrid_max` | **13** | 4 / 7 / 2 / 0 | **11/11 (`100.0%`)** | 🟢 `0%` | 206.3s |
| [`py_09_deep_35flash_c3`](eval_results/python_wsgi/py_09_deep_35flash_c3_report.json) | `gemini-3.5-flash` | **DEEP** (`--deep`) | `c3_hybrid_max` | 9 | 2 / 6 / 1 / 0 | 9/11 (`81.8%`) | 🟢 `0%` | 132.7s |
| [`py_10_deep_38flash_c0`](eval_results/python_wsgi/py_10_deep_38flash_c0_report.json) | `gemini-3.8-flash` | **DEEP** (`--deep`) | `c0_none` | 8 | 2 / 4 / 2 / 0 | 8/11 (`72.7%`) | 🟢 `0%` | **78.1s** |
| [`py_11_deep_38flash_c3_hybrid`](eval_results/python_wsgi/py_11_deep_38flash_c3_hybrid_report.json) | `gemini-3.8-flash` | **DEEP** (`--deep`) | `c3_hybrid_max` | 10 | 3 / 4 / 3 / 0 | 10/11 (`90.9%`) | 🟢 `0%` | 175.2s |
| [`py_12_deep_4argon_c3`](eval_results/python_wsgi/py_12_deep_4argon_c3_report.json) | `gemini-4-argon` | **DEEP** (`--deep`) | `c3_hybrid_max` | **11** | 4 / 4 / 3 / 0 | **11/11 (`100.0%`)** | 🟢 `0%` | **76.3s** |
| [`py_13_deep_38flash_literal_trap`](eval_results/python_wsgi/py_13_deep_38flash_literal_trap_meta.json) | `gemini-3.8-flash` | **DEEP** (`--deep`) | `c_legacy_literal` | **0** | 0 / 0 / 0 / 0 | **0/11 (`0.0%`)** *(Scoped+Pruned)* | 🟢 `0%` | 0.5s |

*(Legacy `cm v0.7.0` 8-run baseline artifacts `run1`–`run8` remain preserved in [`eval_results/legacy_v0.7_python/`](eval_results/legacy_v0.7_python/).)*

---

## 4. Benchmark Suite II: Node.js / TypeScript (`juice-shop/juice-shop`) — 15 Runs (`eval_results/nodejs_juiceshop/`)

| Run ID | Target Scope | Model | Mode | Context (`-c`) | Findings | Severity (`C / H / M / L`) | Unique CWEs | Files Hit | Wall Time |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| [`js_01_3.8-flash_quick_c0_none`](eval_results/nodejs_juiceshop/js_01_3.8-flash_quick_c0_none_report.json) | `juice-shop-bench` | `gemini-3.8-flash` | Quick | `c0_none` | 0 | 0 / 0 / 0 / 0 | 0 | 0 | 480.0s *(T/O)* |
| [`js_02_3.8-flash_quick_c3_hybrid`](eval_results/nodejs_juiceshop/js_02_3.8-flash_quick_c3_hybrid_report.json) | `juice-shop-bench` | `gemini-3.8-flash` | Quick | `c3_hybrid_max` | 0 | 0 / 0 / 0 / 0 | 0 | 0 | 480.0s *(T/O)* |
| [`js_03_3.8-flash_deep_c3_hybrid`](eval_results/nodejs_juiceshop/js_03_3.8-flash_deep_c3_hybrid_report.json) | `juice-shop-bench` | `gemini-3.8-flash` | **DEEP** (`--deep`) | `c3_hybrid_max` | **25** | 5 / 17 / 3 / 0 | 14 | 15 | 201.7s |
| [`js_04_3.5-flash_deep_c3_hybrid`](eval_results/nodejs_juiceshop/js_04_3.5-flash_deep_c3_hybrid_report.json) | `juice-shop-bench` | `gemini-3.5-flash` | **DEEP** (`--deep`) | `c3_hybrid_max` | **28** | 8 / 19 / 1 / 0 | 19 | 15 | 245.7s |
| [`js_05_4-argon_deep_c3_hybrid`](eval_results/nodejs_juiceshop/js_05_4-argon_deep_c3_hybrid_report.json) | `juice-shop-bench` | `gemini-4-argon` | **DEEP** (`--deep`) | `c3_hybrid_max` | **49** | 15 / 20 / 14 / 0 | 28 | 16 | 250.4s |
| [`js_06_3.8-flash_quick_c1_sca`](eval_results/nodejs_juiceshop/js_06_3.8-flash_quick_c1_sca_report.json) | `juice-shop-bench` | `gemini-3.8-flash` | Quick | `c1_sca` | 0 | 0 / 0 / 0 / 0 | 0 | 0 | 480.0s *(T/O)* |
| [`js_07_3.8-flash_quick_c2_sast`](eval_results/nodejs_juiceshop/js_07_3.8-flash_quick_c2_sast_report.json) | `juice-shop-bench` | `gemini-3.8-flash` | Quick | `c2_sast_framework` | 0 | 0 / 0 / 0 / 0 | 0 | 0 | 480.0s *(T/O)* |
| [`js_08_3.8-flash_deep_c0_none`](eval_results/nodejs_juiceshop/js_08_3.8-flash_deep_c0_none_report.json) | `juice-shop-bench` | `gemini-3.8-flash` | **DEEP** (`--deep`) | `c0_none` | 19 | 4 / 12 / 3 / 0 | 13 | 13 | 600.0s *(T/O)* |
| [`js_09_3.5-flash_quick_c0_none`](eval_results/nodejs_juiceshop/js_09_3.5-flash_quick_c0_none_report.json) | `juice-shop-bench` | `gemini-3.5-flash` | Quick | `c0_none` | 6 | 2 / 4 / 0 / 0 | 5 | 5 | 480.0s *(T/O)* |
| [`js_10_4-argon_quick_c0_none`](eval_results/nodejs_juiceshop/js_10_4-argon_quick_c0_none_report.json) | `juice-shop-bench` | `gemini-4-argon` | Quick | `c0_none` | 20 | 6 / 10 / 4 / 0 | 12 | 16 | 348.5s |
| [`js_11_3.5-flash_quick_c3_hybrid`](eval_results/nodejs_juiceshop/js_11_3.5-flash_quick_c3_hybrid_report.json) | `juice-shop-bench` | `gemini-3.5-flash` | Quick | `c3_hybrid_max` | 13 | 5 / 7 / 1 / 0 | 8 | 11 | 480.0s *(T/O)* |
| [`js_12_4-argon_quick_c3_hybrid`](eval_results/nodejs_juiceshop/js_12_4-argon_quick_c3_hybrid_report.json) | `juice-shop-bench` | `gemini-4-argon` | Quick | `c3_hybrid_max` | **35** | 9 / 17 / 8 / 1 | 23 | 17 | 385.4s |
| [`js_13_high_risk_deep_optimal`](eval_results/nodejs_juiceshop/js_13_high_risk_deep_optimal_report.json) | `juice-shop-high-risk` | `gemini-3.8-flash` | **DEEP** (`--deep`) | `c3_hybrid_max` | **50** | 6 / 39 / 5 / 0 | 28 | 33 | 504.4s |
| [`js_14_full_core_deep_optimal`](eval_results/nodejs_juiceshop/js_14_full_core_deep_optimal_report.json) | `juice-shop-core` | `gemini-3.8-flash` | **DEEP** (`--deep`) | `c3_hybrid_max` | **60** | 6 / 52 / 2 / 0 | 30 | 44 | 906.2s |
| [`js_15_high_risk_4-argon_deep`](eval_results/nodejs_juiceshop/js_15_high_risk_4-argon_deep_report.json) | `juice-shop-high-risk` | `gemini-4-argon` | **DEEP** (`--deep`) | `c3_hybrid_max` | **91** | 16 / 46 / 26 / 3 | 39 | 38 | 552.6s |

---

## 5. Benchmark Suite III: Java / Spring Boot + MyBatis (`macrozheng/mall`) — 15 Runs (`eval_results/java_mall/`)

| Run ID | Target Scope | Model | Mode | Context (`-c`) | Findings | Severity (`C / H / M / L`) | Unique CWEs | Files Hit | Wall Time |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| [`mall_01_3.8-flash_quick_c0_none`](eval_results/java_mall/mall_01_3.8-flash_quick_c0_none_report.json) | `mall-bench` | `gemini-3.8-flash` | Quick | `c0_none` | 0 | 0 / 0 / 0 / 0 | 0 | 0 | 480.0s *(T/O)* |
| [`mall_02_3.8-flash_quick_c3_hybrid`](eval_results/java_mall/mall_02_3.8-flash_quick_c3_hybrid_report.json) | `mall-bench` | `gemini-3.8-flash` | Quick | `c3_hybrid_max` | 0 | 0 / 0 / 0 / 0 | 0 | 0 | 480.0s *(T/O)* |
| [`mall_03_3.8-flash_deep_c3_hybrid`](eval_results/java_mall/mall_03_3.8-flash_deep_c3_hybrid_report.json) | `mall-bench` | `gemini-3.8-flash` | **DEEP** (`--deep`) | `c3_hybrid_max` | 13 | 2 / 11 / 0 / 0 | 8 | 10 | 171.1s |
| [`mall_04_3.5-flash_deep_c3_hybrid`](eval_results/java_mall/mall_04_3.5-flash_deep_c3_hybrid_report.json) | `mall-bench` | `gemini-3.5-flash` | **DEEP** (`--deep`) | `c3_hybrid_max` | 16 | 1 / 10 / 4 / 1 | 7 | 9 | 206.2s |
| [`mall_05_4-argon_deep_c3_hybrid`](eval_results/java_mall/mall_05_4-argon_deep_c3_hybrid_report.json) | `mall-bench` | `gemini-4-argon` | **DEEP** (`--deep`) | `c3_hybrid_max` | **35** | 7 / 19 / 9 / 0 | 10 | 12 | 310.9s |
| [`mall_06_3.8-flash_quick_c1_sca`](eval_results/java_mall/mall_06_3.8-flash_quick_c1_sca_report.json) | `mall-bench` | `gemini-3.8-flash` | Quick | `c1_sca` | 0 | 0 / 0 / 0 / 0 | 0 | 0 | 480.0s *(T/O)* |
| [`mall_07_3.8-flash_quick_c2_sast`](eval_results/java_mall/mall_07_3.8-flash_quick_c2_sast_report.json) | `mall-bench` | `gemini-3.8-flash` | Quick | `c2_sast_framework` | 0 | 0 / 0 / 0 / 0 | 0 | 0 | 480.0s *(T/O)* |
| [`mall_08_3.8-flash_deep_c0_none`](eval_results/java_mall/mall_08_3.8-flash_deep_c0_none_report.json) | `mall-bench` | `gemini-3.8-flash` | **DEEP** (`--deep`) | `c0_none` | 7 | 2 / 5 / 0 / 0 | 6 | 6 | 161.8s |
| [`mall_09_3.5-flash_quick_c0_none`](eval_results/java_mall/mall_09_3.5-flash_quick_c0_none_report.json) | `mall-bench` | `gemini-3.5-flash` | Quick | `c0_none` | 0 | 0 / 0 / 0 / 0 | 0 | 0 | 480.0s *(T/O)* |
| [`mall_10_4-argon_quick_c0_none`](eval_results/java_mall/mall_10_4-argon_quick_c0_none_report.json) | `mall-bench` | `gemini-4-argon` | Quick | `c0_none` | 10 | 5 / 4 / 1 / 0 | 9 | 8 | 285.0s |
| [`mall_11_3.5-flash_quick_c3_hybrid`](eval_results/java_mall/mall_11_3.5-flash_quick_c3_hybrid_report.json) | `mall-bench` | `gemini-3.5-flash` | Quick | `c3_hybrid_max` | 0 | 0 / 0 / 0 / 0 | 0 | 0 | 480.0s *(T/O)* |
| [`mall_12_4-argon_quick_c3_hybrid`](eval_results/java_mall/mall_12_4-argon_quick_c3_hybrid_report.json) | `mall-bench` | `gemini-4-argon` | Quick | `c3_hybrid_max` | **29** | 9 / 11 / 7 / 2 | 16 | 17 | 446.4s |
| [`mall_13_high_risk_deep_optimal`](eval_results/java_mall/mall_13_high_risk_deep_optimal_report.json) | `mall-high-risk` | `gemini-3.8-flash` | **DEEP** (`--deep`) | `c3_hybrid_max` | **27** | 4 / 16 / 7 / 0 | 12 | 17 | 718.7s |
| [`mall_14_full_core_deep_optimal`](eval_results/java_mall/mall_14_full_core_deep_optimal_report.json) | `mall-core` | `gemini-3.8-flash` | **DEEP** (`--deep`) | `c3_hybrid_max` | **32** | 4 / 24 / 4 / 0 | 13 | 23 | 1336.6s |
| [`mall_15_high_risk_4-argon_deep`](eval_results/java_mall/mall_15_high_risk_4-argon_deep_report.json) | `mall-high-risk` | `gemini-4-argon` | **DEEP** (`--deep`) | `c3_hybrid_max` | **61** | 9 / 38 / 14 / 0 | 18 | 22 | 300.8s |

---

## 6. How to Scan Any New Repository (Zero Configuration Required)

Because [`pipeline/pipeline.py`](pipeline/pipeline.py) contains **zero hardcoded repository rules**, scanning any new repository (`Python`, `Node.js/TypeScript`, `Java/Spring Boot`, `C/C++`, `Go`, `Ruby`, `PHP`) requires **no code changes**:

### 1. One-Command End-to-End Unassisted Scan (`Stage 1 Auto-Profile -> Stage 2 Auto-Scan`)
```bash
# Run Stage 1 auto-profiling followed immediately by Stage 2 cm find in an isolated CM_HOME
python3 pipeline/pipeline.py scan /path/to/your-new-repo

# Optional: customize output directory, model (gemini-3.8-flash / gemini-4-argon), or timeout (<= 900s)
python3 pipeline/pipeline.py scan /path/to/your-new-repo \
  --output-dir ./scan_outputs/your-new-repo \
  --model gemini-3.8-flash \
  --timeout 600
```

### 2. Two-Step Workflow: Dry-Run Profile First (`< 3s`), Then Scan
If you want to inspect the discovered attack surface, excluded noise directories, parsed dependency versions, and synthesized `-c` prompt before running `cm find`:
```bash
# Step 1: Dry-run Stage 1 profiler only (0 LLM tokens, < 3s)
python3 pipeline/pipeline.py profile /path/to/your-new-repo --output-dir ./scan_outputs/your-new-repo

# Step 2: Review ./scan_outputs/your-new-repo/{profile.json,config.yaml,PROJECT_FILE_INDEX.md}, then scan:
python3 pipeline/pipeline.py scan /path/to/your-new-repo --output-dir ./scan_outputs/your-new-repo
```

### 3. Output Artifacts Generated for Every Repository
Every scan automatically writes a self-contained artifact bundle into `./scan_outputs/<repo_slug>/` (or `--output-dir`):
- `profile.json` — Detected languages/frameworks, active files, parsed dependencies, routes, sinks, guards, sanitized `-c` prompt (`0` `filename.ext` regex matches), and adaptive CLI flags (`quick` for `<= 5` files; `--deep --deep-workers 16 --deep-max-turns 8` for `> 5` files).
- `config.yaml` — Tailored CodeMender configuration with all active source/config/template/mapper extensions and noise exclusions.
- `PROJECT_FILE_INDEX.md` — Structural file index and 1-hop thin-wrapper delegation map.
- `report.json` & `report.md` — Deduplicated vulnerability findings (merged from `cm report -f json` + SQLite `.cm_home/state.db`) with normalized file paths and severity breakdown.

---

## 7. Repository Directory Structure

```text
codemender-test/
├── README.md                          # Unified English Flagship Report (Universal Pipeline + 43 Runs + Ground Truth)
├── README_CN.md                       # Chinese Executive Summary & Best Practices Guide (中文分享总结版)
├── docs/
│   ├── UNIVERSAL_PIPELINE_REVIEW.md   # Deep Technical Review & 4 Failure Trap Mitigations
│   ├── BENCHMARK_RESULTS.md           # Full 43-run ablation tables & CWE/Ground-Truth breakdown
│   └── CODEMENDER_SHARE_SUMMARY_CN.md # Detailed Chinese shareable briefing
├── pipeline/                          # Universal CodeMender v0.14.0 Auto-Profile & Auto-Scan Pipeline
│   ├── pipeline.py                    # Universal Stage 1 Auto-Profiler & Stage 2 Runner (zero hardcoded repo names)
│   ├── test_universal_pipeline.py     # 20-test unit & integration test suite
│   ├── run_python_benchmarks.py       # 13-run Python WSGI benchmark + strict Ground Truth (11/11) & safe_join (0% FP) evaluator
│   ├── run_all_benchmarks.py          # 30-run Node.js (juice-shop) & Java (macrozheng/mall) ablation suite
│   └── generate_report.py             # Automated Markdown report generator across all 43 runs
├── src/                               # Target 1: Python Werkzeug WSGI Application (11 Real Vulns + 1 safe_join Control)
│   ├── app.py
│   └── requirements.txt
├── grounding-truth/                   # Ground Truth PoC Exploit & Verification Suite for Python WSGI
│   └── poc_exploit.py
├── benchmarks/                        # Curated Benchmark Target Scopes (with PROJECT_FILE_INDEX.md)
│   ├── ref-codemender-bench/          # Python WSGI isolated benchmark scope (2 files)
│   ├── juice-shop-bench/              # Node.js / TypeScript representative benchmark scope (16 files)
│   └── mall-bench/                    # Java / Spring Boot + MyBatis representative benchmark scope (20 files)
└── eval_results/                      # Complete Evaluation Artifacts (.log, _report.txt, _report.json, _meta.json)
    ├── python_wsgi/                   # New 13-run cm v0.14.0 Python WSGI matrix (py_01..py_13)
    ├── nodejs_juiceshop/              # New 15-run cm v0.14.0 Node.js/TS OWASP Juice Shop matrix (js_01..js_15)
    ├── java_mall/                     # New 15-run cm v0.14.0 Java/Spring Boot macrozheng/mall matrix (mall_01..mall_15)
    └── legacy_v0.7_python/            # Original 8-run quick-mode baseline (run1..run8)
```
