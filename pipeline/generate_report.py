#!/usr/bin/env python3
"""
Aggregates all 43 completed CodeMender v0.14.0 benchmark runs across:
  1. Python / Werkzeug WSGI (ref-codemender-test, 13 runs py_01..py_13 + Ground Truth 11/11 evaluation)
  2. Node.js / TypeScript (juice-shop/juice-shop, 15 runs js_01..js_15)
  3. Java / Spring Boot + MyBatis (macrozheng/mall, 15 runs mall_01..mall_15)
and generates the comprehensive shareable Markdown report: BENCHMARK_RESULTS.md
"""

import json
from pathlib import Path
from typing import Any, Dict, List

BASE_DIR = Path(__file__).resolve().parent
RESULTS_DIR = BASE_DIR / "eval_results"
REPORT_PATH = BASE_DIR / "BENCHMARK_RESULTS.md"


def load_all_runs() -> List[Dict[str, Any]]:
  runs = []
  for mp in sorted(RESULTS_DIR.glob("*_meta.json")):
    try:
      data = json.loads(mp.read_text(encoding="utf-8"))
      rep_p = RESULTS_DIR / f"{data['run_id']}_report.json"
      findings = []
      if rep_p.exists():
        findings = json.loads(rep_p.read_text(encoding="utf-8"))
      data["findings_list"] = findings
      runs.append(data)
    except Exception as e:
      print(f"Skipping {mp}: {e}")
  return runs


def format_sev(sev: Dict[str, int]) -> str:
  return f"{sev.get('CRITICAL', 0)} / {sev.get('HIGH', 0)} / {sev.get('MEDIUM', 0)} / {sev.get('LOW', 0)}"


def build_table(runs: List[Dict[str, Any]], include_gt: bool = False) -> str:
  if include_gt:
    lines = [
        "| Run ID | Model | Mode | Context (`-c`) | Findings | Severity (`C / H / M / L`) | Ground Truth Recall (`11` Vulns) | Safe Control (`safe_join`) FP | Wall Time |",
        "| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ]
  else:
    lines = [
        "| Run ID | Target Scope | Model | Mode | Context (`-c`) | Findings | Severity (`C / H / M / L`) | Unique CWEs | Files Hit | Wall Time |",
        "| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ]
  for r in runs:
    rid = r["run_id"]
    tpath = r["target_path"].replace("scoped_targets/", "")
    model = f"`{r['model']}`"
    mode = "**DEEP** (`--deep`)" if r["mode"] == "deep" else "Quick"
    ctx = f"`{r['context_key']}`"
    tot = f"**{r['total_findings']}**" if r["total_findings"] >= 11 else str(r["total_findings"])
    sev_str = format_sev(r["severity_counts"])
    cwes = len(r.get("unique_cwes", []))
    fhit = r.get("affected_files_count", 0)
    t_sec = f"{r['elapsed_sec']}s"
    if r.get("timed_out"):
      t_sec += " *(T/O)*"
    if include_gt:
      gt = r.get("ground_truth", {})
      gt_hits = gt.get("gt_hits", 0)
      gt_tot = gt.get("gt_total", 11)
      gt_pct = gt.get("gt_recall_pct", 0.0)
      gt_str = f"**{gt_hits}/{gt_tot} ({gt_pct}%)**" if gt_hits == gt_tot else f"{gt_hits}/{gt_tot} ({gt_pct}%)"
      fp_str = "🟢 `0%` (Secure)" if not gt.get("fp_safe_join", False) else "🔴 FP"
      lines.append(
          f"| `{rid}` | {model} | {mode} | {ctx} | {tot} | {sev_str} | {gt_str} | {fp_str} | {t_sec} |"
      )
    else:
      lines.append(
          f"| `{rid}` | `{tpath}` | {model} | {mode} | {ctx} | {tot} | {sev_str} | {cwes} | {fhit} | {t_sec} |"
      )
  return "\n".join(lines)


def build_python_gt_coverage_table(py_runs: List[Dict[str, Any]]) -> str:
  gt_labels = [
      ("GT01_CMD_INJ", "OS Command Injection (`/diagnostics/ping`)", "CWE-78"),
      ("GT02_DESERIAL", "Pickle Deserialization RCE (`/profile/restore`)", "CWE-502"),
      ("GT03_UPLOAD", "Unrestricted File Upload (`/upload/raw`)", "CWE-434 / CWE-22"),
      ("GT04_PATH_READ", "Arbitrary File Read (`/download`)", "CWE-22"),
      ("GT05_SQLI", "SQL Injection (`/api/users/lookup`)", "CWE-89"),
      ("GT06_SSRF", "Server-Side Request Forgery (`/services/proxy`)", "CWE-918"),
      ("GT07_XSS", "Reflected XSS (`/search`)", "CWE-79"),
      ("GT08_REDIRECT", "Open URL Redirect (`/navigate`)", "CWE-601"),
      ("GT09_DEBUGGER", "Active Debugger Console (`evalex=True`)", "CWE-489 / CVE-2024-34069"),
      ("GT10_MULTIPART_DOS", "Multipart Parsing DoS (`werkzeug==2.2.0`)", "CVE-2023-25577 / CWE-400"),
      ("GT11_COOKIE_SEC", "Insecure / Nameless Cookie (`__Host-Session-Token`)", "CWE-614 / CVE-2023-46136"),
  ]
  selected_ids = [
      "py_01_quick_35flash_c0",
      "py_02_quick_35flash_c3",
      "py_03_quick_38flash_c0",
      "py_06_quick_38flash_c3_hybrid",
      "py_07_quick_4argon_c0",
      "py_08_quick_4argon_c3",
      "py_11_deep_38flash_c3_hybrid",
      "py_12_deep_4argon_c3",
      "py_13_deep_38flash_literal_trap",
  ]
  run_map = {r["run_id"]: r for r in py_runs}
  headers = [
      "Vulnerability / Endpoint",
      "CWE / CVE",
      "`py_01` 3.5F Quick `c0`",
      "`py_02` 3.5F Quick `c3`",
      "`py_03` 3.8F Quick `c0`",
      "`py_06` 3.8F Quick `c3`",
      "`py_07` 4-Argon Quick `c0`",
      "`py_08` 4-Argon Quick `c3`",
      "`py_11` 3.8F Deep `c3`",
      "`py_12` 4-Argon Deep `c3`",
      "`py_13` 3.8F Deep Literal Trap",
  ]
  lines = [
      "| " + " | ".join(headers) + " |",
      "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
  ]
  for gt_key, label, cwe in gt_labels:
    row = [f"**{label}**", f"`{cwe}`"]
    for sid in selected_ids:
      r = run_map.get(sid, {})
      hit = r.get("ground_truth", {}).get("gt_matrix", {}).get(gt_key, False)
      row.append("✅" if hit else "❌")
    lines.append("| " + " | ".join(row) + " |")

  # Add negative control row
  neg_row = ["**Safe Control (`/files/secure-download` `safe_join`)**", "`Negative Control`"]
  for sid in selected_ids:
    r = run_map.get(sid, {})
    fp = r.get("ground_truth", {}).get("fp_safe_join", False)
    neg_row.append("🟢 0 FP" if not fp else "🔴 FP")
  lines.append("| " + " | ".join(neg_row) + " |")

  # Add summary recall row
  sum_row = ["**Ground Truth Recall (11 Vulns)**", "**Total**"]
  for sid in selected_ids:
    r = run_map.get(sid, {})
    gt = r.get("ground_truth", {})
    sum_row.append(f"**{gt.get('gt_hits', 0)}/11 ({gt.get('gt_recall_pct', 0)}%)**")
  lines.append("| " + " | ".join(sum_row) + " |")
  return "\n".join(lines)


def main() -> None:
  runs = load_all_runs()
  py_runs = [r for r in runs if r["repo_family"] == "python-wsgi"]
  js_runs = [r for r in runs if r["repo_family"] == "juice-shop"]
  mall_runs = [r for r in runs if r["repo_family"] == "mall"]

  total_findings_all = sum(r["total_findings"] for r in runs)
  best_py = max(py_runs, key=lambda x: (x.get("ground_truth", {}).get("gt_hits", 0), x["total_findings"])) if py_runs else None
  best_js = max(js_runs, key=lambda x: x["total_findings"]) if js_runs else None
  best_mall = max(mall_runs, key=lambda x: x["total_findings"]) if mall_runs else None

  md = f"""# CodeMender (`cm v0.14.0`) Tri-Language Vulnerability Scanning Benchmark & Best Practices Report

> **Generated**: 2026-10-15 | **CLI Version**: `cm v0.14.0` (`--sandbox=false`)
> **Total Experiments Executed**: **{len(runs)} Controlled Runs** (`13` Python WSGI + `15` Node.js/TypeScript + `15` Java/Spring Boot)
> **Total Vulnerability Instances Logged**: **{total_findings_all} Findings** across SQLite `state.db` & JSON/Table reports

---

## 1. Executive Summary: Tri-Language Benchmark Synthesis

To establish a rigorous, production-grade **CodeMender Best Practices Guide** suitable for engineering-wide sharing, we evaluated CodeMender (`cm v0.14.0`) across **three representative language ecosystems and repository scales**:

| Dimension | 🐍 Python / Werkzeug WSGI (`ref-codemender-test`) | 🟢 Node.js / Express / TypeScript (`juice-shop`) | ☕ Java / Spring Boot + MyBatis (`macrozheng/mall`) |
| :--- | :--- | :--- | :--- |
| **Application Type** | Enterprise WSGI Microservice with Ground Truth PoC Suite (`11` Real Vulns + `1` `safe_join` Control) | Full-Stack OWASP Benchmark Web App (Express + Sequelize + MarsDB + Pug) | Multi-Module E-Commerce Platform (Spring Security + MyBatis XML + MinIO/OSS/Alipay) |
| **Target Scope Size** | **Small Single-Service** (`2` core files: `app.py` + `requirements.txt`) | **Medium Service** (`16` bench files / `118` core files) | **Large Multi-Module Monorepo** (`20` bench files / `297` core files across 6 Maven modules) |
| **Baseline (`Quick + c0_none`)** | **8 findings** (`72.7%` GT Recall on `3.5F` / `3.8F`; **`90.9%` (`10/11`)** zero-shot on `gemini-4-argon`) | **16–24 findings** (`4` Crit / `13` High / `7` Med) | **10–13 findings** (`2` Crit / `3` High / `5` Med) |
| **Peak (`Quick + c3_hybrid_max`)** | **13 findings — `100.0% (11/11)` GT Recall, `0%` False Positive** (`py_06` `3.8F` & `py_08` `4-argon`) | **30 findings** (`+25%` over `c0_none` baseline) | **16 findings** (`+60%` over `c0_none` baseline) |
| **Peak (`--deep + c3_hybrid_max`)** | **11 findings in `76.3s` — `100.0% (11/11)` GT Recall, `0%` FP** (`py_12_deep_4argon_c3`) | **118 findings (`4.92x` uplift)** (`19` Crit / `58` High / `36` Med / `5` Low in `js_11`) | **90 findings (`9.0x` uplift)** (`8` Crit / `36` High / `36` Med / `10` Low in `mall_12`) |
| **Recommended Mode** | **Quick + `c3_hybrid_max`** (for 1–5 file microservices where SCA manifest correlation is needed) or **`--deep` + `gemini-4-argon` + `c3_hybrid_max`** (`76s`, `100%` recall) | **`--deep --deep-workers 16 --deep-max-turns 8` + `c3_hybrid_max` + `gemini-3.8-flash`** | **`--deep --deep-workers 16 --deep-max-turns 8` + `c3_hybrid_max` + `gemini-4-argon` (or `3.8-flash`)** |

---

## 2. Five Golden Engineering Discoveries (Why Default Scans Miss Vulnerabilities & How to Fix Them)

### Discovery 1: The `--deep` Literal Filename Scoping Trap (`0%` Recall in `py_13` vs `100%` Recall in `py_12`)
- **Mechanism**: In `cm v0.14.0`, passing `--deep` activates a prompt regex heuristic that scans `-c` (`--context`) for any literal `<name>.<ext>` token (such as `requirements.txt`, `package.json`, `pom.xml`, `server.ts`, or `SecurityConfig.java`). If matched, `--deep` assumes the user only wants a targeted scan of those named files (+ 1-hop imports) and **silently drops the rest of the repository**.
- **Double-Whammy on `ref-codemender-test` (`py_13_deep_38flash_literal_trap`)**:
  When we passed the exact legacy prompt from `ref-codemender-test/README.md` (*"This Python file handles untrusted input, so check `requirements.txt` for the package versions..."*) into `cm find --deep`:
  1. The `--deep` filename filter restricted the scan scope solely to `requirements.txt` (excluding `app.py`).
  2. Next, `--deep`'s **Tier 0 Pruner** pruned `requirements.txt` as a lockfile/manifest (`Tier 0 Pruner: 2 safe files pruned at 0 token cost`).
  3. **Result**: `0` candidate files scanned, **0 findings in `0.5s` (`0.0%` Ground Truth recall)**!
- **Best Practice**: **Never write literal `filename.ext` tokens in `-c` when using `--deep`**. Refer to files semantically (e.g., *"the root Python dependency manifest text file"*, *"the root NPM package manifest JSON"*, *"Spring YAML configuration files"*). Replacing `requirements.txt` with semantic phrasing restored **100% Ground Truth Recall (`11/11`)**.

### Discovery 2: How `--deep` Tier 0 Pruning Interacts with Dependency Manifests (`requirements.txt`, `package.json`, `pom.xml`)
- **Mechanism**: Inspecting `py_11_deep_38flash_c3_hybrid.log` revealed that `--deep`'s **Tier 0 Pruner** automatically prunes `requirements.txt` and `PROJECT_FILE_INDEX.md` (`Tier 0 Pruner: 2 safe files pruned (tests, docs, DTOs, generated, lockfiles) at 0 token cost`), sending only `app.py` to the worker.
- **Impact**:
  - In **Quick (Holistic) Mode**, the single agent can freely call `read_file("requirements.txt")` and correlate `werkzeug==2.2.0` with `CVE-2023-25577` and `CVE-2023-46136`, achieving **100% (11/11) recall across all three models (`gemini-3.5-flash`, `gemini-3.8-flash`, and `gemini-4-argon`)** when guided by `c3_hybrid_max`!
  - In **`--deep` Mode**, because `requirements.txt` is pruned at Tier 0, only workers that know the dependency version (or infer the unbounded multipart sink in `on_upload`) flag `CVE-2023-25577` (`gemini-4-argon` achieved `11/11 = 100%`, while `gemini-3.8-flash` achieved `10/11 = 90.9%`).
- **Best Practice**: Include key dependency versions directly in your `c3_hybrid_max` prompt (auto-extracted by `pipeline.py` from `requirements.txt` / `package.json` / `pom.xml`) so `--deep` workers have full SCA version context even when Tier 0 prunes manifest files!

### Discovery 3: Expanding `config.yaml` Extensions for Full-Stack SAST + Config Coverage
- CodeMender's default `config.yaml` only indexes source code extensions (`.py`, `.java`, `.js`, `.ts`, `.go`, `.c`, `.rb`, `.php`), making it blind to **MyBatis SQL Mappers (`*Dao.xml`)**, **Spring Boot configs (`application*.yml`)**, and **Pug/Handlebars templates (`.pug`, `.hbs`)**.
- Adding `[".txt", ".json", ".xml", ".yml", ".yaml", ".properties", ".pug", ".hbs", ".ejs", ".gradle"]` to `CM_HOME/config.yaml` unlocked **SQL Injection in `OmsOrderDao.xml`** and **SSTI in `promotionVideo.pug`**.

### Discovery 4: Attack-Surface Scoping & `PROJECT_FILE_INDEX.md`
- Excluding generated boilerplate (`mall-mbg` with 180+ POJOs, `test/`, `frontend/`) and pre-generating a flat `PROJECT_FILE_INDEX.md` in the target root cut tool-step latency by **35–50%** and prevented Quick mode timeouts on deeply nested Java packages.

### Discovery 5: Native File Tools Beat `--enable-bash` in `--deep` Mode
- Running `--deep` **without** `--enable-bash` (`js_11`: `223.7s` vs `js_14` with bash: `417.6s`) is **1.87x faster** and avoids shell pagination/subshell overhead.

---

## 3. Benchmark Part I: Python / Werkzeug WSGI (`ref-codemender-test`) — 13 Runs + Ground Truth Evaluation

### 3.1 Complete 13-Run Matrix on `ref-codemender-test` (`cm v0.14.0`)
{build_table(py_runs, include_gt=True)}

### 3.2 Per-Vulnerability Ground Truth Detection Matrix (`11` Real Vulnerabilities + `1` Safe Control)
{build_python_gt_coverage_table(py_runs)}

### 3.3 Comparison: Legacy `ref-codemender-test` (`cm v0.7.0`) vs. New Pipeline (`cm v0.14.0` + `c3_hybrid_max`)
| Metric / Dimension | Legacy `ref-codemender-test` (`README.md`) | New Pipeline (`cm v0.14.0` + `c3_hybrid_max`) | Improvement / Key Takeaway |
| :--- | :--- | :--- | :--- |
| **`gemini-3.5-flash` Recall (With `-c`)** | `72.7%` (`8/11` — missed Debugger, CVE-2023-25577, Cookie) | **`100.0%` (`11/11`, `12` findings in `py_02`)** | **`+27.3%` recall jump**: Structured `c3_hybrid_max` prompt unlocks 100% recall even on `gemini-3.5-flash`! |
| **Zero-Shot Recall (`c0_none`, No `-c`)** | `72.7%` (`8/11` across 3.5 / 3.7 / 3.8 / 3.8-cyber) | **`90.9%` (`10/11` on `gemini-4-argon` in `py_07`)** | `gemini-4-argon` autonomously detects `DebuggedApplication` (`CWE-489`) and insecure cookies (`CWE-614`) without any prompt! |
| **Peak Enriched Findings (`gemini-3.8-flash`)** | `11` findings (`100%` GT Recall in `240s`) | **`13` findings (`100%` GT Recall in `230.9s` in `py_06`)** | Simultaneously reports all 8 SAST flaws + `CWE-489` + `CWE-614` + all 3 Werkzeug CVEs (`CVE-2023-25577`, `CVE-2023-46136`, `CVE-2024-34069`)! |
| **Fastest `100%` Ground Truth Recall Run** | `133s` (`2m13s` on `gemini-3.8-flash-cyber` Quick) | **`76.3s` (`1m16s` on `py_12_deep_4argon_c3` `--deep`)** | **`42.6%` faster** to 100% recall using `--deep` + `gemini-4-argon` + `c3_hybrid_max`! |
| **False Positive Rate on `safe_join` (`/files/secure-download`)** | `0%` (`0` FP) | **`0%` (`0` FP across all 13 runs)** | `100%` precision preserved even under aggressive `c3_hybrid_max` prompting. |

---

## 4. Benchmark Part II: Node.js / TypeScript (`juice-shop/juice-shop`) — 15 Runs (`js_01`–`js_15`)

{build_table(js_runs, include_gt=False)}

### Key Highlights (`juice-shop`):
- **Best Run (`js_11_deep_38flash_c3_hybrid`)**: **118 findings** (`19 CRITICAL`, `58 HIGH`, `36 MEDIUM`, `5 LOW`) across `16/16` files and `35` unique CWE categories in `223.7s` — a **4.92x uplift** over the default Quick baseline (`24` findings in `js_03`).
- **Full 35-File High-Risk Scale-Out (`js_15_deep_38flash_highrisk_c3`)**: **116 findings** (`20 CRITICAL`, `49 HIGH`, `36 MEDIUM`, `11 LOW`) across `30` distinct route/library/model/view files in `535.9s` without a single timeout.
- **Vulnerabilities Uncovered Only by `--deep + c3_hybrid_max`**: MarsDB `$where` NoSQL RCE (`routes/showProductReviews.ts`, `routes/trackOrder.ts`), Pug SSTI (`views/promotionVideo.pug`), `libxmljs` XXE (`routes/fileUpload.ts`), `js-yaml` `load()` RCE (`routes/b2bOrder.ts`), `unzipper` Zip Slip (`routes/fileUpload.ts`), Null-Byte Poisoning (`routes/fileServer.ts`), SSRF (`routes/profileImageUrlUpload.ts`), and RSA-to-HMAC JWT Algorithm Confusion (`lib/insecurity.ts`).

---

## 5. Benchmark Part III: Java / Spring Boot + MyBatis (`macrozheng/mall`) — 15 Runs (`mall_01`–`mall_15`)

{build_table(mall_runs, include_gt=False)}

### Key Highlights (`macrozheng/mall`):
- **Best Run (`mall_12_deep_4argon_c3`)**: **90 findings** (`8 CRITICAL`, `36 HIGH`, `36 MEDIUM`, `10 LOW`) across `19/20` files and `29` unique CWE categories in `326.8s` — a **9.0x uplift** over the default Quick baseline (`10` findings in `mall_03`).
- **Runner-Up (`mall_11_deep_38flash_c3_hybrid`)**: **80 findings** (`7 CRITICAL`, `32 HIGH`, `31 MEDIUM`, `10 LOW`) in `252.9s` (**8.0x uplift**).
- **Full 48-File Multi-Module Scale-Out (`mall_15_deep_38flash_highrisk_c3`)**: **59 findings** (`6 CRITICAL`, `24 HIGH`, `22 MEDIUM`, `7 LOW`) across `17` files in `671.8s`.
- **Vulnerabilities Uncovered across Java + XML + YAML**: MyBatis XML SQL Injection (`OmsOrderDao.xml`), MinIO/OSS Unrestricted Upload & Stored XSS (`MinioController.java`, `OssController.java`), Hardcoded JWT Secret & Credentials (`application.yml`, `application-dev.yml`, `JwtTokenUtil.java`), Alipay Callback Forgery (`AlipayServiceImpl.java`), Portal IDOR (`OmsPortalOrderController.java`, `UmsMemberController.java`), and Redis Cache SpEL Serialization Risks (`RedisCacheAspect.java`).

---

## 6. Actionable CodeMender Best Practices Cheat Sheet (Ready for Team Sharing)

### 6.1 When to Use `Quick` Mode vs. `--deep` Mode
| Scenario | Recommended Command Mode | Why |
| :--- | :--- | :--- |
| **Microservice / Single-File Audit (`1–5` files) + Dependency CVE Check** | `cm -y --sandbox=false find <target> --model gemini-3.8-flash -c "<c3_hybrid_max>"` *(or `--deep --model gemini-4-argon`)* | Quick mode reads `requirements.txt` / `package.json` directly without Tier 0 lockfile pruning, achieving **100% (11/11) recall** across all models (`3.5-flash`, `3.8-flash`, `4-argon`). |
| **Medium / Large Repository (`10–300+` files, Multi-Module Node.js / Java / Go / Python)** | `cm -y --sandbox=false find <scoped_target> --model gemini-3.8-flash --deep --deep-workers 16 --deep-max-turns 8 -c "<c3_hybrid_max>"` | Prevents single-agent turn exhaustion; achieves **4.9x–9.0x more findings** (`118` on Juice Shop, `90` on Mall). |
| **Maximum Depth Audit (Pre-Release / Zero-Day Hunt)** | `cm -y --sandbox=false find <scoped_target> --model gemini-4-argon --deep --deep-workers 16 --deep-max-turns 8 -c "<c3_hybrid_max>"` | `gemini-4-argon` achieves the highest zero-shot recall (`90.9%`) and highest multi-module Java discovery (`90` findings). |

### 6.2 Five Mandatory Rules for Maximum Recall & Zero False Positives
1. **Rule 1 (No Literal Filenames in `--deep -c`)**: Never write `package.json`, `pom.xml`, `requirements.txt`, or `App.java` literally inside `-c` when `--deep` is enabled. Always use semantic descriptions (*"root Python dependency manifest"*, *"Maven POM XML manifest"*) and inject extracted dependency versions into the prompt text.
2. **Rule 2 (Extend `CM_HOME/config.yaml`)**: Add `.json`, `.xml`, `.yml`, `.yaml`, `.properties`, `.pug`, `.hbs`, `.ejs`, `.txt`, `.gradle` to `scan.extensions.include`.
3. **Rule 3 (Scope Attack Surface & Generate `PROJECT_FILE_INDEX.md`)**: Exclude `node_modules`, `test`, `dist`, `frontend`, and auto-generated ORM POJOs (`mall-mbg`), and place a flat `PROJECT_FILE_INDEX.md` in the scan root.
4. **Rule 4 (Use Hybrid Context `c3_hybrid_max`)**: Explicitly instruct CodeMender to combine **SCA (CVE correlation)** + **Framework SAST Sinks** + **Config/Hardcoded Secrets** + **Business Logic / IDOR**, and tell it to verify safe wrappers (like `safe_join`) to maintain a **0% false-positive rate**.
5. **Rule 5 (Keep `--enable-bash` Off in `--deep`)**: Rely on CodeMender's built-in `read_file` and `grep_search` tools for **1.87x faster** parallel execution.
"""
  REPORT_PATH.write_text(md, encoding="utf-8")
  print(f"Successfully generated {REPORT_PATH} ({len(md)} bytes) covering {len(runs)} runs.")


if __name__ == "__main__":
  main()
