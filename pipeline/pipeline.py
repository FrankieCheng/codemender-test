#!/usr/bin/env python3
"""
Universal CodeMender Security Scanning & Benchmarking Pipeline
Supports Node.js/TypeScript (e.g., OWASP Juice Shop) and Java/Spring Boot (e.g., macrozheng/mall).

Key Features:
1. Language-aware config.yaml generation (adds .json, .xml, .yml, .yaml, .properties, .pug, .hbs, .gradle
   so CodeMender can inspect package.json, pom.xml, MyBatis *Dao.xml, application.yml, and templates).
2. Intelligent Attack Surface Scoping (filters out unit tests,frontend spec files, codefixes challenge
   archives, and MyBatis Generator boilerplate POJOs so --deep focuses on high-value code).
3. Automated Context Engineering (-c) Generator:
   - c0_none: Baseline (no context)
   - c1_sca: Dependency & CVE correlation (auto-extracts dependencies from package.json / pom.xml)
   - c2_framework: Framework-specific SAST sinks (Express/Sequelize/Pug/JWT vs Spring/MyBatis/MinIO/OSS/Alipay)
   - c3_hybrid_max: Combined SCA + SAST + Config/Secrets + Business Logic exhaustive prompt
4. Supports both Holistic Scan (`cm find`) and Specialist-recommended Deep Scan (`cm find --deep`).
5. Evaluates across models (`gemini-3.5-flash`, `gemini-3.8-flash`, `gemini-4-argon`, `gemini-3.8-flash-cyber`).
6. Automatically collects .log, .txt, .json reports, parses SQLite state.db for rich details, and
   updates the live Markdown benchmark report (`BENCHMARK_RESULTS.md`).
"""

import argparse
import datetime
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

BASE_DIR = Path(__file__).resolve().parent
CM_BIN = BASE_DIR / "bin" / "cm"
RESULTS_DIR = BASE_DIR / "eval_results"
SCOPED_TARGETS_DIR = BASE_DIR / "scoped_targets"
GCP_PROJECT = "cloud-llm-preview1"


def create_cm_config(cm_home: Path, exclude_dirs: List[str]) -> None:
  """Creates an isolated CM_HOME with a language-aware config.yaml."""
  cm_home.mkdir(parents=True, exist_ok=True)
  exclude_list_str = json.dumps(exclude_dirs)
  config_content = f"""# Auto-generated CodeMender Pipeline Config
server: {{}}

scan:
  extensions:
    include: [".py", ".txt", ".java", ".go", ".js", ".ts", ".c", ".cc", ".cpp", ".h", ".rb", ".php", ".json", ".xml", ".yml", ".yaml", ".properties", ".pug", ".hbs", ".ejs", ".gradle"]
    exclude: [".min.js", ".generated.go", ".pb.go", ".spec.ts", ".test.ts", ".unit.test.ts"]
  exclude_dirs: {exclude_list_str}
  max_file_size_kb: 500
  incremental: false

output:
  format: table

tools:
  confirm_commands: false
  confirm_writes: false
"""
  (cm_home / "config.yaml").write_text(config_content, encoding="utf-8")


def prepare_scoped_targets() -> Dict[str, Path]:
  """
  Builds curated/scoped target directories for fast & high-recall --deep scanning
  as well as full-repo targets with intelligent exclusions.
  """
  SCOPED_TARGETS_DIR.mkdir(parents=True, exist_ok=True)

  # 1. Juice Shop Core Attack Surface (Backend routes, lib, models, views, server.ts, package.json, config)
  js_src = BASE_DIR / "targets" / "juice-shop"
  js_scoped = SCOPED_TARGETS_DIR / "juice-shop-core"
  if js_scoped.exists():
    shutil.rmtree(js_scoped)
  js_scoped.mkdir(parents=True, exist_ok=True)

  for item in ["package.json", "server.ts", "app.ts", "tsconfig.json"]:
    src_f = js_src / item
    if src_f.exists():
      shutil.copy2(src_f, js_scoped / item)

  for folder in ["routes", "lib", "models", "views", "config"]:
    src_d = js_src / folder
    if src_d.exists():
      shutil.copytree(src_d, js_scoped / folder)

  # Also create a high-priority routes+lib+models subset for rapid multi-model --deep comparison
  js_high = SCOPED_TARGETS_DIR / "juice-shop-high-risk"
  if js_high.exists():
    shutil.rmtree(js_high)
  js_high.mkdir(parents=True, exist_ok=True)
  for item in ["package.json", "server.ts"]:
    if (js_src / item).exists():
      shutil.copy2(js_src / item, js_high / item)
  (js_high / "routes").mkdir(exist_ok=True)
  (js_high / "lib").mkdir(exist_ok=True)
  (js_high / "models").mkdir(exist_ok=True)
  (js_high / "views").mkdir(exist_ok=True)

  high_risk_routes = [
      "login.ts", "search.ts", "fileUpload.ts", "fileServer.ts", "b2bOrder.ts",
      "profileImageUrlUpload.ts", "profileImageFileUpload.ts", "userProfile.ts",
      "redirect.ts", "updateUserProfile.ts", "showProductReviews.ts",
      "updateProductReviews.ts", "likeProductReviews.ts", "createProductReviews.ts",
      "changePassword.ts", "resetPassword.ts", "2fa.ts", "basket.ts",
      "basketItems.ts", "order.ts", "trackOrder.ts", "dataErasure.ts",
      "dataExport.ts", "videoHandler.ts", "logfileServer.ts", "keyServer.ts",
      "quarantineServer.ts", "easterEgg.ts", "payment.ts", "wallet.ts",
      "deluxe.ts", "coupon.ts", "captcha.ts", "imageCaptcha.ts", "verify.ts"
  ]
  for r in high_risk_routes:
    if (js_src / "routes" / r).exists():
      shutil.copy2(js_src / "routes" / r, js_high / "routes" / r)
  for l in ["insecurity.ts", "utils.ts", "webhook.ts", "botUtils.ts"]:
    if (js_src / "lib" / l).exists():
      shutil.copy2(js_src / "lib" / l, js_high / "lib" / l)
  for m in ["user.ts", "card.ts", "feedback.ts", "complaint.ts", "index.ts"]:
    if (js_src / "models" / m).exists():
      shutil.copy2(js_src / "models" / m, js_high / "models" / m)
  for v in os.listdir(js_src / "views"):
    vp = js_src / "views" / v
    if vp.is_file():
      shutil.copy2(vp, js_high / "views" / v)

  # 2. Mall Core Attack Surface (Excludes auto-generated mall-mbg POJOs and document/)
  mall_src = BASE_DIR / "targets" / "mall"
  mall_scoped = SCOPED_TARGETS_DIR / "mall-core"
  if mall_scoped.exists():
    shutil.rmtree(mall_scoped)
  mall_scoped.mkdir(parents=True, exist_ok=True)

  if (mall_src / "pom.xml").exists():
    shutil.copy2(mall_src / "pom.xml", mall_scoped / "pom.xml")

  for mod in ["mall-security", "mall-common", "mall-admin", "mall-portal", "mall-search", "mall-demo"]:
    src_m = mall_src / mod
    if src_m.exists():
      shutil.copytree(
          src_m,
          mall_scoped / mod,
          ignore=shutil.ignore_patterns("test", "target", "*.iml", ".DS_Store")
      )

  # Also create a high-risk subset of mall for rapid --deep iteration across models & contexts
  mall_high = SCOPED_TARGETS_DIR / "mall-high-risk"
  if mall_high.exists():
    shutil.rmtree(mall_high)
  mall_high.mkdir(parents=True, exist_ok=True)
  shutil.copy2(mall_src / "pom.xml", mall_high / "pom.xml")
  for mod in ["mall-security", "mall-common"]:
    shutil.copytree(
        mall_src / mod,
        mall_high / mod,
        ignore=shutil.ignore_patterns("test", "target")
    )
  # Copy key controllers, services, configs, custom DAO XMLs, and application*.yml from mall-admin & mall-portal
  for mod in ["mall-admin", "mall-portal", "mall-search"]:
    src_m = mall_src / mod
    dst_m = mall_high / mod
    dst_m.mkdir(parents=True, exist_ok=True)
    if (src_m / "pom.xml").exists():
      shutil.copy2(src_m / "pom.xml", dst_m / "pom.xml")
    # Copy resources (dao/*.xml and *.yml)
    res_src = src_m / "src" / "main" / "resources"
    if res_src.exists():
      shutil.copytree(res_src, dst_m / "src" / "main" / "resources")

  # Copy specific security-sensitive controllers/services in mall-admin & mall-portal
  admin_java = mall_src / "mall-admin/src/main/java/com/macro/mall"
  admin_dst = mall_high / "mall-admin/src/main/java/com/macro/mall"
  for sub in ["config", "bo", "component", "validator"]:
    if (admin_java / sub).exists():
      shutil.copytree(admin_java / sub, admin_dst / sub)
  (admin_dst / "controller").mkdir(parents=True, exist_ok=True)
  for c in [
      "MinioController.java", "OssController.java", "UmsAdminController.java",
      "OmsOrderController.java", "PmsProductController.java",
      "UmsRoleController.java", "UmsResourceController.java",
      "UmsMenuController.java"
  ]:
    if (admin_java / "controller" / c).exists():
      shutil.copy2(admin_java / "controller" / c, admin_dst / "controller" / c)
  (admin_dst / "service/impl").mkdir(parents=True, exist_ok=True)
  for s in [
      "UmsAdminServiceImpl.java", "OssServiceImpl.java",
      "OmsOrderServiceImpl.java", "PmsProductServiceImpl.java"
  ]:
    if (admin_java / "service/impl" / s).exists():
      shutil.copy2(admin_java / "service/impl" / s, admin_dst / "service/impl" / s)

  portal_java = mall_src / "mall-portal/src/main/java/com/macro/mall/portal"
  portal_dst = mall_high / "mall-portal/src/main/java/com/macro/mall/portal"
  for sub in ["config", "component", "util"]:
    if (portal_java / sub).exists():
      shutil.copytree(portal_java / sub, portal_dst / sub)
  (portal_dst / "controller").mkdir(parents=True, exist_ok=True)
  for c in [
      "AlipayController.java", "UmsMemberController.java",
      "OmsPortalOrderController.java", "OmsCartItemController.java",
      "UmsMemberReceiveAddressController.java", "HomeController.java",
      "MemberReadHistoryController.java"
  ]:
    if (portal_java / "controller" / c).exists():
      shutil.copy2(portal_java / "controller" / c, portal_dst / "controller" / c)
  (portal_dst / "service/impl").mkdir(parents=True, exist_ok=True)
  for s in [
      "AlipayServiceImpl.java", "UmsMemberServiceImpl.java",
      "OmsPortalOrderServiceImpl.java"
  ]:
    if (portal_java / "service/impl" / s).exists():
      shutil.copy2(portal_java / "service/impl" / s, portal_dst / "service/impl" / s)

  # 3. Fast Representative Benchmark Subsets (~15 key files each) for rapid 20-run matrix comparison
  js_bench = SCOPED_TARGETS_DIR / "juice-shop-bench"
  if js_bench.exists():
    shutil.rmtree(js_bench)
  js_bench.mkdir(parents=True, exist_ok=True)
  for item in ["package.json", "server.ts"]:
    if (js_src / item).exists():
      shutil.copy2(js_src / item, js_bench / item)
  for sub in ["routes", "lib", "models", "views"]:
    (js_bench / sub).mkdir(exist_ok=True)
  for r in [
      "login.ts", "search.ts", "fileUpload.ts", "fileServer.ts", "b2bOrder.ts",
      "profileImageUrlUpload.ts", "userProfile.ts", "redirect.ts",
      "showProductReviews.ts", "updateProductReviews.ts", "trackOrder.ts",
      "dataErasure.ts"
  ]:
    if (js_src / "routes" / r).exists():
      shutil.copy2(js_src / "routes" / r, js_bench / "routes" / r)
  if (js_src / "lib/insecurity.ts").exists():
    shutil.copy2(js_src / "lib/insecurity.ts", js_bench / "lib/insecurity.ts")
  if (js_src / "models/user.ts").exists():
    shutil.copy2(js_src / "models/user.ts", js_bench / "models/user.ts")
  if (js_src / "views/promotionVideo.pug").exists():
    shutil.copy2(js_src / "views/promotionVideo.pug", js_bench / "views/promotionVideo.pug")

  mall_bench = SCOPED_TARGETS_DIR / "mall-bench"
  if mall_bench.exists():
    shutil.rmtree(mall_bench)
  mall_bench.mkdir(parents=True, exist_ok=True)
  shutil.copy2(mall_src / "pom.xml", mall_bench / "pom.xml")
  bench_files = [
      "mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java",
      "mall-security/src/main/java/com/macro/mall/security/config/SecurityConfig.java",
      "mall-security/src/main/java/com/macro/mall/security/config/IgnoreUrlsConfig.java",
      "mall-security/src/main/java/com/macro/mall/security/aspect/RedisCacheAspect.java",
      "mall-common/src/main/java/com/macro/mall/common/util/RequestUtil.java",
      "mall-admin/src/main/java/com/macro/mall/controller/MinioController.java",
      "mall-admin/src/main/java/com/macro/mall/controller/OssController.java",
      "mall-admin/src/main/java/com/macro/mall/controller/UmsAdminController.java",
      "mall-admin/src/main/java/com/macro/mall/service/impl/UmsAdminServiceImpl.java",
      "mall-admin/src/main/resources/dao/OmsOrderDao.xml",
      "mall-admin/src/main/resources/dao/PmsProductDao.xml",
      "mall-admin/src/main/resources/application.yml",
      "mall-admin/src/main/resources/application-dev.yml",
      "mall-portal/src/main/java/com/macro/mall/portal/controller/AlipayController.java",
      "mall-portal/src/main/java/com/macro/mall/portal/controller/UmsMemberController.java",
      "mall-portal/src/main/java/com/macro/mall/portal/controller/OmsPortalOrderController.java",
      "mall-portal/src/main/java/com/macro/mall/portal/service/impl/AlipayServiceImpl.java",
      "mall-portal/src/main/resources/application.yml",
      "mall-portal/src/main/resources/application-dev.yml",
  ]
  for bf in bench_files:
    src_bf = mall_src / bf
    dst_bf = mall_bench / bf
    if src_bf.exists():
      dst_bf.parent.mkdir(parents=True, exist_ok=True)
      shutil.copy2(src_bf, dst_bf)

  # 4. Python WSGI Ground-Truth Benchmark (ref-codemender-test/src isolated from grounding-truth)
  py_src = BASE_DIR / "ref-codemender-test" / "src"
  py_bench = SCOPED_TARGETS_DIR / "ref-codemender-bench"
  if py_bench.exists():
    shutil.rmtree(py_bench)
  py_bench.mkdir(parents=True, exist_ok=True)
  if py_src.exists():
    for item in ["app.py", "requirements.txt"]:
      if (py_src / item).exists():
        shutil.copy2(py_src / item, py_bench / item)
    (py_bench / "storage").mkdir(exist_ok=True)
    (py_bench / "storage" / "sample.txt").write_text("benign sample file\n", encoding="utf-8")
    (py_bench / "uploads").mkdir(exist_ok=True)

  result_targets = {
      "juice-shop-bench": js_bench,
      "juice-shop-high-risk": js_high,
      "juice-shop-core": js_scoped,
      "mall-bench": mall_bench,
      "mall-high-risk": mall_high,
      "mall-core": mall_scoped,
      "ref-codemender-bench": py_bench,
  }

  # Generate PROJECT_FILE_INDEX.md in each scoped target root to eliminate
  # deep directory traversal overhead (especially in Java src/main/java/... trees)
  for tname, tdir in result_targets.items():
    rel_files = []
    for root, _, files in os.walk(tdir):
      for f in sorted(files):
        if f == "PROJECT_FILE_INDEX.md":
          continue
        full_p = Path(root) / f
        rel_files.append(str(full_p.relative_to(tdir)))
    rel_files.sort()
    manifest_text = (
        f"# Project File Index ({tname} - {len(rel_files)} files)\n"
        "# Use these relative paths directly with read_file / grep_search instead of walking directories with list_dir:\n\n"
        + "\n".join(rel_files)
        + "\n"
    )
    (tdir / "PROJECT_FILE_INDEX.md").write_text(manifest_text, encoding="utf-8")
    # Initialize a minimal git marker so CodeMender sets the sandbox boundary
    # strictly to this scoped target directory.
    if not (tdir / ".git").exists():
      subprocess.run(["git", "init", "-q"], cwd=str(tdir), check=False)

  return result_targets


CONTEXT_PROMPTS = {
    "python-wsgi": {
        "c0_none": None,
        "c1_sca": (
            "This Python WSGI web application handles untrusted user input. "
            "Check the root Python dependency manifest text file for pinned package versions "
            "(such as Werkzeug and Requests) and correlate them with known public CVEs "
            "(including multipart form parsing DoS CVE-2023-25577, nameless cookie parsing CVE-2023-46136, "
            "and debugger PIN predictability CVE-2024-34069) alongside application flaws. "
            "Give a complete list of every security vulnerability ranked by severity."
        ),
        "c2_sast_framework": (
            "Audit all Python WSGI route handlers, database queries, file operations, session cookies, "
            "and application factory configuration. Specifically hunt for: "
            "1) OS Command Injection via shell execution, 2) Insecure Deserialization via Python pickle, "
            "3) SQL Injection via string formatting in SQLite queries, 4) Arbitrary File Read and Path Traversal "
            "(distinguishing unsafe path joining from safe_join confinement), 5) Unrestricted File Upload, "
            "6) Server-Side Request Forgery (SSRF), 7) Reflected XSS, 8) Open Redirect, "
            "9) Active Werkzeug DebuggedApplication interactive console (evalex=True), and "
            "10) Insecure session cookies missing Secure or HttpOnly flags."
        ),
        "c3_hybrid_max": (
            "Perform an exhaustive full-stack Python WSGI security audit combining SAST, SCA, and Configuration analysis: "
            "0) First read the project file index markdown document in the root directory to see all target files. "
            "1) Inspect the root Python dependency manifest text file for vulnerable package versions (such as Werkzeug 2.2.0) "
            "and correlate them with reachable application sinks (unbounded multipart form parsing DoS CVE-2023-25577 on upload endpoints, "
            "nameless cookie shadow parsing CVE-2023-46136, and predictable debugger PIN CVE-2024-34069). "
            "2) Trace all untrusted request query parameters, form fields, cookies, and uploaded files across every WSGI endpoint: "
            "identify OS Command Injection (CWE-78), Pickle Insecure Deserialization (CWE-502), SQL Injection (CWE-89), "
            "Path Traversal File Read (CWE-22), Unrestricted File Upload (CWE-434/CWE-22), SSRF (CWE-918), Reflected XSS (CWE-79), "
            "Open Redirect (CWE-601), Active Debug Console with evalex=True (CWE-489), and Session Cookies missing Secure/HttpOnly (CWE-614). "
            "3) Verify whether endpoints using safe_join are properly confined to avoid false positives. "
            "Enumerate every distinct security vulnerability without stopping early."
        ),
        "c_legacy_literal": (
            "This Python file handles untrusted input, so check requirements.txt for the package versions "
            "and hunt down any vulnerabilities. Please be thorough—give me a full list of every security flaw "
            "you find, ranked by severity, rather than stopping at the worst one."
        ),
    },
    "juice-shop": {
        "c0_none": None,
        "c1_sca": (
            "This Node.js and TypeScript web application handles untrusted user input. "
            "Check the root NPM package manifest JSON file for vulnerable dependency versions "
            "(such as express-jwt, jsonwebtoken, sanitize-html, MarsDB, libxml2, notevil, pug, multer, unzipper, sequelize) "
            "and correlate with known CVEs. Be thorough and list every security flaw you find ranked by severity."
        ),
        "c2_sast_framework": (
            "Audit all Express route handlers, middleware, Sequelize queries, NoSQL MarsDB queries, "
            "and Pug or Handlebars view templates. Focus on: 1) SQL Injection via raw queries or string interpolation, "
            "2) NoSQL Injection ($where or MarsDB), 3) RCE and VM Sandbox Escape (notevil, eval, vm), "
            "4) XXE and YAML deserialization (libxml, js-yaml), 5) Arbitrary File Read, Path Traversal, and Zip Slip (unzipper), "
            "6) SSRF in URL image uploads and webhooks, 7) SSTI and XSS in Pug or HBS templates, "
            "8) Weak JWT secrets, algorithm confusion (RS256 to HS256, none), broken authentication, 2FA bypass, and IDOR."
        ),
        "c3_hybrid_max": (
            "Exhaustive Security Audit (SAST + SCA + Config + Business Logic): "
            "0) First read the project file index markdown document in the root directory to see all file paths without wasting tool steps on directory listing. "
            "1) Inspect the root NPM package manifest JSON file and correlate outdated dependencies (jsonwebtoken 0.4.0, express-jwt 0.1.3, "
            "sanitize-html 1.4.2, marsdb, js-yaml, unzipper, notevil, pug) with known CVEs and exploit sinks in code. "
            "2) Trace untrusted request body, query, params, headers, and uploaded files across all route handlers, the insecurity helper library, "
            "Sequelize models, and Pug templates. Identify ALL instances of SQLi, NoSQLi, Command and Code Injection, XXE, SSRF, Path Traversal, "
            "Zip Slip, SSTI, XSS, Open Redirect, CSRF, hardcoded secrets or private keys, weak password hashing (unsalted MD5), "
            "JWT algorithm confusion, mass assignment, and IDOR or price manipulation. "
            "Do not stop at the worst vulnerability—enumerate every distinct security finding across all files."
        ),
    },
    "mall": {
        "c0_none": None,
        "c1_sca": (
            "This Java and Spring Boot multi-module application handles untrusted input. "
            "Check the root Maven POM XML manifest across all modules for dependency versions (Spring Boot, Druid, Hutool, MyBatis, "
            "MinIO, Aliyun OSS, Alipay SDK, OkHttp, BouncyCastle) and correlate with known CVEs. "
            "Give a complete list of every security vulnerability ranked by severity."
        ),
        "c2_sast_framework": (
            "Audit this Java Spring Boot and MyBatis e-commerce application across controllers, service implementations, "
            "MyBatis XML mappers in the dao resources folder, security filters in mall-security, and Spring YAML configuration files. "
            "Specifically hunt for: 1) SQL Injection via dollar-sign string substitution in MyBatis XML mappers or OrderBy clauses, "
            "2) Arbitrary File Upload, Path Traversal, and Stored XSS in MinioController and OssController, "
            "3) Hardcoded credentials, JWT secrets, database, Redis, MinIO, and Alipay keys in Spring YAML configuration files, "
            "4) Broken Access Control and IDOR in mall-portal (cart, order, address, coupon endpoints lacking ownership checks), "
            "5) Authentication and JWT token validation flaws in JwtTokenUtil and SecurityConfig, "
            "6) Alipay payment callback verification bypass or order tampering, and exposed Actuator, Swagger, or Druid endpoints."
        ),
        "c3_hybrid_max": (
            "Perform an exhaustive full-stack Java and Spring Boot security audit combining SAST, SCA, Configuration, and Business Logic analysis: "
            "0) First read the project file index markdown document in the root directory to see all exact file paths immediately without calling list_dir on nested Java package directories. "
            "1) Check the root Maven POM XML manifest for vulnerable libraries (Hutool, Druid, MyBatis, MinIO, Aliyun OSS, Alipay SDK). "
            "2) Inspect all MyBatis DAO XML mapper files for SQL Injection via dollar-sign interpolation or unvalidated ORDER BY parameters. "
            "3) Inspect MinioController, OssController, AlipayController, UmsAdminController, UmsMemberController, OmsPortalOrderController, "
            "and UmsMemberReceiveAddressController for unrestricted file upload, stored XSS, path traversal, SSRF, IDOR (horizontal privilege escalation), "
            "mass assignment, and payment callback forgery. "
            "4) Inspect mall-security (JwtTokenUtil, SecurityConfig, IgnoreUrlsConfig) and all Spring YAML config files for hardcoded JWT secrets, "
            "default passwords, weak crypto, exposed Spring Boot Actuator endpoints, Druid monitor unauthenticated access, and permissive CORS. "
            "Report every single vulnerability found across Java, XML, and YAML files without stopping early."
        ),
    },
}


def extract_db_findings(cm_home: Path) -> List[Dict[str, Any]]:
  """Reads detailed findings directly from CodeMender's SQLite state.db."""
  db_path = cm_home / "state.db"
  if not db_path.exists():
    return []
  try:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r[0] for r in cur.fetchall()]
    if "findings" not in tables:
      conn.close()
      return []
    cur.execute("SELECT * FROM findings")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows
  except Exception as e:
    print(f"[WARN] Failed to read SQLite state.db: {e}")
    return []


def parse_log_metrics(log_text: str) -> Dict[str, Any]:
  """Extracts tool steps, latency, tokens, and discovered file counts from cm stdout/stderr."""
  metrics = {
      "files_discovered": 0,
      "tool_steps": 0,
      "duration_str": "N/A",
      "tokens_in": "0",
      "tokens_out": "0",
      "tokens_total": "0",
  }
  m_files = re.search(r"Found (\d+) source files", log_text)
  if m_files:
    metrics["files_discovered"] = int(m_files.group(1))

  # Standard scan completion line:
  # Completed 7 tool steps in 2m13s | Tokens: 264k in / 5k out / 283k total
  m_comp = re.search(
      r"Completed (\d+) tool steps in ([^|]+)\|\s*Tokens:\s*([^\s]+)\s*in\s*/\s*([^\s]+)\s*out\s*/\s*([^\s]+)\s*total",
      log_text,
  )
  if m_comp:
    metrics["tool_steps"] = int(m_comp.group(1))
    metrics["duration_str"] = m_comp.group(2).strip()
    metrics["tokens_in"] = m_comp.group(3).strip()
    metrics["tokens_out"] = m_comp.group(4).strip()
    metrics["tokens_total"] = m_comp.group(5).strip()
  return metrics


def run_single_experiment(
    run_id: str,
    repo_family: str,
    target_path: Path,
    model: str,
    deep: bool,
    context_key: str,
    deep_workers: int = 16,
    deep_max_turns: int = 5,
    enable_bash: bool = False,
    timeout_sec: int = 900,
) -> Dict[str, Any]:
  """Executes a single isolated CodeMender scan run and saves all artifacts."""
  RESULTS_DIR.mkdir(parents=True, exist_ok=True)
  cm_home = RESULTS_DIR / f".cm_home_{run_id}"
  if cm_home.exists():
    shutil.rmtree(cm_home)

  exclude_dirs = [
      "node_modules", ".git", "dist", "build", "coverage", "test", "tests",
      "cypress", "screenshots", "vagrant", "docker", "document", "mall-mbg"
  ]
  create_cm_config(cm_home, exclude_dirs)

  env = os.environ.copy()
  env["GOOGLE_CLOUD_PROJECT"] = GCP_PROJECT
  env["CLOUDSDK_CORE_PROJECT"] = GCP_PROJECT
  env["CM_HOME"] = str(cm_home)
  env["CMOC_DEEP_MAX_TURNS"] = str(deep_max_turns)

  context_prompt = CONTEXT_PROMPTS.get(repo_family, {}).get(context_key)

  cmd = [
      str(CM_BIN),
      "-y",
      "--sandbox=false",
      "find",
      str(target_path),
      "--model",
      model,
  ]
  if deep:
    cmd.extend(["--deep", "--deep-workers", str(deep_workers), "--deep-max-turns", str(deep_max_turns)])
  if enable_bash:
    cmd.append("--enable-bash")
  if context_prompt:
    cmd.extend(["-c", context_prompt])

  log_path = RESULTS_DIR / f"{run_id}.log"
  txt_report_path = RESULTS_DIR / f"{run_id}_report.txt"
  json_report_path = RESULTS_DIR / f"{run_id}_report.json"
  db_dump_path = RESULTS_DIR / f"{run_id}_db_findings.json"
  meta_path = RESULTS_DIR / f"{run_id}_meta.json"

  print(f"\n============================================================")
  print(f"[START] {run_id}")
  print(f"  Target : {target_path}")
  print(f"  Model  : {model}")
  print(f"  Mode   : {'DEEP (--deep)' if deep else 'QUICK (standard)'}")
  print(f"  Context: {context_key}")
  print(f"  Command: {' '.join(cmd)}")
  print(f"============================================================")
  sys.stdout.flush()

  t0 = time.time()
  timed_out = False
  exit_code = -1
  try:
    with open(log_path, "w", encoding="utf-8") as lf:
      proc = subprocess.run(
          cmd,
          env=env,
          stdout=lf,
          stderr=subprocess.STDOUT,
          timeout=timeout_sec,
          cwd=str(BASE_DIR),
      )
      exit_code = proc.returncode
  except subprocess.TimeoutExpired:
    timed_out = True
    print(f"[WARN] {run_id} timed out after {timeout_sec}s (partial findings preserved in state.db)")

  elapsed_sec = round(time.time() - t0, 1)

  # Export table & JSON reports via `cm report`
  try:
    rep_txt = subprocess.run(
        [str(CM_BIN), "-y", "report", "-f", "table"],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    txt_report_path.write_text(rep_txt.stdout, encoding="utf-8")
  except Exception as e:
    print(f"[WARN] report table failed: {e}")

  findings = []
  try:
    rep_json = subprocess.run(
        [str(CM_BIN), "-y", "report", "-f", "json"],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    raw_json = rep_json.stdout.strip()
    # Extract JSON array from output if banner is present
    idx = raw_json.find("[")
    if idx != -1:
      raw_json = raw_json[idx:]
      findings = json.loads(raw_json)
    json_report_path.write_text(json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8")
  except Exception as e:
    print(f"[WARN] report json parse failed: {e}")

  db_findings = extract_db_findings(cm_home)
  db_dump_path.write_text(json.dumps(db_findings, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
  if not findings and db_findings:
    findings = db_findings
    json_report_path.write_text(json.dumps(findings, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

  log_text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
  log_metrics = parse_log_metrics(log_text)

  sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
  cwe_set = set()
  files_with_findings = set()
  for f in findings:
    sev = str(f.get("severity", "")).upper()
    if sev in sev_counts:
      sev_counts[sev] += 1
    vid = f.get("vuln_id") or f.get("cwe_id") or ""
    if vid:
      cwe_set.add(vid)
    fpath = f.get("file_path") or ""
    if fpath:
      files_with_findings.add(fpath)

  meta = {
      "run_id": run_id,
      "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
      "repo_family": repo_family,
      "target_path": str(target_path.relative_to(BASE_DIR)),
      "model": model,
      "mode": "deep" if deep else "quick",
      "context_key": context_key,
      "context_prompt": context_prompt,
      "deep_workers": deep_workers if deep else 1,
      "deep_max_turns": deep_max_turns if deep else None,
      "enable_bash": enable_bash,
      "exit_code": exit_code,
      "timed_out": timed_out,
      "elapsed_sec": elapsed_sec,
      "total_findings": len(findings),
      "severity_counts": sev_counts,
      "unique_cwes": sorted(list(cwe_set)),
      "affected_files_count": len(files_with_findings),
      "log_metrics": log_metrics,
  }
  meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
  print(
      f"[DONE] {run_id} in {elapsed_sec}s -> {len(findings)} findings "
      f"(Crit:{sev_counts['CRITICAL']} High:{sev_counts['HIGH']} "
      f"Med:{sev_counts['MEDIUM']} Low:{sev_counts['LOW']})"
  )
  sys.stdout.flush()
  return meta


if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("--prepare-only", action="store_true")
  parser.add_argument("--run-id", type=str)
  parser.add_argument("--repo-family", type=str, choices=["juice-shop", "mall", "python-wsgi"])
  parser.add_argument("--target", type=str)
  parser.add_argument("--model", type=str, default="gemini-3.8-flash")
  parser.add_argument("--deep", action="store_true")
  parser.add_argument("--context", type=str, default="c0_none")
  parser.add_argument("--workers", type=int, default=16)
  parser.add_argument("--max-turns", type=int, default=5)
  parser.add_argument("--enable-bash", action="store_true")
  parser.add_argument("--timeout", type=int, default=900)
  args = parser.parse_args()

  targets = prepare_scoped_targets()
  if args.prepare_only:
    for k, v in targets.items():
      cnt = sum(len(files) for _, _, files in os.walk(v))
      print(f"Prepared {k}: {v} ({cnt} files)")
    sys.exit(0)

  if args.run_id and args.repo_family and args.target:
    tpath = BASE_DIR / args.target
    run_single_experiment(
        run_id=args.run_id,
        repo_family=args.repo_family,
        target_path=tpath,
        model=args.model,
        deep=args.deep,
        context_key=args.context,
        deep_workers=args.workers,
        deep_max_turns=args.max_turns,
        enable_bash=args.enable_bash,
        timeout_sec=args.timeout,
    )
