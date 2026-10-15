#!/usr/bin/env python3
"""
Executes the 13-experiment CodeMender v0.14.0 Benchmark Suite on ref-codemender-test (Python WSGI)
and evaluates Ground Truth Recall (11 real vulnerabilities + 1 safe_join negative control).
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import sys
from pathlib import Path
from typing import Any, Dict, List
from pipeline import BASE_DIR, RESULTS_DIR, prepare_scoped_targets, run_single_experiment

PYTHON_EXPERIMENTS = [
    # --- Quick Mode Baselines & Context Ablation ---
    ("py_01_quick_35flash_c0", "python-wsgi", "scoped_targets/ref-codemender-bench", "gemini-3.5-flash", False, "c0_none", 1, 5, 420),
    ("py_02_quick_35flash_c3", "python-wsgi", "scoped_targets/ref-codemender-bench", "gemini-3.5-flash", False, "c3_hybrid_max", 1, 5, 420),
    ("py_03_quick_38flash_c0", "python-wsgi", "scoped_targets/ref-codemender-bench", "gemini-3.8-flash", False, "c0_none", 1, 5, 420),
    ("py_04_quick_38flash_c1_sca", "python-wsgi", "scoped_targets/ref-codemender-bench", "gemini-3.8-flash", False, "c1_sca", 1, 5, 420),
    ("py_05_quick_38flash_c2_sast", "python-wsgi", "scoped_targets/ref-codemender-bench", "gemini-3.8-flash", False, "c2_sast_framework", 1, 5, 420),
    ("py_06_quick_38flash_c3_hybrid", "python-wsgi", "scoped_targets/ref-codemender-bench", "gemini-3.8-flash", False, "c3_hybrid_max", 1, 5, 420),
    ("py_07_quick_4argon_c0", "python-wsgi", "scoped_targets/ref-codemender-bench", "gemini-4-argon", False, "c0_none", 1, 5, 480),
    ("py_08_quick_4argon_c3", "python-wsgi", "scoped_targets/ref-codemender-bench", "gemini-4-argon", False, "c3_hybrid_max", 1, 5, 480),

    # --- Deep Mode (--deep) Multi-Model & Context Comparison ---
    ("py_09_deep_35flash_c3", "python-wsgi", "scoped_targets/ref-codemender-bench", "gemini-3.5-flash", True, "c3_hybrid_max", 16, 8, 480),
    ("py_10_deep_38flash_c0", "python-wsgi", "scoped_targets/ref-codemender-bench", "gemini-3.8-flash", True, "c0_none", 16, 8, 480),
    ("py_11_deep_38flash_c3_hybrid", "python-wsgi", "scoped_targets/ref-codemender-bench", "gemini-3.8-flash", True, "c3_hybrid_max", 16, 8, 480),
    ("py_12_deep_4argon_c3", "python-wsgi", "scoped_targets/ref-codemender-bench", "gemini-4-argon", True, "c3_hybrid_max", 16, 8, 540),

    # --- Literal Filename Scoping Trap Verification on ref-codemender-test's Legacy Prompt ---
    ("py_13_deep_38flash_literal_trap", "python-wsgi", "scoped_targets/ref-codemender-bench", "gemini-3.8-flash", True, "c_legacy_literal", 16, 8, 420),
]

# Ground Truth 11 real vulnerabilities matched strictly against (title + vuln_type + vuln_id + snippet)
GROUND_TRUTH_RULES = [
    ("GT01_CMD_INJ", "OS Command Injection (/diagnostics/ping)", ["on_ping", "cwe-78", "command injection"]),
    ("GT02_DESERIAL", "Pickle Insecure Deserialization (/profile/restore)", ["on_profile_restore", "cwe-502", "pickle", "deserialization"]),
    ("GT03_UPLOAD", "Unrestricted File Upload / Path Traversal (/upload/raw)", ["on_upload_raw", "upload_raw", "upload/raw", "raw upload", "cwe-434", "file upload", "file write"]),
    ("GT04_PATH_READ", "Arbitrary File Read / Path Traversal (/download)", ["def on_download(", "download endpoint", "arbitrary file read", "path traversal file read"]),
    ("GT05_SQLI", "SQL Injection (/api/users/lookup)", ["on_user_lookup", "cwe-89", "sql injection"]),
    ("GT06_SSRF", "Server-Side Request Forgery (/services/proxy)", ["on_service_proxy", "cwe-918", "ssrf", "request forgery"]),
    ("GT07_XSS", "Reflected XSS (/search)", ["on_search", "cwe-79", "xss", "cross-site scripting"]),
    ("GT08_REDIRECT", "Open URL Redirect (/navigate)", ["on_navigate", "cwe-601", "open redirect", "redirection"]),
    ("GT09_DEBUGGER", "Active Werkzeug Debugger / PIN RCE (DebuggedApplication)", ["debuggedapplication", "evalex", "cwe-489", "cve-2024-34069", "debug console", "debugger"]),
    ("GT10_MULTIPART_DOS", "Multipart Form Parsing DoS (CVE-2023-25577)", ["def on_upload(", "cve-2023-25577", "multipart", "cwe-400", "denial of service"]),
    ("GT11_COOKIE_SEC", "Insecure Session Cookie / Nameless Cookie (CWE-614 / CVE-2023-46136)", ["on_auth_session", "cwe-614", "cve-2023-46136", "cookie"]),
]


def evaluate_ground_truth(run_id: str) -> Dict[str, Any]:
  """Evaluates a Python benchmark run against the 11 Ground Truth vulnerabilities and checks for false positives on safe_join."""
  rep_path = RESULTS_DIR / f"{run_id}_report.json"
  db_path = RESULTS_DIR / f"{run_id}_db_findings.json"
  findings = []
  if rep_path.exists():
    try:
      findings = json.loads(rep_path.read_text(encoding="utf-8"))
    except Exception:
      pass
  if not findings and db_path.exists():
    try:
      findings = json.loads(db_path.read_text(encoding="utf-8"))
    except Exception:
      pass

  matched_gt = {}
  for gt_id, gt_name, keywords in GROUND_TRUTH_RULES:
    matched_gt[gt_id] = False
    for f in findings:
      # Match strictly against header fields + code snippet (avoiding incidental words in prose analysis)
      strict_blob = " ".join([
          str(f.get("title", "")),
          str(f.get("vuln_type", "")),
          str(f.get("vuln_id", "")),
          str(f.get("cwe_id", "")),
          str(f.get("snippet", "")),
          str(f.get("location", "")),
      ]).lower()
      if gt_id == "GT04_PATH_READ" and "on_secure_download" in strict_blob:
        continue
      if any(k in strict_blob for k in keywords):
        matched_gt[gt_id] = True
        break

  # Check false positive on on_secure_download / safe_join
  fp_safe_join = False
  for f in findings:
    title_loc = (str(f.get("title", "")) + " " + str(f.get("location", ""))).lower()
    if "secure_download" in title_loc or "secure-download" in title_loc:
      fp_safe_join = True

  hits = sum(1 for v in matched_gt.values() if v)
  return {
      "gt_hits": hits,
      "gt_total": len(GROUND_TRUTH_RULES),
      "gt_recall_pct": round(hits * 100.0 / len(GROUND_TRUTH_RULES), 1),
      "gt_matrix": matched_gt,
      "fp_safe_join": fp_safe_join,
  }


def run_one(exp):
  run_id, repo_family, target_rel, model, deep, context_key, workers, max_turns, timeout_sec = exp
  meta_path = RESULTS_DIR / f"{run_id}_meta.json"
  if meta_path.exists():
    try:
      existing = json.loads(meta_path.read_text(encoding="utf-8"))
      if (existing.get("total_findings", 0) > 0 or run_id == "py_13_deep_38flash_literal_trap") and not existing.get("timed_out", False):
        gt_eval = evaluate_ground_truth(run_id)
        existing["ground_truth"] = gt_eval
        meta_path.write_text(json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[SKIP] {run_id} already completed ({existing['total_findings']} findings, GT {gt_eval['gt_hits']}/11 ({gt_eval['gt_recall_pct']}%))")
        return existing
    except Exception:
      pass

  meta = run_single_experiment(
      run_id=run_id,
      repo_family=repo_family,
      target_path=BASE_DIR / target_rel,
      model=model,
      deep=deep,
      context_key=context_key,
      deep_workers=workers,
      deep_max_turns=max_turns,
      enable_bash=False,
      timeout_sec=timeout_sec,
  )
  gt_eval = evaluate_ground_truth(run_id)
  meta["ground_truth"] = gt_eval
  meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
  print(f"[GT EVAL] {run_id}: Recall = {gt_eval['gt_hits']}/{gt_eval['gt_total']} ({gt_eval['gt_recall_pct']}%) | FP on safe_join = {gt_eval['fp_safe_join']}")
  return meta


def main():
  prepare_scoped_targets()
  print(f"Starting {len(PYTHON_EXPERIMENTS)} Python WSGI (ref-codemender-test) benchmark experiments...")
  with ThreadPoolExecutor(max_workers=4) as pool:
    futs = [pool.submit(run_one, exp) for exp in PYTHON_EXPERIMENTS]
    for f in as_completed(futs):
      try:
        f.result()
      except Exception as e:
        print(f"[ERR] Experiment failed: {e}")
  print("All Python WSGI benchmark experiments finished!")


if __name__ == "__main__":
  main()
