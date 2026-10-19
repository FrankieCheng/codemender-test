#!/usr/bin/env python3
"""
Parallel End-to-End CodeMender Verify -> Fix Automation Runner for `ref-codemender-test/src`
Runs in the `fix` branch:
1. Seeds isolated per-finding `CM_HOME` and `target` workspaces from the verified 11/11 Ground Truth `retest_py_wsgi_quick` state (12 findings across `src/app.py` and `src/requirements.txt`).
2. Injects the pre-built target runtime virtualenv (`/tmp/cm_py_venv/bin`) into `PATH` and sets `PYTHONDONTWRITEBYTECODE=1` so `cm verify` and `cm fix` agents can immediately execute `werkzeug.test.Client` PoCs without filesystem searches or `.pyc` git dirtiness.
3. Runs `cm verify` followed immediately by `cm fix` in parallel across all 12 findings (`max_workers=12`), capturing per-finding `.exploit/` PoCs, verification statuses, and unified git patches (`git diff src/`).
4. Applies all generated patches cleanly to `ref-codemender-test/src/app.py` and `ref-codemender-test/src/requirements.txt` and exports `eval_results/python_wsgi/py_16_verify_and_fix_summary.json`.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time

REPO_ROOT = Path("/usr/local/google/home/hongbocheng/projects/codemender-pipeline/ref-codemender-test").resolve()
SRC_DIR = REPO_ROOT / "src"
PIPELINE_DIR = REPO_ROOT / "pipeline"
sys.path.insert(0, str(PIPELINE_DIR))

CM_BIN = Path("/usr/local/google/home/hongbocheng/bin/cm")
SEED_RUN_DIR = Path("/usr/local/google/home/hongbocheng/projects/codemender-pipeline/scan_outputs/retest_py_wsgi_quick")
OUT_DIR = Path("/usr/local/google/home/hongbocheng/projects/codemender-pipeline/scan_outputs/verify_and_fix_run")
CM_HOME = OUT_DIR / ".cm_home"
SCOPED_TARGET = SEED_RUN_DIR / "scoped_target"
EVAL_OUT_DIR = REPO_ROOT / "eval_results" / "python_wsgi"
VENV_BIN = "/tmp/cm_py_venv/bin"


def extract_db_state(cm_home: Path):
  db_path = cm_home / "state.db"
  if not db_path.exists():
    return [], []
  conn = sqlite3.connect(str(db_path))
  conn.row_factory = sqlite3.Row
  cur = conn.cursor()
  tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
  findings = []
  patches = []
  if "findings" in tables:
    findings = [dict(r) for r in cur.execute("SELECT * FROM findings").fetchall()]
  for t in tables:
    if t != "findings":
      try:
        rows = [dict(r) for r in cur.execute(f"SELECT * FROM {t}").fetchall()]
        patches.append({"table": t, "rows": rows})
      except Exception:
        pass
  conn.close()
  return findings, patches


def prepare_worker_workspace(idx: int):
  w_cm = OUT_DIR / f"worker_cm_{idx:02d}"
  w_tgt = OUT_DIR / f"worker_tgt_{idx:02d}"
  for p in (w_cm, w_tgt):
    if p.exists():
      shutil.rmtree(p)
  shutil.copytree(SEED_RUN_DIR / ".cm_home", w_cm)
  shutil.copytree(
      SCOPED_TARGET,
      w_tgt,
      ignore=shutil.ignore_patterns(".exploit", "__pycache__", "*.pyc", "PROJECT_FILE_INDEX.md"),
  )

  # Ensure clean git working tree inside w_tgt without tracked .pyc or index noise
  gi = w_tgt / ".gitignore"
  gi.write_text("__pycache__/\n*.pyc\n.exploit/\n", encoding="utf-8")
  subprocess.run(["git", "add", "-A"], cwd=str(w_tgt), capture_output=True)
  subprocess.run(
      ["git", "commit", "-m", "clean workspace for verify and fix"],
      cwd=str(w_tgt),
      capture_output=True,
  )

  # Rewrite paths in worker state.db to point to w_tgt
  conn = sqlite3.connect(str(w_cm / "state.db"))
  conn.execute("UPDATE sessions SET target=?, project_root=?", (str(w_tgt), str(w_tgt)))
  for fid, fp in conn.execute("SELECT finding_id, file_path FROM findings").fetchall():
    conn.execute(
        "UPDATE findings SET file_path=? WHERE finding_id=?",
        (fp.replace(str(SCOPED_TARGET), str(w_tgt)), fid),
    )
  conn.commit()
  conn.close()
  return w_cm, w_tgt


def process_one_finding(idx: int, f: dict, total: int, verify_dir: Path, fix_dir: Path):
  fid = f.get("finding_id") or f.get("id")
  title = f.get("title", "")
  fpath = f.get("file_path", "")
  fname = Path(fpath).name
  sline = f.get("start_line", 1)
  eline = f.get("end_line", 300)

  w_cm, w_tgt = prepare_worker_workspace(idx)

  env = os.environ.copy()
  env["CM_HOME"] = str(w_cm)
  env["PATH"] = f"{VENV_BIN}:{env.get('PATH', '')}"
  env["VIRTUAL_ENV"] = "/tmp/cm_py_venv"
  env["PYTHONDONTWRITEBYTECODE"] = "1"

  # --- Phase A: cm verify ---
  v_log = verify_dir / f"verify_{idx:02d}_{fid[:8]}.log"
  v_context = (
      f"FAST TRACK INSTRUCTIONS: werkzeug==2.2.0 and requests are already installed in python3 on PATH. "
      f"(1) Do NOT run git log, git status, or filesystem searches. "
      f"(2) Read src/{fname} around lines {sline}-{eline}. "
      f"(3) Write .exploit/PLAN.md, .exploit/exploit.sh (using python3 + werkzeug.test.Client without starting a background server), "
      f".exploit/LOG.md, .exploit/info.yaml, and .exploit/REPORT.md in minimal turns, run chmod +x .exploit/exploit.sh && .exploit/exploit.sh once, "
      f"then immediately call report_finding and finish."
  )
  v_cmd = [
      str(CM_BIN),
      "-y",
      "--bypass-warning",
      "--sandbox=false",
      "verify",
      str(fid),
      "--model",
      "gemini-3.8-flash",
      "--no-reset",
      "--unrestricted",
      "--skip-exploit-verification",
      "-c",
      v_context,
  ]
  print(f"  [Verify START {idx:02d}/{total}] {fid[:8]} | {fname}:{sline}-{eline} | {title}", flush=True)
  tv0 = time.time()
  v_rc = -1
  v_timed_out = False
  try:
    with open(v_log, "w", encoding="utf-8") as vf:
      vp = subprocess.run(
          v_cmd,
          env=env,
          cwd=str(w_tgt),
          stdin=subprocess.DEVNULL,
          stdout=vf,
          stderr=subprocess.STDOUT,
          timeout=540,
      )
      v_rc = vp.returncode
  except subprocess.TimeoutExpired:
    v_timed_out = True
  v_dur = round(time.time() - tv0, 2)

  db_after_v, _ = extract_db_state(w_cm)
  row_after_v = next((x for x in db_after_v if (x.get("finding_id") or x.get("id")) == fid), {})
  status_after_v = row_after_v.get("status", "UNKNOWN")
  verified_flag = row_after_v.get("verified", 0)

  exploit_dir = w_tgt / ".exploit"
  exploit_files = sorted([p.name for p in exploit_dir.iterdir()]) if exploit_dir.exists() else []
  exploit_sh_ok = False
  exploit_sh_output = ""
  if (exploit_dir / "exploit.sh").exists():
    try:
      ep = subprocess.run(
          ["bash", ".exploit/exploit.sh"],
          env=env,
          cwd=str(w_tgt),
          capture_output=True,
          text=True,
          timeout=15,
      )
      exploit_sh_ok = (ep.returncode == 0)
      exploit_sh_output = (ep.stdout + "\n" + ep.stderr).strip()[-600:]
    except Exception as e:
      exploit_sh_output = str(e)

  print(
      f"  [Verify DONE  {idx:02d}/{total}] {fid[:8]} | {v_dur}s | rc={v_rc} | status={status_after_v} | verified={verified_flag} | exploit_sh_ok={exploit_sh_ok} | files={exploit_files}",
      flush=True,
  )

  # Reset any modifications to src/ made during verify (keep .exploit/ intact for cm fix)
  subprocess.run(["git", "checkout", "--", "src/"], cwd=str(w_tgt), capture_output=True)

  # --- Phase B: cm fix ---
  fx_log = fix_dir / f"fix_{idx:02d}_{fid[:8]}.log"
  fx_context = (
      f"FAST TRACK INSTRUCTIONS: werkzeug==2.2.0 and requests are already installed in python3 on PATH. "
      f"(1) Do NOT run pytest (no test suite exists), git log, or filesystem searches. "
      f"(2) Read src/{fname} lines {max(1, sline-10)}-{eline+15}. "
      f"(3) Apply the minimal security fix directly to src/{fname} using search_and_replace. "
      f"(4) If .exploit/exploit.sh exists, run bash .exploit/exploit.sh once to verify the exploit now fails, then finish immediately."
  )
  fx_cmd = [
      str(CM_BIN),
      "-y",
      "--bypass-warning",
      "--sandbox=false",
      "fix",
      str(fid),
      "--model",
      "gemini-3.8-flash",
      "--unrestricted",
      "-c",
      fx_context,
  ]
  print(f"  [Fix    START {idx:02d}/{total}] {fid[:8]} | {fname}:{sline}-{eline}", flush=True)
  tf0 = time.time()
  fx_rc = -1
  fx_timed_out = False
  try:
    with open(fx_log, "w", encoding="utf-8") as fxf:
      fxp = subprocess.run(
          fx_cmd,
          env=env,
          cwd=str(w_tgt),
          input="y\ny\ny\ny\ny\n",
          stdout=fxf,
          stderr=subprocess.STDOUT,
          text=True,
          timeout=540,
      )
      fx_rc = fxp.returncode
  except subprocess.TimeoutExpired:
    fx_timed_out = True
  fx_dur = round(time.time() - tf0, 2)

  db_after_fx, other_tables_fx = extract_db_state(w_cm)
  row_after_fx = next((x for x in db_after_fx if (x.get("finding_id") or x.get("id")) == fid), {})
  status_after_fx = row_after_fx.get("status", "UNKNOWN")

  diff_proc = subprocess.run(
      ["git", "diff", "src/"],
      cwd=str(w_tgt),
      capture_output=True,
      text=True,
  )
  worker_diff = diff_proc.stdout.strip()
  patch_rows = []
  for tbl in other_tables_fx:
    if tbl["table"] == "patches" and tbl["rows"]:
      patch_rows = tbl["rows"]

  # Save worker diff to file if non-empty
  patch_file = fix_dir / f"patch_{idx:02d}_{fid[:8]}.diff"
  if worker_diff:
    patch_file.write_text(worker_diff + "\n", encoding="utf-8")

  # Re-run exploit.sh after fix to confirm exploit is blocked (exit != 0)
  exploit_blocked_after_fix = None
  if (exploit_dir / "exploit.sh").exists() and worker_diff:
    try:
      ep2 = subprocess.run(
          ["bash", ".exploit/exploit.sh"],
          env=env,
          cwd=str(w_tgt),
          capture_output=True,
          text=True,
          timeout=15,
      )
      exploit_blocked_after_fix = (ep2.returncode != 0)
    except Exception:
      pass

  print(
      f"  [Fix    DONE  {idx:02d}/{total}] {fid[:8]} | {fx_dur}s | rc={fx_rc} | status={status_after_fx} | has_diff={bool(worker_diff)} | db_patches={len(patch_rows)} | exploit_blocked={exploit_blocked_after_fix}",
      flush=True,
  )

  v_log_text = v_log.read_text(encoding="utf-8", errors="ignore") if v_log.exists() else ""
  fx_log_text = fx_log.read_text(encoding="utf-8", errors="ignore") if fx_log.exists() else ""

  return {
      "index": idx,
      "finding_id": fid,
      "file_path": f"src/{fname}",
      "start_line": sline,
      "end_line": eline,
      "title": title,
      "severity": f.get("severity"),
      "vuln_id": f.get("vuln_id") or f.get("vuln_type"),
      "verify": {
          "exit_code": v_rc,
          "timed_out": v_timed_out,
          "duration_seconds": v_dur,
          "status_after_verify": status_after_v,
          "verified_flag": verified_flag,
          "exploit_files": exploit_files,
          "exploit_sh_succeeded_on_unpatched": exploit_sh_ok,
          "exploit_sh_output": exploit_sh_output,
          "log_file": str(v_log),
          "log_tail": "\n".join(v_log_text.splitlines()[-20:]),
      },
      "fix": {
          "exit_code": fx_rc,
          "timed_out": fx_timed_out,
          "duration_seconds": fx_dur,
          "status_after_fix": status_after_fx,
          "has_git_diff": bool(worker_diff),
          "git_diff": worker_diff,
          "db_patches_count": len(patch_rows),
          "db_patches": patch_rows,
          "exploit_blocked_after_fix": exploit_blocked_after_fix,
          "log_file": str(fx_log),
          "log_tail": "\n".join(fx_log_text.splitlines()[-20:]),
      },
      "db_row_final": row_after_fx,
  }


def main():
  t_start = time.time()
  OUT_DIR.mkdir(parents=True, exist_ok=True)
  if CM_HOME.exists():
    shutil.rmtree(CM_HOME)
  shutil.copytree(SEED_RUN_DIR / ".cm_home", CM_HOME)

  # Ensure scoped_target/src has clean copies of ref-codemender-test/src before running verify & fix
  shutil.copy2(SRC_DIR / "app.py", SCOPED_TARGET / "src" / "app.py")
  shutil.copy2(SRC_DIR / "requirements.txt", SCOPED_TARGET / "src" / "requirements.txt")

  initial_findings, _ = extract_db_state(CM_HOME)
  print(f"[1/3] Loaded {len(initial_findings)} findings from 11/11 GT scan to verify and fix.", flush=True)
  (OUT_DIR / "01_initial_findings.json").write_text(json.dumps(initial_findings, indent=2), encoding="utf-8")

  verify_dir = OUT_DIR / "verify_logs"
  fix_dir = OUT_DIR / "fix_logs"
  verify_dir.mkdir(exist_ok=True)
  fix_dir.mkdir(exist_ok=True)

  print(f"[2/3] Launching 12 parallel isolated workers for `cm verify` -> `cm fix` ...", flush=True)
  results = []
  with ThreadPoolExecutor(max_workers=12) as ex:
    futs = [
        ex.submit(process_one_finding, idx, f, len(initial_findings), verify_dir, fix_dir)
        for idx, f in enumerate(initial_findings, 1)
    ]
    for fut in as_completed(futs):
      results.append(fut.result())
  results.sort(key=lambda x: x["index"])

  # Apply all generated worker diffs onto REPO_ROOT/src
  print("[3/3] Applying generated security patches from `cm fix` workers onto `ref-codemender-test/src` ...", flush=True)
  applied_patches = []
  failed_patches = []
  for r in results:
    diff_text = r["fix"]["git_diff"]
    if not diff_text:
      # Check if db_patches has diff content
      for pr in r["fix"].get("db_patches", []):
        for k in ("diff", "patch", "content", "unified_diff"):
          if pr.get(k):
            diff_text = pr[k]
            break
    if diff_text:
      patch_path = fix_dir / f"apply_{r['index']:02d}_{r['finding_id'][:8]}.patch"
      patch_path.write_text(diff_text + "\n", encoding="utf-8")
      ap = subprocess.run(
          ["git", "apply", "--3way", "--recount", str(patch_path)],
          cwd=str(REPO_ROOT),
          capture_output=True,
          text=True,
      )
      if ap.returncode == 0:
        applied_patches.append(r["finding_id"])
        print(f"  [APPLIED] {r['finding_id'][:8]} ({r['title']})", flush=True)
      else:
        failed_patches.append({"finding_id": r["finding_id"], "title": r["title"], "stderr": ap.stderr})
        print(f"  [CONFLICT/MANUAL] {r['finding_id'][:8]} ({r['title']}): {ap.stderr.strip()}", flush=True)

  final_git_diff = subprocess.run(
      ["git", "diff", "src/"],
      cwd=str(REPO_ROOT),
      capture_output=True,
      text=True,
  ).stdout

  # Strip db_row_final before saving summary JSON
  final_findings = []
  for r in results:
    row = r.pop("db_row_final", None)
    if row:
      final_findings.append(row)

  summary = {
      "target_dir": str(SRC_DIR),
      "total_wall_clock_seconds": round(time.time() - t_start, 2),
      "initial_findings_count": len(initial_findings),
      "verified_or_poc_confirmed_count": sum(
          1 for r in results
          if r["verify"]["verified_flag"] == 1
          or r["verify"]["status_after_verify"] == "VERIFIED"
          or r["verify"]["exploit_sh_succeeded_on_unpatched"]
      ),
      "fix_diff_generated_count": sum(1 for r in results if r["fix"]["has_git_diff"] or r["fix"]["db_patches_count"] > 0),
      "applied_patches_count": len(applied_patches),
      "applied_patches": applied_patches,
      "failed_patches": failed_patches,
      "results": results,
      "final_git_diff_src": final_git_diff,
  }
  (OUT_DIR / "verify_and_fix_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
  EVAL_OUT_DIR.mkdir(parents=True, exist_ok=True)
  (EVAL_OUT_DIR / "py_16_verify_and_fix_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
  print(f"=== COMPLETED ALL VERIFY & FIX STEPS IN {summary['total_wall_clock_seconds']}s ===", flush=True)


if __name__ == "__main__":
  main()
