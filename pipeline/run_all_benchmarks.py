#!/usr/bin/env python3
"""
Master Background Benchmark Runner for CodeMender Pipeline (juice-shop & mall)
Runs in GCP project `cloud-llm-preview1` across:
- Models: gemini-3.5-flash, gemini-3.8-flash, gemini-4-argon, gemini-3.8-flash-cyber
- Modes: Quick Scan vs Specialist-recommended Deep Scan (--deep)
- Context (-c) Strategies: c0_none, c1_sca, c2_sast_framework, c3_hybrid_max

Continuously updates BENCHMARK_RESULTS.md after every completed run.
"""

import importlib
from pathlib import Path
import subprocess
import sys
import traceback
import generate_report
import pipeline

# Ordered from fastest/highest-signal comparisons to exhaustive deep runs
# so we rapidly populate the comparison matrix and converge on the optimal solution.
EXPERIMENTS = [
    # Stage A: Immediate Head-to-Head on Mall (Java/Spring Boot): Quick vs Deep & Context (-c) & Models
    ("mall_01_3.8-flash_quick_c0_none", "mall", "scoped_targets/mall-bench", "gemini-3.8-flash", False, "c0_none", 16, 8, False, 480),
    ("mall_02_3.8-flash_quick_c3_hybrid", "mall", "scoped_targets/mall-bench", "gemini-3.8-flash", False, "c3_hybrid_max", 16, 8, False, 480),
    ("mall_03_3.8-flash_deep_c3_hybrid", "mall", "scoped_targets/mall-bench", "gemini-3.8-flash", True, "c3_hybrid_max", 16, 8, True, 600),
    ("mall_04_3.5-flash_deep_c3_hybrid", "mall", "scoped_targets/mall-bench", "gemini-3.5-flash", True, "c3_hybrid_max", 16, 8, False, 600),
    ("mall_05_4-argon_deep_c3_hybrid", "mall", "scoped_targets/mall-bench", "gemini-4-argon", True, "c3_hybrid_max", 16, 8, False, 600),

    # Stage B: Immediate Head-to-Head on Juice Shop (Node.js/TS): Quick vs Deep & Context (-c) & Models
    ("js_01_3.8-flash_quick_c0_none", "juice-shop", "scoped_targets/juice-shop-bench", "gemini-3.8-flash", False, "c0_none", 16, 8, False, 480),
    ("js_02_3.8-flash_quick_c3_hybrid", "juice-shop", "scoped_targets/juice-shop-bench", "gemini-3.8-flash", False, "c3_hybrid_max", 16, 8, False, 480),
    ("js_03_3.8-flash_deep_c3_hybrid", "juice-shop", "scoped_targets/juice-shop-bench", "gemini-3.8-flash", True, "c3_hybrid_max", 16, 8, True, 600),
    ("js_04_3.5-flash_deep_c3_hybrid", "juice-shop", "scoped_targets/juice-shop-bench", "gemini-3.5-flash", True, "c3_hybrid_max", 16, 8, False, 600),
    ("js_05_4-argon_deep_c3_hybrid", "juice-shop", "scoped_targets/juice-shop-bench", "gemini-4-argon", True, "c3_hybrid_max", 16, 8, False, 600),

    # Stage C: Context (-c) Ablation Matrix (c0_none vs c1_sca vs c2_sast_framework vs c3_hybrid_max)
    ("mall_06_3.8-flash_quick_c1_sca", "mall", "scoped_targets/mall-bench", "gemini-3.8-flash", False, "c1_sca", 16, 8, False, 480),
    ("mall_07_3.8-flash_quick_c2_sast", "mall", "scoped_targets/mall-bench", "gemini-3.8-flash", False, "c2_sast_framework", 16, 8, False, 480),
    ("mall_08_3.8-flash_deep_c0_none", "mall", "scoped_targets/mall-bench", "gemini-3.8-flash", True, "c0_none", 16, 8, False, 600),
    ("js_06_3.8-flash_quick_c1_sca", "juice-shop", "scoped_targets/juice-shop-bench", "gemini-3.8-flash", False, "c1_sca", 16, 8, False, 480),
    ("js_07_3.8-flash_quick_c2_sast", "juice-shop", "scoped_targets/juice-shop-bench", "gemini-3.8-flash", False, "c2_sast_framework", 16, 8, False, 480),
    ("js_08_3.8-flash_deep_c0_none", "juice-shop", "scoped_targets/juice-shop-bench", "gemini-3.8-flash", True, "c0_none", 16, 8, False, 600),

    # Stage D: Model Ablation Matrix in Quick Mode (3.5-flash vs 3.8-flash vs 4-argon vs 3.8-flash-cyber)
    ("mall_09_3.5-flash_quick_c0_none", "mall", "scoped_targets/mall-bench", "gemini-3.5-flash", False, "c0_none", 16, 8, False, 480),
    ("mall_10_4-argon_quick_c0_none", "mall", "scoped_targets/mall-bench", "gemini-4-argon", False, "c0_none", 16, 8, False, 480),
    ("mall_11_3.5-flash_quick_c3_hybrid", "mall", "scoped_targets/mall-bench", "gemini-3.5-flash", False, "c3_hybrid_max", 16, 8, False, 480),
    ("mall_12_4-argon_quick_c3_hybrid", "mall", "scoped_targets/mall-bench", "gemini-4-argon", False, "c3_hybrid_max", 16, 8, False, 480),
    ("js_09_3.5-flash_quick_c0_none", "juice-shop", "scoped_targets/juice-shop-bench", "gemini-3.5-flash", False, "c0_none", 16, 8, False, 480),
    ("js_10_4-argon_quick_c0_none", "juice-shop", "scoped_targets/juice-shop-bench", "gemini-4-argon", False, "c0_none", 16, 8, False, 480),
    ("js_11_3.5-flash_quick_c3_hybrid", "juice-shop", "scoped_targets/juice-shop-bench", "gemini-3.5-flash", False, "c3_hybrid_max", 16, 8, False, 480),
    ("js_12_4-argon_quick_c3_hybrid", "juice-shop", "scoped_targets/juice-shop-bench", "gemini-4-argon", False, "c3_hybrid_max", 16, 8, False, 480),

    # Stage E: Expanded High-Risk & Full Core Repository Deep Scans (--deep)
    ("mall_13_high_risk_deep_optimal", "mall", "scoped_targets/mall-high-risk", "gemini-3.8-flash", True, "c3_hybrid_max", 16, 8, False, 1800),
    ("js_13_high_risk_deep_optimal", "juice-shop", "scoped_targets/juice-shop-high-risk", "gemini-3.8-flash", True, "c3_hybrid_max", 16, 8, False, 1800),
    ("mall_14_full_core_deep_optimal", "mall", "scoped_targets/mall-core", "gemini-3.8-flash", True, "c3_hybrid_max", 16, 8, False, 2400),
    ("js_14_full_core_deep_optimal", "juice-shop", "scoped_targets/juice-shop-core", "gemini-3.8-flash", True, "c3_hybrid_max", 16, 8, False, 2400),
]


def main() -> None:
  skip_prepare = "--skip-prepare" in sys.argv
  filter_prefix = None
  for arg in sys.argv[1:]:
    if arg.startswith("--filter="):
      filter_prefix = arg.split("=", 1)[1]

  if not skip_prepare:
    print("Preparing scoped targets...")
    targets = pipeline.prepare_scoped_targets()
    for name, path in targets.items():
      cnt = sum(len(files) for _, _, files in subprocess.os.walk(path))
      print(f"  {name}: {path} ({cnt} files)")
    generate_report.REPORT_PATH.write_text(generate_report.generate_markdown(), encoding="utf-8")

  for (
      run_id,
      repo_family,
      target_rel,
      model,
      deep,
      context_key,
      workers,
      max_turns,
      enable_bash,
      timeout_sec,
  ) in EXPERIMENTS:
    if filter_prefix and not run_id.startswith(filter_prefix):
      continue
    importlib.reload(pipeline)
    importlib.reload(generate_report)
    meta_file = pipeline.BASE_DIR / "eval_results" / f"{run_id}_meta.json"
    log_file = pipeline.BASE_DIR / "eval_results" / f"{run_id}.log"
    if meta_file.exists() or log_file.exists():
      print(f"[SKIP] {run_id} already completed or in progress.")
      continue
    try:
      pipeline.run_single_experiment(
          run_id=run_id,
          repo_family=repo_family,
          target_path=pipeline.BASE_DIR / target_rel,
          model=model,
          deep=deep,
          context_key=context_key,
          deep_workers=workers,
          deep_max_turns=max_turns,
          enable_bash=enable_bash,
          timeout_sec=timeout_sec,
      )
    except Exception as e:
      print(f"[ERROR] {run_id} failed: {e}")
      traceback.print_exc()

    # Update live Markdown report after every run
    try:
      md = generate_report.generate_markdown()
      generate_report.REPORT_PATH.write_text(md, encoding="utf-8")
      print(f"[REPORT UPDATED] {generate_report.REPORT_PATH}")
    except Exception as e:
      print(f"[WARN] Failed to update report: {e}")
    sys.stdout.flush()


if __name__ == "__main__":
  main()
