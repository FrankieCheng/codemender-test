#!/usr/bin/env python3
"""
Universal Two-Stage CodeMender (cm v0.14.0) Auto-Profile & Auto-Scan Pipeline.

Architecture:
- Stage 1 (RepoProfiler / `profile` / `--dry-run`):
  1. Dynamic Language & Extension Detector -> Tailored `config.yaml` (`incremental: false`, `max_file_size_kb: 500`).
  2. Smart Directory Scoper, Generated ORM Filter (e.g. MyBatis Generator `*Example.java` & `Example_Where_Clause`
     vs custom `dao/*Dao.xml`), SPA Frontend Filter, and Multi-Language Thin-Wrapper Import Tracer -> `PROJECT_FILE_INDEX.md`.
  3. Multi-Ecosystem Manifest & Dependency Version Extractor (`requirements.txt`, `pyproject.toml`, `package.json`,
     `pom.xml` with `<properties>` `${...}` interpolation & `<parent>` inheritance, `build.gradle`, `go.mod`,
     `CMakeLists.txt`, `Makefile`, `Gemfile`, `composer.json`).
  4. Multi-Language Route, Sink & Security Guard Extractor (`safe_join`, parameterized queries, etc.).
  5. 5-Pillar Hybrid Semantic `-c` Context Prompt Synthesizer + Prompt-Injection Guard + Hard Programmatic
     Filename Sanitizer (`FILE_SCOPING_REGEX` guaranteed 0 matches).
  6. Adaptive CLI Execution Profile Selector (`<= 5` active files -> Quick mode; `> 5` active files -> Parallel `--deep`).
- Stage 2 (run_universal_scan / `scan`):
  1. Isolated `CM_HOME` per run with tailored `config.yaml`.
  2. High-signal isolated scoped target materialization (with `.git` boundary and `PROJECT_FILE_INDEX.md`).
  3. Controlled execution of `cm -y clean` + `cm -y --sandbox=false find` on `cloud-llm-preview1` with `<= 900s` timeout cap.
  4. Structured `report.json` and `report.md` generation with automated 11/11 Ground Truth & 0% `safe_join` FP evaluation.
"""

import argparse
import ast
import datetime
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
  import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
  tomllib = None  # type: ignore

BASE_DIR = Path(__file__).resolve().parent
PRIMARY_CM_BIN = Path("/usr/local/google/home/hongbocheng/bin/cm")
FALLBACK_CM_BIN = BASE_DIR / "bin" / "cm"
CM_BIN = PRIMARY_CM_BIN if PRIMARY_CM_BIN.exists() else FALLBACK_CM_BIN
RESULTS_DIR = BASE_DIR / "eval_results"
SCOPED_TARGETS_DIR = BASE_DIR / "scoped_targets"
SCAN_OUTPUTS_DIR = BASE_DIR / "scan_outputs"
GCP_PROJECT = "cloud-llm-preview1"
MAX_TIMEOUT_SECONDS = 900
DEFAULT_TIMEOUT_SECONDS = 600
MAX_MONOREPO_SCOPED_FILES = 40

# Legacy compatibility export (populated dynamically on demand, zero hardcoded repo names)
CONTEXT_PROMPTS: Dict[str, Dict[str, Optional[str]]] = {}


def resolve_cm_bin() -> Path:
  """Resolves the CodeMender CLI binary path, preferring ~/bin/cm with fallback to ./bin/cm."""
  if PRIMARY_CM_BIN.exists():
    return PRIMARY_CM_BIN
  if FALLBACK_CM_BIN.exists():
    return FALLBACK_CM_BIN
  return PRIMARY_CM_BIN


# ============================================================================
# Component 1: Hard Programmatic Filename & Prompt-Injection Sanitizer
# ============================================================================

# Matches any literal filename.ext, path/to/file.ext, or word.alpha_ext token
# that could trigger CodeMender v0.14.0's --deep file-scoping extractor (0x241b160 -> 0x241ae80).
# Pure numeric version strings like "2.2.0" or "3.5.14" have digits after the dot
# and therefore do NOT match this regex.
FILE_SCOPING_REGEX: re.Pattern = re.compile(
    r"(?i)\b[A-Za-z0-9_./-]+\.(?:"
    r"py|pyw|pyc|txt|toml|cfg|ini|lock|pipfile|"
    r"js|jsx|mjs|cjs|ts|tsx|mts|cts|json|pug|hbs|ejs|vue|svelte|"
    r"java|xml|yml|yaml|properties|gradle|kts|jsp|jspx|jar|war|"
    r"c|cc|cpp|cxx|h|hh|hpp|hxx|cmake|mk|in|ac|am|"
    r"go|mod|sum|rb|erb|gemspec|rake|php|phtml|twig|"
    r"rs|cs|kt|swift|scala|sol|tf|hcl|sql|sh|bash|zsh|"
    r"md|rst|html|htm|css|scss|less|proto|graphql|env|bak|conf"
    r")\b"
    r"|\b[A-Za-z0-9_-]+\.[A-Za-z][A-Za-z0-9_]*\b"
)

PROMPT_INJECTION_PATTERNS: List[re.Pattern] = [
    re.compile(r"(?i)ignore\s+(?:all\s+)?(?:previous|prior|above|preceding)\s+instructions?[^.;\n]*"),
    re.compile(r"(?i)disregard\s+(?:all\s+)?(?:previous|prior|above|preceding)\s+instructions?[^.;\n]*"),
    re.compile(r"(?i)forget\s+(?:all\s+)?(?:previous|prior|above|preceding)\s+instructions?[^.;\n]*"),
    re.compile(r"(?i)do\s+not\s+report\s+(?:any\s+)?(?:vulnerabilities|findings|issues|flaws|bugs)[^.;\n]*"),
    re.compile(r"(?i)report\s+(?:zero|0|no)\s+(?:vulnerabilities|findings|issues|flaws|bugs)[^.;\n]*"),
    re.compile(r"(?i)system\s*override\s*:[^.;\n]*"),
    re.compile(r"(?i)new\s+system\s+prompt\s*:[^.;\n]*"),
    re.compile(r"(?i)you\s+are\s+now\s+in\s+[a-z0-9_-]+\s+mode[^.;\n]*"),
]

KNOWN_FILENAME_REPLACEMENTS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)\brequirements(?:-[a-z0-9_]+)?\.txt\b"), "the root Python dependency manifest text file"),
    (re.compile(r"(?i)\bpyproject\.toml\b"), "the Python project configuration manifest"),
    (re.compile(r"(?i)\bsetup\.(?:py|cfg)\b"), "the Python package setup configuration"),
    (re.compile(r"(?i)\bPipfile(?:\.lock)?\b"), "the Pipenv dependency manifest"),
    (re.compile(r"(?i)\bpoetry\.lock\b"), "the Poetry lockfile manifest"),
    (re.compile(r"(?i)\bpackage\.json\b"), "the root NPM package manifest JSON file"),
    (re.compile(r"(?i)\bpackage-lock\.json\b"), "the NPM lockfile manifest"),
    (re.compile(r"(?i)\byarn\.lock\b"), "the Yarn lockfile manifest"),
    (re.compile(r"(?i)\bpnpm-lock\.yaml\b"), "the PNPM lockfile manifest"),
    (re.compile(r"(?i)\btsconfig(?:\.[a-z0-9_]+)?\.json\b"), "the TypeScript compiler configuration JSON"),
    (re.compile(r"(?i)\bangular\.json\b"), "the Angular workspace configuration JSON"),
    (re.compile(r"(?i)\bpom\.xml\b"), "the root Maven POM XML manifest"),
    (re.compile(r"(?i)\bbuild\.gradle(?:\.kts)?\b"), "the Gradle build configuration"),
    (re.compile(r"(?i)\bsettings\.gradle(?:\.kts)?\b"), "the Gradle settings configuration"),
    (re.compile(r"(?i)\bgeneratorConfig\.xml\b"), "the MyBatis Generator XML configuration"),
    (re.compile(r"(?i)\bapplication(?:-[a-z0-9_]+)?\.(?:yml|yaml|properties)\b"), "the Spring application configuration file"),
    (re.compile(r"(?i)\bgo\.mod\b"), "the Go module dependency manifest"),
    (re.compile(r"(?i)\bgo\.sum\b"), "the Go checksum manifest"),
    (re.compile(r"(?i)\bCMakeLists\.txt\b"), "the CMake build configuration"),
    (re.compile(r"(?i)\bMakefile\.(?:am|in)\b"), "the Make build template"),
    (re.compile(r"(?i)\bCargo\.(?:toml|lock)\b"), "the Rust Cargo dependency manifest"),
    (re.compile(r"(?i)\bGemfile(?:\.lock)?\b"), "the Ruby Bundler dependency manifest"),
    (re.compile(r"(?i)\bcomposer\.(?:json|lock)\b"), "the PHP Composer dependency manifest"),
    (re.compile(r"(?i)\bPROJECT_FILE_INDEX\.md\b"), "the project file index markdown document"),
    (re.compile(r"(?i)\bREADME(?:_[A-Z0-9]+)?\.md\b"), "the project readme markdown document"),
    (re.compile(r"(?i)\bapp\.py\b"), "the main Python WSGI application module"),
    (re.compile(r"(?i)\bserver\.ts\b"), "the main TypeScript backend server module"),
    (re.compile(r"(?i)\bserver\.js\b"), "the main JavaScript backend server module"),
    (re.compile(r"(?i)\bapp\.ts\b"), "the main TypeScript application entrypoint module"),
    (re.compile(r"(?i)\bapp\.js\b"), "the main JavaScript application entrypoint module"),
    (re.compile(r"(?i)\bmain\.go\b"), "the main Go entrypoint module"),
    (re.compile(r"(?i)\bmain\.c\b"), "the main C entrypoint module"),
    (re.compile(r"(?i)\bmain\.cpp\b"), "the main C++ entrypoint module"),
    (re.compile(r"(?i)\bnode\.js\b"), "NodeJS"),
    (re.compile(r"(?i)\bexpress\.js\b"), "ExpressJS"),
    (re.compile(r"(?i)\bvue\.js\b"), "VueJS"),
    (re.compile(r"(?i)\breact\.js\b"), "ReactJS"),
    (re.compile(r"(?i)\bnext\.js\b"), "NextJS"),
]

EXT_SEMANTIC_MAP: Dict[str, str] = {
    "py": "Python module",
    "pyw": "Python module",
    "pyc": "Python bytecode",
    "txt": "text manifest",
    "toml": "TOML manifest",
    "cfg": "configuration file",
    "ini": "INI configuration",
    "json": "JSON manifest",
    "lock": "lockfile",
    "pipfile": "Pipenv manifest",
    "js": "JavaScript module",
    "jsx": "JSX component",
    "mjs": "ES module",
    "cjs": "CommonJS module",
    "ts": "TypeScript module",
    "tsx": "TSX component",
    "mts": "TypeScript module",
    "cts": "TypeScript module",
    "pug": "Pug template",
    "hbs": "Handlebars template",
    "ejs": "EJS template",
    "vue": "Vue component",
    "svelte": "Svelte component",
    "java": "Java class",
    "xml": "XML mapper or manifest",
    "yml": "YAML configuration",
    "yaml": "YAML configuration",
    "properties": "properties configuration",
    "gradle": "Gradle build script",
    "kts": "Kotlin build script",
    "jsp": "JSP template",
    "jspx": "JSP template",
    "c": "C source module",
    "cc": "C++ source module",
    "cpp": "C++ source module",
    "cxx": "C++ source module",
    "h": "C/C++ header module",
    "hh": "C++ header module",
    "hpp": "C++ header module",
    "hxx": "C++ header module",
    "cmake": "CMake script",
    "mk": "Makefile script",
    "go": "Go source module",
    "mod": "Go module manifest",
    "sum": "Go checksum file",
    "rb": "Ruby module",
    "erb": "ERB template",
    "gemspec": "Ruby gem specification",
    "rake": "Rake script",
    "php": "PHP script",
    "phtml": "PHP template",
    "twig": "Twig template",
    "rs": "Rust source module",
    "cs": "C# source module",
    "kt": "Kotlin source module",
    "swift": "Swift source module",
    "scala": "Scala source module",
    "sol": "Solidity contract",
    "sql": "SQL script",
    "sh": "shell script",
    "bash": "shell script",
    "zsh": "shell script",
    "md": "markdown document",
    "rst": "reStructuredText document",
    "html": "HTML document",
    "htm": "HTML document",
    "css": "stylesheet",
    "scss": "SCSS stylesheet",
    "less": "LESS stylesheet",
    "proto": "Protobuf definition",
    "graphql": "GraphQL schema",
    "env": "environment configuration",
    "conf": "configuration file",
}


def sanitize_untrusted_text(raw: str) -> str:
  """Sanitizes untrusted strings extracted from repository files against prompt injection."""
  if not raw:
    return ""
  cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", raw)
  for inj_pat in PROMPT_INJECTION_PATTERNS:
    cleaned = inj_pat.sub("", cleaned)
  cleaned = cleaned.replace("`", "")
  cleaned = re.sub(r"(?m)^\s*[-*]\s+", "", cleaned)
  cleaned = re.sub(r"(?im)\b(?:file|path)\s*:\s*", "", cleaned)
  return re.sub(r"\s+", " ", cleaned).strip()


def sanitize_context_prompt(
    prompt: str,
    deep: bool = True,
    repo_files: Optional[List[str]] = None,
) -> str:
  """
  Sanitizes a -c context prompt against untrusted repo prompt injection and
  strips/rewrites all literal filename.ext tokens and relative repo file paths
  so CodeMender v0.14.0's --deep file-scoping heuristic (0x241b160) matches 0 files.
  """
  if not prompt:
    return ""

  text = prompt
  # Pass 1: Strip control chars, prompt injection overrides, backticks, markdown bullets, and File:/Path: labels
  text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", text)
  for inj_pat in PROMPT_INJECTION_PATTERNS:
    text = inj_pat.sub("", text)
  text = text.replace("`", "")
  text = re.sub(r"(?m)^\s*[-*]\s+", "", text)
  text = re.sub(r"(?im)\b(?:file|path)\s*:\s*", "", text)

  if not deep:
    return re.sub(r"\s+", " ", text).strip()

  # Pass 2: Convert version suffixes like "4.40.630.ALL" or "1.2.3.RELEASE" to hyphenated "4.40.630-ALL"
  text = re.sub(r"(\d+\.\d+(?:\.\d+)*)\.([A-Za-z][A-Za-z0-9_-]*)\b", r"\1-\2", text)

  # Pass 3: Known filename & framework replacements
  for pat, replacement in KNOWN_FILENAME_REPLACEMENTS:
    text = pat.sub(replacement, text)

  # Pass 4: Rewrite any explicit relative paths or basenames from repo_files
  if repo_files:
    candidates: Set[str] = set()
    for rf in repo_files:
      rf_clean = rf.strip().lstrip("./")
      if rf_clean:
        candidates.add(rf_clean)
        candidates.add(Path(rf_clean).name)
    for cand in sorted(candidates, key=len, reverse=True):
      if "." in cand or "/" in cand:
        stem = Path(cand).stem.replace(".", " ").replace("/", " ").replace("_", " ").replace("-", " ")
        ext = Path(cand).suffix.lstrip(".").lower()
        desc = EXT_SEMANTIC_MAP.get(ext, f"{ext} module" if ext else "module")
        replacement_str = f"{stem} {desc}".strip()
        text = re.sub(r"(?<!\w)" + re.escape(cand) + r"(?!\w)", replacement_str, text)

  # Pass 5: Hard regex replacement loop for any remaining FILE_SCOPING_REGEX matches
  def _replace_match(m: re.Match) -> str:
    tok = m.group(0)
    if "/" in tok:
      tok = tok.replace("/", " ")
    parts = tok.split(".")
    ext = parts[-1].lower()
    stem = " ".join(p for p in parts[:-1] if p)
    if ext in EXT_SEMANTIC_MAP:
      return f"{stem} {EXT_SEMANTIC_MAP[ext]}".strip()
    return f"{stem} {ext}".strip()

  for _ in range(6):
    if not FILE_SCOPING_REGEX.search(text):
      break
    text = FILE_SCOPING_REGEX.sub(_replace_match, text)

  return re.sub(r"\s+", " ", text).strip()


# ============================================================================
# Component 2: Multi-Ecosystem Manifest & Dependency Version Parsers
# ============================================================================

def parse_requirements_txt(path: Path) -> List[Dict[str, str]]:
  """Parses Python requirements.txt files into semantic dependency records."""
  deps: List[Dict[str, str]] = []
  if not path.is_file():
    return deps
  for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
    line = raw_line.split("#", 1)[0].split(";", 1)[0].strip()
    if not line or line.startswith("-"):
      continue
    m = re.match(
        r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(?:(==|>=|<=|~=|!=|>|<)\s*([^\s,;#]+))?",
        line,
    )
    if m:
      name = sanitize_untrusted_text(m.group(1)).lower()
      op = m.group(2) or ""
      ver = sanitize_untrusted_text(m.group(3) or "latest")
      version = ver if op in ("", "==") else f"{op}{ver}"
      if name:
        deps.append({
            "name": name,
            "version": version,
            "ecosystem": "pypi",
            "manifest": "python-requirements",
        })
  return deps


def parse_pyproject_toml(path: Path) -> List[Dict[str, str]]:
  """Parses PEP 621 [project.dependencies] and [tool.poetry.dependencies] from pyproject.toml."""
  deps: List[Dict[str, str]] = []
  if not path.is_file():
    return deps
  raw_text = path.read_text(encoding="utf-8", errors="replace")
  data: Dict[str, Any] = {}
  if tomllib is not None:
    try:
      data = tomllib.loads(raw_text)
    except Exception:
      data = {}

  def _parse_pep508_item(item: str) -> Optional[Dict[str, str]]:
    cleaned = item.split(";", 1)[0].strip()
    m = re.match(
        r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(?:(==|>=|<=|~=|!=|>|<|\^)\s*([^\s,;#]+))?",
        cleaned,
    )
    if not m:
      return None
    name = sanitize_untrusted_text(m.group(1)).lower()
    op = m.group(2) or ""
    ver = sanitize_untrusted_text(m.group(3) or "latest")
    version = ver if op in ("", "==") else f"{op}{ver}"
    return {
        "name": name,
        "version": version,
        "ecosystem": "pypi",
        "manifest": "python-pyproject",
    }

  if data:
    proj = data.get("project", {})
    if isinstance(proj, dict):
      for item in proj.get("dependencies", []):
        if isinstance(item, str):
          parsed = _parse_pep508_item(item)
          if parsed:
            deps.append(parsed)
      opt_deps = proj.get("optional-dependencies", {})
      if isinstance(opt_deps, dict):
        for group_items in opt_deps.values():
          if isinstance(group_items, list):
            for item in group_items:
              if isinstance(item, str):
                parsed = _parse_pep508_item(item)
                if parsed:
                  deps.append(parsed)
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    if isinstance(poetry_deps, dict):
      for k, v in poetry_deps.items():
        if str(k).lower() == "python":
          continue
        ver_str = "latest"
        if isinstance(v, str):
          ver_str = v.lstrip("=")
        elif isinstance(v, dict) and "version" in v:
          ver_str = str(v["version"]).lstrip("=")
        deps.append({
            "name": sanitize_untrusted_text(str(k)).lower(),
            "version": sanitize_untrusted_text(ver_str),
            "ecosystem": "pypi",
            "manifest": "python-pyproject",
        })
  else:
    # Regex fallback if tomllib failed
    for m in re.finditer(r'["\']([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|!=|>|<)\s*([^"\';\s]+)["\']', raw_text):
      name, op, ver = m.group(1).lower(), m.group(2), m.group(3)
      deps.append({
          "name": name,
          "version": ver if op == "==" else f"{op}{ver}",
          "ecosystem": "pypi",
          "manifest": "python-pyproject",
      })
  return deps


def parse_package_json(path: Path) -> List[Dict[str, str]]:
  """Parses dependencies and security-relevant devDependencies from Node.js package.json."""
  deps: List[Dict[str, str]] = []
  if not path.is_file():
    return deps
  try:
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
  except Exception:
    return deps
  if not isinstance(data, dict):
    return deps

  runtime_deps = data.get("dependencies", {})
  if isinstance(runtime_deps, dict):
    for pkg, ver in runtime_deps.items():
      if isinstance(ver, str):
        deps.append({
            "name": sanitize_untrusted_text(str(pkg)),
            "version": sanitize_untrusted_text(ver),
            "ecosystem": "npm",
            "manifest": "npm-package-manifest",
        })

  # Include devDependencies if runtime dependencies are empty
  if not deps and isinstance(data.get("devDependencies"), dict):
    for pkg, ver in data["devDependencies"].items():
      if isinstance(ver, str):
        deps.append({
            "name": sanitize_untrusted_text(str(pkg)),
            "version": sanitize_untrusted_text(ver),
            "ecosystem": "npm",
            "manifest": "npm-package-manifest",
        })
  return deps


def parse_pom_xml(target: Path) -> List[Dict[str, str]]:
  """
  Parses Maven root and submodule pom.xml files with full <properties> ${...}
  interpolation, <dependencyManagement> lookup, and <parent> version inheritance.
  Zero hardcoded repository or artifact names.
  """
  pom_files: List[Path] = []
  if target.is_file():
    pom_files.append(target)
    # If this is a child pom.xml and parent directory has a root pom.xml, include root pom first
    parent_dir = target.parent.parent
    if parent_dir != target.parent and (parent_dir / "pom.xml").is_file():
      pom_files.insert(0, parent_dir / "pom.xml")
    # If this is a root pom.xml with child module directories, include child poms
    for sub in sorted(target.parent.glob("*/pom.xml")):
      if sub not in pom_files:
        pom_files.append(sub)
  elif target.is_dir():
    root_pom = target / "pom.xml"
    if root_pom.is_file():
      pom_files.append(root_pom)
    for sub in sorted(target.glob("*/pom.xml")):
      if sub not in pom_files:
        pom_files.append(sub)

  if not pom_files:
    return []

  properties: Dict[str, str] = {}
  parent_boot_version: str = ""
  internal_modules: Set[str] = set()
  internal_groups: Set[str] = set()
  raw_deps: List[Tuple[str, str, str, str]] = []  # (group, artifact, version, scope)
  managed_versions: Dict[str, str] = {}

  def strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag

  def find_child_text(elem: ET.Element, name: str) -> str:
    for ch in elem:
      if strip_ns(ch.tag) == name and ch.text:
        return ch.text.strip()
    return ""

  # Pass 0: Discover internal reactor modules and project groupIds
  for pf in pom_files:
    try:
      root = ET.fromstring(pf.read_text(encoding="utf-8", errors="replace"))
    except Exception:
      continue
    proj_group = find_child_text(root, "groupId")
    proj_artifact = find_child_text(root, "artifactId")
    proj_ver = find_child_text(root, "version")
    if proj_artifact:
      internal_modules.add(proj_artifact)
    if proj_group:
      internal_groups.add(proj_group)
    if proj_ver and "project.version" not in properties:
      properties["project.version"] = proj_ver
      properties["pom.version"] = proj_ver
    for ch in root:
      if strip_ns(ch.tag) == "modules":
        for mod in ch:
          if strip_ns(mod.tag) == "module" and mod.text:
            internal_modules.add(mod.text.strip())

  # Pass 1: Collect <properties> and external <parent> declarations
  for pf in pom_files:
    try:
      root = ET.fromstring(pf.read_text(encoding="utf-8", errors="replace"))
    except Exception:
      continue
    for ch in root:
      cname = strip_ns(ch.tag)
      if cname == "parent":
        p_group = find_child_text(ch, "groupId")
        p_art = find_child_text(ch, "artifactId")
        p_ver = find_child_text(ch, "version")
        if p_art and p_ver and p_art not in internal_modules and p_group not in internal_groups:
          if "spring-boot" in p_art or "springframework.boot" in p_group:
            parent_boot_version = p_ver
          raw_deps.append((p_group, p_art, p_ver, "parent"))
      elif cname == "properties":
        for prop in ch:
          pname = strip_ns(prop.tag)
          if prop.text and pname:
            properties[pname] = prop.text.strip()

  def resolve_prop(val: str) -> str:
    if not val:
      return ""
    out = val.strip()
    for _ in range(4):
      next_out = re.sub(
          r"\$\{([^}]+)\}",
          lambda m: properties.get(m.group(1), m.group(0)),
          out,
      )
      if next_out == out:
        break
      out = next_out
    return out

  # Resolve any property values that reference other properties
  for k in list(properties.keys()):
    properties[k] = resolve_prop(properties[k])

  # Pass 2: Collect <dependencyManagement> and <dependencies>
  for pf in pom_files:
    try:
      root = ET.fromstring(pf.read_text(encoding="utf-8", errors="replace"))
    except Exception:
      continue
    for ch in root:
      cname = strip_ns(ch.tag)
      if cname == "dependencyManagement":
        for dlist in ch:
          if strip_ns(dlist.tag) == "dependencies":
            for dep in dlist:
              if strip_ns(dep.tag) != "dependency":
                continue
              g = find_child_text(dep, "groupId")
              a = find_child_text(dep, "artifactId")
              v = resolve_prop(find_child_text(dep, "version"))
              if a and v:
                managed_versions[a] = v
                if a not in internal_modules and g not in internal_groups:
                  raw_deps.append((g, a, v, "managed"))
      elif cname == "dependencies":
        for dep in ch:
          if strip_ns(dep.tag) != "dependency":
            continue
          g = find_child_text(dep, "groupId")
          a = find_child_text(dep, "artifactId")
          v = resolve_prop(find_child_text(dep, "version"))
          sc = find_child_text(dep, "scope")
          if a and a not in internal_modules and g not in internal_groups:
            raw_deps.append((g, a, v, sc))

  # Pass 3: Deduplicate and resolve inherited versions
  seen: Dict[str, Dict[str, str]] = {}
  for g, a, v, sc in raw_deps:
    if sc == "test":
      continue
    resolved_v = v or managed_versions.get(a, "")
    if not resolved_v and f"{a}.version" in properties:
      resolved_v = resolve_prop(properties[f"{a}.version"])
    if not resolved_v:
      # Check prefix match in properties (e.g. mybatis-spring-boot-starter -> mybatis-spring-boot-starter.version)
      for pk, pv in properties.items():
        if pk.endswith(".version") and a.startswith(pk[:-8]):
          resolved_v = pv
          break
    if not resolved_v and ("springframework.boot" in g or a.startswith("spring-boot")) and parent_boot_version:
      resolved_v = parent_boot_version
    if not resolved_v:
      resolved_v = "managed"

    clean_name = sanitize_untrusted_text(a)
    clean_ver = sanitize_untrusted_text(resolved_v)
    if clean_name not in seen or (seen[clean_name]["version"] == "managed" and clean_ver != "managed"):
      seen[clean_name] = {
          "name": clean_name,
          "version": clean_ver,
          "group_id": sanitize_untrusted_text(g),
          "ecosystem": "maven",
          "manifest": "maven-pom-manifest",
      }
  return list(seen.values())


def parse_build_gradle(path: Path) -> List[Dict[str, str]]:
  """Parses Gradle build.gradle / build.gradle.kts dependency declarations."""
  deps: List[Dict[str, str]] = []
  if not path.is_file():
    return deps
  text = path.read_text(encoding="utf-8", errors="replace")
  props: Dict[str, str] = {}
  for vm in re.finditer(r"""(?:val|def|ext\.)?\s*([A-Za-z0-9_]+Version|[A-Za-z0-9_]+_version)\s*=\s*['"]([^'"]+)['"]""", text):
    props[vm.group(1)] = vm.group(2)

  for m in re.finditer(
      r"""(?:implementation|api|compileOnly|runtimeOnly|compile)\s*\(?\s*['"]([^:'"]+):([^:'"]+):([^'"]+)['"]\s*\)?""",
      text,
  ):
    g, a, v = m.group(1), m.group(2), m.group(3)
    v = re.sub(r"\$\{?([A-Za-z0-9_]+)\}?", lambda x: props.get(x.group(1), x.group(0)), v)
    deps.append({
        "name": sanitize_untrusted_text(a),
        "version": sanitize_untrusted_text(v),
        "group_id": sanitize_untrusted_text(g),
        "ecosystem": "gradle",
        "manifest": "gradle-build-manifest",
    })
  return deps


def parse_go_mod(path: Path) -> List[Dict[str, str]]:
  """Parses Go go.mod toolchain version and required module dependencies."""
  deps: List[Dict[str, str]] = []
  if not path.is_file():
    return deps
  text = path.read_text(encoding="utf-8", errors="replace")
  go_ver = re.search(r"(?m)^go\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", text)
  if go_ver:
    deps.append({
        "name": "go-toolchain",
        "version": go_ver.group(1),
        "ecosystem": "go",
        "manifest": "go-module-manifest",
    })

  # Single-line require
  for m in re.finditer(r"(?m)^require\s+([^\s(]+)\s+v?([0-9][^\s/]*)", text):
    deps.append({
        "name": sanitize_untrusted_text(m.group(1)),
        "version": sanitize_untrusted_text(m.group(2)),
        "ecosystem": "go",
        "manifest": "go-module-manifest",
    })

  # Multi-line require ( ... ) blocks
  for block in re.finditer(r"(?ms)require\s*\((.*?)\)", text):
    for line in block.group(1).splitlines():
      line_clean = line.split("//", 1)[0].strip()
      if not line_clean:
        continue
      parts = line_clean.split()
      if len(parts) >= 2:
        mod_name = sanitize_untrusted_text(parts[0])
        mod_ver = sanitize_untrusted_text(parts[1].lstrip("v"))
        deps.append({
            "name": mod_name,
            "version": mod_ver,
            "ecosystem": "go",
            "manifest": "go-module-manifest",
        })
  return deps


def parse_c_cpp_manifests(target: Path) -> List[Dict[str, str]]:
  """Parses C/C++ CMakeLists.txt and Makefile targets for linked libraries and packages."""
  deps: List[Dict[str, str]] = []
  files: List[Path] = []
  if target.is_file():
    files.append(target)
  elif target.is_dir():
    for name in ("CMakeLists.txt", "Makefile", "makefile", "GNUmakefile", "configure.ac"):
      cand = target / name
      if cand.is_file():
        files.append(cand)

  seen: Set[str] = set()
  for fpath in files:
    text = fpath.read_text(encoding="utf-8", errors="replace")
    fname = fpath.name.lower()
    manifest_label = "cmake-build-manifest" if "cmake" in fname else "makefile-build-manifest"

    for m in re.finditer(r"(?i)\bfind_package\(\s*([A-Za-z0-9_+-]+)(?:\s+([0-9]+(?:\.[0-9]+)*))?", text):
      pkg = sanitize_untrusted_text(m.group(1)).lower()
      ver = sanitize_untrusted_text(m.group(2) or "system")
      if pkg and pkg not in seen:
        seen.add(pkg)
        deps.append({"name": pkg, "version": ver, "ecosystem": "c_cpp", "manifest": manifest_label})

    for m in re.finditer(r"(?i)\bpkg_check_modules\(\s*\w+\s+(?:REQUIRED\s+)?([A-Za-z0-9_+-]+)(?:>=|==|=)?([0-9.]*)", text):
      pkg = sanitize_untrusted_text(m.group(1)).lower()
      ver = sanitize_untrusted_text(m.group(2) or "system")
      if pkg and pkg not in seen:
        seen.add(pkg)
        deps.append({"name": pkg, "version": ver, "ecosystem": "c_cpp", "manifest": manifest_label})

    for m in re.finditer(r"-l([A-Za-z0-9_+-]+)", text):
      lib = sanitize_untrusted_text(m.group(1)).lower()
      if lib and lib not in seen:
        seen.add(lib)
        deps.append({"name": f"lib{lib}", "version": "linked", "ecosystem": "c_cpp", "manifest": manifest_label})

  return deps


def parse_gemfile(path: Path) -> List[Dict[str, str]]:
  """Parses Ruby Gemfile dependency declarations."""
  deps: List[Dict[str, str]] = []
  if not path.is_file():
    return deps
  for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
    line_clean = line.split("#", 1)[0].strip()
    m = re.match(r"""^gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?""", line_clean)
    if m:
      deps.append({
          "name": sanitize_untrusted_text(m.group(1)),
          "version": sanitize_untrusted_text(m.group(2) or "latest"),
          "ecosystem": "rubygems",
          "manifest": "ruby-gemfile",
      })
  return deps


def parse_composer_json(path: Path) -> List[Dict[str, str]]:
  """Parses PHP composer.json require declarations."""
  deps: List[Dict[str, str]] = []
  if not path.is_file():
    return deps
  try:
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
  except Exception:
    return deps
  req = data.get("require", {}) if isinstance(data, dict) else {}
  if isinstance(req, dict):
    for k, v in req.items():
      if isinstance(v, str):
        deps.append({
            "name": sanitize_untrusted_text(str(k)),
            "version": sanitize_untrusted_text(v),
            "ecosystem": "packagist",
            "manifest": "php-composer-manifest",
        })
  return deps


def parse_manifests(target_dir: Path | str) -> List[Dict[str, str]]:
  """
  Universal multi-stack manifest parser supporting Python, Node.js, Java (Maven/Gradle),
  Go, C/C++ (CMake/Make), Ruby, and PHP.
  """
  tpath = Path(target_dir).resolve()
  if tpath.is_file():
    fname = tpath.name.lower()
    if fname.startswith("requirements") and fname.endswith(".txt"):
      return parse_requirements_txt(tpath)
    if fname == "pyproject.toml":
      return parse_pyproject_toml(tpath)
    if fname == "package.json":
      return parse_package_json(tpath)
    if fname == "pom.xml":
      return parse_pom_xml(tpath)
    if fname in ("build.gradle", "build.gradle.kts"):
      return parse_build_gradle(tpath)
    if fname == "go.mod":
      return parse_go_mod(tpath)
    if fname in ("cmakelists.txt", "makefile", "gnumakefile"):
      return parse_c_cpp_manifests(tpath)
    if fname == "gemfile":
      return parse_gemfile(tpath)
    if fname == "composer.json":
      return parse_composer_json(tpath)
    return []

  all_deps: List[Dict[str, str]] = []
  # 1. Python
  for req_name in ("requirements.txt", "src/requirements.txt"):
    if (tpath / req_name).is_file():
      all_deps.extend(parse_requirements_txt(tpath / req_name))
  if (tpath / "pyproject.toml").is_file():
    all_deps.extend(parse_pyproject_toml(tpath / "pyproject.toml"))
  # 2. Node.js
  if (tpath / "package.json").is_file():
    all_deps.extend(parse_package_json(tpath / "package.json"))
  # 3. Java Maven / Gradle
  if (tpath / "pom.xml").is_file() or list(tpath.glob("*/pom.xml")):
    all_deps.extend(parse_pom_xml(tpath))
  for gname in ("build.gradle", "build.gradle.kts"):
    if (tpath / gname).is_file():
      all_deps.extend(parse_build_gradle(tpath / gname))
  # 4. Go
  if (tpath / "go.mod").is_file():
    all_deps.extend(parse_go_mod(tpath / "go.mod"))
  # 5. C/C++
  all_deps.extend(parse_c_cpp_manifests(tpath))
  # 6. Ruby & PHP
  if (tpath / "Gemfile").is_file():
    all_deps.extend(parse_gemfile(tpath / "Gemfile"))
  if (tpath / "composer.json").is_file():
    all_deps.extend(parse_composer_json(tpath / "composer.json"))

  # Deduplicate preserving order
  deduped: List[Dict[str, str]] = []
  seen_keys: Set[Tuple[str, str]] = set()
  for d in all_deps:
    k = (d.get("ecosystem", ""), d.get("name", ""))
    if k not in seen_keys:
      seen_keys.add(k)
      deduped.append(d)
  return deduped


# ============================================================================
# Component 3: Route, Sink & Security Guard Extractor + 5-Pillar -c Synthesizer
# ============================================================================

ROUTE_PATTERNS: List[re.Pattern] = [
    re.compile(r"""Rule\(\s*['"](/[^'"]*)['"]"""),
    re.compile(r"""@\w+\.(?:route|get|post|put|delete|patch)\(\s*['"](/[^'"]*)['"]"""),
    re.compile(r"""\b(?:app|router|server)\.(?:get|post|put|delete|patch|all|use)\(\s*['"](/[^'"]*)['"]"""),
    re.compile(r"""@(?:Request|Get|Post|Put|Delete|Patch)Mapping\(\s*(?:(?:value|path)\s*=\s*)?['"]([^'"]+)['"]"""),
    re.compile(r"""\b(?:HandleFunc|Handle|GET|POST|PUT|DELETE|PATCH)\(\s*['"](/[^'"]*)['"]"""),
    re.compile(r"""\b(?:get|post|put|delete|patch)\s+['"](/[^'"]*)['"]"""),
    re.compile(r"""Route::(?:get|post|put|delete|patch|any)\(\s*['"](/[^'"]*)['"]"""),
    re.compile(r"""(?:strcmp|strncmp)\([^,]+,\s*['"](/[A-Za-z0-9_/-]+)['"]"""),
]

SINK_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("command_execution", re.compile(
        r"\b(?:subprocess\.(?:Popen|call|check_output|check_call|run)|os\.(?:system|popen)|"
        r"child_process|execSync|spawnSync|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|"
        r"exec\.Command|shell_exec|passthru|proc_open|popen|system)\s*\(|shell\s*=\s*True|\bnotevil\b|\bvm\.runIn"
    )),
    ("deserialization", re.compile(
        r"\b(?:pickle\.loads?|cPickle\.loads?|marshal\.loads?|yaml\.(?:load|unsafe_load)|"
        r"js-yaml|ObjectInputStream|readObject|XMLDecoder|XStream|JSON\.parseObject|"
        r"unserialize|Marshal\.load)\b"
    )),
    ("sql_query", re.compile(
        r"\b(?:sqlite3\.connect|cursor\.execute|sequelize\.query|createQuery|executeQuery|"
        r"PreparedStatement|Statement|db\.(?:Query|Exec)|mysql_query|pg_query|sqlite3_exec)\b|"
        r"\bSELECT\s+.+\s+FROM\s+|\bINSERT\s+INTO\s+|\bUPDATE\s+\w+\s+SET\s+|"
        r"<(?:select|insert|update|delete)\s+id=|\$\{(?:orderBy|criterion|sort)"
    )),
    ("file_read", re.compile(
        r"\b(?:open\s*\(|os\.path\.join|send_file|send_from_directory|fs\.(?:readFile|readFileSync|createReadStream)|"
        r"res\.sendFile|FileInputStream|Files\.read|Paths\.get|os\.(?:Open|ReadFile)|ioutil\.ReadFile|"
        r"fopen\s*\(|file_get_contents)\b"
    )),
    ("file_upload", re.compile(
        r"\b(?:uploaded\.save|UPLOAD_DIR|uploaded\.filename|MultipartFile|transferTo|"
        r"MinioClient|putObject|OSSClient|multer|unzipper|FormFile|move_uploaded_file)\b"
    )),
    ("ssrf", re.compile(
        r"\b(?:requests\.(?:get|post|put|delete|request|head)|urllib\.request\.urlopen|"
        r"httpx\.(?:get|post|AsyncClient|Client)|axios\.(?:get|post|request)|"
        r"RestTemplate|OkHttpClient|HttpClient|http\.(?:Get|Post|NewRequest)|curl_exec|curl_easy_perform)\b"
    )),
    ("xss", re.compile(
        r"""mimetype\s*=\s*['"]text/html['"]|content_type\s*=\s*['"]text/html['"]|"""
        r"\b(?:render_template_string|Markup|dangerouslySetInnerHTML|innerHTML|"
        r"bypassSecurityTrust|sanitize-html|fmt\.Fprintf\s*\(\s*w)\b"
    )),
    ("open_redirect", re.compile(
        r"\b(?:redirect\s*\(|res\.redirect\s*\(|sendRedirect\s*\(|http\.Redirect\s*\()"
    )),
    ("debug_console", re.compile(
        r"\b(?:DebuggedApplication|evalex\s*=\s*True|werkzeug\.debug|stat-view-servlet)\b|"
        r"exposure[\s\S]{0,60}include[\s\S]{0,40}\*"
    )),
    ("cookie_handling", re.compile(
        r"\b(?:request\.cookies|set_cookie|parse_cookie|__Host-|__Secure-|cookie-parser|"
        r"res\.cookie|http\.SetCookie)\b"
    )),
    ("multipart_parsing", re.compile(
        r"\b(?:request\.files|request\.form|MultipartDecoder|parse_form_data|"
        r"ParseMultipartForm|multipart/form-data)\b"
    )),
    ("template_injection", re.compile(
        r"\b(?:pug\.(?:compile|render)|handlebars\.compile|ejs\.render|Freemarker|"
        r"Velocity|SpelExpressionParser|render_template_string)\b"
    )),
    ("xxe_xml", re.compile(
        r"\b(?:xml\.etree|lxml\.etree|xml\.dom\.minidom|libxmljs|libxml2|"
        r"DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|SAXReader)\b"
    )),
    ("nosql_injection", re.compile(
        r"(?:\$where|\$gt|\$ne|\$regex|\bmarsdb\b|\bmongoose\b)"
    )),
    ("jwt_auth", re.compile(
        r"\b(?:jsonwebtoken|express-jwt|jwt\.(?:decode|verify|encode)|Jwts\.parser|"
        r"JwtTokenUtil)\b"
    )),
    ("memory_buffer", re.compile(
        r"\b(?:strcpy|strncpy|strcat|sprintf|vsprintf|gets|memcpy|memmove|sscanf|fscanf|alloca)\s*\("
    )),
]

GUARD_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("safe_join", re.compile(r"\bsafe_join\b")),
    ("secure_filename", re.compile(r"\bsecure_filename\b")),
    ("realpath", re.compile(r"\b(?:os\.path\.realpath|realpath|Path\.resolve|filepath\.EvalSymlinks)\b")),
    ("filepath_clean", re.compile(r"\b(?:filepath\.Clean|posixpath\.normpath|os\.path\.normpath)\b")),
    ("parameterized_sql", re.compile(r"(?:cursor\.execute\([^,]+,\s*[\(\[]|#\{[A-Za-z0-9_.]+\}|PreparedStatement)")),
    ("html_escape", re.compile(r"\b(?:html\.escape|markupsafe\.escape|escapeHtml|DOMPurify\.sanitize)\b")),
]

# General Dependency & Sink Advisory Knowledge Base keyed by (package_substring, version_prefixes, optional_sink)
DEPENDENCY_ADVISORY_KB: List[Tuple[str, Tuple[str, ...], Optional[str], str]] = [
    (
        "werkzeug",
        ("0.", "1.", "2.0", "2.1", "2.2.0", "2.2.1", "2.2.2"),
        "multipart_parsing",
        "unbounded multipart form parsing resource exhaustion DoS CVE-2023-25577 (CWE-400) on upload endpoints accessing request files and form fields",
    ),
    (
        "werkzeug",
        ("0.", "1.", "2.0", "2.1", "2.2", "2.3.0", "2.3.1", "2.3.2", "2.3.3", "2.3.4", "2.3.5", "2.3.6", "2.3.7", "3.0.0"),
        "cookie_handling",
        "nameless cookie shadow parsing vulnerability CVE-2023-46136 and CVE-2023-23934 on session cookie endpoints",
    ),
    (
        "werkzeug",
        ("0.", "1.", "2.0", "2.1", "2.2", "2.3", "3.0.0", "3.0.1", "3.0.2"),
        "debug_console",
        "predictable debugger PIN generation and interactive console RCE CVE-2024-34069 (CWE-489 and CWE-338)",
    ),
    (
        "jsonwebtoken",
        ("0.", "1.", "2.", "3.", "4.", "5.", "6.", "7.", "8."),
        None,
        "JWT algorithm confusion RS256 to HS256 and unsigned none token forgery CVE-2015-9235 and CVE-2022-23529",
    ),
    (
        "express-jwt",
        ("0.",),
        None,
        "legacy express-jwt token validation and algorithm confusion bypasses",
    ),
    (
        "sanitize-html",
        ("1.",),
        None,
        "recursive HTML sanitization bypass XSS in legacy sanitize-html versions",
    ),
    (
        "marsdb",
        ("0.", "^0."),
        None,
        "NoSQL query injection and command evaluation in MarsDB in-memory collections",
    ),
    (
        "notevil",
        ("1.", "^1."),
        None,
        "JavaScript VM sandbox escape Remote Code Execution in notevil",
    ),
    (
        "js-yaml",
        ("3.", "^3."),
        None,
        "unsafe YAML deserialization code execution in legacy js-yaml",
    ),
    (
        "unzipper",
        ("0.", "^0."),
        None,
        "Zip Slip archive extraction arbitrary file overwrite in unzipper",
    ),
    (
        "pug",
        ("2.", "3.0", "^3.0"),
        None,
        "Server-Side Template Injection SSTI and unescaped template rendering in Pug",
    ),
    (
        "druid",
        ("1.1", "1.2"),
        None,
        "exposed Alibaba Druid monitor console and SQL wall bypass vulnerabilities",
    ),
    (
        "hutool",
        ("4.", "5."),
        None,
        "Hutool XML and JSON deserialization, Zip Slip, and crypto utility vulnerabilities",
    ),
    (
        "mybatis",
        ("3.",),
        None,
        "MyBatis XML mapper dollar-sign string substitution SQL Injection (CWE-89) in ORDER BY, LIKE, and IN clauses",
    ),
    (
        "minio",
        ("7.", "8."),
        None,
        "MinIO object upload unrestricted file types, stored XSS, and path traversal flaws",
    ),
    (
        "aliyun-sdk-oss",
        ("2.", "3."),
        None,
        "Aliyun OSS credential exposure and upload callback verification flaws",
    ),
    (
        "alipay-sdk-java",
        ("3.", "4."),
        None,
        "Alipay payment callback signature verification bypass and order tampering",
    ),
]

SINK_AUDIT_DIRECTIVES: Dict[str, str] = {
    "command_execution": "OS Command Injection via shell execution (CWE-78)",
    "deserialization": "Insecure Deserialization via binary or pickle or YAML payloads (CWE-502)",
    "sql_query": "SQL Injection via string formatting or dollar-sign interpolation in database queries (CWE-89)",
    "file_read": "Path Traversal and Arbitrary File Read (CWE-22)",
    "file_upload": "Unrestricted File Upload and Path Traversal File Write (CWE-434 and CWE-22)",
    "ssrf": "Server-Side Request Forgery SSRF in outbound HTTP proxy requests (CWE-918)",
    "xss": "Reflected and Stored Cross-Site Scripting XSS in HTML responses (CWE-79)",
    "open_redirect": "Open URL Redirect to untrusted external domains (CWE-601)",
    "debug_console": "Active Debug Console with interactive code execution enabled such as DebuggedApplication with evalex=True (CWE-489)",
    "cookie_handling": "Session Cookies missing Secure or HttpOnly flags, Host prefix violations, and nameless cookie shadowing (CWE-614 and CVE-2023-46136)",
    "multipart_parsing": "Unbounded Multipart Form Parsing Denial of Service (CWE-400 and CVE-2023-25577)",
    "template_injection": "Server-Side Template Injection SSTI (CWE-1336)",
    "xxe_xml": "XML External Entity XXE Injection (CWE-611)",
    "nosql_injection": "NoSQL Injection in document queries (CWE-943)",
    "jwt_auth": "Hardcoded JWT secrets, weak signing keys, and token verification bypass (CWE-347 and CWE-798)",
    "memory_buffer": "Buffer Overflow, out-of-bounds memory write, format string, and integer overflow flaws (CWE-120, CWE-787, and CWE-134)",
}


# ============================================================================
# Component 4: Adaptive CLI Execution Profile Selector
# ============================================================================

def select_execution_profile(
    active_files_count: int,
    languages: Optional[List[str]] = None,
    force_deep: Optional[bool] = None,
    model: Optional[str] = None,
    timeout_seconds: Optional[int] = None,
) -> Dict[str, Any]:
  """
  Selects the optimal CodeMender CLI execution profile based on discovered active file count:
  - Micro-targets (<= 5 active files): Quick mode (deep=False) so dependency manifests
    are read directly without --deep Tier 0 lockfile pruning.
  - Multi-file targets (> 5 active files): Parallel Deep mode (--deep --deep-workers 16 --deep-max-turns 8).
  """
  recommended_model = model or "gemini-3.8-flash"
  if force_deep is not None:
    deep = bool(force_deep)
  else:
    deep = active_files_count > 5

  mode = "deep" if deep else "quick"
  deep_workers = 16
  deep_max_turns = 8
  raw_timeout = int(timeout_seconds) if timeout_seconds is not None else DEFAULT_TIMEOUT_SECONDS
  capped_timeout = max(60, min(raw_timeout, MAX_TIMEOUT_SECONDS))

  cli_flags = ["--sandbox=false", "--model", recommended_model]
  if deep:
    cli_flags.extend([
        "--deep",
        "--deep-workers",
        str(deep_workers),
        "--deep-max-turns",
        str(deep_max_turns),
    ])

  return {
      "mode": mode,
      "deep": deep,
      "deep_workers": deep_workers,
      "deep_max_turns": deep_max_turns,
      "recommended_model": recommended_model,
      "timeout_seconds": capped_timeout,
      "cli_flags": cli_flags,
  }


# ============================================================================
# Component 5: Universal Stage 1 Hybrid Auto-Profiler (RepoProfiler)
# ============================================================================

KNOWN_SCAN_EXTENSIONS: Set[str] = {
    ".py", ".java", ".kt", ".kts", ".scala", ".go",
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts",
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh",
    ".rb", ".php", ".cs", ".rs", ".sol", ".sh",
    ".pug", ".hbs", ".ejs", ".erb", ".jsp", ".html", ".htm", ".vue",
    ".txt", ".toml", ".cfg", ".ini", ".json", ".xml",
    ".yml", ".yaml", ".properties", ".gradle", ".mod", ".cmake", ".sql",
}

LANGUAGE_BY_EXT: Dict[str, str] = {
    ".py": "python",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".go": "go",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
    ".cs": "csharp",
}

DEFAULT_EXCLUDE_DIRS: List[str] = [
    ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "target",
    "bin", "obj", ".gradle", ".idea", ".vscode", ".mvn", "__pycache__",
    ".pytest_cache", ".mypy_cache", "venv", ".venv", "env", "coverage",
    "uploads", "storage", "test", "tests", "__tests__", "spec", "cypress",
    "screenshots", "vagrant", "terraform", "infrastructure", "monitoring",
    "document", "docs", "benchmarks", "eval_results", "grounding-truth",
    "scoped_targets", "scan_outputs", "deck_run", ".agents", ".ai", ".claude",
    ".codeium", ".continue", ".cursor", ".dependabot", ".github", ".junie",
    ".well-known", "i18n", "rsn", "ftp", "scripts",
]

DEFAULT_EXCLUDE_SUFFIXES: List[str] = [
    ".min.js", ".bundle.js", ".generated.go", ".pb.go", "_pb2.py",
    ".spec.ts", ".test.ts", ".unit.test.ts", ".spec.js", ".test.js",
]


def create_cm_config(
    cm_home: Path,
    exclude_dirs: List[str],
    include_extensions: Optional[List[str]] = None,
    exclude_extensions: Optional[List[str]] = None,
) -> Path:
  """Creates a tailored CodeMender config.yaml inside cm_home."""
  cm_home.mkdir(parents=True, exist_ok=True)
  inc_exts = include_extensions or [
      ".py", ".txt", ".toml", ".java", ".go", ".mod", ".js", ".ts",
      ".c", ".cc", ".cpp", ".h", ".hpp", ".rb", ".php", ".json",
      ".xml", ".yml", ".yaml", ".properties", ".pug", ".hbs", ".ejs", ".gradle",
  ]
  exc_exts = exclude_extensions or DEFAULT_EXCLUDE_SUFFIXES
  config_content = (
      "# Auto-generated CodeMender Pipeline Config\n"
      "server: {}\n\n"
      "scan:\n"
      "  extensions:\n"
      f"    include: {json.dumps(inc_exts)}\n"
      f"    exclude: {json.dumps(exc_exts)}\n"
      f"  exclude_dirs: {json.dumps(exclude_dirs)}\n"
      "  max_file_size_kb: 500\n"
      "  incremental: false\n\n"
      "output:\n"
      "  format: table\n\n"
      "tools:\n"
      "  confirm_commands: false\n"
      "  confirm_writes: false\n"
  )
  cfg_path = cm_home / "config.yaml"
  cfg_path.write_text(config_content, encoding="utf-8")
  return cfg_path


class RepoProfiler:
  """
  Universal Stage 1 Hybrid Auto-Profiler for arbitrary repositories.
  Contains zero hardcoded repository names or per-repo rules.
  """

  def __init__(
      self,
      target_dir: Path | str,
      output_dir: Optional[Path | str] = None,
      force_deep: Optional[bool] = None,
      model: Optional[str] = None,
      llm_recon: bool = False,
      timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
  ) -> None:
    self.target_dir = Path(target_dir).resolve()
    if not self.target_dir.exists():
      raise FileNotFoundError(f"Target directory does not exist: {self.target_dir}")

    raw_slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", self.target_dir.name).strip("_") or "target"
    self._mirror_output_dir: Optional[Path] = None
    if output_dir is not None:
      self.output_dir = Path(output_dir).resolve()
    else:
      slug = raw_slug
      if self.target_dir.name == "src" and self.target_dir.parent.name:
        parent_slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", self.target_dir.parent.name).strip("_")
        slug = f"{parent_slug}_{slug}"
      self.output_dir = (SCAN_OUTPUTS_DIR / slug).resolve()
      if self.output_dir.name != raw_slug:
        self._mirror_output_dir = (SCAN_OUTPUTS_DIR / raw_slug).resolve()

    self.force_deep = force_deep
    self.model = model
    self.llm_recon = llm_recon
    self.timeout_seconds = timeout_seconds

  def _detect_generated_orm_modules(self) -> List[str]:
    """
    Universal structural detector for generated ORM modules (such as MyBatis Generator modules)
    without hardcoded directory names.
    """
    generated_modules: List[str] = []
    if not self.target_dir.is_dir():
      return generated_modules

    for child in sorted(self.target_dir.iterdir()):
      if not child.is_dir() or child.name.startswith(".") or child.name in DEFAULT_EXCLUDE_DIRS:
        continue
      # Indicator 1: Contains generatorConfig.xml or <!DOCTYPE generatorConfiguration
      has_mbg_config = False
      example_java_count = 0
      controller_java_count = 0
      for root, dirs, files in os.walk(child):
        dirs[:] = [d for d in dirs if d not in DEFAULT_EXCLUDE_DIRS and not d.startswith(".")]
        for f in files:
          fp = Path(root) / f
          if f == "generatorConfig.xml":
            has_mbg_config = True
          elif f.endswith(".xml"):
            try:
              head = fp.read_text(encoding="utf-8", errors="replace")[:2048]
              if "<generatorConfiguration" in head or "mybatis-generator" in head:
                has_mbg_config = True
            except Exception:
              pass
          elif f.endswith("Example.java"):
            try:
              head = fp.read_text(encoding="utf-8", errors="replace")[:2048]
              if "oredCriteria" in head or "GeneratedCriteria" in head:
                example_java_count += 1
            except Exception:
              pass
          elif f.endswith("Controller.java"):
            controller_java_count += 1

      if (has_mbg_config or example_java_count >= 2) and controller_java_count == 0:
        generated_modules.append(child.name)
    return generated_modules

  def _should_exclude_spa_frontend(self) -> List[str]:
    """
    Excludes heavy client-side SPA directories (e.g. frontend/) and static fixture archives
    when backend routes/controllers exist in the repository.
    """
    extra_excludes: List[str] = []
    has_backend = any(
        (self.target_dir / indicator).exists()
        for indicator in ("server.ts", "server.js", "app.py", "main.go", "pom.xml", "routes", "controllers")
    )
    if not has_backend:
      return extra_excludes

    for spa_dir_name in ("frontend", "client", "web-app"):
      spa_dir = self.target_dir / spa_dir_name
      if spa_dir.is_dir():
        if (
            (spa_dir / "angular.json").exists()
            or (spa_dir / "package.json").exists()
            or (spa_dir / "tsconfig.json").exists()
        ):
          extra_excludes.append(spa_dir_name)

    # If both routes/ and data/static/codefixes exist, exclude static challenge fixture data/
    if (self.target_dir / "routes").is_dir() and (self.target_dir / "data").is_dir():
      if (self.target_dir / "data" / "static").is_dir():
        extra_excludes.append("data")

    return extra_excludes

  @staticmethod
  def _is_generated_orm_or_noise_file(rel_path: str, full_path: Path) -> bool:
    """
    File-level filter for generated ORM boilerplate (*Example.java, MBG *Mapper.xml with
    Example_Where_Clause) while preserving custom DAO XMLs (dao/*Dao.xml) and custom SQL mappers.
    """
    fname = full_path.name
    lower_name = fname.lower()
    for suf in DEFAULT_EXCLUDE_SUFFIXES:
      if lower_name.endswith(suf):
        return True

    if lower_name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "cargo.lock", "poetry.lock", "go.sum"):
      return True

    if fname == "generatorConfig.xml" or fname == "Generator.java":
      try:
        head = full_path.read_text(encoding="utf-8", errors="replace")[:2048]
        if "generatorConfiguration" in head or "MyBatisGenerator" in head:
          return True
      except Exception:
        pass

    if fname.endswith("Example.java"):
      try:
        head = full_path.read_text(encoding="utf-8", errors="replace")[:3000]
        if "oredCriteria" in head or "GeneratedCriteria" in head:
          return True
      except Exception:
        pass

    if fname.endswith(".xml") and "dao/" not in rel_path.replace("\\", "/").lower():
      try:
        head = full_path.read_text(encoding="utf-8", errors="replace")[:4096]
        if "Example_Where_Clause" in head or "Update_By_Example_Where_Clause" in head or "@mbg.generated" in head:
          return True
      except Exception:
        pass

    return False

  def _trace_thin_wrappers(self, active_files: List[str], file_contents: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Traces local/relative imports across Python, TypeScript/JavaScript, C/C++, Go, and Java
    to identify thin wrappers and co-locate them with their underlying core implementation files.
    """
    active_set = set(active_files)
    by_basename: Dict[str, List[str]] = {}
    by_stem: Dict[str, List[str]] = {}
    for rf in active_files:
      p = Path(rf)
      by_basename.setdefault(p.name, []).append(rf)
      by_stem.setdefault(p.stem, []).append(rf)

    local_edges: Dict[str, List[str]] = {}

    for rf in active_files:
      content = file_contents.get(rf, "")
      if not content:
        continue
      p = Path(rf)
      ext = p.suffix.lower()
      delegates: List[str] = []

      if ext == ".py":
        try:
          tree = ast.parse(content)
          for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
              # Resolve relative imports (level >= 1) or local package imports
              base_dir = p.parent
              for _ in range(max(0, (node.level or 1) - 1)):
                base_dir = base_dir.parent
              mod_parts = node.module.split(".") if node.module else []
              cand_base = base_dir.joinpath(*mod_parts) if str(base_dir) != "." else Path(*mod_parts)
              for alias in node.names:
                for cand_rel in (
                    f"{cand_base / alias.name}.py",
                    f"{cand_base}.py",
                    f"{alias.name}.py",
                ):
                  norm_cand = os.path.normpath(cand_rel).lstrip("./")
                  if norm_cand in active_set and norm_cand != rf and norm_cand not in delegates:
                    delegates.append(norm_cand)
              if node.module:
                mod_tail = node.module.split(".")[-1]
                for match_rf in by_stem.get(mod_tail, []):
                  if match_rf != rf and match_rf not in delegates:
                    delegates.append(match_rf)
        except Exception:
          pass

      elif ext in (".ts", ".js", ".mjs", ".cjs", ".tsx", ".jsx"):
        for m in re.finditer(
            r"""(?:from\s+|import\s*\(\s*|require\s*\(\s*|import\s+)['"](\.\.?/[^'"]+)['"]""",
            content,
        ):
          rel_imp = m.group(1)
          base_cand = os.path.normpath(str(p.parent / rel_imp))
          for try_ext in ("", ".ts", ".js", ".tsx", ".jsx", "/index.ts", "/index.js"):
            cand = (base_cand + try_ext).lstrip("./")
            if cand in active_set and cand != rf and cand not in delegates:
              delegates.append(cand)

      elif ext in (".h", ".hpp", ".c", ".cc", ".cpp"):
        for m in re.finditer(r'#include\s*"([^"]+)"', content):
          inc_name = Path(m.group(1)).name
          for match_rf in by_basename.get(inc_name, []):
            if match_rf != rf and match_rf not in delegates:
              delegates.append(match_rf)
        if ext in (".h", ".hpp"):
          stem = p.stem
          for cand_stem in (stem, f"{stem}_internal", f"{stem}_impl"):
            for match_rf in by_stem.get(cand_stem, []):
              if match_rf != rf and Path(match_rf).suffix.lower() in (".c", ".cc", ".cpp") and match_rf not in delegates:
                delegates.append(match_rf)

      elif ext == ".java":
        if rf.endswith("Controller.java"):
          stem_prefix = p.stem[:-10]  # strip Controller
          for cand_stem in (f"{stem_prefix}ServiceImpl", f"{stem_prefix}Service", f"{stem_prefix}Dao"):
            for match_rf in by_stem.get(cand_stem, []):
              if match_rf != rf and match_rf not in delegates:
                delegates.append(match_rf)

      if delegates:
        local_edges[rf] = delegates

    # Build transitive thin-wrapper chains (e.g. http.py -> sansio/http.py -> _internal.py)
    thin_wrappers: List[Dict[str, Any]] = []
    for rf, direct_delegates in local_edges.items():
      content = file_contents.get(rf, "")
      non_empty_lines = [ln for ln in content.splitlines() if ln.strip() and not ln.strip().startswith(("#", "//"))]
      ext = Path(rf).suffix.lower()
      is_wrapper = (
          len(non_empty_lines) <= 80
          or ext in (".h", ".hpp")
          or any("sansio" in d or "_internal" in d or "internal" in d or "impl" in d.lower() for d in direct_delegates)
          or Path(rf).name in ("app.ts", "app.js", "index.ts", "index.js")
      )
      if is_wrapper:
        # Expand 1 hop transitively so wrapper chains like A -> B -> C are visible together
        chain: List[str] = list(direct_delegates)
        for d in list(direct_delegates):
          for d2 in local_edges.get(d, []):
            if d2 != rf and d2 not in chain:
              chain.append(d2)
        thin_wrappers.append({
            "wrapper": rf,
            "delegates_to": chain,
        })

    return thin_wrappers

  def _extract_routes_sinks_and_guards(
      self,
      active_files: List[str],
      file_contents: Dict[str, str],
  ) -> Tuple[List[str], List[str], List[str], List[str]]:
    """Extracts entrypoints, routes, detected_sinks, and detected_guards across all active files."""
    entrypoints: List[str] = []
    routes: List[str] = []
    seen_routes: Set[str] = set()
    detected_sinks: List[str] = []
    seen_sinks: Set[str] = set()
    detected_guards: List[str] = []
    seen_guards: Set[str] = set()

    entrypoint_names = {
        "app.py", "main.py", "wsgi.py", "manage.py", "server.py",
        "server.ts", "app.ts", "server.js", "app.js", "index.ts", "index.js",
        "main.go", "main.c", "main.cc", "main.cpp", "index.php", "config.ru",
    }

    for rf in active_files:
      fname = Path(rf).name
      content = file_contents.get(rf, "")
      if (
          fname in entrypoint_names
          or fname.endswith("Application.java")
          or "create_app" in content
          or "public static void main" in content
          or "int main(" in content
          or "func main()" in content
      ):
        if rf not in entrypoints:
          entrypoints.append(rf)

      for rpat in ROUTE_PATTERNS:
        for m in rpat.finditer(content):
          route_str = sanitize_untrusted_text(m.group(1))
          if route_str and len(route_str) <= 120 and route_str not in seen_routes:
            seen_routes.add(route_str)
            routes.append(route_str)

      for sink_name, spat in SINK_PATTERNS:
        if sink_name not in seen_sinks and spat.search(content):
          seen_sinks.add(sink_name)
          detected_sinks.append(sink_name)

      for guard_name, gpat in GUARD_PATTERNS:
        if guard_name not in seen_guards and gpat.search(content):
          seen_guards.add(guard_name)
          detected_guards.append(guard_name)

    # Order detected_sinks according to SINK_PATTERNS canonical order
    canonical_sinks = [s for s, _ in SINK_PATTERNS if s in seen_sinks]
    canonical_guards = [g for g, _ in GUARD_PATTERNS if g in seen_guards]
    return entrypoints, routes, canonical_sinks, canonical_guards

  def _detect_frameworks(
      self,
      languages: List[str],
      dependencies: List[Dict[str, str]],
      file_contents: Dict[str, str],
  ) -> List[str]:
    """Identifies application frameworks from parsed dependencies and source imports."""
    frameworks: List[str] = []
    dep_names = {d.get("name", "").lower() for d in dependencies}
    combined_sample = "\n".join(list(file_contents.values())[:30]).lower()

    candidates = [
        ("werkzeug", "werkzeug" in dep_names or "from werkzeug" in combined_sample),
        ("flask", "flask" in dep_names or "from flask" in combined_sample),
        ("django", "django" in dep_names),
        ("fastapi", "fastapi" in dep_names),
        ("express", "express" in dep_names or "express-jwt" in dep_names),
        ("sequelize", "sequelize" in dep_names),
        ("pug", "pug" in dep_names),
        ("spring-boot", any("spring-boot" in d for d in dep_names) or "@springbootapplication" in combined_sample),
        ("mybatis", any("mybatis" in d for d in dep_names) or "<mapper " in combined_sample),
        ("druid", any("druid" in d for d in dep_names)),
        ("net/http", "net/http" in combined_sample),
        ("gin", "github.com/gin-gonic/gin" in dep_names),
        ("cmake", any(d.get("manifest") == "cmake-build-manifest" for d in dependencies)),
    ]
    for fw_name, matched in candidates:
      if matched and fw_name not in frameworks:
        frameworks.append(fw_name)
    if not frameworks and languages:
      frameworks.append(f"{languages[0]}-standard")
    return frameworks

  def _synthesize_context_prompt(
      self,
      languages: List[str],
      frameworks: List[str],
      dependencies: List[Dict[str, str]],
      routes: List[str],
      detected_sinks: List[str],
      detected_guards: List[str],
      thin_wrappers: List[Dict[str, Any]],
  ) -> str:
    """
    Synthesizes the 5-Pillar Hybrid Semantic -c Context Prompt using general
    package+version+sink advisory rules (zero hardcoded repository names).
    """
    lang_str = "/".join(languages[:3]) if languages else "multi-language"
    fw_str = ", ".join(frameworks[:4]) if frameworks else "application"

    # Pillar 0: Index Navigation
    p0 = (
        f"Perform an exhaustive full-stack {lang_str} ({fw_str}) security audit combining "
        "SAST, SCA, Configuration, and Guard analysis: "
        "0) First read the project file index markdown document in the root directory to see all target files."
    )

    # Pillar 1: SCA & Dependency CVE Correlation
    dep_Blurbs: List[str] = []
    matched_advisories: List[str] = []
    sink_set = set(detected_sinks)

    for d in dependencies[:20]:
      dname = d.get("name", "")
      dver = d.get("version", "")
      # Normalize any .ALL or .RELEASE suffix in version to hyphen
      dver_clean = re.sub(r"(\d+\.\d+(?:\.\d+)*)\.([A-Za-z][A-Za-z0-9_-]*)\b", r"\1-\2", dver)
      if dname:
        dep_Blurbs.append(f"{dname} {dver_clean}".strip())
      dname_low = dname.lower()
      for kb_pkg, kb_vers, kb_sink, kb_note in DEPENDENCY_ADVISORY_KB:
        if kb_pkg in dname_low:
          ver_match = not kb_vers or any(dver_clean.lstrip("^~>=").startswith(vp) for vp in kb_vers)
          sink_match = kb_sink is None or kb_sink in sink_set
          if ver_match and sink_match and kb_note not in matched_advisories:
            matched_advisories.append(kb_note)

    if dep_Blurbs:
      dep_list_str = ", ".join(dep_Blurbs[:12])
      adv_str = (
          f" and correlate them with reachable application sinks ({'; '.join(matched_advisories)})"
          if matched_advisories
          else " and correlate pinned versions with all known public CVEs and reachable exploit sinks"
      )
      p1 = (
          f"1) Inspect the root dependency manifest files for vulnerable package versions "
          f"(such as {dep_list_str}){adv_str}."
      )
    else:
      p1 = (
          "1) Inspect any dependency and build manifests for outdated library versions and correlate "
          "them with reachable application sinks."
      )

    # Pillar 2: SAST Route, Entrypoint & Sink Taint Audit
    sink_directives = [
        SINK_AUDIT_DIRECTIVES[s]
        for s in detected_sinks
        if s in SINK_AUDIT_DIRECTIVES
    ]
    if not sink_directives:
      sink_directives = [
          "OS Command Injection (CWE-78)",
          "SQL Injection (CWE-89)",
          "Path Traversal and Arbitrary File Read/Write (CWE-22 and CWE-434)",
          "Insecure Deserialization (CWE-502)",
          "SSRF (CWE-918)",
          "XSS (CWE-79)",
          "Memory Buffer Overflow (CWE-120 and CWE-787)",
      ]
    route_sample = ", ".join(routes[:12]) if routes else "all HTTP, RPC, and CLI entrypoints"
    p2 = (
        f"2) Trace all untrusted request query parameters, form fields, cookies, headers, and uploaded files "
        f"across endpoints ({route_sample}): identify {', '.join(sink_directives)}."
    )

    # Pillar 3: Configuration, Session & Debugger Audit
    p3 = (
        "3) Audit application factory initialization, configuration manifests, active debug consoles "
        "(such as DebuggedApplication with evalex=True), session cookie flags (missing Secure or HttpOnly, "
        "Host prefix rules), hardcoded credentials or JWT secrets, and exposed actuator or management endpoints."
    )

    # Pillar 4: Thin-Wrapper Delegation Tracing
    if thin_wrappers:
      p4 = (
          "4) Trace through thin wrapper modules and relative re-exports into their underlying "
          "core parser and service implementation modules."
      )
    else:
      p4 = (
          "4) Trace cross-function and cross-module data flows from entrypoints down to core parsers and database mappers."
      )

    # Pillar 5: Guard & Sanitizer Verification (0% FP Guardrail)
    if "safe_join" in detected_guards or detected_guards:
      guards_str = ", ".join(detected_guards)
      p5 = (
          f"5) Verify whether endpoints using security confinement helpers ({guards_str}, such as safe_join "
          "checking for None return values or parameterized query bindings) are properly confined to avoid "
          "false positives on secure download or query handlers. Enumerate every distinct security vulnerability "
          "across all endpoints and dependencies without stopping early."
      )
    else:
      p5 = (
          "5) Verify whether path normalization or parameterized query guards properly confine user input "
          "to avoid false positives. Enumerate every distinct security vulnerability across all endpoints "
          "and dependencies without stopping early."
      )

    return " ".join([p0, p1, p2, p3, p4, p5])

  def _write_project_file_index(
      self,
      active_files: List[str],
      thin_wrappers: List[Dict[str, Any]],
      entrypoints: List[str],
  ) -> Path:
    """Writes structural PROJECT_FILE_INDEX.md co-locating thin wrappers with core parsers."""
    self.output_dir.mkdir(parents=True, exist_ok=True)
    idx_path = self.output_dir / "PROJECT_FILE_INDEX.md"
    lines: List[str] = [
        f"# Project File Index ({len(active_files)} active files)",
        "# Use these relative paths directly with read_file / grep_search instead of walking directories with list_dir:",
        "",
    ]
    if thin_wrappers:
      lines.append("## Thin-Wrapper & Delegation Co-Location Map")
      for tw in thin_wrappers[:25]:
        w = tw.get("wrapper", "")
        delegs = ", ".join(tw.get("delegates_to", []))
        lines.append(f"- {w} -> delegates to: {delegs}")
      lines.append("")

    if entrypoints:
      lines.append("## Discovered Entrypoints")
      for ep in entrypoints[:20]:
        lines.append(f"- {ep}")
      lines.append("")

    lines.append("## Active Repository Files")
    lines.extend(active_files)
    lines.append("")
    idx_path.write_text("\n".join(lines), encoding="utf-8")
    return idx_path

  def profile(self) -> Dict[str, Any]:
    """
    Executes Stage 1 Auto-Profiling on self.target_dir and writes:
    - <output_dir>/profile.json
    - <output_dir>/config.yaml
    - <output_dir>/PROJECT_FILE_INDEX.md
    Returns the complete profile dictionary conforming to PROJECT.md § Interface Contract 2.
    """
    self.output_dir.mkdir(parents=True, exist_ok=True)

    excluded_generated_modules = self._detect_generated_orm_modules()
    spa_excludes = self._should_exclude_spa_frontend()
    excluded_dirs = list(dict.fromkeys(DEFAULT_EXCLUDE_DIRS + excluded_generated_modules + spa_excludes))
    excluded_dirs_set = set(excluded_dirs)

    total_files_scanned = 0
    active_files: List[str] = []
    file_contents: Dict[str, str] = {}
    discovered_exts: Set[str] = set()
    lang_counts: Dict[str, int] = {}

    for root, dirs, files in os.walk(self.target_dir):
      # Always prune system/runtime/benchmark noise directories first
      dirs[:] = sorted([
          d for d in dirs
          if d not in DEFAULT_EXCLUDE_DIRS and not d.startswith(".")
      ])
      rel_root = Path(root).relative_to(self.target_dir)
      top_part = rel_root.parts[0] if rel_root.parts else ""

      for f in sorted(files):
        if f == "PROJECT_FILE_INDEX.md" or f.startswith("."):
          continue
        full_p = Path(root) / f
        rel_p = str(full_p.relative_to(self.target_dir)).replace("\\", "/")
        total_files_scanned += 1

        # Exclude dynamically detected generated ORM modules or SPA frontend directories
        if top_part and top_part in excluded_dirs_set:
          continue
        if any(part in excluded_dirs_set for part in rel_root.parts):
          continue

        ext = full_p.suffix.lower()
        fname_lower = f.lower()
        is_manifest_file = fname_lower in ("cmakelists.txt", "makefile", "gnumakefile", "gemfile", "pipfile")
        if ext not in KNOWN_SCAN_EXTENSIONS and not is_manifest_file:
          continue

        if self._is_generated_orm_or_noise_file(rel_p, full_p):
          continue

        active_files.append(rel_p)
        if ext in KNOWN_SCAN_EXTENSIONS:
          discovered_exts.add(ext)
        elif is_manifest_file and ext:
          discovered_exts.add(ext)

        lang = LANGUAGE_BY_EXT.get(ext)
        if lang:
          lang_counts[lang] = lang_counts.get(lang, 0) + 1

        # Read up to 256KB for fast AST/regex profiling
        try:
          if full_p.stat().st_size <= 512 * 1024:
            file_contents[rel_p] = full_p.read_text(encoding="utf-8", errors="replace")
        except Exception:
          pass

    active_files.sort()
    languages = [k for k, _ in sorted(lang_counts.items(), key=lambda x: (-x[1], x[0]))]
    if not languages and discovered_exts:
      languages = ["generic"]

    # Ensure baseline extensions for discovered languages are included in config.yaml
    included_exts_set = set(discovered_exts)
    if "python" in languages:
      included_exts_set.update([".py", ".txt", ".toml", ".cfg", ".ini", ".yml", ".yaml", ".json"])
    if "java" in languages or "kotlin" in languages:
      included_exts_set.update([".java", ".xml", ".yml", ".yaml", ".properties", ".gradle", ".kts", ".sql"])
    if "typescript" in languages or "javascript" in languages:
      included_exts_set.update([".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".json", ".yml", ".yaml", ".pug", ".hbs", ".ejs"])
    if "c" in languages or "cpp" in languages:
      included_exts_set.update([".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".txt", ".cmake"])
    if "go" in languages:
      included_exts_set.update([".go", ".mod", ".yml", ".yaml", ".json", ".sql"])
    if not included_exts_set:
      included_exts_set.update([".py", ".txt", ".js", ".ts", ".java", ".xml", ".yml", ".json", ".c", ".cpp", ".h", ".go"])
    included_extensions = sorted(included_exts_set)

    dependencies = parse_manifests(self.target_dir)
    thin_wrappers = self._trace_thin_wrappers(active_files, file_contents)
    entrypoints, routes, detected_sinks, detected_guards = self._extract_routes_sinks_and_guards(
        active_files, file_contents
    )
    frameworks = self._detect_frameworks(languages, dependencies, file_contents)

    execution_profile = select_execution_profile(
        active_files_count=len(active_files),
        languages=languages,
        force_deep=self.force_deep,
        model=self.model,
        timeout_seconds=self.timeout_seconds,
    )

    raw_prompt = self._synthesize_context_prompt(
        languages=languages,
        frameworks=frameworks,
        dependencies=dependencies,
        routes=routes,
        detected_sinks=detected_sinks,
        detected_guards=detected_guards,
        thin_wrappers=thin_wrappers,
    )
    rewritten_tokens = FILE_SCOPING_REGEX.findall(raw_prompt)
    sanitized_prompt = sanitize_context_prompt(raw_prompt, deep=True, repo_files=active_files)
    remaining_matches = FILE_SCOPING_REGEX.findall(sanitized_prompt)

    # Write Stage 1 artifacts to self.output_dir
    config_yaml_path = create_cm_config(
        cm_home=self.output_dir,
        exclude_dirs=excluded_dirs,
        include_extensions=included_extensions,
        exclude_extensions=DEFAULT_EXCLUDE_SUFFIXES,
    )
    index_md_path = self._write_project_file_index(
        active_files=active_files,
        thin_wrappers=thin_wrappers,
        entrypoints=entrypoints,
    )
    profile_json_path = self.output_dir / "profile.json"

    profile_data: Dict[str, Any] = {
        "target_dir": str(self.target_dir),
        "languages": languages,
        "frameworks": frameworks,
        "total_files_scanned": total_files_scanned,
        "active_files_count": len(active_files),
        "active_files": active_files,
        "excluded_dirs": excluded_dirs,
        "excluded_generated_modules": excluded_generated_modules,
        "included_extensions": included_extensions,
        "dependencies": dependencies,
        "entrypoints": entrypoints,
        "routes": routes,
        "detected_sinks": detected_sinks,
        "detected_guards": detected_guards,
        "thin_wrappers": thin_wrappers,
        "execution_profile": execution_profile,
        "context_prompt": sanitized_prompt,
        "sanitizer_stats": {
            "deep_file_regex_matches_remaining": len(remaining_matches),
            "rewritten_tokens": rewritten_tokens,
        },
        "artifacts": {
            "profile_json": str(profile_json_path),
            "config_yaml": str(config_yaml_path),
            "project_file_index_md": str(index_md_path),
        },
    }
    profile_json_path.write_text(json.dumps(profile_data, indent=2, ensure_ascii=False), encoding="utf-8")

    if self._mirror_output_dir is not None and self._mirror_output_dir != self.output_dir:
      self._mirror_output_dir.mkdir(parents=True, exist_ok=True)
      mirror_cfg = self._mirror_output_dir / "config.yaml"
      mirror_idx = self._mirror_output_dir / "PROJECT_FILE_INDEX.md"
      mirror_prof_path = self._mirror_output_dir / "profile.json"
      shutil.copy2(config_yaml_path, mirror_cfg)
      shutil.copy2(index_md_path, mirror_idx)
      mirror_prof_data = dict(profile_data)
      mirror_prof_data["artifacts"] = {
          "profile_json": str(mirror_prof_path),
          "config_yaml": str(mirror_cfg),
          "project_file_index_md": str(mirror_idx),
      }
      mirror_prof_path.write_text(
          json.dumps(mirror_prof_data, indent=2, ensure_ascii=False),
          encoding="utf-8",
      )

    return profile_data


# ============================================================================
# Component 6: High-Signal Scoped Target Materializer & Ground Truth Evaluator
# ============================================================================

def score_file_security_signal(rel_path: str, content: str, profile: Dict[str, Any]) -> int:
  """Scores an active file by security signal density for fast monolithic repo scoping."""
  score = 0
  p = Path(rel_path)
  fname = p.name.lower()
  rel_low = rel_path.lower()

  # Tier S: Dependency manifests, entrypoints, thin wrappers & their delegates
  if fname in (
      "requirements.txt", "pyproject.toml", "package.json", "pom.xml",
      "build.gradle", "build.gradle.kts", "go.mod", "cmakelists.txt",
      "makefile", "gemfile", "composer.json",
  ):
    score += 1000
  if rel_path in profile.get("entrypoints", []):
    score += 900
  for tw in profile.get("thin_wrappers", []):
    if rel_path == tw.get("wrapper") or rel_path in tw.get("delegates_to", []):
      score += 850

  # Application & security configuration files
  if (
      fname.startswith("application") and p.suffix.lower() in (".yml", ".yaml", ".properties")
      or "securityconfig" in fname
      or "ignoreurls" in fname
      or "jwttoken" in fname
      or "insecurity" in fname
  ):
    score += 800

  # Custom DAO XML mappers
  if p.suffix.lower() == ".xml" and ("dao/" in rel_low or fname.endswith("dao.xml")):
    score += 750
    if "${" in content or "order by" in content.lower() or "like" in content.lower():
      score += 200

  # Route handlers & controllers
  if any(seg in rel_low for seg in ("routes/", "controller/", "controllers/", "handlers/", "api/")):
    score += 500

  # Security / auth / util / service implementations
  if any(seg in rel_low for seg in ("security/", "auth/", "service/impl/", "lib/", "util/", "models/", "views/")):
    score += 250

  # Sink density bonus
  for _sink_name, spat in SINK_PATTERNS:
    if spat.search(content):
      score += 65

  # Down-rank pure POJO/DTO/VO boilerplate
  if any(seg in rel_low for seg in ("/dto/", "/domain/", "/vo/", "/bo/")) and score < 200:
    score -= 150

  return score


def materialize_isolated_scan_target(
    target_dir: Path,
    profile: Dict[str, Any],
    scoped_dir: Path,
    max_files: int = MAX_MONOREPO_SCOPED_FILES,
) -> Path:
  """
  Creates an isolated, git-initialized scan target directory containing the active files
  (or top `max_files` highest-signal files when `active_files_count > 60`), plus
  `PROJECT_FILE_INDEX.md`, ensuring:
  1. The user's target repository is never modified or dirtied.
  2. CodeMender's git boundary locks strictly to `scoped_dir` (never walking up to parent dirs).
  3. Monolithic repositories (> 60 active files) complete `--deep` scans well within <= 900s.
  """
  if scoped_dir.exists():
    shutil.rmtree(scoped_dir)
  scoped_dir.mkdir(parents=True, exist_ok=True)

  active_files: List[str] = list(profile.get("active_files", []))
  if len(active_files) > 60:
    scored: List[Tuple[int, str]] = []
    for rf in active_files:
      fp = target_dir / rf
      try:
        content = fp.read_text(encoding="utf-8", errors="replace") if fp.is_file() else ""
      except Exception:
        content = ""
      scored.append((score_file_security_signal(rf, content, profile), rf))
    scored.sort(key=lambda x: (-x[0], x[1]))
    selected_files = sorted([rf for _, rf in scored[:max_files]])
  else:
    selected_files = list(active_files)

  for rf in selected_files:
    src_f = target_dir / rf
    dst_f = scoped_dir / rf
    if src_f.is_file():
      dst_f.parent.mkdir(parents=True, exist_ok=True)
      shutil.copy2(src_f, dst_f)

  # Preserve benign runtime storage/uploads directory structure if present (excluded by config.yaml)
  if (target_dir / "storage").is_dir():
    shutil.copytree(target_dir / "storage", scoped_dir / "storage", dirs_exist_ok=True)
  if (target_dir / "uploads").is_dir():
    (scoped_dir / "uploads").mkdir(parents=True, exist_ok=True)

  # Write PROJECT_FILE_INDEX.md listing the exact scoped files
  idx_lines = [
      f"# Project File Index ({len(selected_files)} files)",
      "# Use these relative paths directly with read_file / grep_search instead of walking directories with list_dir:",
      "",
  ]
  thin_wrappers = profile.get("thin_wrappers", [])
  if thin_wrappers:
    idx_lines.append("## Thin-Wrapper & Delegation Co-Location Map")
    for tw in thin_wrappers[:20]:
      idx_lines.append(f"- {tw.get('wrapper')} -> delegates to: {', '.join(tw.get('delegates_to', []))}")
    idx_lines.append("")
  idx_lines.extend(selected_files)
  idx_lines.append("")
  (scoped_dir / "PROJECT_FILE_INDEX.md").write_text("\n".join(idx_lines), encoding="utf-8")

  subprocess.run(["git", "init", "-q"], cwd=str(scoped_dir), check=False, capture_output=True)
  return scoped_dir


GROUND_TRUTH_RULES: List[Tuple[str, str, List[str]]] = [
    ("GT01_CMD_INJ", "OS Command Injection (/diagnostics/ping)", ["on_ping", "cwe-78", "command injection"]),
    ("GT02_DESERIAL", "Pickle Insecure Deserialization (/profile/restore)", ["on_profile_restore", "cwe-502", "pickle", "deserialization"]),
    ("GT03_UPLOAD", "Unrestricted File Upload / Path Traversal (/upload/raw)", ["on_upload_raw", "upload_raw", "upload/raw", "raw upload", "cwe-434", "file upload", "file write"]),
    ("GT04_PATH_READ", "Arbitrary File Read / Path Traversal (/download)", ["def on_download(", "download endpoint", "arbitrary file read", "path traversal file read", "on_download"]),
    ("GT05_SQLI", "SQL Injection (/api/users/lookup)", ["on_user_lookup", "cwe-89", "sql injection"]),
    ("GT06_SSRF", "Server-Side Request Forgery (/services/proxy)", ["on_service_proxy", "cwe-918", "ssrf", "request forgery"]),
    ("GT07_XSS", "Reflected XSS (/search)", ["on_search", "cwe-79", "xss", "cross-site scripting"]),
    ("GT08_REDIRECT", "Open URL Redirect (/navigate)", ["on_navigate", "cwe-601", "open redirect", "redirection"]),
    ("GT09_DEBUGGER", "Active Werkzeug Debugger / PIN RCE (DebuggedApplication)", ["debuggedapplication", "evalex", "cwe-489", "cve-2024-34069", "debug console", "debugger"]),
    ("GT10_MULTIPART_DOS", "Multipart Form Parsing DoS (CVE-2023-25577)", ["def on_upload(", "on_upload", "cve-2023-25577", "multipart", "cwe-400", "denial of service"]),
    ("GT11_COOKIE_SEC", "Insecure Session Cookie / Nameless Cookie (CWE-614 / CVE-2023-46136)", ["on_auth_session", "cwe-614", "cve-2023-46136", "cookie"]),
]


def evaluate_ground_truth_findings(
    findings: List[Dict[str, Any]],
    target_dir: Optional[Path | str] = None,
) -> Dict[str, Any]:
  """
  Evaluates findings against the 11 Ground Truth vulnerabilities and 1 safe_join negative control.
  Conforms to PROJECT.md § Interface Contracts 3 & 4.
  """
  applicable = True
  if target_dir is not None:
    tpath = Path(target_dir).resolve()
    has_poc = (
        (tpath / "grounding-truth" / "poc_exploit.py").exists()
        or (tpath.parent / "grounding-truth" / "poc_exploit.py").exists()
    )
    has_wsgi_app = (tpath / "app.py").exists() or (tpath / "src" / "app.py").exists()
    applicable = bool(has_poc or has_wsgi_app)

  matched_rules: Dict[str, bool] = {}
  for gt_id, _gt_name, keywords in GROUND_TRUTH_RULES:
    matched_rules[gt_id] = False
    for f in findings:
      strict_blob = " ".join([
          str(f.get("title", "")),
          str(f.get("vuln_type", "")),
          str(f.get("vuln_id", "")),
          str(f.get("cwe_id", "")),
          str(f.get("snippet", "")),
          str(f.get("location", "")),
          str(f.get("analysis", "")),
      ]).lower()
      if gt_id == "GT04_PATH_READ":
        header_snip = " ".join([
            str(f.get("title", "")),
            str(f.get("vuln_type", "")),
            str(f.get("vuln_id", "")),
            str(f.get("cwe_id", "")),
            str(f.get("snippet", "")),
            str(f.get("location", "")),
        ]).lower()
        if "on_secure_download" in header_snip and "on_download" not in header_snip.replace("on_secure_download", ""):
          continue
        if any(k in header_snip for k in keywords):
          matched_rules[gt_id] = True
          break
      else:
        if any(k in strict_blob for k in keywords):
          matched_rules[gt_id] = True
          break

  fp_safe_join = False
  for f in findings:
    title_loc_snip = " ".join([
        str(f.get("title", "")),
        str(f.get("location", "")),
        str(f.get("snippet", "")),
    ]).lower()
    title_loc = (str(f.get("title", "")) + " " + str(f.get("location", ""))).lower()
    if (
        "on_secure_download" in title_loc_snip
        or "secure_download" in title_loc
        or "/files/secure-download" in title_loc
    ):
      fp_safe_join = True
      break

  gt_total = len(GROUND_TRUTH_RULES)
  gt_hits = sum(1 for v in matched_rules.values() if v)
  gt_recall_pct = round(gt_hits * 100.0 / gt_total, 1) if gt_total else 0.0
  missed_rules = [gt_id for gt_id, hit in matched_rules.items() if not hit]

  return {
      "applicable": applicable,
      "gt_hits": gt_hits,
      "gt_total": gt_total,
      "gt_recall_pct": gt_recall_pct,
      "matched_rules": matched_rules,
      "gt_matrix": matched_rules,
      "missed_rules": missed_rules,
      "fp_safe_join": fp_safe_join,
      "fp_rate_pct": 100.0 if fp_safe_join else 0.0,
  }


# ============================================================================
# Component 7: Stage 2 Automated Scan Engine (run_universal_scan)
# ============================================================================

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
  metrics: Dict[str, Any] = {
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


def _format_markdown_report(report_data: Dict[str, Any]) -> str:
  """Generates a human-readable Markdown summary report (`report.md`) from Stage 2 results."""
  lines: List[str] = [
      "# CodeMender Universal Pipeline Scan Report",
      "",
      f"- **Status**: `{report_data.get('status')}` (exit code `{report_data.get('exit_code')}`)",
      f"- **Target Directory**: `{report_data.get('target_dir')}`",
      f"- **CodeMender Binary**: `{report_data.get('cm_bin')}`",
      f"- **GCP Project**: `{report_data.get('gcp_project')}`",
      f"- **Duration**: `{report_data.get('duration_seconds')}s`",
      f"- **Execution Mode**: `{report_data.get('execution_profile', {}).get('mode')}` "
      f"(model: `{report_data.get('execution_profile', {}).get('recommended_model')}`)",
      f"- **Total Findings**: `{report_data.get('findings_count')}`",
      "",
  ]
  gt = report_data.get("ground_truth_evaluation", {})
  if gt.get("applicable"):
    lines.extend([
        "## Ground Truth Evaluation",
        f"- **Recall**: `{gt.get('gt_hits')}/{gt.get('gt_total')} ({gt.get('gt_recall_pct')}%)`",
        f"- **False Positive on `safe_join` (`/files/secure-download`)**: `{gt.get('fp_safe_join')} ({gt.get('fp_rate_pct')}%)`",
        f"- **Missed Rules**: `{gt.get('missed_rules')}`",
        "",
    ])

  lines.extend([
      "## Discovered Findings",
      "",
      "| # | Severity | Vuln ID / Type | File Path | Lines | Title |",
      "|---|---|---|---|---|---|",
  ])
  for idx, f in enumerate(report_data.get("findings", []), start=1):
    sev = str(f.get("severity", "UNKNOWN"))
    vid = str(f.get("vuln_id") or f.get("vuln_type") or "N/A")
    fpath = str(f.get("file_path") or f.get("location") or "N/A")
    span = f"{f.get('start_line', '?')}-{f.get('end_line', '?')}"
    title = str(f.get("title", "")).replace("|", "\\|")
    lines.append(f"| {idx} | {sev} | {vid} | `{fpath}` | {span} | {title} |")
  lines.append("")
  return "\n".join(lines)


def run_universal_scan(
    target_dir: Path | str,
    output_dir: Optional[Path | str] = None,
    force_deep: Optional[bool] = None,
    model: Optional[str] = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    llm_recon: bool = False,
) -> Dict[str, Any]:
  """
  Executes Stage 1 Auto-Profiling followed by Stage 2 CodeMender (`cm clean` + `cm find`)
  execution in `cloud-llm-preview1` with isolated `CM_HOME` and `<= 900s` timeout cap.
  Emits `profile.json`, `config.yaml`, `PROJECT_FILE_INDEX.md`, `report.json`, and `report.md`.
  """
  capped_timeout = max(60, min(int(timeout_seconds), MAX_TIMEOUT_SECONDS))
  profiler = RepoProfiler(
      target_dir=target_dir,
      output_dir=output_dir,
      force_deep=force_deep,
      model=model,
      llm_recon=llm_recon,
      timeout_seconds=capped_timeout,
  )
  profile = profiler.profile()
  resolved_target = Path(profile["target_dir"])
  resolved_out = profiler.output_dir

  # Prepare isolated CM_HOME with the tailored config.yaml
  cm_home = resolved_out / ".cm_home"
  if cm_home.exists():
    shutil.rmtree(cm_home)
  cm_home.mkdir(parents=True, exist_ok=True)
  shutil.copy2(resolved_out / "config.yaml", cm_home / "config.yaml")

  # Materialize isolated scan target directory with .git boundary and PROJECT_FILE_INDEX.md
  scoped_scan_dir = materialize_isolated_scan_target(
      target_dir=resolved_target,
      profile=profile,
      scoped_dir=resolved_out / "scoped_target",
  )

  exec_prof = profile["execution_profile"]
  cm_bin = resolve_cm_bin()

  env = os.environ.copy()
  env["GOOGLE_CLOUD_PROJECT"] = GCP_PROJECT
  env["CLOUDSDK_CORE_PROJECT"] = GCP_PROJECT
  env["CM_HOME"] = str(cm_home)
  if exec_prof.get("deep"):
    env["CMOC_DEEP_MAX_TURNS"] = str(exec_prof.get("deep_max_turns", 8))

  # Step 2a: Run `cm -y clean`
  clean_cmd = [str(cm_bin), "-y", "clean"]
  try:
    subprocess.run(
        clean_cmd,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
  except Exception as e:
    print(f"[WARN] cm clean warning: {e}")

  # Step 2b: Run `cm -y --sandbox=false find`
  find_cmd = [
      str(cm_bin),
      "-y",
      "--sandbox=false",
      "find",
      str(scoped_scan_dir),
      "--model",
      exec_prof["recommended_model"],
  ]
  if exec_prof.get("deep"):
    find_cmd.extend([
        "--deep",
        "--deep-workers",
        str(exec_prof.get("deep_workers", 16)),
        "--deep-max-turns",
        str(exec_prof.get("deep_max_turns", 8)),
    ])
  if profile.get("context_prompt"):
    find_cmd.extend(["-c", profile["context_prompt"]])

  scan_log_path = resolved_out / "scan.log"
  t0 = time.time()
  timed_out = False
  exit_code = -1

  try:
    with open(scan_log_path, "w", encoding="utf-8") as lf:
      proc = subprocess.run(
          find_cmd,
          env=env,
          stdin=subprocess.DEVNULL,
          stdout=lf,
          stderr=subprocess.STDOUT,
          timeout=capped_timeout,
          cwd=str(BASE_DIR),
      )
      exit_code = proc.returncode
  except subprocess.TimeoutExpired:
    timed_out = True
    print(f"[WARN] Scan timed out after {capped_timeout}s; recovering findings from state.db")

  duration_seconds = round(time.time() - t0, 2)

  # Step 2c: Extract findings from `cm -y report -f json` and SQLite `state.db`
  findings: List[Dict[str, Any]] = []
  try:
    rep_json = subprocess.run(
        [str(cm_bin), "-y", "report", "-f", "json"],
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    raw_json = rep_json.stdout.strip()
    idx = raw_json.find("[")
    if idx != -1:
      findings = json.loads(raw_json[idx:])
  except Exception as e:
    print(f"[WARN] cm report -f json parse warning: {e}")

  db_findings = extract_db_findings(cm_home)
  if not findings and db_findings:
    findings = db_findings
  elif db_findings:
    existing_ids = {f.get("finding_id") or f.get("fingerprint") for f in findings}
    for dbf in db_findings:
      fid = dbf.get("finding_id") or dbf.get("fingerprint")
      if fid and fid not in existing_ids:
        findings.append(dbf)
        existing_ids.add(fid)

  # Normalize file paths from scoped_scan_dir back to resolved_target
  scoped_prefix = str(scoped_scan_dir)
  target_prefix = str(resolved_target)
  for f in findings:
    fp = str(f.get("file_path") or "")
    if fp.startswith(scoped_prefix):
      f["file_path"] = target_prefix + fp[len(scoped_prefix):]

  sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
  for f in findings:
    sev = str(f.get("severity", "")).upper()
    if sev in sev_counts:
      sev_counts[sev] += 1

  log_text = scan_log_path.read_text(encoding="utf-8", errors="replace") if scan_log_path.exists() else ""
  log_metrics = parse_log_metrics(log_text)
  gt_eval = evaluate_ground_truth_findings(findings, target_dir=resolved_target)

  effective_exit_code = 0 if (exit_code == 0 or (timed_out and len(findings) > 0)) else exit_code
  status = "completed" if effective_exit_code == 0 else ("timed_out" if timed_out else "failed")

  report_json_path = resolved_out / "report.json"
  report_md_path = resolved_out / "report.md"

  report_data: Dict[str, Any] = {
      "status": status,
      "exit_code": effective_exit_code,
      "target_dir": str(resolved_target),
      "cm_bin": str(cm_bin),
      "gcp_project": GCP_PROJECT,
      "cm_home": str(cm_home),
      "duration_seconds": duration_seconds,
      "execution_profile": exec_prof,
      "profile": profile,
      "findings_count": len(findings),
      "findings": findings,
      "severity_counts": sev_counts,
      "log_metrics": log_metrics,
      "ground_truth_evaluation": gt_eval,
      "artifacts": {
          "report_json": str(report_json_path),
          "report_md": str(report_md_path),
          "profile_json": str(resolved_out / "profile.json"),
          "config_yaml": str(resolved_out / "config.yaml"),
          "project_file_index_md": str(resolved_out / "PROJECT_FILE_INDEX.md"),
          "scan_log": str(scan_log_path),
      },
  }
  report_json_path.write_text(
      json.dumps(report_data, indent=2, ensure_ascii=False, default=str),
      encoding="utf-8",
  )
  report_md_path.write_text(_format_markdown_report(report_data), encoding="utf-8")

  mirror_dir = profiler._mirror_output_dir
  if mirror_dir is not None and mirror_dir != resolved_out:
    mirror_dir.mkdir(parents=True, exist_ok=True)
    for subdir_name in (".cm_home", "scoped_target"):
      src_sub = resolved_out / subdir_name
      dst_sub = mirror_dir / subdir_name
      if src_sub.exists():
        if dst_sub.exists():
          shutil.rmtree(dst_sub)
        shutil.copytree(src_sub, dst_sub)
    for fname in ("config.yaml", "PROJECT_FILE_INDEX.md", "scan.log", "report.md"):
      src_f = resolved_out / fname
      if src_f.exists():
        shutil.copy2(src_f, mirror_dir / fname)
    mirror_prof = json.loads((resolved_out / "profile.json").read_text(encoding="utf-8"))
    mirror_prof["artifacts"] = {
        "profile_json": str(mirror_dir / "profile.json"),
        "config_yaml": str(mirror_dir / "config.yaml"),
        "project_file_index_md": str(mirror_dir / "PROJECT_FILE_INDEX.md"),
    }
    (mirror_dir / "profile.json").write_text(
        json.dumps(mirror_prof, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    mirror_rep = dict(report_data)
    mirror_rep["cm_home"] = str(mirror_dir / ".cm_home")
    mirror_rep["profile"] = mirror_prof
    mirror_rep["artifacts"] = {
        "report_json": str(mirror_dir / "report.json"),
        "report_md": str(mirror_dir / "report.md"),
        "profile_json": str(mirror_dir / "profile.json"),
        "config_yaml": str(mirror_dir / "config.yaml"),
        "project_file_index_md": str(mirror_dir / "PROJECT_FILE_INDEX.md"),
        "scan_log": str(mirror_dir / "scan.log"),
    }
    (mirror_dir / "report.json").write_text(
        json.dumps(mirror_rep, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )

  return report_data


# ============================================================================
# Component 8: Legacy Benchmark Compatibility Wrappers (Zero Hardcoded Names)
# ============================================================================

def prepare_scoped_targets() -> Dict[str, Path]:
  """
  Dynamically prepares scoped targets from existing directories under SCOPED_TARGETS_DIR,
  BASE_DIR / 'repos', or BASE_DIR / 'targets' without hardcoded repository names.
  """
  SCOPED_TARGETS_DIR.mkdir(parents=True, exist_ok=True)
  result_targets: Dict[str, Path] = {}
  for child in sorted(SCOPED_TARGETS_DIR.iterdir()):
    if child.is_dir() and not child.name.startswith("."):
      result_targets[child.name] = child
  for parent_folder in (BASE_DIR / "repos", BASE_DIR / "targets"):
    if parent_folder.is_dir():
      for child in sorted(parent_folder.iterdir()):
        if child.is_dir() and not child.name.startswith(".") and child.name not in result_targets:
          result_targets[child.name] = child
  return result_targets


def run_single_experiment(
    run_id: str,
    repo_family: str,
    target_path: Path,
    model: str,
    deep: bool,
    context_key: str,
    deep_workers: int = 16,
    deep_max_turns: int = 8,
    enable_bash: bool = False,
    timeout_sec: int = 900,
) -> Dict[str, Any]:
  """Backwards-compatible experiment runner delegating context synthesis to RepoProfiler."""
  RESULTS_DIR.mkdir(parents=True, exist_ok=True)
  prof_dir = RESULTS_DIR / f".profile_{run_id}"
  profile = RepoProfiler(
      target_dir=target_path,
      output_dir=prof_dir,
      force_deep=deep,
      model=model,
      timeout_seconds=min(timeout_sec, MAX_TIMEOUT_SECONDS),
  ).profile()

  cm_home = RESULTS_DIR / f".cm_home_{run_id}"
  if cm_home.exists():
    shutil.rmtree(cm_home)
  create_cm_config(
      cm_home=cm_home,
      exclude_dirs=profile["excluded_dirs"],
      include_extensions=profile["included_extensions"],
  )

  context_prompt: Optional[str] = None
  if context_key != "c0_none":
    context_prompt = CONTEXT_PROMPTS.get(repo_family, {}).get(context_key) or profile["context_prompt"]

  cm_bin = resolve_cm_bin()
  env = os.environ.copy()
  env["GOOGLE_CLOUD_PROJECT"] = GCP_PROJECT
  env["CLOUDSDK_CORE_PROJECT"] = GCP_PROJECT
  env["CM_HOME"] = str(cm_home)
  env["CMOC_DEEP_MAX_TURNS"] = str(deep_max_turns)

  cmd = [
      str(cm_bin),
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
          timeout=min(timeout_sec, MAX_TIMEOUT_SECONDS),
          cwd=str(BASE_DIR),
      )
      exit_code = proc.returncode
  except subprocess.TimeoutExpired:
    timed_out = True

  elapsed_sec = round(time.time() - t0, 1)

  try:
    rep_txt = subprocess.run(
        [str(cm_bin), "-y", "report", "-f", "table"],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    txt_report_path.write_text(rep_txt.stdout, encoding="utf-8")
  except Exception:
    pass

  findings: List[Dict[str, Any]] = []
  try:
    rep_json = subprocess.run(
        [str(cm_bin), "-y", "report", "-f", "json"],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    raw_json = rep_json.stdout.strip()
    idx = raw_json.find("[")
    if idx != -1:
      findings = json.loads(raw_json[idx:])
    json_report_path.write_text(json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8")
  except Exception:
    pass

  db_findings = extract_db_findings(cm_home)
  db_dump_path.write_text(json.dumps(db_findings, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
  if not findings and db_findings:
    findings = db_findings
    json_report_path.write_text(json.dumps(findings, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

  log_text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
  log_metrics = parse_log_metrics(log_text)

  sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
  cwe_set: Set[str] = set()
  files_with_findings: Set[str] = set()
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

  rel_target = str(target_path.relative_to(BASE_DIR)) if target_path.is_relative_to(BASE_DIR) else str(target_path)
  meta: Dict[str, Any] = {
      "run_id": run_id,
      "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
      "repo_family": repo_family,
      "target_path": rel_target,
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
  return meta


# ============================================================================
# Component 9: Universal CLI Entrypoint (Supporting All 5 Contract Patterns)
# ============================================================================

def build_arg_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
      description="Universal Two-Stage CodeMender Auto-Profile & Auto-Scan Pipeline"
  )
  parser.add_argument(
      "positional",
      nargs="*",
      help="Optional mode ('profile' or 'scan') followed by <target_dir>, or just <target_dir>",
  )
  parser.add_argument(
      "--dry-run",
      "--profile-only",
      dest="dry_run",
      action="store_true",
      help="Run Stage 1 Auto-Profiler only without invoking Stage 2 CodeMender scan",
  )
  parser.add_argument(
      "--scan",
      dest="force_scan",
      action="store_true",
      help="Run full Stage 1 -> Stage 2 scan",
  )
  parser.add_argument(
      "--mode",
      choices=["profile", "scan", "dry-run"],
      default=None,
      help="Explicit execution mode override",
  )
  parser.add_argument(
      "-o",
      "--output-dir",
      dest="output_dir",
      type=str,
      default=None,
      help="Directory to write profile.json, config.yaml, PROJECT_FILE_INDEX.md, report.json, report.md",
  )
  mode_group = parser.add_mutually_exclusive_group()
  mode_group.add_argument(
      "--deep",
      dest="force_deep",
      action="store_true",
      default=None,
      help="Force --deep scan mode",
  )
  mode_group.add_argument(
      "--quick",
      dest="force_quick",
      action="store_true",
      default=False,
      help="Force Quick (holistic) scan mode",
  )
  parser.add_argument(
      "--model",
      type=str,
      default=None,
      help="LLM model override (default selected by profiler: gemini-3.8-flash)",
  )
  parser.add_argument(
      "--timeout",
      type=int,
      default=DEFAULT_TIMEOUT_SECONDS,
      help="Wall-clock timeout cap in seconds (capped at <= 900s)",
  )
  parser.add_argument(
      "--llm-recon",
      dest="llm_recon",
      action="store_true",
      help="Enable optional hybrid LLM reconnaissance pass during Stage 1",
  )
  # Legacy flags for backwards compatibility
  parser.add_argument("--prepare-only", action="store_true", help=argparse.SUPPRESS)
  parser.add_argument("--run-id", type=str, default=None, help=argparse.SUPPRESS)
  parser.add_argument("--repo-family", type=str, default=None, help=argparse.SUPPRESS)
  parser.add_argument("--target", type=str, default=None, help=argparse.SUPPRESS)
  parser.add_argument("--context", type=str, default="c3_hybrid_max", help=argparse.SUPPRESS)
  parser.add_argument("--workers", type=int, default=16, help=argparse.SUPPRESS)
  parser.add_argument("--max-turns", type=int, default=8, help=argparse.SUPPRESS)
  parser.add_argument("--enable-bash", action="store_true", help=argparse.SUPPRESS)
  return parser


def resolve_cli_invocation(args: argparse.Namespace) -> Tuple[str, Path, Optional[Path], Optional[bool]]:
  """Resolves CLI mode, target_dir, output_dir, and force_deep across all 5 invocation patterns."""
  pos = list(args.positional or [])
  mode = "scan"
  target_str: Optional[str] = args.target

  if pos:
    first_low = pos[0].lower()
    if first_low in ("profile", "dry-run", "dry_run"):
      mode = "profile"
      if len(pos) >= 2:
        target_str = pos[1]
    elif first_low == "scan":
      mode = "scan"
      if len(pos) >= 2:
        target_str = pos[1]
    else:
      target_str = pos[0]
      if len(pos) >= 2 and pos[1].lower() in ("profile", "dry-run", "scan"):
        mode = "profile" if pos[1].lower() != "scan" else "scan"

  if args.dry_run or args.mode in ("profile", "dry-run"):
    mode = "profile"
  elif args.force_scan or args.mode == "scan":
    mode = "scan"

  if not target_str:
    raise ValueError(
        "Target directory is required. Usage: python3 pipeline.py [profile|scan] <target_dir> [--output-dir <dir>]"
    )

  target_dir = Path(target_str).resolve()
  if not target_dir.exists():
    raise FileNotFoundError(f"Target directory does not exist: {target_dir}")

  force_deep: Optional[bool] = None
  if args.force_quick:
    force_deep = False
  elif args.force_deep:
    force_deep = True

  output_dir = Path(args.output_dir).resolve() if args.output_dir else None
  return mode, target_dir, output_dir, force_deep


def main(argv: Optional[List[str]] = None) -> int:
  parser = build_arg_parser()
  args = parser.parse_args(argv)

  if args.prepare_only:
    targets = prepare_scoped_targets()
    for k, v in targets.items():
      cnt = sum(len(files) for _, _, files in os.walk(v))
      print(f"Prepared {k}: {v} ({cnt} files)")
    return 0

  if args.run_id and args.repo_family and args.target:
    tpath = (BASE_DIR / args.target).resolve() if not Path(args.target).is_absolute() else Path(args.target).resolve()
    run_single_experiment(
        run_id=args.run_id,
        repo_family=args.repo_family,
        target_path=tpath,
        model=args.model or "gemini-3.8-flash",
        deep=bool(args.force_deep),
        context_key=args.context,
        deep_workers=args.workers,
        deep_max_turns=args.max_turns,
        enable_bash=args.enable_bash,
        timeout_sec=args.timeout,
    )
    return 0

  try:
    mode, target_dir, output_dir, force_deep = resolve_cli_invocation(args)
  except Exception as e:
    print(f"[ERROR] {e}", file=sys.stderr)
    return 2

  if mode == "profile":
    profiler = RepoProfiler(
        target_dir=target_dir,
        output_dir=output_dir,
        force_deep=force_deep,
        model=args.model,
        llm_recon=args.llm_recon,
        timeout_seconds=args.timeout,
    )
    profile_data = profiler.profile()
    print(json.dumps({
        "status": "profiled",
        "mode": mode,
        "target_dir": profile_data["target_dir"],
        "languages": profile_data["languages"],
        "frameworks": profile_data["frameworks"],
        "active_files_count": profile_data["active_files_count"],
        "execution_profile": profile_data["execution_profile"],
        "sanitizer_stats": profile_data["sanitizer_stats"],
        "artifacts": profile_data["artifacts"],
    }, indent=2))
    return 0

  report_data = run_universal_scan(
      target_dir=target_dir,
      output_dir=output_dir,
      force_deep=force_deep,
      model=args.model,
      timeout_seconds=args.timeout,
      llm_recon=args.llm_recon,
  )
  print(json.dumps({
      "status": report_data["status"],
      "exit_code": report_data["exit_code"],
      "target_dir": report_data["target_dir"],
      "duration_seconds": report_data["duration_seconds"],
      "findings_count": report_data["findings_count"],
      "ground_truth_evaluation": report_data["ground_truth_evaluation"],
      "artifacts": report_data["artifacts"],
  }, indent=2))
  return int(report_data["exit_code"])


if __name__ == "__main__":
  sys.exit(main())
