# CodeMender (`cm v0.14.0`) 跨语言安全扫描基准评测与最佳实践总结（中文分享版）

> **评测规模**：共 **43 组受控消融实验**（涵盖 **Python WSGI**、**Node.js/TypeScript**、**Java/Spring Boot** 三大语言技术栈，累计检出 **1,654+** 个漏洞实例）+ **8 组历史基线对比**
> **运行环境**：`cm v0.14.0` (`--sandbox=false`) | GCP Project: `cloud-llm-preview1`
> **核心导航**：
> - 🏛️ **两阶段通用架构深度评审与四大陷阱规避报告**：[`docs/UNIVERSAL_PIPELINE_REVIEW.md`](./docs/UNIVERSAL_PIPELINE_REVIEW.md)
> - 🇺🇸 **英文主报告**：[`README.md`](./README.md) | 完整 43 组实验详表：[`docs/BENCHMARK_RESULTS.md`](./docs/BENCHMARK_RESULTS.md)
> - ⚙️ **两阶段自动化画像与扫描流水线**：[`pipeline/pipeline.py`](./pipeline/pipeline.py)、[`pipeline/test_universal_pipeline.py`](./pipeline/test_universal_pipeline.py)、[`pipeline/run_python_benchmarks.py`](./pipeline/run_python_benchmarks.py)、[`pipeline/run_all_benchmarks.py`](./pipeline/run_all_benchmarks.py)、[`pipeline/generate_report.py`](./pipeline/generate_report.py)

---

## 一、 三大语言技术栈基准测试核心结论一览

我们将 Python 基准项目（[`src/`](./src)，含 11 个 Ground Truth 真实漏洞 + 1 个 `safe_join` 安全对照负样本）与中大型工业级靶场 **Node.js/TypeScript (`juice-shop`)**、**Java/Spring Boot (`macrozheng/mall`)** 进行了统一流水线评测：

| 评测维度 | 🐍 Python / Werkzeug WSGI ([`src/`](./src)) | 🟢 Node.js / Express / TS ([`benchmarks/juice-shop-bench/`](./benchmarks/juice-shop-bench)) | ☕ Java / Spring Boot + MyBatis ([`benchmarks/mall-bench/`](./benchmarks/mall-bench)) |
| :--- | :--- | :--- | :--- |
| **项目特征与代码规模** | 轻量微服务（`app.py` + `requirements.txt`），带 **11 个 Ground Truth 漏洞 PoC + 1 个防误报负样本** | 中大型全栈 Web 应用（Express + Sequelize + MarsDB + Pug 模板，16 核 / 118 全量文件） | 大型多模块电商微服务（6 个 Maven 子模块、MyBatis XML、MinIO/OSS/Alipay，20 核 / 297 全量文件） |
| **默认基线 (`Quick + c0_none`)** | **8 个漏洞 (`72.7%` 召回率)**（3.5F / 3.8F）；**`gemini-4-argon` 零提示词即达 `90.9% (10/11)`** | **16–24 个漏洞**（4 Crit / 13 High / 7 Med，受限于单 Agent 轮次上限） | **10–13 个漏洞**（2 Crit / 3 High / 5 Med，大量步骤消耗在 `list_dir` 遍历目录） |
| **`Quick + c3_hybrid_max` 混合提示词** | **13 个漏洞 — `100.0% (11/11)` 召回率、`0%` 误报**（连 `3.5-flash` 都从旧版 `72.7%` 跃升至 **`100%`**！） | **30 个漏洞**（相比无提示词基线提升 **`+25%`**） | **16 个漏洞**（相比无提示词基线提升 **`+60%`**） |
| **`--deep + c3_hybrid_max` 深度并发模式** | **11 个漏洞 (`76.3s`) — `100.0% (11/11)` 召回率、`0%` 误报**（`gemini-4-argon` 比旧版快 **42.6%**） | **118 个漏洞 (`4.92x` 提升)**（19 Crit / 58 High / 36 Med / 5 Low，覆盖 35 类 CWE） | **90 个漏洞 (`9.0x` 提升)**（8 Crit / 36 High / 36 Med / 10 Low，覆盖 Java + XML + YAML） |
| **最佳推荐配置** | **小微项目 (1–5 文件)**：`Quick + c3_hybrid_max` 或 `--deep + gemini-4-argon + c3_hybrid_max` | **中大型项目**：`--deep --deep-workers 16 --deep-max-turns 8 + c3_hybrid_max + gemini-3.8-flash` | **多模块工程**：`--deep --deep-workers 16 --deep-max-turns 8 + c3_hybrid_max + gemini-4-argon / 3.8-flash` |

---

## 二、 本次复测的四大重磅新发现

### 1. 实锤 `--deep` 模式下的「字面文件名过滤 + Tier 0 剪枝」双重陷阱（`py_13` 召回率直接跌至 `0%`！）
- **实验现象**：在 [`py_13_deep_38flash_literal_trap`](./eval_results/python_wsgi/py_13_deep_38flash_literal_trap_meta.json) 中，我们将旧版原版提示词：
  > *"This Python file handles untrusted input, so check `requirements.txt` for the package versions and hunt down any vulnerabilities..."*
  直接传给 `cm find --deep`，结果 **耗时仅 0.5 秒就退出，检出 0 个漏洞（Ground Truth 召回率 `0.0%`）**！
- **根因链路**：
  1. **第一步（Prompt 正则收敛）**：`cm v0.14.0` 的 `--deep` 启发式解析器检测到 `-c` 中包含字面文件名 `requirements.txt`，于是将扫描范围强制收敛为**仅扫描 `requirements.txt`**（直接丢弃了核心代码 `app.py`）。
  2. **第二步（Tier 0 Pruner 静态剪枝）**：紧接着，`--deep` 内置的 **Tier 0 Pruner** 将 `requirements.txt` 识别为依赖清单/锁文件并直接剪枝跳过（日志：`Tier 0 Pruner: 2 safe files pruned (tests, docs, DTOs, generated, lockfiles) at 0 token cost`）。
  3. **最终结果**：`1 - 1 = 0` 个待扫描文件，导致整个项目被静默跳过！
- **破局方案**：在 `--deep` 的 `-c` 提示词中**严禁出现带后缀的字面文件名**（用 *"root Python dependency manifest text file"* 替代 `requirements.txt`），并在流水线预处理阶段自动将依赖清单中的关键版本号（如 `Werkzeug 2.2.0`）注入到 `-c` 提示词文本中。改造后（[`py_12`](./eval_results/python_wsgi/py_12_deep_4argon_c3_report.json)），`--deep` 在 **76.3 秒内即达成 `100.0% (11/11)` 召回率**！

### 2. 结构化混合提示词 (`c3_hybrid_max`) 让轻量模型 `gemini-3.5-flash` 也实现了 `100%` 召回率
- 在旧版测试中，`gemini-3.5-flash` 即使加上固定提示词也只能检出 **8/11 (`72.7%`)**（漏掉了 `DebuggedApplication evalex=True`、`CVE-2023-25577` Multipart DoS 和 Cookie `Secure/HttpOnly` 属性缺失）。
- 在新版流水线 [`py_02_quick_35flash_c3`](./eval_results/python_wsgi/py_02_quick_35flash_c3_report.json) 中，借助结构化的 `c3_hybrid_max`（显式引导 SAST + SCA 依赖关联 + 调试器/Cookie 配置审计），**`gemini-3.5-flash` 一举检出 12 个漏洞，达成 `100.0% (11/11)` Ground Truth 召回率**！

### 3. `gemini-4-argon` 展现出最强的零样本（Zero-Shot `c0_none`）深度推理能力
- 在完全不提供 `-c` 提示词的裸扫基线对比中：
  - `gemini-3.5-flash` (`py_01`) 与 `gemini-3.8-flash` (`py_03`) 均检出 **8/11 (`72.7%`)** 常规 SAST 漏洞；
  - **`gemini-4-argon` ([`py_07`](./eval_results/python_wsgi/py_07_quick_4argon_c0_report.json)) 在零提示词下自主检出 10/11 (`90.9%`)**，无需任何提示即主动抓出了 `DebuggedApplication(app, evalex=True)` 远程代码执行隐患（`CWE-489`）以及 `__Host-Session-Token` 缺失 `Secure/HttpOnly` 标志（`CWE-614`）！

### 4. 全部 13 组实验在安全负样本（`safe_join`）上保持 `0%` 误报率
- `src/app.py` 中的 `/files/secure-download` 端点使用了 `werkzeug.security.safe_join(BASE_STORAGE_DIR, filename)` 防御路径穿越。在全部 13 组 `cm v0.14.0` 实验（包括最高强度的 `c3_hybrid_max` 提示词）中，**没有任何一次实验对该安全端点产生误报（False Positive = `0%`）**。

---

## 三、 Python (`src/`) 13 组实验完整数据表

| 实验编号 | 模型 | 扫描模式 | 提示词策略 (`-c`) | 检出总数 | 严重度分布 (`C / H / M / L`) | Ground Truth 召回率 (`11` 个真实漏洞) | `safe_join` 负样本误报 | 耗时 |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| [`py_01_quick_35flash_c0`](./eval_results/python_wsgi/py_01_quick_35flash_c0_report.json) | `gemini-3.5-flash` | Quick | `c0_none` (无) | 8 | 2 / 4 / 2 / 0 | 8/11 (`72.7%`) | 🟢 `0%` | 169.7s |
| [`py_02_quick_35flash_c3`](./eval_results/python_wsgi/py_02_quick_35flash_c3_report.json) | `gemini-3.5-flash` | Quick | `c3_hybrid_max` | **12** | 3 / 5 / 4 / 0 | **11/11 (`100.0%`)** | 🟢 `0%` | 202.7s |
| [`py_03_quick_38flash_c0`](./eval_results/python_wsgi/py_03_quick_38flash_c0_report.json) | `gemini-3.8-flash` | Quick | `c0_none` (无) | 8 | 4 / 3 / 1 / 0 | 8/11 (`72.7%`) | 🟢 `0%` | 296.7s |
| [`py_04_quick_38flash_c1_sca`](./eval_results/python_wsgi/py_04_quick_38flash_c1_sca_report.json) | `gemini-3.8-flash` | Quick | `c1_sca` | **11** | 2 / 7 / 2 / 0 | **11/11 (`100.0%`)** | 🟢 `0%` | 330.6s |
| [`py_05_quick_38flash_c2_sast`](./eval_results/python_wsgi/py_05_quick_38flash_c2_sast_report.json) | `gemini-3.8-flash` | Quick | `c2_sast_framework` | 10 | 3 / 4 / 3 / 0 | 10/11 (`90.9%`) | 🟢 `0%` | 163.7s |
| [`py_06_quick_38flash_c3_hybrid`](./eval_results/python_wsgi/py_06_quick_38flash_c3_hybrid_report.json) | `gemini-3.8-flash` | Quick | `c3_hybrid_max` | **13** | 4 / 6 / 3 / 0 | **11/11 (`100.0%`)** | 🟢 `0%` | 230.9s |
| [`py_07_quick_4argon_c0`](./eval_results/python_wsgi/py_07_quick_4argon_c0_report.json) | `gemini-4-argon` | Quick | `c0_none` (无) | 10 | 3 / 5 / 2 / 0 | **10/11 (`90.9%`)** | 🟢 `0%` | 307.2s |
| [`py_08_quick_4argon_c3`](./eval_results/python_wsgi/py_08_quick_4argon_c3_report.json) | `gemini-4-argon` | Quick | `c3_hybrid_max` | **13** | 4 / 7 / 2 / 0 | **11/11 (`100.0%`)** | 🟢 `0%` | 206.3s |
| [`py_09_deep_35flash_c3`](./eval_results/python_wsgi/py_09_deep_35flash_c3_report.json) | `gemini-3.5-flash` | **DEEP** (`--deep`) | `c3_hybrid_max` | 9 | 2 / 6 / 1 / 0 | 9/11 (`81.8%`) | 🟢 `0%` | 132.7s |
| [`py_10_deep_38flash_c0`](./eval_results/python_wsgi/py_10_deep_38flash_c0_report.json) | `gemini-3.8-flash` | **DEEP** (`--deep`) | `c0_none` (无) | 8 | 2 / 4 / 2 / 0 | 8/11 (`72.7%`) | 🟢 `0%` | **78.1s** |
| [`py_11_deep_38flash_c3_hybrid`](./eval_results/python_wsgi/py_11_deep_38flash_c3_hybrid_report.json) | `gemini-3.8-flash` | **DEEP** (`--deep`) | `c3_hybrid_max` | 10 | 3 / 4 / 3 / 0 | 10/11 (`90.9%`) | 🟢 `0%` | 175.2s |
| [`py_12_deep_4argon_c3`](./eval_results/python_wsgi/py_12_deep_4argon_c3_report.json) | `gemini-4-argon` | **DEEP** (`--deep`) | `c3_hybrid_max` | **11** | 4 / 4 / 3 / 0 | **11/11 (`100.0%`)** | 🟢 `0%` | **76.3s** |
| [`py_13_deep_38flash_literal_trap`](./eval_results/python_wsgi/py_13_deep_38flash_literal_trap_meta.json) | `gemini-3.8-flash` | **DEEP** (`--deep`) | `c_legacy_literal` *(含 `requirements.txt` 字面名)* | **0** | 0 / 0 / 0 / 0 | **0/11 (`0.0%`)** *(被过滤+剪枝)* | 🟢 `0%` | 0.5s |

---

## 四、 CodeMender 团队实战落地「五条黄金准则」

1. **准则 1：按仓库规模选择 `Quick` vs `--deep` 模式**
   - **单文件/微型服务（`1–5` 个文件）且需读取依赖清单做 CVE 关联**：优先使用 `Quick + c3_hybrid_max`（因为 Quick 模式不会在 Tier 0 剪枝 `requirements.txt` / `package.json`），或使用 `--deep + gemini-4-argon + c3_hybrid_max`。
   - **中大型仓库或多模块工程（`10–300+` 个文件）**：必须启用 `--deep --deep-workers 16 --deep-max-turns 8`，检出量可达默认模式的 **4.9 倍（Node.js）至 9.0 倍（Java）**。
2. **准则 2：`--deep` 模式下 `-c` 提示词严禁包含字面文件名 (`<name>.<ext>`)**
   - 切勿在 `-c` 中出现 `requirements.txt`、`package.json`、`pom.xml`、`server.ts` 等带扩展名的文件名，否则会触发 `--deep` 的单文件收敛与 Tier 0 锁文件剪枝（如 `py_13` 直接归零）。务必使用语义化描述（如 *"root Python dependency manifest"*），并由前置脚本自动提取关键依赖版本号填入提示词。
3. **准则 3：必须扩展 `CM_HOME/config.yaml` 的文件后缀白名单**
   - 将 `.json`, `.xml`, `.yml`, `.yaml`, `.properties`, `.pug`, `.hbs`, `.ejs`, `.txt`, `.gradle` 加入 `scan.extensions.include`，确保 MyBatis `*Dao.xml` SQL 注入、Spring `application.yml` 硬编码密钥及模板 SSTI 均在扫描视野内。
4. **准则 4：裁剪非攻击面噪音并预生成 `PROJECT_FILE_INDEX.md`**
   - 排除 `node_modules`、`test`、`frontend` 及自动生成的 POJO 模块（如 `mall-mbg`），并在靶标根目录生成扁平化的 `PROJECT_FILE_INDEX.md`，帮助 Agent 一步定位高危文件，节省 **35%–50%** 的目录遍历开销。
5. **准则 5：采用四维混合提示词 (`c3_hybrid_max`) 并关闭 `--enable-bash`**
   - 在 `-c` 中同时声明 **SCA 依赖版本关联 + 框架级 SAST 危险函数 + 配置文件与凭据审计 + 业务逻辑/越权 (IDOR)**，并提醒验证安全封装（如 `safe_join`）；同时在 `--deep` 下保持 `--enable-bash` 关闭，执行速度提升 **1.87 倍**。

---

## 五、 实战操作指南：如何用本流水线扫描任意一个全新的代码库？

由于 [`pipeline/pipeline.py`](./pipeline/pipeline.py) 采用**零仓库名硬编码**的通用两阶段（`Stage 1 自动画像 -> Stage 2 自动扫描`）架构，当你需要扫描任何一个新的本地代码库或 Git 仓库（支持 `Python`、`Node.js/TypeScript`、`Java/Spring Boot`、`C/C++`、`Go`、`Ruby`、`PHP`）时，**无需修改任何代码或手动编写提示词**，只需按以下步骤执行：

### 方式一：一键全自动端到端扫描（推荐日常使用）
直接将新代码库路径传给 `pipeline.py scan`：
```bash
# 一键完成 Stage 1 自动画像 + Stage 2 隔离环境调用 cm find 扫描并输出报告
python3 pipeline/pipeline.py scan /path/to/your-new-repo

# 可选参数：指定输出目录、指定模型（如 gemini-3.8-flash 或 gemini-4-argon）、指定超时时间（上限 900s）
python3 pipeline/pipeline.py scan /path/to/your-new-repo \
  --output-dir ./scan_outputs/your-new-repo \
  --model gemini-3.8-flash \
  --timeout 600
```

**流水线在后台自动为你完成的 6 件事**：
1. **自动生成专属 `config.yaml`**：自动扫描新仓库的语言与配置文件后缀（如 `.py`, `.java`, `.xml`, `.yml`, `.ts`, `.pug`, `.c`, `.go` 等），开启 `incremental: false` 并排除构建产物与锁文件。
2. **自动裁剪噪音与生成 `PROJECT_FILE_INDEX.md`**：自动识别并剔除前端 SPA 静态目录（`frontend/`）、自动生成的 ORM 代码（如 MyBatis Generator 生成的 `*Example.java` 与 `Example_Where_Clause` XML，同时精准保留手写的 `dao/*Dao.xml`），追踪跨文件薄封装调用链（如 `http.py -> sansio/http.py`），并生成 `PROJECT_FILE_INDEX.md`。对于超过 60 个活跃文件的大型单体仓库，会自动按安全信号密度筛选 Top 40 高危核心文件构建带独立 `.git` 边界的 `scoped_target/`。
3. **自动解析依赖版本（SCA）**：自动从 `requirements.txt`、`pyproject.toml`、`package.json`、`pom.xml`（支持 `<properties>` `${...}` 变量插值）、`go.mod`、`CMakeLists.txt`/`Makefile`、`Gemfile`、`composer.json` 提取依赖包名与精确版本号。
4. **自动合成五维 `-c` 提示词并执行硬正则清洗**：将依赖版本、路由端点、危险函数（Sink）与安全封装校验（如 `safe_join`、`realpath`、`filepath.Clean`、参数化查询）合成为结构化提示词，并通过 `sanitize_context_prompt()` 强制清除所有 `<name>.<ext>` 字面文件名（确保 `FILE_SCOPING_REGEX` 匹配数为 `0`，彻底规避 `--deep` 0% 召回率陷阱）。
5. **自适应选择 `Quick` vs `--deep` 模式**：
   - 若新仓库活跃文件数 **`<= 5`**（微型服务）：自动采用 `Quick` 模式（防止 Tier 0 剪枝依赖清单）。
   - 若新仓库活跃文件数 **`> 5`**（多文件/多模块工程）：自动启用 `--deep --deep-workers 16 --deep-max-turns 8` 并发深度模式。
6. **自动提取与落盘结构化报告**：自动合并 `cm -y report -f json` 与 SQLite `.cm_home/state.db` 中的漏洞记录，将文件路径还原为原仓库路径，并生成机器可读的 `report.json` 与可视化表格报告 `report.md`。

---

### 方式二：分步执行（先 Dry-Run 预览画像，再启动扫描）
如果你面对的是一个从未见过的超大型复杂仓库，建议先运行 **Stage 1 Dry-Run 画像模式**（耗时 `< 3 秒`，消耗 `0` Token）检查画像结果，确认无误后再执行扫描：
```bash
# 第一步：仅运行 Stage 1 静态画像（也可使用 --dry-run 参数）
python3 pipeline/pipeline.py profile /path/to/your-new-repo --output-dir ./scan_outputs/your-new-repo

# 检查生成的画像产物：
# 1. ./scan_outputs/your-new-repo/profile.json          -> 查看识别出的语言、活跃文件列表、依赖版本、合成的 -c 提示词及推荐 CLI 参数
# 2. ./scan_outputs/your-new-repo/config.yaml           -> 查看自动生成的后缀白名单与排除目录
# 3. ./scan_outputs/your-new-repo/PROJECT_FILE_INDEX.md -> 查看入口文件与薄封装调用链索引

# 第二步：确认画像后，启动完整扫描（支持通过 --deep 或 --quick 手动覆盖模式）
python3 pipeline/pipeline.py scan /path/to/your-new-repo --output-dir ./scan_outputs/your-new-repo
```

---

### 扫描输出目录结构说明（`./scan_outputs/<repo_name>/`）
每次扫描完成后，输出目录下会包含以下完整产物：
- `report.md`：人类可读的 Markdown 漏洞汇总报告（含严重度统计与完整漏洞列表）。
- `report.json`：结构化 JSON 报告（含每个漏洞的 `title`、`severity`、`vuln_id`/`CWE`、`file_path`、`start_line`、`snippet`、`analysis` 以及执行耗时/Token 统计）。
- `profile.json`、`config.yaml`、`PROJECT_FILE_INDEX.md`：Stage 1 生成的完整仓库画像与配置。
- `scan.log` & `.cm_home/state.db`：CodeMender 原始执行日志与底层 SQLite 状态库（可用于后续执行 `CM_HOME=./scan_outputs/<repo_name>/.cm_home cm verify <finding-id>` 或 `cm fix <finding-id>`）。

