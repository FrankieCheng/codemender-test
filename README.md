# CodeMender 多模型漏洞扫描与 Ground Truth 基准评测报告

**评测环境与配置**：
- **扫描目标**：[src](file:///usr/local/google/home/hongbocheng/projects/codemender/src)（包含核心应用 [app.py](file:///usr/local/google/home/hongbocheng/projects/codemender/src/app.py) 与依赖版本 [requirements.txt](file:///usr/local/google/home/hongbocheng/projects/codemender/src/requirements.txt)）
- **真值验证脚本**：[grounding-truth/poc_exploit.py](file:///usr/local/google/home/hongbocheng/projects/codemender/grounding-truth/poc_exploit.py)（基于 Werkzeug WSGI Client 的端到端安全行为测试套件）
- **执行参数**：`--sandbox=false`
- **数据与隔离**：每轮扫描执行完毕后保存终端原始输出日志 (`.log`)、`cm report` 文本报告 (`.txt`) 及结构化报告 (`.json`)，并在进入下一轮前执行 `cm clean` 清理本地 SQLite 数据库缓存与会话状态。
- **输出归档目录**：[eval_results/](file:///usr/local/google/home/hongbocheng/projects/codemender/eval_results)

---

## 1. Ground Truth 真值基准验证结果

通过在隔离虚拟环境中运行 [grounding-truth/poc_exploit.py](file:///usr/local/google/home/hongbocheng/projects/codemender/grounding-truth/poc_exploit.py)，对应用及底层 Werkzeug 2.2.0 依赖的 12 项安全机制进行直接执行验证，结果如下：

| # | 测试项 (Test Item) | 测试机制 / 目标端点 | 漏洞/安全标准 | 实际执行判定 |
| :---: | :--- | :--- | :--- | :---: |
| 1 | **Multipart Part Limits** | `POST /upload` (1500 parts) | CVE-2023-25577 (DoS 资源耗尽) | 🔴 **SECURITY ISSUE DETECTED** |
| 2 | **Cookie Header Parsing** | `GET /auth/session` (无名 Cookie 注入) | CVE-2023-46136 / CWE-614 | 🔴 **SECURITY ISSUE DETECTED** |
| 3 | **Debugger PIN Predictability** | `werkzeug.debug` (环境属性逆向 PIN) | CVE-2024-34069 / CWE-489 | 🔴 **SECURITY ISSUE DETECTED** |
| 4 | **Storage Path Traversal** | `GET /download?file=../app.py` | 任意文件读取 (CWE-22) | 🔴 **SECURITY ISSUE DETECTED** |
| 5 | **safe_join File Access** | `GET /files/secure-download` | 目录穿越防范机制 | 🟢 **VERIFIED SECURE** |
| 6 | **Insecure Deserialization** | `POST /profile/restore` (pickle.loads) | 远程代码执行 RCE (CWE-502) | 🔴 **SECURITY ISSUE DETECTED** |
| 7 | **SQL Query Injection** | `GET /api/users/lookup` (字符串拼接) | SQL 注入绕过 (CWE-89) | 🔴 **SECURITY ISSUE DETECTED** |
| 8 | **Service Proxy (SSRF)** | `GET /services/proxy` (127.0.0.1 探测) | 服务端请求伪造 (CWE-918) | 🔴 **SECURITY ISSUE DETECTED** |
| 9 | **Unrestricted File Upload** | `POST /upload/raw` (危险扩展名 shell.py) | 任意文件写入 (CWE-434/22) | 🔴 **SECURITY ISSUE DETECTED** |
| 10 | **Command Sanitization** | `GET /diagnostics/ping` (shell 管道注入) | 命令注入 (CWE-78) | 🔴 **SECURITY ISSUE DETECTED** |
| 11 | **Search Output Encoding** | `GET /search?q=<script>` (未经转义) | 反射型 XSS (CWE-79) | 🔴 **SECURITY ISSUE DETECTED** |
| 12 | **URL Redirection Validation** | `GET /navigate?target=https://...` | 开放重定向 (CWE-601) | 🔴 **SECURITY ISSUE DETECTED** |

> **真值汇总**：代码库与运行环境中实际共存在 **11 个安全缺陷**，以及 **1 项已安全加固的防御机制**（`safe_join`）。

---

## 2. 8 轮模型扫描基准全景对比表

| 轮次 | 模型 (Model) | 上下文引导 (`-c`) | 检出数 | 严重级别分布 (Crit / High / Med / Low) | Ground Truth 召回率 | 工具交互步数 | 耗时 | Token 消耗 (In / Out / Total) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Run 1** | `gemini-3.5-flash` | 无 | 8 | 2 / 4 / 2 / 0 | 72.7% (8/11) | 5 步 | 2m06s | 192k / 3k / 199k |
| **Run 2** | `gemini-3.7-flash` | 无 | 8 | 2 / 5 / 1 / 0 | 72.7% (8/11) | 6 步 | 2m41s | 152k / 3k / 164k |
| **Run 3** | `gemini-3.8-flash` | 无 | 8 | 2 / 4 / 2 / 0 | 72.7% (8/11) | 7 步 | 2m48s | 163k / 3k / 176k |
| **Run 4** | `gemini-3.8-flash-cyber` | 无 | 8 | 2 / 4 / 2 / 0 | 72.7% (8/11) | 8 步 | 1m39s | 229k / 3k / 237k |
| **Run 5** | `gemini-3.5-flash` | 有 (固化提示词) | 8 | 3 / 3 / 1 / 1 | 72.7% (8/11) | 5 步 | 2m27s | 17k / 83 / 17k |
| **Run 6** | `gemini-3.7-flash` | 有 (固化提示词) | 9 | 2 / 5 / 2 / 0 | 81.8% (9/11) | 5 步 | 2m22s | 161k / 3k / 173k |
| **Run 7** | `gemini-3.8-flash` | 有 (固化提示词) | **11** | **3 / 4 / 4 / 0** | **100% (11/11)** | 7 步 | 4m00s | 305k / 5k / 325k |
| **Run 8** | `gemini-3.8-flash-cyber` | 有 (固化提示词) | **11** | **3 / 4 / 3 / 1** | **100% (11/11)** | 7 步 | 2m13s | 264k / 5k / 283k |

---

## 3. 漏洞分类检出覆盖矩阵 (Ground Truth 对照)

| Ground Truth 漏洞项 | CWE / CVE 标识 | 3.5-flash (无 -c) | 3.7-flash (无 -c) | 3.8-flash (无 -c) | 3.8-cyber (无 -c) | 3.5-flash (有 -c) | 3.7-flash (有 -c) | 3.8-flash (有 -c) | 3.8-cyber (有 -c) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **OS Command Injection** | CWE-78 | ✅ Crit | ✅ Crit | ✅ Crit | ✅ Crit | ✅ Crit | ✅ Crit | ✅ Crit | ✅ Crit |
| **Insecure Deserialization** | CWE-502 | ✅ Crit | ✅ Crit | ✅ Crit | ✅ Crit | ✅ Crit | ✅ Crit | ✅ Crit | ✅ Crit |
| **Arbitrary File Upload** | CWE-434/22 | ✅ High | ✅ High | ✅ High | ✅ High | ✅ Crit | ✅ High | ✅ Crit | ✅ Crit |
| **Arbitrary File Read** | CWE-22 | ✅ High | ✅ High | ✅ High | ✅ High | ✅ High | ✅ High | ✅ High | ✅ High |
| **SQL Injection** | CWE-89 | ✅ High | ✅ High | ✅ High | ✅ High | ✅ High | ✅ High | ✅ High | ✅ High |
| **Server-Side Request Forgery** | CWE-918 | ✅ High | ✅ High | ✅ High | ✅ High | ✅ High | ✅ High | ✅ High | ✅ High |
| **Reflected XSS** | CWE-79 | ✅ Med | ✅ High | ✅ Med | ✅ Med | ✅ Med | ✅ Med | ✅ Med | ✅ Med |
| **Open Redirect** | CWE-601 | ✅ Med | ✅ Med | ✅ Med | ✅ Med | ✅ Low | ✅ Med | ✅ Med | ✅ Med |
| **Active Debugger Console** | CWE-489 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ High | ✅ High | ✅ High |
| **Multipart Parsing DoS** | CVE-2023-25577 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Med | ✅ Med |
| **Insecure Session Cookie** | CWE-614 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Med | ✅ Low |

---

## 4. 关键洞察与模型表现深度分析

### 1. 提示词 `-c` 对 SCA（软件成分分析）与深层漏洞发现的决定性影响
- **无 `-c`（Baseline）**：
  所有 4 个模型（3.5、3.7、3.8、3.8-cyber）均表现稳定，一致精准检出业务逻辑层的 8 项经典 OWASP 漏洞，达成 72.7% 的 Ground Truth 召回率，但**全部忽略了第三方依赖版本与配置安全隐患**。
- **添加 `-c`（引导关联 `requirements.txt` 并做全量排查）**：
  - **`gemini-3.8-flash` 与 `gemini-3.8-flash-cyber`** 展现出顶尖的综合安全分析能力：
    - 成功将 `werkzeug==2.2.0` 与 **CVE-2023-25577**（多部件表单解析拒绝服务）进行了精准关联；
    - 捕获了调试中间件 `DebuggedApplication` 暴露的交互式控制台风险（CWE-489）；
    - 检出了会话 Cookie 缺失 `Secure` 与 `HttpOnly` 属性的缺陷（CWE-614）；
    - **两者均达到 100% (11/11) 的 Ground Truth 完美召回率**。
  - **`gemini-3.7-flash`**：成功检出了 Debugger 控制台风险，召回率提升至 81.8% (9/11)，但尚未将依赖版本映射至特定 CVE。
  - **`gemini-3.5-flash`**：检出项仍为 8 项，但对漏洞危险度定级做出了更激进的调整。

### 2. `gemini-3.8-flash` vs `gemini-3.8-flash-cyber` 专项对比
- **漏洞发现完整性**：两款模型在有 `-c` 引导下均检出了全部 11 项漏洞，召回率并列第一。
- **推理与执行效率**：
  - `gemini-3.8-flash-cyber` 表现出更优的执行速度（有上下文时仅耗时 **2m13s** vs 3.8-flash 的 **4m00s**，提速约 **45%**）。
  - `gemini-3.8-flash-cyber` 的漏洞命名更加标准规范，直接在标题中明确标注了关联的 CWE / CVE 编号（例如 `CWE-400 (CVE-2023-25577)`、`CWE-489` 等）。

---

## 5. 归档文件索引

所有测试原始输出已全部完整落地在 [eval_results/](file:///usr/local/google/home/hongbocheng/projects/codemender/eval_results) 目录：
- **无上下文组**：
  - [run1_gemini-3.5-flash_no-context.log](file:///usr/local/google/home/hongbocheng/projects/codemender/eval_results/run1_gemini-3.5-flash_no-context.log) / [report.txt](file:///usr/local/google/home/hongbocheng/projects/codemender/eval_results/run1_gemini-3.5-flash_no-context_report.txt) / [report.json](file:///usr/local/google/home/hongbocheng/projects/codemender/eval_results/run1_gemini-3.5-flash_no-context_report.json)
  - [run2_gemini-3.7-flash_no-context.log](file:///usr/local/google/home/hongbocheng/projects/codemender/eval_results/run2_gemini-3.7-flash_no-context.log) / [report.txt](file:///usr/local/google/home/hongbocheng/projects/codemender/eval_results/run2_gemini-3.7-flash_no-context_report.txt) / [report.json](file:///usr/local/google/home/hongbocheng/projects/codemender/eval_results/run2_gemini-3.7-flash_no-context_report.json)
  - [run3_gemini-3.8-flash_no-context.log](file:///usr/local/google/home/hongbocheng/projects/codemender/eval_results/run3_gemini-3.8-flash_no-context.log) / [report.txt](file:///usr/local/google/home/hongbocheng/projects/codemender/eval_results/run3_gemini-3.8-flash_no-context_report.txt) / [report.json](file:///usr/local/google/home/hongbocheng/projects/codemender/eval_results/run3_gemini-3.8-flash_no-context_report.json)
  - [run4_gemini-3.8-flash-cyber_no-context.log](file:///usr/local/google/home/hongbocheng/projects/codemender/eval_results/run4_gemini-3.8-flash-cyber_no-context.log) / [report.txt](file:///usr/local/google/home/hongbocheng/projects/codemender/eval_results/run4_gemini-3.8-flash-cyber_no-context_report.txt) / [report.json](file:///usr/local/google/home/hongbocheng/projects/codemender/eval_results/run4_gemini-3.8-flash-cyber_no-context_report.json)
- **有上下文 (`-c`) 组**：
  - [run5_gemini-3.5-flash_with-context.log](file:///usr/local/google/home/hongbocheng/projects/codemender/eval_results/run5_gemini-3.5-flash_with-context.log) / [report.txt](file:///usr/local/google/home/hongbocheng/projects/codemender/eval_results/run5_gemini-3.5-flash_with-context_report.txt) / [report.json](file:///usr/local/google/home/hongbocheng/projects/codemender/eval_results/run5_gemini-3.5-flash_with-context_report.json)
  - [run6_gemini-3.7-flash_with-context.log](file:///usr/local/google/home/hongbocheng/projects/codemender/eval_results/run6_gemini-3.7-flash_with-context.log) / [report.txt](file:///usr/local/google/home/hongbocheng/projects/codemender/eval_results/run6_gemini-3.7-flash_with-context_report.txt) / [report.json](file:///usr/local/google/home/hongbocheng/projects/codemender/eval_results/run6_gemini-3.7-flash_with-context_report.json)
  - [run7_gemini-3.8-flash_with-context.log](file:///usr/local/google/home/hongbocheng/projects/codemender/eval_results/run7_gemini-3.8-flash_with-context.log) / [report.txt](file:///usr/local/google/home/hongbocheng/projects/codemender/eval_results/run7_gemini-3.8-flash_with-context_report.txt) / [report.json](file:///usr/local/google/home/hongbocheng/projects/codemender/eval_results/run7_gemini-3.8-flash_with-context_report.json)
  - [run8_gemini-3.8-flash-cyber_with-context.log](file:///usr/local/google/home/hongbocheng/projects/codemender/eval_results/run8_gemini-3.8-flash-cyber_with-context.log) / [report.txt](file:///usr/local/google/home/hongbocheng/projects/codemender/eval_results/run8_gemini-3.8-flash-cyber_with-context_report.txt) / [report.json](file:///usr/local/google/home/hongbocheng/projects/codemender/eval_results/run8_gemini-3.8-flash-cyber_with-context_report.json)
