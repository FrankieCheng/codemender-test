# CodeMender (`cm v0.14.0`) 端到端漏洞验证 (`cm verify`) 与自动修复 (`cm fix`) 实战评测报告

> **关联分支**：[`fix`](https://github.com/FrankieCheng/codemender-test/tree/fix)
> **自动化流水线脚本**：[`pipeline/run_verify_and_fix.py`](../pipeline/run_verify_and_fix.py)
> **原始评测数据 JSON**：[`eval_results/python_wsgi/py_16_verify_and_fix_summary.json`](../eval_results/python_wsgi/py_16_verify_and_fix_summary.json)
> **已修复目标源码**：[`src/app.py`](../src/app.py)、[`src/requirements.txt`](../src/requirements.txt)

---

## 一、 核心结论与端到端闭环指标总览

在完成第一阶段 `cm find`（100% 召回 [`src/app.py`](../src/app.py) 与 [`src/requirements.txt`](../src/requirements.txt) 中全部 **11 个 Ground Truth 真实漏洞 / 12 个独立检出项**，且对 `/files/secure-download` 安全负样本保持 **`0%` 误报**）的基础上，我们在 `fix` 分支进一步构建并实测了 **Stage 3 自动漏洞验证（`cm verify`）$\rightarrow$ Stage 4 自动补丁生成与回归验证（`cm fix`）** 的全自动并发流水线：

| 评估阶段与核心指标 | 实测结果 (`cm v0.14.0`, `gemini-3.8-flash`) | 关键说明 |
| :--- | :---: | :--- |
| **输入漏洞总数（来自 Stage 2 `cm find`）** | **12 个检出项**（覆盖 **11 / 11** 真实漏洞） | 含 11 个 `src/app.py` 代码/配置缺陷 + 1 个 `src/requirements.txt` 依赖版本 CVE |
| **Stage 3：`cm verify` 验证通过率 (`status=VERIFIED`)** | **12 / 12 (`100.0%`)** | 全部 12 个漏洞均成功生成 `.exploit/exploit.sh`、`PLAN.md`、`LOG.md`、`REPORT.md`、`info.yaml` |
| **Stage 3：自动生成的 PoC 在未修复代码上触发成功率** | **12 / 12 (`100.0%`)** | 12 个 `.exploit/exploit.sh` 均通过 `werkzeug.test.Client` 动态复现漏洞并返回 `EXPLOIT SUCCESSFUL` (`rc=0`) |
| **Stage 4：`cm fix` 自动修复成功率 (`status=FIXED`)** | **12 / 12 (`100.0%`)** | 全部 12 个漏洞均在 `state.db` 的 `patches` 表生成正式补丁记录并直接完成源码修改 |
| **Stage 4：合并修复后代码阻断全部 12 个 PoC 攻击成功率** | **12 / 12 (`100.0%`)** | 将全部 12 个补丁合并至 [`src/app.py`](../src/app.py) 与 [`src/requirements.txt`](../src/requirements.txt) 后，重跑全部 12 个 `exploit.sh` 均被成功拦截 (`rc=1`) |
| **12 路并发端到端总耗时（12 次 `verify` + 12 次 `fix`）** | **`665.09s` (`~11.1 分钟`)** | 相比单线程串行执行（预计 `~90 分钟`），通过独立工作区并发架构提速 **8.1 倍** |

---

## 二、 `cm verify` 与 `cm fix` 四大工程陷阱与架构级解决方案

在将 `cm verify` 与 `cm fix` 集成到无人值守后台流水线时，我们发现并解决了 4 个直接影响成功率与耗时的关键工程问题：

### 1. 陷阱一：非交互模式下 `run_command` 责任确认拦截（导致立即报错退出 `rc=1`）
- **现象**：仅传递 `-y --sandbox=false` 时，一旦 `cm verify` 或 `cm fix` 代理尝试调用 `run_command` 执行 PoC 脚本，CLI 会立即退出并报错：
  `Error: executing tool run_command: responsibility warning: warning not acknowledged. Please run interactively once to acknowledge or pass --bypass-warning`
- **解决方案**：在非交互自动化流水线中，必须同时传递全局参数 **`-y --bypass-warning --sandbox=false`**。

### 2. 陷阱二：目标运行环境缺少依赖包导致 Agent 执行全盘搜索（单步耗时 30s+ 进而引发超时）
- **现象**：`cm verify` 代理在验证漏洞时会自动编写 Python PoC 并运行 `python3 -c "import werkzeug"`。如果系统默认 `python3` 未预装目标项目的依赖（如 `werkzeug==2.2.0`、`requests`），代理会触发回退逻辑执行 `find / -name "werkzeug" 2>/dev/null` 在根目录全盘搜索，浪费大量轮次并导致超时。
- **解决方案**：在流水线启动前预构建包含目标项目依赖的专用虚拟环境（`/tmp/cm_py_venv`），并在子进程环境变量中注入 `PATH="/tmp/cm_py_venv/bin:$PATH"` 与 `PYTHONDONTWRITEBYTECODE=1`，使 `werkzeug.test.Client` 在 `300ms` 内即可直接完成内存级 WSGI 请求验证，无需启动后台端口或扫描磁盘。

### 3. 陷阱三：多任务并发时 `.exploit/` 目录与 `state.db` 锁冲突
- **现象**：`cm verify` 会在目标仓库根目录下创建 `.exploit/PLAN.md`、`.exploit/exploit.sh`、`.exploit/REPORT.md`。如果在同一个目标目录上并发运行多个 `cm verify` 或 `cm fix` 进程，不同漏洞的 PoC 脚本会互相覆盖。
- **解决方案**：[`pipeline/run_verify_and_fix.py`](../pipeline/run_verify_and_fix.py) 为每个待验证漏洞 `idx` 克隆独立的 `worker_cm_XX`（独立 `state.db`）和 `worker_tgt_XX`（独立源码树与 `.git` 边界），并动态重写 `state.db` 中 `sessions.target`、`sessions.project_root` 与 `findings.file_path` 指向对应的隔离工作区。

### 4. 陷阱四：`.pyc` 字节码污染 Git 状态与单文件多补丁顶部 `import` 冲突
- **现象**：Python 运行 PoC 时生成的 `__pycache__/app.cpython-*.pyc` 若被 Git 追踪，会导致 `cm fix` 在检查 `git diff` 时多耗费 2~3 轮清理二进制文件；此外，多个 `cm fix` Worker 同时向 `src/app.py` 顶部添加 `from werkzeug.exceptions import ...` 或 `from werkzeug.utils import ...` 时，顺序执行 `git apply` 会在文件头部产生 3 行合并冲突。
- **解决方案**：在隔离工作区初始化时写入 `.gitignore`（忽略 `__pycache__/`、`*.pyc`、`.exploit/`）并设置 `PYTHONDONTWRITEBYTECODE=1`；在汇总合并阶段使用 `git apply --3way --recount` 并自动归并顶部导入声明。

---

## 三、 12 个漏洞逐项验证 (`cm verify`) 与自动修复 (`cm fix`) 实测明细表

| 序号 | 漏洞 ID | 目标位置 | 漏洞类别 (CWE) 与标题 | 严重度 | `cm verify` 状态与耗时 | 未修复前 PoC 触发 (`exploit.sh`) | `cm fix` 状态、耗时与补丁 ID | `cm fix` 生成的核心修复方案 | 修复后阻断 PoC 复测 |
| :---: | :---: | :--- | :--- | :---: | :---: | :---: | :---: | :--- | :---: |
| **01** | `689978b6` | `src/app.py:211-221` | **CWE-78**：诊断 Ping 接口 `host` 参数未过滤导致 OS 命令注入 | 🔴 CRITICAL | `VERIFIED`<br>(`200.05s`) | ✅ 成功触发<br>(`127.0.0.1; echo ...`) | `FIXED` (`152.71s`)<br>`patch_id: f614911a` | 移除 `shell=True`，改为参数列表 `["ping", "-c", "1", host]` 调用 `subprocess.check_output` | 🛡️ **已阻断** (`rc=1`) |
| **02** | `8889d8a8` | `src/app.py:155-166` | **CWE-502**：`/profile/restore` 反序列化不可信 Pickle 载荷导致 RCE | 🔴 CRITICAL | `VERIFIED`<br>(`195.67s`) | ✅ 成功触发<br>(`pickle.loads` RCE) | `FIXED` (`154.02s`)<br>`patch_id: 2a5c32d3` | 将危险的 `pickle.loads(decoded)` 替换为安全的 `json.loads(decoded)` | 🛡️ **已阻断** (`rc=1`) |
| **03** | `5c006a3a` | `src/app.py:168-180` | **CWE-89**：`/api/users/lookup` 字符串拼接导致 SQL 注入 | 🟠 HIGH | `VERIFIED`<br>(`193.25s`) | ✅ 成功触发<br>(`' OR '1'='1` 拖库) | `FIXED` (`82.24s`)<br>`patch_id: 1c0d98ab` | 改为参数化预编译查询 `SELECT ... WHERE username = ?` 并传入 `(username,)` | 🛡️ **已阻断** (`rc=1`) |
| **04** | `dc5a1194` | `src/app.py:125-138` | **CWE-22**：`/download` 接口 `os.path.join` 路径穿越任意文件读取 | 🟠 HIGH | `VERIFIED`<br>(`268.38s`) | ✅ 成功触发<br>(`../app.py` 源码泄露) | `FIXED` (`83.09s`)<br>`patch_id: 49d9ce90` | 使用 `werkzeug.security.safe_join(BASE_STORAGE_DIR, filename)` 并校验 `target_path is None` | 🛡️ **已阻断** (`rc=1`) |
| **05** | `856b9353` | `src/app.py:101-109` | **CWE-22**：`/upload/raw` 上传文件名未净化导致路径穿越任意文件覆写 | 🟠 HIGH | `VERIFIED`<br>(`209.78s`) | ✅ 成功触发<br>(`../traversal_proof.txt`) | `FIXED` (`208.04s`)<br>`patch_id: 05c55d6e` | 引入 `secure_filename(uploaded.filename)` 与 `safe_join(UPLOAD_DIR, filename)` 双重校验 | 🛡️ **已阻断** (`rc=1`) |
| **06** | `f999b21f` | `src/app.py:182-192` | **CWE-918**：`/services/proxy` 未校验目标地址导致服务端请求伪造 (SSRF) | 🟠 HIGH | `VERIFIED`<br>(`295.92s`) | ✅ 成功触发<br>(内网回环地址探测) | `FIXED` (`365.15s`)<br>`patch_id: e3b55a8b` | 新增 `is_safe_url()` 解析域名 IP（拦截回环/私网/链路本地/保留地址）并禁用自动重定向循环校验 | 🛡️ **已阻断** (`rc=1`) |
| **07** | `54b45520` | `src/app.py:194-204` | **CWE-79**：`/search` 搜索结果页未转义 `q` 参数导致反射型 XSS | 🟠 HIGH | `VERIFIED`<br>(`218.65s`) | ✅ 成功触发<br>(`<script>alert(1)</script>`) | `FIXED` (`103.65s`)<br>`patch_id: 41fd5204` | 使用 `from html import escape` 对查询参数执行 `escape(request.args.get("q", ""))` | 🛡️ **已阻断** (`rc=1`) |
| **08** | `bae7db3f` | `src/app.py:206-209` | **CWE-601**：`/navigate` 未校验 `target` 参数导致任意外部 URL 开放重定向 | 🟡 MEDIUM | `VERIFIED`<br>(`210.99s`) | ✅ 成功触发<br>(`https://evil.example.com`) | `FIXED` (`188.34s`)<br>`patch_id: 47292e4e` | 使用 `urlsplit(target)` 校验 `scheme`、`netloc` 及 `//`、`/\\` 前缀，仅允许站内相对路径重定向 | 🛡️ **已阻断** (`rc=1`) |
| **09** | `8f471a9b` | `src/app.py:111-123` | **CWE-614**：会话 Cookie 缺少 `Secure`/`HttpOnly` 且违反 `__Host-` 前缀规范 | 🟡 MEDIUM | `VERIFIED`<br>(`186.08s`) | ✅ 成功触发<br>(明文/脚本可读 Cookie) | `FIXED` (`130.95s`)<br>`patch_id: 970fd690` | 在 `response.set_cookie` 中强制启用 `path="/"`, `secure=True`, `httponly=True`, `samesite="Lax"` | 🛡️ **已阻断** (`rc=1`) |
| **10** | `be7f77a9` | `src/app.py:94-99` | **CWE-400**：Multipart 表单解析未限制字段数导致资源耗尽 DoS (`CVE-2023-25577`) | 🟠 HIGH | `VERIFIED`<br>(`215.99s`) | ✅ 成功触发<br>(2,500 个表单分片无限制解析) | `FIXED` (`308.88s`)<br>`patch_id: 96991df1` | 显式校验分片数量上限（超限抛出 `413 RequestEntityTooLarge`）并配合升级 Werkzeug | 🛡️ **已阻断** (`rc=1`) |
| **11** | `3447fd77` | `src/app.py:247-252` | **CWE-489**：启用 `DebuggedApplication(app, evalex=True)` 导致交互式调试器 RCE | 🔴 CRITICAL | `VERIFIED`<br>(`277.46s`) | ✅ 成功触发<br>(`/debug/error` 暴露 `EVALEX = true`) | `FIXED` (`159.73s`)<br>`patch_id: 1c0d9fd3` | 将 `create_app(debug: bool = False)` 默认关闭调试模式，并将 `evalex` 强制设为 `False` | 🛡️ **已阻断** (`rc=1`) |
| **12** | `af5b7281` | `src/requirements.txt:1` | **CWE-1395**：锁定含多个高危 CVE 的 `werkzeug==2.2.0` 依赖版本 | 🟠 HIGH | `VERIFIED`<br>(`450.87s`) | ✅ 成功触发<br>(验证 `werkzeug==2.2.0` 受影响) | `FIXED` (`181.89s`)<br>`patch_id: 562ca72e` | 将 [`src/requirements.txt`](../src/requirements.txt) 中的 `werkzeug==2.2.0` 升级至安全版本 `werkzeug>=3.0.3` | 🛡️ **已阻断** (`rc=1`) |

---

## 四、 `cm fix` 自动生成的完整代码修复 Diff（[`src/app.py`](../src/app.py) & [`src/requirements.txt`](../src/requirements.txt)）

```diff
diff --git a/src/app.py b/src/app.py
index fc7bd33..bc2be00 100644
--- a/src/app.py
+++ b/src/app.py
@@ -6,17 +6,22 @@ file storage, search indexing, and network services.
 """
 
 import os
+from html import escape
 import json
 import base64
 import pickle
 import sqlite3
 import subprocess
+import ipaddress
+import socket
+import urllib.parse
 import requests
+from urllib.parse import urlsplit
 from werkzeug.wrappers import Request, Response
 from werkzeug.routing import Map, Rule
-from werkzeug.exceptions import HTTPException, NotFound
-from werkzeug.utils import redirect
+from werkzeug.exceptions import HTTPException, NotFound, RequestEntityTooLarge
+from werkzeug.utils import redirect, secure_filename
 from werkzeug.security import safe_join
 from werkzeug.debug import DebuggedApplication
 
@@ -43,6 +48,28 @@ def init_database() -> sqlite3.Connection:
     return conn
 
 
+def is_safe_url(target_url: str) -> bool:
+    """Validate that the URL uses HTTP/HTTPS and resolves to a public, non-internal IP."""
+    try:
+        parsed = urllib.parse.urlparse(target_url)
+        if parsed.scheme not in ("http", "https"):
+            return False
+        hostname = parsed.hostname
+        if not hostname:
+            return False
+        addr_infos = socket.getaddrinfo(hostname, None)
+        if not addr_infos:
+            return False
+        for addr_info in addr_infos:
+            ip_str = addr_info[4][0].split("%")[0]
+            ip = ipaddress.ip_address(ip_str)
+            if not ip.is_global or ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
+                return False
+        return True
+    except Exception:
+        return False
+
+
 class Application:
     """WSGI Application built on Werkzeug."""
 
@@ -96,6 +123,8 @@ class Application:
         files = request.files
         form_data = request.form
         uploaded_count = len(files) + len(form_data)
+        if uploaded_count > 1000:
+            raise RequestEntityTooLarge("Too many multipart fields/files.")
         return Response(f"Processed {uploaded_count} multipart fields/files successfully.", mimetype="text/plain")
 
     def on_upload_raw(self, request: Request) -> Response:
@@ -104,9 +133,15 @@ class Application:
         if not uploaded or not uploaded.filename:
             return Response("No file provided", status=400, mimetype="text/plain")
 
-        destination = os.path.join(UPLOAD_DIR, uploaded.filename)
+        filename = secure_filename(uploaded.filename)
+        if not filename:
+            return Response("Invalid filename", status=400, mimetype="text/plain")
+
+        destination = safe_join(UPLOAD_DIR, filename)
+        if destination is None:
+            return Response("Invalid filename", status=400, mimetype="text/plain")
+
         uploaded.save(destination)
-        return Response(f"Saved file to {destination}", mimetype="text/plain")
+        return Response(f"Saved file to {filename}", mimetype="text/plain")
 
     def on_auth_session(self, request: Request) -> Response:
         """Handle user session state and authentication tokens."""
@@ -119,15 +154,22 @@ class Application:
         )
         if request.method == "POST":
             new_token = request.form.get("token", "dummy-session-12345")
-            response.set_cookie("__Host-Session-Token", new_token, path="/", secure=False, httponly=False)
+            response.set_cookie(
+                "__Host-Session-Token",
+                new_token,
+                path="/",
+                secure=True,
+                httponly=True,
+                samesite="Lax",
+            )
         return response
 
     def on_download(self, request: Request) -> Response:
         """Retrieve and stream files from local storage."""
         filename = request.args.get("file", "sample.txt")
-        target_path = os.path.join(BASE_STORAGE_DIR, filename)
+        target_path = safe_join(BASE_STORAGE_DIR, filename)
 
-        if not os.path.exists(target_path):
+        if target_path is None or not os.path.exists(target_path):
             return Response(f"File not found: {filename}", status=404, mimetype="text/plain")
 
         try:
@@ -156,7 +198,7 @@ class Application:
 
         try:
             decoded = base64.b64decode(payload)
-            profile = pickle.loads(decoded)
+            profile = json.loads(decoded)
             return Response(f"Profile restored: {repr(profile)}", mimetype="text/plain")
         except Exception as e:
             return Response(f"Restore failed: {str(e)}", status=400, mimetype="text/plain")
@@ -165,10 +207,10 @@ class Application:
         """Query user account metadata by username."""
         username = request.args.get("username", "")
         cursor = self.db.cursor()
-        query = f"SELECT id, username, email, role FROM users WHERE username = '{username}'"
+        query = "SELECT id, username, email, role FROM users WHERE username = ?"
 
         try:
-            cursor.execute(query)
+            cursor.execute(query, (username,))
             rows = cursor.fetchall()
             results = [{"id": r[0], "username": r[1], "email": r[2], "role": r[3]} for r in rows]
             return Response(json.dumps(results), mimetype="application/json")
@@ -182,7 +224,15 @@ class Application:
             return Response("Missing url parameter", status=400, mimetype="text/plain")
 
         try:
-            resp = requests.get(target_url, timeout=3)
+            current_url = target_url
+            for _ in range(5):
+                if not is_safe_url(current_url):
+                    return Response("Invalid or disallowed URL", status=400, mimetype="text/plain")
+                resp = requests.get(current_url, timeout=3, allow_redirects=False)
+                if resp.is_redirect and "location" in resp.headers:
+                    current_url = urllib.parse.urljoin(current_url, resp.headers["location"])
+                else:
+                    break
             return Response(resp.text, mimetype=resp.headers.get("content-type", "text/plain"))
         except Exception as e:
             return Response(f"Proxy request failed: {str(e)}", status=502, mimetype="text/plain")
@@ -190,7 +240,7 @@ class Application:
     def on_search(self, request: Request) -> Response:
         """Render search query results page."""
-        query = request.args.get("q", "")
+        query = escape(request.args.get("q", ""))
         html = f"""<!DOCTYPE html>
 <html>
 <body>
@@ -202,14 +252,17 @@ class Application:
     def on_navigate(self, request: Request) -> Response:
         """Redirect client to specified destination."""
         target = request.args.get("target", "/")
+        parsed = urlsplit(target)
+        if parsed.scheme or parsed.netloc or not target.startswith("/") or target.startswith(("//", "/\\")):
+            target = "/"
         return redirect(target)
 
     def on_ping(self, request: Request) -> Response:
         """Execute network connectivity diagnostic check."""
         host = request.args.get("host", "127.0.0.1")
-        cmd = f"ping -c 1 {host}"
+        cmd = ["ping", "-c", "1", host]
         try:
-            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True, timeout=3)
+            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=3)
             return Response(output, mimetype="text/plain")
         except subprocess.CalledProcessError as e:
             return Response(f"Command failed:\n{e.output}", status=500, mimetype="text/plain")
@@ -240,11 +293,11 @@ class Application:
         return self.wsgi_app(environ, start_response)
 
 
-def create_app(debug: bool = True):
+def create_app(debug: bool = False):
     """Application factory initializing WSGI application."""
     app = Application()
     if debug:
-        app = DebuggedApplication(app, evalex=True)
+        app = DebuggedApplication(app, evalex=False)
     return app
 
 
@@ -255,5 +308,5 @@ VulnerableApp = Application
 if __name__ == "__main__":
     from werkzeug.serving import run_simple
     print("[*] Starting server on http://127.0.0.1:5000 ...")
-    app = create_app(debug=True)
+    app = create_app(debug=False)
     run_simple("127.0.0.1", 5000, app, use_reloader=False)
diff --git a/src/requirements.txt b/src/requirements.txt
index 09ba00c..d97bb8a 100644
--- a/src/requirements.txt
+++ b/src/requirements.txt
@@ -1,3 +1,3 @@
-werkzeug==2.2.0
+werkzeug>=3.0.3
 pytest>=7.0.0
 requests>=2.28.0
```
