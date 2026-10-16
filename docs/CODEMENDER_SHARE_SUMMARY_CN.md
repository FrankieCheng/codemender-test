# CodeMender v0.14.0 深度测评与规模化最佳实践 — 演讲故事线与技术分享手册

> **核心叙事主线（The Storyline）**：**《如何真正释放 AI 安全 Agent 的潜力：从 0%–4.7% 的“盲扫陷阱”到 100% Ground Truth 召回》**  
> 本手册与 12 页分享 PPT（[CodeMender_Best_Practices_Deck.pptx](file:///usr/local/google/home/hongbocheng/projects/codemender-pipeline/CodeMender_Best_Practices_Deck.pptx) / [CodeMender_Best_Practices_Deck.pdf](file:///usr/local/google/home/hongbocheng/projects/codemender-pipeline/CodeMender_Best_Practices_Deck.pdf) / [Google Slides 在线版](https://docs.google.com/presentation/d/1R76pFsnEVvTIAmWAy-W0NInr4LDVABAGjgdg-ncMQCQ/edit)）一一对应。全篇不再是孤立的数据表格堆砌，而是以**“四幕剧（4-Act Play）”**的逻辑，串联起我们在 **Python + Node.js (`OWASP Juice Shop`) + Java (`macrozheng/mall`)** 三大语料库、**30 组受控实验**中踩坑、破局、验证与工程化落地的完整故事。

---

## 0. 术语与缩写速查表（Glossary）

为了便于跨团队分享，以下说明 PPT 与报告中出现的专有缩写：

| 缩写 / 代号 | 全称 / 含义 | 在故事中的角色 |
| :--- | :--- | :--- |
| **`GT`** | **Ground Truth（标准漏洞真值基准）** | 衡量工具“到底漏了多少真实漏洞”的标尺（Python 11 个、Juice Shop 26 个、Java Mall 22 个核心审计基准点）。 |
| **`FP`** | **False Positive（误报率）** | 将已有安全防护（如 `safe_join`、MyBatis `#{}`、网关白名单）误判为漏洞的比例。全部 30 组实验中 CodeMender 保持 **0.0% FP**。 |
| **`-c`** | **`--context`（自定义上下文提示词参数）** | CodeMender CLI 的核心引导开关，用于向 Agent 注入项目级威胁情报与审计清单。 |
| **`c0_none`** | **无 `-c` 对照组（Zero Context）** | 仅靠模型自主探索（盲扫），不传 `-c` 参数的基准实验组。 |
| **`c1_sca` / `c2_sast`** | **单一维度 `-c` 实验组** | 仅注入依赖审计（SCA）或仅注入静态代码模式（SAST）的消融实验组。 |
| **`c3_hybrid_max`** | **五维混合引导模板（5-Pillar Hybrid Context）** | 同时包含 **SAST + SCA + Config + Logic + InfoLeak** 五大支柱与文件路由表（`PROJECT_FILE_INDEX.md`）的最佳实践模板。 |
| **`HR` / `MR`** | **High-Risk / Medium-Risk Slice（高危/中危切片）** | 针对高风险路由/Controller 或中风险微服务的聚焦文件切片（通常 15–50 个文件）。 |
| **`Argon` / `Flash`** | **`gemini-4-argon` / `gemini-3-flash`** | 参测的两款核心推理模型（Argon 擅长跨文件深度污点追踪，Flash 兼具高速度与高性价比）。 |

---

## 1. 四幕故事结构总览（The 4-Act Story Arc）

1. **第一幕（Act I · 痛点与悖论 | Slides 1–2）—— 为什么极强的 AI 安全 Agent 开箱即用只有 0%–4.7%？**
   - 抛出反直觉现象：同一个 `CodeMender v0.14.0` 二进制包，直接对业务仓库跑默认命令，经常超时 0 产出或只扫出冰山一角（0%–4.7%）；但经过正确的上下文与并发编排后，却能以 **0% 误报** 达成 **95.5%–100% 的 Ground Truth 召回**。
   - 揭示破局的**“三把钥匙（3 Keys）”**：**给 Agent 眼睛（Visibility）**、**给 Agent 并发与视野（Concurrency & File Co-location）**、**给 Agent 一张安全寻宝图（`-c` 5-Pillar Map）**。
2. **第二幕（Act II · 破局三部曲 | Slides 3–6）—— 一步步解开束缚 CodeMender 的三道枷锁**
   - **Step 1（解开视野盲区）**：复盘三个真实的 0% 翻车现场（480s 单线程超时、`config.yaml` 过滤 `.xml/.yml/.pug`、字面量 `requirements.txt` 正则与锁文件裁剪器的连环陷阱），让 Agent 先“看得见”所有高危文件。
   - **Step 2（开启跨文件污点追踪）**：展示 `--deep` 16 线程并发 + `PROJECT_FILE_INDEX.md` 如何打通 `Controller -> Service -> MyBatis DAO` 调用链，并在真实防线（`safe_join` / `#{}`）面前做到 **0% 误报**。
   - **Step 3（注入 `-c` 五维安全地图）**：用 9 组严格的 `c0_none`（无 `-c`）vs `c3_hybrid_max`（带 `-c`）同范围对照实验回答核心灵魂拷问：**“既然有了 `--deep` 和最强的 `gemini-4-argon` 模型，还需要写 `-c` 吗？”** 证明哪怕是 Argon，不带 `-c` 也会漏掉 **46%–54%** 的标准漏洞。
3. **第三幕（Act III · 实战破案与规模化验证 | Slides 7–10）—— 从双面板数据验证到两大明星项目的 100% 破案实录**
   - **数据验证（Slide 7）**：为什么带 `-c` 不仅让漏洞发现量暴涨 **2.9x–9.0x**，反而让 `gemini-3-flash` 扫描速度快了 **3 倍**（从 600s 超时降到 202s）？
   - **规模化切片（Slide 8）**：面对 297 个文件的 Java 单体仓库，如何通过 3 级范围切片（1–5 / 15–50 / 20–50 文件）避免 Agent 把推理轮次浪费在 150+ 个自动生成的 MyBatis POJO 上？
   - **破案故事 1（Slide 9 · OWASP Juice Shop）**：如何从不带 `-c` 的 `53.8%`（14/26），追查到带 `-c` 的 `92.3%`（24/26），再到揪出漏网的 `V03`（`resetPassword.ts`）和 `V15`（`videoHandler.ts`），最终拿下 **26/26 (100%)** 全满贯？
   - **破案故事 2（Slide 10 · Java Spring `macrozheng/mall`）**：如何在 20 个核心文件中精准区分 MyBatis `${}` 注入与 `#{}` 安全绑定，让文件级检出率从 `47.1%`（8/17）跃升至 **100%（17/17）**？
4. **第四幕（Act IV · 工程化落地与演进路线 | Slides 11–12）—— 把所有经验浓缩成 2 条自动化 CLI 命令**
   - 展示 `codemender-pipeline` 如何把上述 4 个步骤全部自动化为 `pipeline.py profile` + `pipeline.py run`，并给出通往 `cm verify` 与 `cm fix` 自动修复闭环的演进路线图。

---

## 2. 逐页演讲稿与核心论据（Slide-by-Slide Speaker Guide）

### Slide 1 · 封面：Unlocking CodeMender at Scale
- **开场白**：今天和大家分享我们在三大跨语言真实项目（Python 微服务、Node.js `OWASP Juice Shop`、Java Spring Boot `macrozheng/mall`）上对 `CodeMender v0.14.0` 进行的 30 组深度测评。我们不打算只列一堆冷冰冰的参数，而是想讲一个故事：**为什么很多团队第一次跑 AI 安全扫描觉得“扫不出东西”或“老是超时”，以及我们如何通过一套可复用的方法论，把同一个工具的真实漏洞召回率从 0%–4.7% 提升到 100%，同时保持 0% 的误报率。**

---

### Slide 2 · 第一幕（The Paradox）：为什么盲扫会卡死，而引导式扫描能做到 100%？
- **演讲逻辑**：
  1. 先看左边的反差：当我们把 `CodeMender` 直接扔给项目跑默认命令时，Node.js 和 Java 在 480 秒后直接 Timeout 挂掉（**0.0% 召回**），Python 也因为一个依赖文件命名问题在 0.5 秒内误判退出，或者在全量盲扫时只扫出 **4.7%** 的问题。
  2. 再看右边：代码一行没改、工具版本也没变，仅仅改变编排方式后，Python 达到 **100% (11/11)**，Juice Shop 达到 **100% (26/26)**，Java Mall 达到 **95.5% 漏洞召回 (21/22) 与 100% 漏洞文件召回 (17/17)**。
  3. **核心洞察**：CodeMender 不是传统的正则扫描器，而是一个拥有有限推理轮次（Turns）的自主安全专家。要让它发挥真正实力，必须给它**三把钥匙**：
     - **Key 1（给它眼睛）**：消除配置与正则盲区；
     - **Key 2（给它并发与调用链视野）**：用 `--deep` + 文件共置索引看清跨文件调用；
     - **Key 3（给它一张安全地图）**：用 `-c` 五维模板代替漫无目的的盲找。

---

### Slide 3 · 第二幕 Step 1（给它眼睛）：消除导致 0% 产出的三大隐蔽陷阱
- **演讲逻辑**：在怪模型“不够聪明”之前，我们先排查为什么 Agent 连文件都没看到就退出了：
  1. **陷阱 1：默认 Quick 模式的 480 秒死锁**。在 `js_01` 和 `mall_01` 中，单 Worker 顺序扫描几十个复杂路由或 Spring 模块，必触发 480 秒硬超时，产出为 0。**解法**：生产环境一律启用 `--deep`（16 Worker 并发）。
  2. **陷阱 2：`config.yaml` 默认扩展名白名单截断了核心攻击面**。默认配置只认 `.py/.js/.ts/.java`，导致 Java 的 MyBatis `OrderDao.xml`（SQL 注入重灾区）、Spring `application.yml`（明文密码）和 Express 的 `videoHandler.pug`（SSTI 模板注入）在扫描前就被直接丢弃。**解法**：自动扩展 `source_extensions`。
  3. **陷阱 3：`py_13` 的 0.5 秒闪退悬案（`requirements.txt` 字面量正则碰撞）**。CodeMender 内部用字面量正则 `(?:^|/)requirements\.txt$` 判断是否有依赖清单。当项目使用 `requirements_vulnerable.txt` 时，Tier 0 裁剪器认为“没有依赖文件”，同时又把所有 `requirements*.txt` 当成锁文件裁剪掉，导致工作队列瞬间变空，0.5 秒直接返回 0 个漏洞！**解法**：在扫描前自动创建标准命名的 `requirements.txt` 软链接或副本。

---

### Slide 4 · 第二幕 Step 2（给它并发与调用链视野）：跨文件污点追踪与 0% 误报验证
- **演讲逻辑**：当 Agent 看到了所有文件，它如何超越传统 SAST（如 Semgrep/SonarQube 动辄 40%+ 的误报）？
  - 传统工具看到 SQL 拼接或文件读取就报警，不管前面有没有校验。
  - 当我们启用 `--deep` 并把关联的薄封装文件（Thin Wrappers / Mappers）放进同一个切片并附上 `PROJECT_FILE_INDEX.md` 时，CodeMender 能够像人类专家一样跨文件追查：
    - 在 Python 中，它穿透 `app_vulnerable.py -> internal_ReadFile -> file_service.py` 抓出路径穿越，同时识别出 `safe_join()` 保护的接口并自动静默（**0 误报**）。
    - 在 Java Mall 中，它从 `UmsAdminController` 一路追踪到 `PmsProductDao.xml` 的 `${}` 拼接，同时确认旁边使用 `#{}` 的查询是安全的（**0 误报**）。

---

### Slide 5 · 第二幕 Step 3（给它安全地图）：回答核心追问——有了 `--deep` 和 Argon，还能省掉 `-c` 吗？
- **演讲逻辑**：很多人会问：*“既然 `--deep` 和 `gemini-4-argon` 这么强，我能不能偷懒不传 `-c` 参数？”*
  - 为了严谨回答这个问题，我们在 **完全相同的文件范围、完全相同的 `--deep` 模式、完全相同的模型** 下，做了 9 组 `c0_none`（无 `-c`）vs `c3_hybrid_max`（带 `-c`）的严格对照实验：
    - **Python (10f)**：Flash 从 `72.7%` 提升至 **`100.0%`**（+27.3%）；
    - **Juice Shop (16f/18f)**：Flash 从 `42.3%` 飙升至 **`92.3%`**（**+50.0%**），Argon 从 `53.8%` 飙升至 **`92.3% -> 100.0%`**（**+46.2%**）；
    - **Java Mall (20f)**：Flash 从 `36.4%` 提升至 **`68.2%`**，Argon 从 `45.5%`（仅覆盖 47.1% 漏洞文件）直接跃升至 **`95.5%`**（覆盖 **100% 漏洞文件**，净增 **+50.0%**）！
  - **结论铁律**：**绝对不能省掉 `-c`！** 如果把无 `-c` 的测试混入生产汇总，三大项目的基准召回率会直接腰斩（漏掉 27%–54% 的标准漏洞）。但把它们作为**消融基线（Ablation Baseline）**展示，恰恰构成了 `-c` 不可或缺的最强铁证。

---

### Slide 6 · 第二幕深入拆解：`-c` 五维安全地图是如何一层层解锁隐藏漏洞的？
- **演讲逻辑**：为什么 `-c` 这么管用？我们在 Python 上做了四阶递进实验（`c0_none -> c1_sca -> c2_sast -> c3_hybrid_max`）：
  - **不带 `-c` (`c0_none`)**：Agent 把所有精力都花在看最显眼的 SQL 注入、命令注入和反序列化上（`72.7%`），完全忽略了依赖版本和敏感信息泄露。
  - **只加 SCA (`c1_sca`)**：立刻抓出 `PyYAML 5.3.1` / `Flask 1.1.2` 等 CVE，但又漏掉了代码逻辑漏洞（`54.5%`）。
  - **只加 SAST (`c2_sast`)**：代码层漏洞全出，但依赖 CVE 为 0（`72.7%`）。
  - **五维全开 (`c3_hybrid_max`：SAST + SCA + Config + Logic + InfoLeak)**：一次性补齐了最容易被模型忽略的 **配置缺陷、越权/免密重置逻辑、错误堆栈泄露与 CVE 依赖**，直达 **100% (11/11)**。

---

### Slide 7 · 第三幕（数据双重印证）：为什么带 `-c` 不仅多抓 2.9x–9.0x 漏洞，反而让扫描快了 3 倍？
- **演讲逻辑**：结合双面板图表（`chart_ablation.png`），揭示一个让人惊喜的工程发现：
  1. **左图看准度（Recall）**：三门语言全面逼近 95.5%–100%。
  2. **右图看深度（Total Verified Bugs）**：Juice Shop 深度漏洞从 19 个暴涨到 **118 个**（+120%），Java Mall 从 10 个暴涨到 **90 个**（**9.0 倍**）。
  3. **为什么带 `-c` 反而快了 3 倍？** 在 Java Mall 20 文件测试中，不带 `-c` 的 `Flash Deep (mall_05)` 像无头苍蝇一样在各个文件间反复试探，耗尽 **600 秒** 才找到 7 个问题；而加上 `-c` 地图的 `Flash Deep (mall_03)` 按图索骥，仅用 **202 秒（快了 3 倍！）** 就精准抓出 **20 个真实漏洞（2.9 倍产出）**。

---

### Slide 8 · 第三幕 Step 4（规模化切片策略）：为什么不要一次性把 297 个文件全塞给 Agent？
- **演讲逻辑**：解决了准度之后，面对动辄几百个文件的单体大仓（如 `macrozheng/mall` 的 297 个文件）怎么扫？
  - 在 `mall_02` 中，我们直接把 297 个文件一次性塞给 Agent。结果发现：仓库里有 **150 多个 MyBatis Generator 自动生成的 `Pms*.java` / `Oms*.java` 纯实体类（POJO）**。Agent 的并发轮次被这些毫无逻辑的 getter/setter 严重稀释，最后只抓出 7 个漏洞（`4.7%`）。
  - **破局方案（3 级智能切片）**：
    1. **1–5 文件（PR 增量扫描）**：`--deep` + `-c`，130–200 秒极速守门；
    2. **15–50 文件（高危 Web 切片）**：将路由、控制器、自定义 XML Mapper 和配置文件打包共置，单次 300–600 秒即可扫透核心攻击面；
    3. **50–300+ 文件（大型单体按业务域切片）**：先剔除自动生成的 POJO/静态资源，再按 `admin` / `portal` / `search` 切分为 20–50 文件的独立 Slice 并行扫描。

---

### Slide 9 · 第三幕破案实录 1：OWASP Juice Shop 是如何从 53.8% 追查到 100% (26/26) 的？
- **演讲逻辑**：用破案的视角复盘 Juice Shop 的完整演进：
  1. **第一阶段（无 `-c` 盲扫，`js_08`）**：在 16 个核心文件上用 Argon 盲扫，只找到 `14/26 (53.8%)`，漏掉了大量隐蔽的 NoSQL `$where` 注入、原型链污染和硬编码密钥。
  2. **第二阶段（注入 `-c` 五维地图，`js_12`）**：同样 16 个文件，加上 `-c` 后瞬间跃升至 **`24/26 (92.3%)`**！但为什么还差 2 个（`V03` 安全问题密码重置、`V15` Pug SSTI）？
  3. **第三阶段（揪出真凶并合龙，`js_15`）**：我们排查发现，并非 CodeMender 扫不出 `V03` 和 `V15`，而是这两个漏洞分别藏在 `routes/resetPassword.ts` 和 `routes/videoHandler.ts`（配合 `views/videoHandler.pug`）中，根本不在最初的 16 文件切片里！把这两个文件纳入形成 **18 文件完整 GT 切片 (`js_15`)** 后，CodeMender 一举达成 **26/26 (100.0% 漏洞召回) 与 18/18 (100.0% 官方挑战分类全覆盖)**！

---

### Slide 10 · 第三幕破案实录 2：Java `macrozheng/mall` 如何实现 100% 漏洞文件召回与 0% 误报？
- **演讲逻辑**：再看国内最经典的 Spring Boot + MyBatis 电商项目 `macrozheng/mall`（60k+ Stars）：
  - 我们构建了包含 **17 个真实含漏洞文件 + 3 个安全对照文件（共 20 个文件、22 个审计检查点）** 的独立基准 [`MALL_AUDIT_REFERENCE.md`](file:///usr/local/google/home/hongbocheng/projects/codemender-pipeline/ref-codemender-test/MALL_AUDIT_REFERENCE.md)。
  - **看点 1（外科手术级 SQLi 识别）**：在 `OrderDao.xml` 和 `ProductDao.xml` 中既有危险的 `${}` 拼接，也有安全的 `#{}` 预编译。CodeMender 100% 抓出所有 `${}` 注入，同时对 `#{}` 保持 **0% 误报**。
  - **看点 2（`-c` 带来的翻倍飞跃）**：不带 `-c` 时，哪怕是 Argon (`mall_06`) 也只能扫出 `8/17 (47.1%)` 的含漏洞文件（完全漏掉了 Actuator 未授权暴露、Swagger 越权、Mongo 缺少事务与全部 6 个 `pom.xml` CVE）；加上 `-c` 后 (`mall_04`)，**17/17 (100.0%) 含漏洞文件全部命中**，22 个检查点命中 21 个（**95.5%**）！

---

### Slide 11 · 第四幕（工程化自动化）：把四步经验浓缩成 2 条 CLI 命令
- **演讲逻辑**：讲了这么多最佳实践，难道每次扫描都要安全工程师手写 `config.yaml`、手写 `PROJECT_FILE_INDEX.md` 和几百行的 `-c` 提示词吗？
  - **完全不需要！** 我们把故事里的全部 4 个步骤封装进了自动化流水线 `pipeline.py`：
    1. `python3 pipeline.py profile --project <repo> --name <app>`：自动探测语言与构建文件、修复 `requirements.txt` 陷阱、放行 `.xml/.yml/.pug`、生成 `PROJECT_FILE_INDEX.md` 并组装五维 `-c` 模板。
    2. `python3 pipeline.py run --profile profiles/<app>.yaml --mode deep --model gemini-4-argon`：自动按最优切片并发调度并输出结构化 JSON/Markdown 报告。
  - **附赠实战贴士**：对于静态代码与依赖审计，**保持 `--enable-bash` 关闭**，速度提升 **1.87 倍**（133s vs 249s），召回率同样是 100%。

---

### Slide 12 · 第四幕收官：六条黄金法则与迈向 `cm fix` 的演进路线图
- **收束全篇**：
  - 左表将我们踩过的每一个坑（Quick 超时、扩展名盲区、`requirements.txt` 闪退、无 `-c` 漏检 50%、单体仓库 POJO 稀释、Bash 拖慢速度）与流水线的自动化机制一一对应。
  - 右侧给出三阶段落地路线：从当前的 **Phase 1（1–5 文件 PR 极速门禁 + 15–50 文件深度巡检）**，走向 **Phase 2（单体大仓按业务域并行切片 + `cm verify` 自动化验证）**，最终在 **Phase 3 打通 `cm fix` 自动生成安全补丁 PR（如自动将 MyBatis `${}` 替换为 `#{}`、升级 CVE 依赖）**，真正实现 AI 安全 Agent 的全闭环守护。
