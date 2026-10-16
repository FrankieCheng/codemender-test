# `macrozheng/mall` 源码安全审计参考集与检出对比分析（非官方标准答案）

> **重要说明（定位与局限性）**：
> 与专门为安全竞赛设计的 OWASP Juice Shop（自带官方 `challenges.yml` 和 `codefixes/` 标准答案）不同，[`macrozheng/mall`](https://github.com/macrozheng/mall) 是一个真实的开源生产级电商脚手架项目（Spring Boot 3 + Spring Security + MyBatis + MinIO/OSS + Alipay），**其官方仓库不包含任何内置的漏洞标准答案（Ground Truth）清单**。
>
> 本文档整理的是基于 **`mall-bench`（20 个核心代表性文件）的人工源码审计参考基线（Curated Code Audit Reference）**，包含已核实的 **17 个含漏洞源码/配置文件（22 个典型安全缺陷）** 与 **3 个安全对照/纯属性容器负样本文件**，以及扩展至全量核心代码（`mall-core` 297 个文件）时的额外高危发现，仅供评估 CodeMender (`cm v0.14.0`) 在大型 Java/Spring Boot 多模块工程上的召回能力与防误报能力参考。

---

## 零、 文档中涉及的实验代号与缩写说明

- **三种扫描目录范围**：
  - **`mall-bench`（核心基准子集，20 个文件）**：精选的 20 个代表性核心文件（包含控制器、支付服务、安全配置、MyBatis XML 与 `pom.xml`）。
  - **`mall-high-risk`（旧称 `HR`，高危攻击面子集，57 个文件）**：包含所有 Controller 控制器、安全鉴权类、工具类与各模块配置文件的中等规模子集。
  - **`mall-core`（全量后端业务核心集，297 个文件）**：剔除 `mall-mbg`（MyBatis Generator 自动生成的样板代码）后的全量手写业务代码与配置。
- **五组核心对比实验代号**：
  - **`mall_03`**：使用 `gemini-3.8-flash` 模型 + `--deep` 并发深度模式扫描 `mall-bench`（20 个核心文件）。
  - **`mall_05`**：使用 `gemini-4-argon` 模型 + `--deep` 并发深度模式扫描 `mall-bench`（20 个核心文件）。
  - **`mall_12`**：使用 `gemini-4-argon` 模型 + `Quick` 快速单代理模式扫描 `mall-bench`（20 个核心文件）。
  - **`mall_08`**：使用 `gemini-3.8-flash` 模型 + `--deep` 并发深度模式 + **无 `-c` (`c0_none`)** 扫描 `mall-bench`（20 个核心文件）。
  - **`mall_10`**：使用 `gemini-4-argon` 模型 + `Quick` 快速单代理模式 + **无 `-c` (`c0_none`)** 扫描 `mall-bench`（20 个核心文件）。
  - **`mall_13`**：使用 `gemini-3.8-flash` 模型 + `--deep` 并发深度模式 + `c3_hybrid_max` 扫描 `mall-high-risk`（57 个高危文件子集）。
  - **`mall_14`**：使用 `gemini-3.8-flash` 模型 + `--deep` 并发深度模式 + `c3_hybrid_max` 扫描 `mall-core`（297 个全量后端核心文件）。
- **常见安全缩写**：
  - **`FP`（False Positive，误报率）**：把本来安全的代码误报为漏洞的比例（越低越好，`0.0%` 表示零误报）。
  - **`IDOR`（Insecure Direct Object Reference，不安全的直接对象引用 / 水平越权）**：接口未校验数据归属（如未校验订单是否属于当前登录用户），导致攻击者可通过遍历 ID 查看或修改他人订单。
  - **`POJO`（Plain Old Java Object，简单 Java 对象）**：仅包含属性字段与 `getter/setter` 方法、不含任何业务逻辑的纯数据承载类。

---

## 一、 `mall-bench`（20 个代表性文件）人工审计基线覆盖率汇总（含无 `-c` vs 有 `-c` 对比）

> 注：在 Quick 模式下不传 `-c` 的 `mall_01` (`3.8-flash`) 与 `mall_09` (`3.5-flash`) 均在 480 秒因目录遍历耗尽轮次而超时（检出 **0 个漏洞，0% 召回率**）；下表列出有产出的两组无 `-c` 运行（`mall_08` 与 `mall_10`）与五维 `-c` (`c3_hybrid_max`) 运行的直接对比：

| 评估维度 | 参考基数 | `mall_08` (`3.8F` Deep **无 `-c`**) | `mall_10` (`4-argon` Quick **无 `-c`**) | `mall_03` (`3.8F` Deep **有 `-c`**) | `mall_05` (`4-argon` Deep **有 `-c`**) | `mall_12` (`4-argon` Quick **有 `-c`**) | `mall_13`/`14` (`3.8F` 高危/全量 **有 `-c`**) | 多轮并集 (Union) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **正样本：17 个含已知缺陷的源码/配置文件** | **17 个文件** | 6 / 17 (**35.3%**) | 8 / 17 (**47.1%**) | 10 / 17 (**58.8%**) | 12 / 17 (**70.6%**) | **17 / 17 (100.0%)** | 12 / 17 (**70.6%**) | **17 / 17 (100.0%)** |
| **正样本：22 个已核实的代码/配置安全缺陷** | **22 个缺陷** | 7 / 22 (**31.8%**) | 10 / 22 (**45.5%**) | 13 / 22 (**59.1%**) | 18 / 22 (**81.8%**) | **21 / 22 (95.5%)** | 16 / 22 (**72.7%**) | **22 / 22 (100.0%)** |
| **负样本：2 个纯 `#{}` 参数化 MyBatis XML + 1 个纯属性 POJO** | **3 个负样本文件** | **0 误报 (`0.0%`)** | **0 误报 (`0.0%`)** | **0 误报 (`0.0%`)** | **0 误报 (`0.0%`)** | **0 误报 (`0.0%`)** | **0 误报 (`0.0%`)** | **0 误报 (`0.0%`)** |

---

## 二、 为什么 `mall-bench` 中有 3 个文件在所有轮次均为 `0` 检出？（负样本防误报验证）

通过对 `targets/mall` 源码进行静态核查，`mall-bench` 的 20 个文件中有 3 个文件本身不含代码级漏洞，起到了**检验误报率（False Positive Control）**的作用：

1. **`mall-admin/src/main/resources/dao/OmsOrderDao.xml`（0 处 `${}`，100% `#{}` 预编译参数化）**
   - 经源码正则核查，该手写 MyBatis XML Mapper 中的所有动态查询条件（`orderSn`、`receiverKeyword`、`status`、`sourceType` 等）均使用安全的 `#{...}` 预编译绑定，**不存在任何 `${...}` 字符串拼接**。CodeMender 在全部 15 轮实验中均未对其误报 SQL 注入（**`0%` 误报**）。
2. **`mall-admin/src/main/resources/dao/PmsProductDao.xml`（0 处 `${}`，100% `#{}` 预编译参数化）**
   - 该文件仅包含 `<select id="getUpdateInfo">` 的 `WHERE p.id=#{id}` 参数化查询，不含 `${}` 拼接，CodeMender 同样保持 **`0%` 误报**。
3. **`mall-security/src/main/java/com/macro/mall/security/config/IgnoreUrlsConfig.java`（纯 `@ConfigurationProperties` 属性承载 POJO）**
   - 该类仅 22 行，是一个空的 `List<String> urls = new ArrayList<>()` Getter/Setter 容器，本身不含任何白名单配置；真正的安全缺陷位于 `mall-admin/src/main/resources/application.yml:33` 与 `mall-portal/src/main/resources/application.yml:21` 的 `secure.ignored.urls` 配置项中——CodeMender 在 `mall_03`、`mall_05`、`mall_12`、`mall_13`、`mall_14` 中 **100% 将该缺陷精准定位到了两个 `application.yml` 文件上**。

---

## 三、 `mall-bench` 22 个已核实安全缺陷逐项命中矩阵（M01–M22，含无 `-c` vs 有 `-c` 对照）

| 编号 | 所属模块与文件 | 已核实的安全缺陷描述 | CWE 漏洞分类 | `mall_08` (`3.8F` Deep **无 `-c`**) | `mall_10` (`4-argon` Quick **无 `-c`**) | `mall_03` (`3.8F` Deep **有 `-c`**) | `mall_05` (`4-argon` Deep **有 `-c`**) | `mall_12` (`4-argon` Quick **有 `-c`**) | `mall_13`/`14` (`3.8F` 高危/全量 **有 `-c`**) |
| :---: | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **M01** | `mall-portal/.../controller/UmsMemberController.java:73` | **短信验证码直接明文返回在 HTTP 响应中** (`getAuthCode` 导致任意账号接管) | `CWE-200` / `CWE-287` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **M02** | `mall-portal/.../controller/UmsMemberController.java:81` | **未认证密码重置接口配合明文验证码导致任意用户密码篡改** (`updatePassword`) | `CWE-640` / `CWE-306` | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| **M03** | `mall-portal/.../controller/OmsPortalOrderController.java:48` | **无签名校验直接调用 `paySuccess` 导致 0 元支付绕过与订单状态篡改** | `CWE-840` / `CWE-306` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **M04** | `mall-portal/.../controller/OmsPortalOrderController.java:84-108` | **订单详情查询 (`detail`)、取消订单 (`cancelUserOrder`)、删除订单未校验 `memberId` 归属导致水平越权 (IDOR)** | `CWE-639` | ❌ | ✅ | ❌ | ✅ | ✅ | ✅ (`mall_13`/`14`) |
| **M05** | `mall-portal/.../service/impl/AlipayServiceImpl.java:81` | **支付宝异步回调 `notify` 未校验 `total_amount` / `seller_id` / `app_id` 及 `TRADE_SUCCESS` 状态导致支付伪造** | `CWE-345` / `CWE-840` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **M06** | `mall-portal/.../service/impl/AlipayServiceImpl.java:108` | **支付宝主动查询 `query(outTradeNo, tradeNo)` 未校验两者绑定关系，可用他人已付款 `tradeNo` 冲抵自己未付款订单** | `CWE-840` / `CWE-639` | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **M07** | `mall-portal/.../controller/AlipayController.java:67` | **`/alipay/**` 全路径免认证暴露，攻击者可未授权调用支付查询与触发回调状态变更** | `CWE-306` / `CWE-639` | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ (`mall_14`) |
| **M08** | `mall-admin/.../controller/MinioController.java:44` | **MinIO 文件上传未校验后缀与 Content-Type，且桶策略设置为 `*` 公开可读，导致存储型 XSS / 恶意文件托管** | `CWE-434` / `CWE-79` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **M09** | `mall-admin/.../controller/MinioController.java:86` | **`/minio/delete` 免认证暴露且直接信任客户端传入 `objectName` 导致任意文件删除** | `CWE-306` / `CWE-22` | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ (`mall_14`) |
| **M10** | `mall-admin/.../controller/OssController.java:32-44` | **阿里云 OSS 上传签名接口免认证暴露 + 回调接口 `/aliyun/oss/callback` 缺少签名验证** | `CWE-306` / `CWE-345` | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ |
| **M11** | `mall-admin/.../controller/UmsAdminController.java:46` | **后台管理员注册接口 `/admin/register` 被放入 `secure.ignored.urls` 免认证白名单，可任意自注册管理员账户** | `CWE-306` / `CWE-269` | ❌ | ✅ | ❌ | ✅ | ✅ | ✅ (`mall_14`) |
| **M12** | `mall-admin/.../controller/UmsAdminController.java:134` | **管理员更新接口批量赋值（Mass Assignment）及越权修改其他管理员密码 (`update` / `updatePassword`)** | `CWE-915` / `CWE-639` | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ (`mall_14`) |
| **M13** | `mall-admin/.../service/impl/UmsAdminServiceImpl.java:212` | **注销登录 (`logout`) 仅清理了 Redis 用户缓存而未将 JWT 令牌加入黑名单吊销，导致已注销令牌仍可使用** | `CWE-613` | ❌ | ✅ | ❌ | ❌ | ✅ | ❌ |
| **M14** | `mall-admin/src/main/resources/application.yml:19` | **`mall-admin` 硬编码弱密钥 `jwt.secret: mySecret`（可离线伪造任意管理员 JWT 令牌）** | `CWE-798` / `CWE-326` | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| **M15** | `mall-admin/src/main/resources/application.yml:33` | **`mall-admin` 安全白名单配置过宽，免认证暴露 `/admin/register`、`/minio/**`、`/actuator/**`、`/druid/**`** | `CWE-284` / `CWE-306` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **M16** | `mall-admin/src/main/resources/application-dev.yml:12` | **`mall-admin` 硬编码 MySQL/Redis/RabbitMQ 密码及 Druid 监控台默认账密 (`admin/admin`)** | `CWE-798` | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| **M17** | `mall-portal/src/main/resources/application.yml:15` | **`mall-portal` 硬编码相同弱密钥 `jwt.secret: mySecret`（前后台共用同一签名密钥导致跨端提权伪造）+ 暴露 Actuator/Druid** | `CWE-798` / `CWE-269` | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| **M18** | `mall-portal/src/main/resources/application-dev.yml:12` | **`mall-portal` 硬编码 Druid 监控台默认弱口令 (`admin/admin`) 与中间件凭证** | `CWE-798` | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| **M19** | `mall-security/.../util/JwtTokenUtil.java:59` | **JWT 解析与刷新缺陷（弱 HMAC 密钥派生、异常吞没及令牌过期刷新边界缺陷）** | `CWE-347` | ❌ | ✅ | ❌ | ❌ | ✅ | ✅ (`mall_13`) |
| **M20** | `mall-security/.../config/SecurityConfig.java:65` | **跨站请求伪造防护（CSRF）全局禁用，且当不存在 `DynamicSecurityService`（如 `mall-portal`）时退化为仅校验登录、无细粒度角色鉴权** | `CWE-352` / `CWE-862` | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **M21** | `mall-common/.../util/RequestUtil.java:25` | **无条件信任客户端 `X-Forwarded-For` / `Proxy-Client-IP` 请求头导致登录审计日志 IP 伪造** | `CWE-290` / `CWE-348` | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **M22** | `pom.xml:155` | **Docker Maven 插件暴露未加密/未认证的远程 Docker 守护进程 (`http://192.168.3.101:2375`) 及过期依赖** | `CWE-306` / `CWE-319` | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ |
| **合计** | **22 个已核实安全缺陷** | **缺陷召回率 (Recall)** | — | **7/22 (`31.8%`)** | **10/22 (`45.5%`)** | **13/22 (`59.1%`)** | **18/22 (`81.8%`)** | **21/22 (`95.5%`)** | **16/22 (`72.7%`)** |

---

## 四、 扩展范围（`mall-high-risk` 57 文件高危子集与 `mall-core` 297 文件全量集）额外发现的高危漏洞

在 `mall_13_high_risk_deep_optimal`（`57` 个高危文件）与 `mall_14_full_core_deep_optimal`（剔除 `mall-mbg` 后的全量 `297` 个核心文件）中，CodeMender 在 `mall-bench` 20 个文件之外进一步检出了以下真实高危漏洞：

1. **全局跨域资源共享（CORS）凭证泄露（`mall-common/.../config/GlobalCorsConfig.java:23`）**
   - 同时配置了 `config.addAllowedOriginPattern("*")` 与 `config.setAllowCredentials(true)`，允许任意第三方恶意站点跨域发起携带用户凭证的请求。
2. **退货申请与收货地址接口水平越权 IDOR（`OmsPortalOrderReturnApplyController.java` / `UmsMemberReceiveAddressServiceImpl.java`）**
   - 退货申请接口直接接受客户端提交的 `OmsOrderReturnApplyParam`（未强制校验订单是否属于当前登录会员，且未校验退款金额上限）。
3. **搜索与后台微服务生产环境硬编码凭证（`mall-search/src/main/resources/application-prod.yml:12`、`mall-admin/src/main/resources/application-prod.yml`）**
   - 生产环境配置文件 `application-prod.yml` 中同样硬编码了 Druid 监控面板默认账密 `admin/admin` 以及明文数据库/Redis 密码。
4. **MyBatis `PageHelper.orderBy()` / `setOrderByClause` 潜在排序注入面（`PmsPortalProductServiceImpl.java` 等）**
   - 虽然手写 `dao/*Dao.xml` 使用了 `#{}` 预编译参数化，但在部分 Service 实现中调用 `PageHelper.orderBy()` 或 `Example.setOrderByClause()` 时直接拼接了排序子句。
