# cmx-data-auth · 数据权限引擎微服务

方案落地实现，对应设计文档 [`../presentation/docs/数据权限完整方案.md`](../docs/数据权限完整方案.md)。
核心主张：**决策（谁能看什么）与执行（在哪里过滤）解耦** —— PDP 部分求值产出语义中立的**约束 AST**，
多个 PEP 后端（SQL / 内存谓词 / ES）各自把它编译成具体查询。DB 从"权威"退化为"众多编译目标之一"。

参照 `cmx-rulesengine` 的"一芯多壳"骨架构建（语义中立核 + 无长驻状态 + store-pg + app + server 薄壳）。

## Crate 分层（一芯多壳）

```
cmx-dataauth-core      语义中立内核：Subject/Resource/约束 AST/部分求值 PDP/多后端编译器  ── 零 DB、零 cmx-* 依赖
   ▲
cmx-dataauth-store-pg  DataAuthStore 的 tokio-postgres 实现 + 层级维度展开器（WITH RECURSIVE）
   ▲
cmx-dataauth-app       平台中立应用层（一芯）：decide/compile 编排 + CRUD handler + 泛型路由 + 租户/认证 + FEEL 脱敏
   ▲
cmx-dataauth-server    独立可跑 bin（cmx-web-chassis 骨架，:8096）
```

- **一芯多壳**：`cmx-dataauth-app` 的 handler 不绑 `State`，故 `dataauth_routes::<S>()` 对任意 state 泛型成立
  （独立壳用 `::<()>()`；未来平台壳可 `::<CmxAppState>()`）。
- 基础设施（cmx-database-pg / cmx-core / cmx-web-chassis / cmx-web-monitor / cmx-service-base）经跨 workspace
  path 复用 `../cmx-container`；FEEL 复用 `../cmx-rulesengine/crates/cmx-rule-feel`。

## M1 已实现能力

| 阶段 | 能力 | 落点 |
| --- | --- | --- |
| D0 | 领域模型 + 约束 AST（True/False/And/Or/Not/Cmp/In/Between/Relation）+ 智能构造化简 | core `ir.rs`/`subject.rs`/`def.rs`/`eval.rs` |
| D1 | SqlCompiler 参数化 `WHERE` 下推（**防注入**：字段白名单 + 值恒走 `$n` 占位） | core `compiler.rs` |
| D1+ | 多后端：RowFilterCompiler（内存谓词闭包）/ EsCompiler（bool/terms/range） | core `compiler.rs` |
| D2 | 层级维度展开（`org=1001` → 全部子孙，`WITH RECURSIVE`） | store-pg `expander.rs` |
| D4 | 列脱敏义务（FULL/PARTIAL/HASH），FEEL `condition_expr` 门 + 角色豁免门 | app `engine.rs` + cmx-rule-feel |
| D4+ | **义务执行器**：内存行集过滤 + 列脱敏（archetype-③，全程不碰 DB） | core `mask.rs` + app `engine::enforce` |
| D5 | 基础 ReBAC 关系元组（`Relation` → `lookup_resources` → `In`） | store-pg + app `engine.rs` |
| D3 | **决策表作策略源**：`source=decisionTable` 的策略经 cmx-rulesengine 求值成内联 Constraint | app `policy_source.rs` |
| D6 | **PEP 中间件自动注入**：业务 handler 权限无感，只声明 `DataScope`；Deny→403 短路 | app `pep.rs` |
| L3 | **物化权限集缓存**（空间换时间）：简单字典授权时算好可见集直接缓存，查询 O(1) 直取，再分配刷新 | app `matcache.rs` |
| — | 部分求值 PDP（超管短路 / Deny 短路 / 无授权 fail-closed / 空维度坍缩 False） | core `pdp.rs` |
| — | db-per-tenant（task_local 租户 scope + 懒备库）+ 决策审计 | app `tenant.rs`/`tenancy.rs` |

## 数据库表（`cmx_dataauth_*`，无外键，幂等 DDL）

`policy`（策略+约束AST模板）· `grant`（策略↔主体+维度值集）· `relation_tuple`（ReBAC）·
`dimension_value`（层级维度树）· `mask_rule`（列脱敏）· `audit_log`（决策审计）。

## 运行

```bash
# 启动（默认端口 8096，库 fico）
DATAAUTH_PG_URL=postgres://postgres:postgres@127.0.0.1:5432/fico SERVER__PORT=8096 \
  cargo run -p cmx-dataauth-server

# 冒烟测试（幂等，可重复跑）
./dataauth.sh
```

配置见 `data-auth-server.toml.example`。环境变量前缀 `DATAAUTH_`（`DATAAUTH_AUTH_MODE=off|jwt`、
`DATAAUTH_TENANCY=single|multi`、`DATAAUTH_PG_URL`…）；框架级端口走 `SERVER__PORT`。

### 安全（P0 加固）

- **认证模式**：`off`（默认，本地信任、含管理面放行，仅供开发）| `jwt`（HS256，**必须携带 `exp` 且校验过期**，
  拒绝默认/空密钥 `change-me`）| API Key。**生产禁 `off`**（off 模式启动会打印醒目告警）。
- **管理面鉴权**：策略/授权/脱敏/维度/关系元组的 CRUD + 审计属**管理面**，jwt/api-key 模式下要求管理员角色
  （`DATAAUTH_ADMIN_ROLES`，默认 `superadmin,admin,dataauth-admin`），否则 403；数据面（`/decide` `/compile`
  `/enforce` `/dict/*/permitted` `/stats`）对认证后调用者开放。管理员角色 ⊋ 决策超管：`dataauth-admin` 可管配置，
  但不会让 `decide` 短路成"看全部数据"。
- **租户白名单**：`DATAAUTH_ALLOWED_TENANTS`（可选，逗号分隔）—— 配置后 JWT `tenant` claim 不在集内即 401。
- **层级继承**：`grant.inherit=false` 只授本节点、不下钻子孙（此前被忽略，现已生效）。

### 认证/管理面冒烟

```bash
# jwt 模式起服务后跑（覆盖 P0 #1/#2/#4）
DATAAUTH_AUTH_MODE=jwt DATAAUTH_JWT_SECRET=test-secret ./dataauth-auth.sh
```

### 决策模型语义

- **主体类型**：`grant.subject_type` ∈ `USER` | `ROLE` | `ORG` | `POST`。`Subject` 携带 `user_id` / `roles` /
  `orgs` / `posts`；ORG/POST 做精确匹配（层级由 IAM 展开后传入）。`GET /dict/{code}/permitted` 支持 `?orgs=&posts=`。
- **策略组合（集合式）**：`permit` 策略的约束描述**可见行集**（多放行取并）；`deny` 策略的约束描述**被拒行集**
  （`True`=拒全部、`False`=不拒、谓词=拒该子集）。最终可见 = `OR(permit) AND NOT(OR(deny))`。**无放行策略 → 拒绝**。
- **priority**：只决定求值/编译顺序（高优先条件在生成 SQL 中靠前）与 trace 可读性，**不做覆盖裁决**；需要"高优先直接拒绝"
  用一条 `deny` 策略（约束 `True`）表达。
- **层级继承**：`grant.inherit=true`（默认）授本节点 + 全部子孙；`false` 只授本节点。
- **生效期**：policy/grant 可选 `validFrom`/`validTo`；求值热路径按 `now()` 过滤未生效/已过期（管理面 list/get 不过滤，可见全部）。
- **列脱敏/隐藏**：`mask_rule.mask_type` ∈ `FULL` | `PARTIAL` | `HASH` | `HIDE`。前三种改呈现值；`HIDE` 从投影**移除该列**
  （`****` ≠ 列不可见）。`DataScope::hidden_columns()` 供业务 handler 从 SELECT 省略隐藏列。
- **ReBAC 多跳**：`lookup_resources` 用 `WITH RECURSIVE` 求主体 userset 闭包（用户 → 所属 `group` → 嵌套组，沿
  `member` 边），再取任一 userset 关联的对象。无 `member`/`group` 元组时退化为单跳。
- **防绕过纵深（RLS 兜底）**：应用层 WHERE 下推为主力；`POST /rls/ddl {table,dimColumn}` 生成 PG RLS DDL
  （ENABLE/FORCE RLS + 按会话 GUC 过滤维度列，GUC 未设→无行 fail-closed）。应用以**非超级用户**连库、事务开始
  `set_config('dataauth.<table>_scope', ids, true)` 写入 scope，则即便调用方漏拼 WHERE，DB 层仍拦截。维度级粗兜底，
  完整残差仍靠应用层。
- **L1 缓存（进程内，读多写少）**：`decide` 决策缓存（`DATAAUTH_DECIDE_CACHE_TTL_SECS`，**默认 0=关闭**，命中仍写审计）
  + `descendants` 展开记忆（`DATAAUTH_DESC_CACHE_TTL_SECS`，默认 60s）。**失效**：任一配置写 bump 全局代际 + 清空缓存
  （fail-fresh，撤销即失效，无陈旧放行）；TTL 兜底多实例。stats 暴露 `decideCacheEntries`/`descCacheEntries`。生产可换 Redis。

## 核心端点（`/api/dataauth/v1/*`）

- `POST /decide` — `{subject, resource}` → `Decision{effect, constraint, obligations, trace}`
- `POST /compile` — `{subject, resource, backend}` → decide + 编译（`backend` ∈ `sql`|`es`|`rowfilter`）
- `POST /enforce` — `{subject, resource, rows}` → decide + **内存过滤 rows + 列脱敏**（archetype-③，不碰 DB）
- `GET /demo/vouchers` — **D6 演示**：权限无感业务 handler，经 `pep::guard` 自动注入 `DataScope`
- `DELETE /demo/vouchers/{id}` — **写/删侧演示**（Action::Delete）：把 `DataScope` 拼进 DELETE（scope 参数在前、自有参数续号）
- `GET /dict/{dictCode}/permitted[?userId=&roles=]` — **L3 物化缓存**：直取主体在该字典的可见条目
- `POST /dict/{dictCode}/refresh` — 失效该字典物化缓存（body 可选 `{subjectType, subjectId}` 精准失效）
- CRUD（管理面，jwt/api-key 需管理员角色）：`/policies` `/grants` `/relation-tuples`（+ `/lookup`）`/mask-rules` `/dimension-values`
  —— 列表支持分页/检索 `?limit=&offset=&q=`，返回 `{items, total, limit, offset}`
- `POST /rls/ddl` — 生成 PG RLS 兜底 DDL（防绕过纵深）
- 治理：`POST /explain`（决策解释）· `GET /policies/overlap?resourceKind=&action=`（策略重叠/冲突分析）· `GET /change-logs`（配置变更审计）
- `/audit-logs`（含 `subjectCtx`/`obligations` 上下文）· `POST /audit-logs/prune?beforeDays=90`（保留期清理）· `/stats` · 根 `/` 监控大盘 · `/_mon` 技术监控

### L3 物化权限集缓存（空间换时间）

对**枚举可穷尽的简单字典**（组织机构/成本中心/项目），授权时就把"某 principal 可见哪些条目"预计算成
ID 集合缓存（键 = `(tenant, dictCode, subjectType, subjectId)`）。前端查字典 O(1) 直取（`GET /dict/{code}/permitted`），
用户有效集 = `cache[user:自身] ∪ cache[role:各角色]` 去重。**再分配即刷新**：`save_grant`/`delete_grant` 精准失效
对应 principal 键，`POST /dict/{code}/refresh` 显式刷新。物化复用 `WITH RECURSIVE` 维度展开；超管/授 `*` → 全量。
判据：仅小字典（大表集合会爆炸，仍走 L1/L2 惰性下推）。载体 M1 进程内，生产换 Redis。

### D3 决策表作策略源

`source=decisionTable` 的策略把 cmx-rulesengine 的 `DecisionBody` JSON 存进 `constraintTpl`；
decide 前用主体事实（roles/dims/attrs）跑决策表，读输出列 `constraint`（Constraint 的 JSON）→ 降解为内联
模板 → 走同一 subst/compose 管道。cmx-rulesengine 作**纯库**复用，core 保持零 rule 依赖。

### D6 PEP 中间件自动注入

给业务路由挂 `pep::guard(ResourceSpec)` 层，中间件读 task_local 主体 → decide + 编译 SQL → 把
`DataScope{whereSql, params, obligations}` 注入请求扩展；**Deny → 403 短路**。业务 handler 只声明
`Extension<DataScope>`（或 `pep::scope_from`），把 `where_sql`/`params` 拼进自己的查询——不 import 任何策略概念。

### decide → compile 示例

```
POST /decide  { subject:{userId:"u42",dims会经grant+维度树展开}, resource:{kind:"voucher",...} }
→ constraint: ou_id IN [1001,100101,100102] AND (owner=u42 OR status=public)

POST /compile { ..., backend:"sql" }
→ { whereSql: "(ou_id IN ($1,$2,$3)) AND ((owner=$4) OR (status=$5))",
    params: ["1001","100101","100102","u42","public"] }
```

## 验证状态

- `cargo build --workspace` ✓（离线 aliyun 镜像）
- `cargo test --workspace` ✓ 47 单测（1 ignored；含 inherit / 条件 Deny / Deny-all / ORG 主体 / 列隐藏 / RLS 生成 回归）
- `cargo clippy --workspace` ✓ 0 警告
- 真机启动 + `dataauth.sh` 端到端 ✓ 59/59（维度展开 / SQL+ES 编译 / Deny / 脱敏三态 / ReBAC 单跳+**多跳组成员** /
  enforce 内存过滤+脱敏 / **列隐藏 HIDE** / D3 决策表源 / L3 物化缓存 / **inherit=false** / **ORG 主体** / **条件 Deny** /
  **RLS DDL 生成** / **列表分页检索** / **审计上下文** / **审计 TTL 清理** / **L1 decide+展开缓存** / **变更审计** / **决策解释** /
  **策略重叠分析** / **生效期 valid_from/to**）
- 认证/管理面 `dataauth-auth.sh`（jwt 模式）✓ 10/10（**#1 管理面 403/200 · #2 exp/密钥/无令牌 401 · #4 删侧 scoped DELETE + 无权 403**）

## 非目标（后续）

D6 PG RLS DDL 生成兜底 · 递归 Zanzibar userset（组→成员多跳）· 报表/流程 WHERE 注入接缝 ·
native pages + OpenAPI/Swagger · L1/L2 缓存（Redis）。
