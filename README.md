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

## 核心端点（`/api/dataauth/v1/*`）

- `POST /decide` — `{subject, resource}` → `Decision{effect, constraint, obligations, trace}`
- `POST /compile` — `{subject, resource, backend}` → decide + 编译（`backend` ∈ `sql`|`es`|`rowfilter`）
- `POST /enforce` — `{subject, resource, rows}` → decide + **内存过滤 rows + 列脱敏**（archetype-③，不碰 DB）
- `GET /demo/vouchers` — **D6 演示**：权限无感业务 handler，经 `pep::guard` 自动注入 `DataScope`
- `GET /dict/{dictCode}/permitted[?userId=&roles=]` — **L3 物化缓存**：直取主体在该字典的可见条目
- `POST /dict/{dictCode}/refresh` — 失效该字典物化缓存（body 可选 `{subjectType, subjectId}` 精准失效）
- CRUD：`/policies`（`source` ∈ `inline`|`decisionTable`）`/grants` `/relation-tuples`（+ `/lookup`）`/mask-rules` `/dimension-values`
- `/audit-logs` · `/stats` · 根 `/` 监控大盘 · `/_mon` 技术监控

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

- `cargo build --workspace` ✓（403 crates，离线 aliyun 镜像）
- `cargo test --workspace` ✓ 39 单测（1 ignored = pep.rs 文档示例）
- `cargo clippy --workspace` ✓ 0 警告
- 真机启动 + `dataauth.sh` 端到端 ✓ 19/19（维度展开 / SQL+ES 编译 / Deny / 脱敏三态 / ReBAC / enforce 内存过滤+脱敏 / D3 决策表源 / D6 PEP 注入 / L3 物化缓存）

## 非目标（后续）

D6 PG RLS DDL 生成兜底 · 递归 Zanzibar userset（组→成员多跳）· 报表/流程 WHERE 注入接缝 ·
native pages + OpenAPI/Swagger · L1/L2 缓存（Redis）。
