//! #18 —— OpenAPI 3.0 契约 + Swagger UI。
//!
//! 手写 `serde_json` 契约（不引 utoipa 依赖，内容自控）。`/api/dataauth/v1/openapi.json` 免认证暴露；
//! `/swagger` 提供 Swagger UI（CDN，联网可用）。门户可反代二者。

use axum::response::Html;
use axum::Json;
use serde_json::{json, Value};

/// OpenAPI 3.0 契约文档。
pub fn spec() -> Value {
    let body = |schema: Value| json!({ "required": true, "content": { "application/json": { "schema": schema } } });
    let ok = |desc: &str| json!({ "200": { "description": desc } });
    let subject_resource = json!({
        "type": "object",
        "properties": {
            "subject": { "$ref": "#/components/schemas/Subject" },
            "resource": { "$ref": "#/components/schemas/Resource" }
        },
        "required": ["subject", "resource"]
    });

    json!({
      "openapi": "3.0.3",
      "info": {
        "title": "cmx-data-auth 数据权限引擎",
        "version": "1.0",
        "description": "决策与执行解耦 · 约束 AST 为轴 · 一次决策多点执行。前缀 /api/dataauth/v1。\n数据面(decide/compile/enforce)认证后开放；管理面(CRUD/审计/治理)需管理员角色。"
      },
      "servers": [ { "url": "/api/dataauth/v1" } ],
      "tags": [
        { "name": "决策", "description": "decide / compile / enforce / explain" },
        { "name": "策略", "description": "策略 CRUD + 重叠分析" },
        { "name": "授权", "description": "grant CRUD" },
        { "name": "ReBAC", "description": "关系元组 + lookup" },
        { "name": "脱敏", "description": "列脱敏规则" },
        { "name": "维度", "description": "层级维度值 + 可见集" },
        { "name": "兜底", "description": "PG RLS DDL 生成" },
        { "name": "审计", "description": "决策审计 / 变更审计 / 大盘" }
      ],
      "paths": {
        "/decide": { "post": {
          "tags": ["决策"], "summary": "决策：Subject×Resource → 残差约束 + 脱敏义务 + 轨迹",
          "requestBody": body(subject_resource.clone()),
          "responses": ok("Decision{effect, constraint, obligations, trace}")
        }},
        "/compile": { "post": {
          "tags": ["决策"], "summary": "决策 + 编译到后端（sql/es/rowfilter）",
          "requestBody": body(json!({ "allOf": [ subject_resource, { "type":"object","properties":{"backend":{"type":"string","enum":["sql","es","rowfilter"]}} } ] })),
          "responses": ok("{ decision, compiled }")
        }},
        "/enforce": { "post": {
          "tags": ["决策"], "summary": "内存执行：过滤 rows + 列脱敏（archetype-③，不碰 DB）",
          "requestBody": body(json!({ "type":"object","properties":{ "subject":{"$ref":"#/components/schemas/Subject"}, "resource":{"$ref":"#/components/schemas/Resource"}, "rows":{"type":"array","items":{"type":"object"}} } })),
          "responses": ok("{ effect, total, kept, filtered, rows, obligations }")
        }},
        "/explain": { "post": {
          "tags": ["决策"], "summary": "决策解释（管理面）：决策 + 人类可读 reasons",
          "requestBody": body(subject_resource),
          "responses": ok("{ decision, explanation[] }")
        }},
        "/policies": {
          "get": { "tags":["策略"], "summary":"分页列策略",
            "parameters": [ pageq_limit(), pageq_offset(), pageq_q() ],
            "responses": ok("{ items[], total, limit, offset }") },
          "post": { "tags":["策略"], "summary":"upsert 策略（需管理员）",
            "requestBody": body(json!({"$ref":"#/components/schemas/PolicyDef"})), "responses": ok("{ id }") }
        },
        "/policies/{id}": {
          "get": { "tags":["策略"], "summary":"取单条策略", "parameters":[ path_id() ], "responses": ok("PolicyDef") },
          "delete": { "tags":["策略"], "summary":"删策略", "parameters":[ path_id() ], "responses": ok("{ deleted }") }
        },
        "/policies/overlap": { "get": {
          "tags":["策略"], "summary":"策略重叠/冲突分析",
          "parameters": [ query_str("resourceKind", true), query_str("action", false) ],
          "responses": ok("{ policyCount, permits, denies, findings[] }")
        }},
        "/grants": {
          "get": { "tags":["授权"], "summary":"分页列授权", "parameters":[ pageq_limit(), pageq_offset(), pageq_q() ], "responses": ok("{ items[], total, limit, offset }") },
          "post": { "tags":["授权"], "summary":"upsert 授权（需管理员）", "requestBody": body(json!({"$ref":"#/components/schemas/Grant"})), "responses": ok("{ id }") }
        },
        "/grants/{id}": { "delete": { "tags":["授权"], "summary":"删授权", "parameters":[ path_id() ], "responses": ok("{ deleted }") } },
        "/relation-tuples": {
          "get": { "tags":["ReBAC"], "summary":"分页列关系元组", "parameters":[ pageq_limit(), pageq_offset(), pageq_q() ], "responses": ok("{ items[], total, ... }") },
          "post": { "tags":["ReBAC"], "summary":"upsert 关系元组", "responses": ok("{ id }") }
        },
        "/relation-tuples/lookup": { "get": { "tags":["ReBAC"], "summary":"查主体可及对象（含 group 多跳）",
          "parameters":[ query_str("objectKind",true), query_str("relation",true), query_str("subjectKind",false), query_str("subjectId",true) ], "responses": ok("{ objectIds[] }") } },
        "/mask-rules": {
          "get": { "tags":["脱敏"], "summary":"列脱敏规则", "parameters":[ query_str("resourceKind",false) ], "responses": ok("MaskRule[]") },
          "post": { "tags":["脱敏"], "summary":"upsert 脱敏规则（FULL/PARTIAL/HASH/HIDE）", "responses": ok("{ id }") }
        },
        "/dimensions/{dimKey}/values": { "get": { "tags":["维度"], "summary":"列某维度全部值", "parameters":[ path_str("dimKey") ], "responses": ok("DimensionValue[]") } },
        "/dimension-values": { "post": { "tags":["维度"], "summary":"upsert 维度值（层级树）", "responses": ok("{ ok }") } },
        "/dict/{dictCode}/permitted": { "get": { "tags":["维度"], "summary":"L3 物化缓存：主体可见字典条目",
          "parameters":[ path_str("dictCode"), query_str("userId",false), query_str("roles",false), query_str("orgs",false), query_str("posts",false) ], "responses": ok("{ entries[], fromCache, count }") } },
        "/rls/ddl": { "post": { "tags":["兜底"], "summary":"生成 PG RLS 兜底 DDL",
          "requestBody": body(json!({"type":"object","properties":{"table":{"type":"string"},"dimColumn":{"type":"string"}},"required":["table","dimColumn"]})),
          "responses": ok("{ ddl[], setScopeSql, guc }") }},
        "/audit-logs": { "get": { "tags":["审计"], "summary":"决策审计（含 subjectCtx/obligations）", "parameters":[ query_int("limit") ], "responses": ok("AuditLog[]") } },
        "/audit-logs/prune": { "post": { "tags":["审计"], "summary":"审计保留期清理 TTL", "parameters":[ query_int("beforeDays") ], "responses": ok("{ deleted }") } },
        "/change-logs": { "get": { "tags":["审计"], "summary":"配置变更审计（谁改了哪条配置）", "parameters":[ query_int("limit") ], "responses": ok("ChangeLog[]") } },
        "/stats": { "get": { "tags":["审计"], "summary":"大盘聚合（计数 + 缓存条目）", "responses": ok("{ policies, grants, tuples, matCacheEntries, decideCacheEntries, descCacheEntries }") } }
      },
      "components": { "schemas": {
        "Subject": { "type":"object", "properties": {
          "tenant":{"type":"string"}, "userId":{"type":"string"}, "roles":{"type":"array","items":{"type":"string"}},
          "orgs":{"type":"array","items":{"type":"string"}}, "posts":{"type":"array","items":{"type":"string"}},
          "dims":{"type":"object"}, "attrs":{"type":"object"} }, "required":["userId"] },
        "Resource": { "type":"object", "properties": {
          "kind":{"type":"string"}, "action":{"type":"string","enum":["read","write","delete","export"]},
          "dimBindings":{"type":"object","additionalProperties":{"type":"string"}}, "rowCtx":{"type":"array","items":{"type":"string"}} }, "required":["kind"] },
        "PolicyDef": { "type":"object", "properties": {
          "id":{"type":"integer"}, "name":{"type":"string"}, "resourceKind":{"type":"string"},
          "action":{"type":"string"}, "source":{"type":"string","enum":["inline","decisionTable"]},
          "constraintTpl":{"type":"object"}, "priority":{"type":"integer"}, "effect":{"type":"string","enum":["permit","deny"]},
          "validFrom":{"type":"string","format":"date-time","nullable":true}, "validTo":{"type":"string","format":"date-time","nullable":true} },
          "required":["name","resourceKind","constraintTpl"] },
        "Grant": { "type":"object", "properties": {
          "id":{"type":"integer"}, "policyId":{"type":"integer"}, "subjectType":{"type":"string","enum":["USER","ROLE","ORG","POST"]},
          "subjectId":{"type":"string"}, "dimKey":{"type":"string","nullable":true}, "dimValues":{"type":"array","items":{}},
          "inherit":{"type":"boolean"}, "validFrom":{"type":"string","format":"date-time","nullable":true}, "validTo":{"type":"string","format":"date-time","nullable":true} },
          "required":["policyId","subjectType","subjectId"] }
      }}
    })
}

fn path_id() -> Value {
    json!({ "name": "id", "in": "path", "required": true, "schema": { "type": "integer" } })
}
fn path_str(name: &str) -> Value {
    json!({ "name": name, "in": "path", "required": true, "schema": { "type": "string" } })
}
fn query_str(name: &str, required: bool) -> Value {
    json!({ "name": name, "in": "query", "required": required, "schema": { "type": "string" } })
}
fn query_int(name: &str) -> Value {
    json!({ "name": name, "in": "query", "required": false, "schema": { "type": "integer" } })
}
fn pageq_limit() -> Value {
    json!({ "name": "limit", "in": "query", "schema": { "type": "integer", "default": 50 } })
}
fn pageq_offset() -> Value {
    json!({ "name": "offset", "in": "query", "schema": { "type": "integer", "default": 0 } })
}
fn pageq_q() -> Value {
    json!({ "name": "q", "in": "query", "schema": { "type": "string" }, "description": "模糊检索" })
}

/// `GET /api/dataauth/v1/openapi.json`（免认证）。
pub async fn openapi_json() -> Json<Value> {
    Json(spec())
}

/// `GET /swagger`（免认证）：Swagger UI（CDN，联网可用）。
pub async fn swagger() -> Html<&'static str> {
    Html(SWAGGER_HTML)
}

const SWAGGER_HTML: &str = r#"<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>cmx-data-auth API</title>
<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
<style>body{margin:0}#swagger-ui{max-width:1100px;margin:0 auto}</style></head>
<body><div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>window.onload=function(){SwaggerUIBundle({url:'/api/dataauth/v1/openapi.json',dom_id:'#swagger-ui',deepLinking:true})}</script>
</body></html>"#;
