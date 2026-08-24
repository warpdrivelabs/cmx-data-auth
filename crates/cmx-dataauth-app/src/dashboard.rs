//! 极简自包含监控大盘（根 `/` 免认证，轮询 `/api/dataauth/v1/stats`）。

use axum::response::Html;

pub async fn dashboard() -> Html<&'static str> {
    Html(PAGE)
}

const PAGE: &str = r#"<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>cmx-dataauth 数据权限引擎</title>
<style>
:root{color-scheme:light dark}
body{margin:0;font-family:ui-sans-serif,system-ui,'PingFang SC','Microsoft YaHei',sans-serif;
background:#0f172a;color:#e2e8f0}
.wrap{max-width:880px;margin:0 auto;padding:40px 24px}
h1{font-size:22px;font-weight:700;margin:0 0 4px}
.sub{color:#94a3b8;font-size:13px;margin-bottom:28px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
.card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:18px}
.card .n{font-size:30px;font-weight:700;color:#818cf8}
.card .l{font-size:12px;color:#94a3b8;margin-top:6px}
.foot{margin-top:28px;color:#64748b;font-size:12px;line-height:1.7}
code{background:#334155;padding:1px 6px;border-radius:4px;font-size:12px}
</style></head><body><div class="wrap">
<h1>🛡️ cmx-dataauth 数据权限引擎</h1>
<div class="sub">决策/执行分离 · 约束 AST 多后端编译 · 部分求值 PDP</div>
<div class="grid">
<div class="card"><div class="n" id="policies">–</div><div class="l">策略 Policy</div></div>
<div class="card"><div class="n" id="grants">–</div><div class="l">授权 Grant</div></div>
<div class="card"><div class="n" id="tuples">–</div><div class="l">关系元组 ReBAC</div></div>
<div class="card"><div class="n" id="recentAudit">–</div><div class="l">近期审计</div></div>
</div>
<div class="foot">
决策端点 <code>POST /api/dataauth/v1/decide</code> · 编译端点 <code>POST /api/dataauth/v1/compile</code><br>
策略/授权/元组/脱敏/维度 CRUD 见 <code>/api/dataauth/v1/*</code> · 技术监控 <code>/_mon</code>
</div>
</div>
<script>
async function tick(){
  try{
    const r=await fetch('/api/dataauth/v1/stats');const j=await r.json();const d=j.data||{};
    for(const k of ['policies','grants','tuples','recentAudit'])
      document.getElementById(k).textContent=d[k]??'–';
  }catch(e){}
}
tick();setInterval(tick,5000);
</script>
</body></html>"#;
