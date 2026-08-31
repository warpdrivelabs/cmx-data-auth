//! #17 —— 数据权限管理工作台（自包含单页，免构建）。
//!
//! 深色主题，标签式导航，纯 vanilla JS 调 `/api/dataauth/v1/*`。off 模式直接可用；jwt/门户模式由反代注入身份。
//! 覆盖：大盘 / 策略 / 授权 / 脱敏 / 维度 / 关系 / 决策解释 / 审计。门户可反代 `/console`。

use axum::response::Html;

pub async fn console() -> Html<&'static str> {
    Html(PAGE)
}

const PAGE: &str = r####"<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>数据权限工作台 · cmx-data-auth</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;font-family:ui-sans-serif,system-ui,'PingFang SC','Microsoft YaHei',sans-serif;background:#0f172a;color:#e2e8f0;font-size:13px}
header{padding:14px 22px;border-bottom:1px solid #1e293b;display:flex;align-items:center;gap:14px}
header h1{font-size:16px;margin:0;font-weight:700}
header .sub{color:#64748b;font-size:12px}
header a{color:#7dd3fc;text-decoration:none;font-size:12px;margin-left:auto}
nav{display:flex;gap:4px;padding:8px 16px;border-bottom:1px solid #1e293b;flex-wrap:wrap}
nav button{background:#1e293b;border:1px solid #334155;color:#cbd5e1;border-radius:8px;padding:6px 12px;cursor:pointer;font-size:12.5px}
nav button.on{background:#6366f1;border-color:#6366f1;color:#fff}
main{padding:18px 22px;max-width:1180px;margin:0 auto}
.tab{display:none}.tab.on{display:block}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:18px}
.card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:14px}
.card .n{font-size:26px;font-weight:800}.card .l{color:#94a3b8;font-size:12px;margin-top:2px}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid #1e293b;vertical-align:top}
th{color:#94a3b8;font-weight:600;font-size:11.5px}
td code{font-family:ui-monospace,Menlo,Consolas,monospace;color:#a5b4fc;word-break:break-all}
.pill{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px}
.pill.permit{background:#064e3b;color:#6ee7b7}.pill.deny{background:#450a0a;color:#fca5a5}
button.del{background:#450a0a;color:#fca5a5;border:1px solid #7f1d1d;border-radius:6px;padding:3px 8px;cursor:pointer;font-size:11px}
button.act{background:#6366f1;color:#fff;border:0;border-radius:8px;padding:8px 14px;cursor:pointer;font-weight:600}
.form{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:14px;margin-bottom:16px}
.form h3{margin:0 0 10px;font-size:13px}
.row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:8px}
.row label{display:flex;flex-direction:column;gap:3px;font-size:11.5px;color:#94a3b8;flex:1;min-width:140px}
input,select,textarea{background:#0f172a;border:1px solid #334155;color:#e2e8f0;border-radius:7px;padding:7px 9px;font-size:12.5px;font-family:inherit}
textarea{font-family:ui-monospace,Menlo,Consolas,monospace;min-height:64px;width:100%}
.hint{color:#64748b;font-size:11px;margin-top:6px}
pre{background:#0b1220;border:1px solid #1e293b;border-radius:10px;padding:12px;overflow:auto;font-size:11.5px;color:#cbd5e1}
.msg{padding:8px 12px;border-radius:8px;margin-bottom:10px;font-size:12px}
.msg.ok{background:#064e3b;color:#6ee7b7}.msg.err{background:#450a0a;color:#fca5a5}
h2{font-size:15px;margin:0 0 12px}
</style></head><body>
<header>
  <h1>🛡 数据权限工作台</h1><span class="sub" id="hdr">cmx-data-auth</span>
  <a href="/swagger" target="_blank">API 文档 ↗</a><a href="/" style="margin-left:14px">监控大盘 ↗</a>
</header>
<nav id="nav"></nav>
<main>
  <div id="msg"></div>
  <div class="tab" data-t="dash"><h2>大盘</h2><div class="cards" id="dashcards"></div></div>
  <div class="tab" data-t="policy"><h2>策略</h2>
    <div class="form"><h3>新建/更新策略</h3>
      <div class="row">
        <label>名称<input id="p_name" placeholder="voucher-read"></label>
        <label>资源 resourceKind<input id="p_kind" placeholder="voucher"></label>
        <label>动作<select id="p_action"><option>read</option><option>write</option><option>delete</option><option>export</option></select></label>
        <label>效果<select id="p_effect"><option>permit</option><option>deny</option></select></label>
      </div>
      <label style="color:#94a3b8;font-size:11.5px">约束 constraintTpl (JSON)</label>
      <textarea id="p_tpl">{"kind":"in","field":"ou_id","values":["$dim:org"]}</textarea>
      <div class="hint">permit=可见行集；deny=被拒行集(True=拒全部)。维度占位 $dim:org，标量 $user。</div>
      <div style="margin-top:10px"><button class="act" onclick="savePolicy()">保存策略</button></div>
    </div>
    <div class="form" style="padding:10px 14px"><div class="row" style="margin:0;align-items:flex-end">
      <label>重叠分析 resourceKind<input id="ov_kind" placeholder="voucher"></label>
      <label>action<input id="ov_action" value="read"></label>
      <button class="act" onclick="overlap()">分析</button></div>
      <pre id="ov_out" style="display:none;margin-top:10px"></pre></div>
    <table><thead><tr><th>id</th><th>名称</th><th>资源/动作</th><th>效果</th><th>源</th><th>约束</th><th></th></tr></thead><tbody id="policy_rows"></tbody></table>
  </div>
  <div class="tab" data-t="grant"><h2>授权</h2>
    <div class="form"><h3>新建授权</h3>
      <div class="row">
        <label>策略 id<input id="g_pid" value="0"></label>
        <label>主体类型<select id="g_stype"><option>USER</option><option>ROLE</option><option>ORG</option><option>POST</option></select></label>
        <label>主体 id<input id="g_sid" placeholder="u42"></label>
        <label>维度键 dimKey<input id="g_dk" placeholder="org"></label>
        <label>维度根值(逗号)<input id="g_dv" placeholder="1001"></label>
        <label>继承<select id="g_inh"><option value="true">是(含子孙)</option><option value="false">否(仅本节点)</option></select></label>
      </div>
      <div style="margin-top:6px"><button class="act" onclick="saveGrant()">保存授权</button></div>
    </div>
    <table><thead><tr><th>id</th><th>策略</th><th>主体</th><th>维度</th><th>继承</th><th>生效期</th><th></th></tr></thead><tbody id="grant_rows"></tbody></table>
  </div>
  <div class="tab" data-t="mask"><h2>脱敏规则</h2>
    <div class="form"><h3>新建脱敏规则</h3>
      <div class="row">
        <label>资源 resourceKind<input id="m_kind" placeholder="voucher"></label>
        <label>列 column<input id="m_col" placeholder="amount"></label>
        <label>类型<select id="m_type"><option>FULL</option><option>PARTIAL</option><option>HASH</option><option>HIDE</option></select></label>
        <label>PARTIAL 模式<input id="m_pat" placeholder="{3}****{4}"></label>
      </div><div class="row">
        <label>FEEL 条件(可空)<input id="m_cond" placeholder="grade < 5"></label>
        <label>豁免角色 minRole<input id="m_role" placeholder="hr"></label>
      </div>
      <div><button class="act" onclick="saveMask()">保存规则</button>
        <input id="m_q" placeholder="按 resourceKind 查" style="margin-left:10px"><button class="act" onclick="loadMask()" style="background:#334155">查询</button></div>
    </div>
    <table><thead><tr><th>id</th><th>资源</th><th>列</th><th>类型</th><th>条件/角色</th></tr></thead><tbody id="mask_rows"></tbody></table>
  </div>
  <div class="tab" data-t="dim"><h2>层级维度</h2>
    <div class="form"><h3>新建/更新维度值</h3>
      <div class="row">
        <label>维度键 dimKey<input id="d_key" placeholder="org"></label>
        <label>值 dimValue<input id="d_val" placeholder="100101"></label>
        <label>父值 parentValue<input id="d_par" placeholder="1001"></label>
        <label>标签<input id="d_lbl" placeholder="上海"></label>
      </div>
      <div><button class="act" onclick="saveDim()">保存</button>
        <input id="d_q" placeholder="dimKey 查树" value="org" style="margin-left:10px"><button class="act" onclick="loadDim()" style="background:#334155">列出</button></div>
    </div>
    <table><thead><tr><th>键</th><th>值</th><th>父</th><th>标签</th><th>depth</th></tr></thead><tbody id="dim_rows"></tbody></table>
  </div>
  <div class="tab" data-t="rebac"><h2>关系元组 (ReBAC)</h2>
    <div class="form"><h3>新建元组 object #relation @ subject</h3>
      <div class="row">
        <label>objectKind<input id="r_ok" placeholder="doc"></label>
        <label>objectId<input id="r_oi" placeholder="D1"></label>
        <label>relation<input id="r_rel" placeholder="viewer"></label>
        <label>subjectKind<input id="r_sk" placeholder="user"></label>
        <label>subjectId<input id="r_si" placeholder="alice"></label>
      </div>
      <div class="hint">组成员多跳：objectKind=group relation=member（用户→组→嵌套组闭包）。</div>
      <div style="margin-top:6px"><button class="act" onclick="saveTuple()">保存元组</button></div>
    </div>
    <table><thead><tr><th>id</th><th>object</th><th>relation</th><th>subject</th><th></th></tr></thead><tbody id="rebac_rows"></tbody></table>
  </div>
  <div class="tab" data-t="decide"><h2>决策解释</h2>
    <div class="form"><h3>试跑 explain</h3>
      <div class="row">
        <label>userId<input id="e_uid" value="u42"></label>
        <label>roles(逗号)<input id="e_roles" placeholder="finance"></label>
        <label>orgs(逗号)<input id="e_orgs" placeholder="1001"></label>
        <label>resource kind<input id="e_kind" value="voucher"></label>
        <label>action<input id="e_action" value="read"></label>
        <label>dimBindings org→列<input id="e_dim" value="org:ou_id"></label>
      </div>
      <div><button class="act" onclick="explain()">解释决策</button></div>
    </div>
    <pre id="e_out" style="display:none"></pre>
  </div>
  <div class="tab" data-t="audit"><h2>审计</h2>
    <h3 style="font-size:13px">决策审计（近 50）</h3>
    <table><thead><tr><th>时间</th><th>用户</th><th>资源/动作</th><th>效果</th><th>约束</th></tr></thead><tbody id="audit_rows"></tbody></table>
    <h3 style="font-size:13px;margin-top:20px">配置变更审计（近 50）</h3>
    <table><thead><tr><th>时间</th><th>操作者</th><th>op</th><th>实体</th><th>详情</th></tr></thead><tbody id="change_rows"></tbody></table>
  </div>
</main>
<script>
const V='/api/dataauth/v1';
const el=id=>document.getElementById(id);
const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function flash(t,ok){const m=el('msg');m.innerHTML=`<div class="msg ${ok?'ok':'err'}">${esc(t)}</div>`;setTimeout(()=>m.innerHTML='',3500)}
async function api(method,path,body){
  const r=await fetch(V+path,{method,headers:{'content-type':'application/json'},body:body?JSON.stringify(body):undefined});
  const j=await r.json().catch(()=>({code:r.status,msg:'非 JSON 响应'}));
  if(j.code!==0){throw new Error(j.msg||('HTTP '+r.status))}
  return j.data;
}
const items=d=>Array.isArray(d)?d:(d&&d.items)||[];
const TABS=[['dash','大盘'],['policy','策略'],['grant','授权'],['mask','脱敏'],['dim','维度'],['rebac','关系'],['decide','决策解释'],['audit','审计']];
function initNav(){el('nav').innerHTML=TABS.map(([k,l])=>`<button data-k="${k}" onclick="go('${k}')">${l}</button>`).join('')}
function go(k){document.querySelectorAll('.tab').forEach(t=>t.classList.toggle('on',t.dataset.t===k));
  document.querySelectorAll('#nav button').forEach(b=>b.classList.toggle('on',b.dataset.k===k));
  ({dash:loadDash,policy:loadPolicy,grant:loadGrant,mask:loadMask,dim:loadDim,rebac:loadRebac,audit:loadAudit}[k]||(()=>{}))();}
async function loadDash(){try{const s=await api('GET','/stats');
  const cards=[['policies','策略'],['grants','授权'],['tuples','关系元组'],['recentAudit','近期审计'],['matCacheEntries','L3缓存'],['decideCacheEntries','decide缓存'],['descCacheEntries','展开缓存']];
  el('dashcards').innerHTML=cards.map(([k,l])=>`<div class="card"><div class="n">${s[k]??0}</div><div class="l">${l}</div></div>`).join('');
}catch(e){flash(e.message,0)}}
async function loadPolicy(){try{const d=await api('GET','/policies?limit=200');
  el('policy_rows').innerHTML=items(d).map(p=>`<tr><td>${p.id}</td><td>${esc(p.name)}</td><td>${esc(p.resourceKind)}/${esc(p.action)}</td>
    <td><span class="pill ${p.effect}">${p.effect}</span></td><td>${esc(p.source||'inline')}</td>
    <td><code>${esc(JSON.stringify(p.constraintTpl))}</code></td>
    <td><button class="del" onclick="delRow('/policies/${p.id}','policy')">删</button></td></tr>`).join('')||'<tr><td colspan=7 style="color:#64748b">无</td></tr>';
}catch(e){flash(e.message,0)}}
async function savePolicy(){try{const tpl=JSON.parse(el('p_tpl').value);
  await api('POST','/policies',{name:el('p_name').value,resourceKind:el('p_kind').value,action:el('p_action').value,effect:el('p_effect').value,constraintTpl:tpl});
  flash('策略已保存',1);loadPolicy();}catch(e){flash('保存失败: '+e.message,0)}}
async function overlap(){try{const d=await api('GET',`/policies/overlap?resourceKind=${encodeURIComponent(el('ov_kind').value)}&action=${encodeURIComponent(el('ov_action').value)}`);
  el('ov_out').style.display='block';el('ov_out').textContent=JSON.stringify(d,null,2);}catch(e){flash(e.message,0)}}
async function loadGrant(){try{const d=await api('GET','/grants?limit=200');
  el('grant_rows').innerHTML=items(d).map(g=>`<tr><td>${g.id}</td><td>${g.policyId}</td><td>${esc(g.subjectType)}:${esc(g.subjectId)}</td>
    <td>${g.dimKey?esc(g.dimKey)+'='+esc(JSON.stringify(g.dimValues)):'-'}</td><td>${g.inherit?'是':'否'}</td>
    <td>${g.validFrom||g.validTo?esc((g.validFrom||'∅')+'~'+(g.validTo||'∅')):'永久'}</td>
    <td><button class="del" onclick="delRow('/grants/${g.id}','grant')">删</button></td></tr>`).join('')||'<tr><td colspan=7 style="color:#64748b">无</td></tr>';
}catch(e){flash(e.message,0)}}
async function saveGrant(){try{const dv=el('g_dv').value.split(',').map(s=>s.trim()).filter(Boolean);
  await api('POST','/grants',{policyId:+el('g_pid').value,subjectType:el('g_stype').value,subjectId:el('g_sid').value,
    dimKey:el('g_dk').value||null,dimValues:dv,inherit:el('g_inh').value==='true'});
  flash('授权已保存',1);loadGrant();}catch(e){flash('保存失败: '+e.message,0)}}
async function loadMask(){try{const q=el('m_q').value?('?resourceKind='+encodeURIComponent(el('m_q').value)):'';const d=await api('GET','/mask-rules'+q);
  el('mask_rows').innerHTML=items(d).map(m=>`<tr><td>${m.id}</td><td>${esc(m.resourceKind)}</td><td>${esc(m.column)}</td><td>${esc(m.maskType)}</td>
    <td>${esc(m.conditionExpr||'')} ${m.minRole?'豁免:'+esc(m.minRole):''}</td></tr>`).join('')||'<tr><td colspan=5 style="color:#64748b">无</td></tr>';
}catch(e){flash(e.message,0)}}
async function saveMask(){try{await api('POST','/mask-rules',{resourceKind:el('m_kind').value,column:el('m_col').value,maskType:el('m_type').value,
    partialPattern:el('m_pat').value||null,conditionExpr:el('m_cond').value||null,minRole:el('m_role').value||null});
  flash('脱敏规则已保存',1);loadMask();}catch(e){flash('保存失败: '+e.message,0)}}
async function loadDim(){try{const d=await api('GET','/dimensions/'+encodeURIComponent(el('d_q').value||'org')+'/values');
  el('dim_rows').innerHTML=items(d).map(x=>`<tr><td>${esc(x.dimKey)}</td><td>${esc(x.dimValue)}</td><td>${esc(x.parentValue||'')}</td><td>${esc(x.label||'')}</td><td>${x.depth??0}</td></tr>`).join('')||'<tr><td colspan=5 style="color:#64748b">无</td></tr>';
}catch(e){flash(e.message,0)}}
async function saveDim(){try{await api('POST','/dimension-values',{dimKey:el('d_key').value,dimValue:el('d_val').value,parentValue:el('d_par').value||null,label:el('d_lbl').value||null});
  flash('维度值已保存',1);loadDim();}catch(e){flash('保存失败: '+e.message,0)}}
async function loadRebac(){try{const d=await api('GET','/relation-tuples?limit=200');
  el('rebac_rows').innerHTML=items(d).map(t=>`<tr><td>${t.id}</td><td><code>${esc(t.objectKind)}:${esc(t.objectId)}</code></td><td>${esc(t.relation)}</td>
    <td><code>${esc(t.subjectKind)}:${esc(t.subjectId)}</code></td><td><button class="del" onclick="delRow('/relation-tuples/${t.id}','tuple')">删</button></td></tr>`).join('')||'<tr><td colspan=5 style="color:#64748b">无</td></tr>';
}catch(e){flash(e.message,0)}}
async function saveTuple(){try{await api('POST','/relation-tuples',{objectKind:el('r_ok').value,objectId:el('r_oi').value,relation:el('r_rel').value,subjectKind:el('r_sk').value,subjectId:el('r_si').value});
  flash('元组已保存',1);loadRebac();}catch(e){flash('保存失败: '+e.message,0)}}
async function explain(){try{const roles=el('e_roles').value.split(',').map(s=>s.trim()).filter(Boolean);
  const orgs=el('e_orgs').value.split(',').map(s=>s.trim()).filter(Boolean);
  const [dk,dc]=(el('e_dim').value||'').split(':');const db={};if(dk&&dc)db[dk]=dc;
  const d=await api('POST','/explain',{subject:{userId:el('e_uid').value,roles,orgs},resource:{kind:el('e_kind').value,action:el('e_action').value,dimBindings:db}});
  el('e_out').style.display='block';el('e_out').textContent=(d.explanation||[]).join('\n')+'\n\n'+JSON.stringify(d.decision,null,2);
}catch(e){flash(e.message,0)}}
async function loadAudit(){try{const a=await api('GET','/audit-logs?limit=50');
  el('audit_rows').innerHTML=(a||[]).map(x=>`<tr><td>${esc((x.createdAt||'').slice(0,19))}</td><td>${esc(x.userId)}</td><td>${esc(x.resourceKind)}/${esc(x.action)}</td>
    <td>${esc(x.effect)}</td><td><code>${esc(JSON.stringify(x.constraintJson))}</code></td></tr>`).join('')||'<tr><td colspan=5 style="color:#64748b">无</td></tr>';
  const c=await api('GET','/change-logs?limit=50');
  el('change_rows').innerHTML=(c||[]).map(x=>`<tr><td>${esc((x.createdAt||'').slice(0,19))}</td><td>${esc(x.actor||'-')}</td><td>${esc(x.op)}</td>
    <td>${esc(x.entityType)}:${esc(x.entityId)}</td><td><code>${esc(JSON.stringify(x.detail))}</code></td></tr>`).join('')||'<tr><td colspan=5 style="color:#64748b">无</td></tr>';
}catch(e){flash(e.message,0)}}
async function delRow(path,kind){if(!confirm('确认删除?'))return;try{await api('DELETE',path);flash('已删除',1);
  ({policy:loadPolicy,grant:loadGrant,tuple:loadRebac}[kind])();}catch(e){flash(e.message,0)}}
initNav();go('dash');
</script></body></html>"####;
