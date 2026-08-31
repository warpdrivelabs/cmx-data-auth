#!/usr/bin/env bash
# cmx-dataauth 冒烟测试：seed 维度树 + 策略 + 授权 + 脱敏 + ReBAC，跑 decide/compile 断言。
#
# 用法（先启动服务）：
#   DATAAUTH_PG_URL=postgres://postgres:postgres@127.0.0.1:5432/fico SERVER__PORT=8098 \
#     cargo run -p cmx-dataauth-server &
#   ./dataauth.sh
set -euo pipefail
B="${DATAAUTH_BASE:-http://127.0.0.1:8098/api/dataauth/v1}"
pass=0; fail=0
chk() { # chk "名称" "期望子串" "实际"
  if [[ "$3" == *"$2"* ]]; then echo "  ✅ $1"; pass=$((pass+1));
  else echo "  ❌ $1"; echo "     期望含: $2"; echo "     实际: $3"; fail=$((fail+1)); fi
}
chkno() { # chkno "名称" "不应含子串" "实际"
  if [[ "$3" != *"$2"* ]]; then echo "  ✅ $1"; pass=$((pass+1));
  else echo "  ❌ $1"; echo "     不应含: $2"; echo "     实际: $3"; fail=$((fail+1)); fi
}
J='content-type: application/json'

echo "== 0. 清理（幂等：删旧策略/授权/元组，避免跨次累积污染）=="
del_all() { # del_all <list-path> <del-prefix>
  for id in $(curl -s "$B/$1" | python3 -c 'import sys,json
try:
  d=json.load(sys.stdin).get("data") or {}
  rows=d.get("items") if isinstance(d,dict) else d
  for x in rows or []: print(x["id"])
except Exception: pass'); do
    curl -s -XDELETE "$B/$2/$id" >/dev/null
  done
}
del_all policies policies
del_all grants grants
del_all relation-tuples relation-tuples
echo "  reset done"

echo "== 1. 维度树 org: 1001 -> {100101,100102} =="
curl -s -XPOST $B/dimension-values -H "$J" -d '{"dimKey":"org","dimValue":"1001","depth":0}' >/dev/null
curl -s -XPOST $B/dimension-values -H "$J" -d '{"dimKey":"org","dimValue":"100101","parentValue":"1001","depth":1}' >/dev/null
curl -s -XPOST $B/dimension-values -H "$J" -d '{"dimKey":"org","dimValue":"100102","parentValue":"1001","depth":1}' >/dev/null
echo "  seeded"

echo "== 2. 策略 + 授权 =="
PID=$(curl -s -XPOST $B/policies -H "$J" -d '{"name":"smoke-voucher","resourceKind":"voucher-smoke","action":"read","effect":"permit","constraintTpl":{"kind":"and","items":[{"kind":"in","field":"ou_id","values":["$dim:org"]},{"kind":"or","items":[{"kind":"cmp","field":"owner","op":"eq","value":"$user"},{"kind":"cmp","field":"status","op":"eq","value":"public"}]}]}}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["id"])')
curl -s -XPOST $B/grants -H "$J" -d "{\"policyId\":$PID,\"subjectType\":\"USER\",\"subjectId\":\"u42\",\"dimKey\":\"org\",\"dimValues\":[\"1001\"]}" >/dev/null
echo "  policy=$PID granted u42@org=1001"

echo "== 3. DECIDE u42 =="
D=$(curl -s -XPOST $B/decide -H "$J" -d '{"subject":{"userId":"u42","roles":["finance"]},"resource":{"kind":"voucher-smoke","action":"read","dimBindings":{"org":"ou_id"},"rowCtx":["owner","status"]}}')
chk "维度展开含子孙 100101" "100101" "$D"
chk "\$user 替换为 u42" '"value":"u42"' "$D"
chk "effect=permitWithConstraint" "permitWithConstraint" "$D"

echo "== 4. COMPILE → SQL 参数化 =="
C=$(curl -s -XPOST $B/compile -H "$J" -d '{"subject":{"userId":"u42","roles":["finance"]},"resource":{"kind":"voucher-smoke","action":"read","dimBindings":{"org":"ou_id"},"rowCtx":["owner","status"]},"backend":"sql"}')
chk "WHERE 含 ou_id IN" "ou_id IN (\$1, \$2, \$3)" "$C"
chk "参数含 public" '"public"' "$C"

echo "== 4b. inherit=false 只授本节点（P0#3 回归）=="
PIH=$(curl -s -XPOST $B/policies -H "$J" -d '{"name":"smoke-inherit","resourceKind":"voucher-inherit","action":"read","effect":"permit","constraintTpl":{"kind":"in","field":"ou_id","values":["$dim:org"]}}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["id"])')
curl -s -XPOST $B/grants -H "$J" -d "{\"policyId\":$PIH,\"subjectType\":\"USER\",\"subjectId\":\"u_inh\",\"dimKey\":\"org\",\"dimValues\":[\"1001\"],\"inherit\":false}" >/dev/null
CIH=$(curl -s -XPOST $B/compile -H "$J" -d '{"subject":{"userId":"u_inh"},"resource":{"kind":"voucher-inherit","action":"read","dimBindings":{"org":"ou_id"},"rowCtx":["ou_id"]},"backend":"sql"}')
# 只应含单占位（仅根 1001）；若 inherit 被忽略会展开成 ou_id IN ($1, $2, $3)。
chk "inherit=false 编译只含单占位（仅根）" 'ou_id IN ($1)' "$CIH"
chk "inherit=false 参数只有 1001" '"params":["1001"]' "$CIH"

echo "== 5. DENY 无授权 u99 =="
D2=$(curl -s -XPOST $B/decide -H "$J" -d '{"subject":{"userId":"u99","roles":["guest"]},"resource":{"kind":"voucher-smoke","action":"read","dimBindings":{"org":"ou_id"},"rowCtx":["owner","status"]}}')
chk "effect=deny" '"effect":"deny"' "$D2"

echo "== 6. ReBAC 关系元组 =="
# object_kind 约定 = field 去 _id 后缀（rptsmoke_id → rptsmoke），故 tuple.objectKind 必须同为 rptsmoke。
curl -s -XPOST $B/relation-tuples -H "$J" -d '{"objectKind":"rptsmoke","objectId":"RX1","relation":"viewer","subjectKind":"user","subjectId":"u77"}' >/dev/null
RP=$(curl -s -XPOST $B/policies -H "$J" -d '{"name":"smoke-report","resourceKind":"report-smoke","action":"read","effect":"permit","constraintTpl":{"kind":"relation","field":"rptsmoke_id","rel":"viewer","subject":"$user"}}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["id"])')
curl -s -XPOST $B/grants -H "$J" -d "{\"policyId\":$RP,\"subjectType\":\"USER\",\"subjectId\":\"u77\"}" >/dev/null
RC=$(curl -s -XPOST $B/compile -H "$J" -d '{"subject":{"userId":"u77","roles":["analyst"]},"resource":{"kind":"report-smoke","action":"read","rowCtx":["rptsmoke_id"]},"backend":"sql"}')
chk "Relation 解析为 rptsmoke_id IN" "rptsmoke_id IN" "$RC"
chk "参数含 RX1" '"RX1"' "$RC"

echo "== 6b. ReBAC 多跳（组成员闭包，P1#6）=="
# alice ∈ eng ∈ eng2；mdoc:MD1 viewer @ group:eng2（经嵌套组）；mdoc:MD2 viewer @ user:alice（直接）
curl -s -XPOST $B/relation-tuples -H "$J" -d '{"objectKind":"group","objectId":"eng","relation":"member","subjectKind":"user","subjectId":"alice"}' >/dev/null
curl -s -XPOST $B/relation-tuples -H "$J" -d '{"objectKind":"group","objectId":"eng2","relation":"member","subjectKind":"group","subjectId":"eng"}' >/dev/null
curl -s -XPOST $B/relation-tuples -H "$J" -d '{"objectKind":"mdoc","objectId":"MD1","relation":"viewer","subjectKind":"group","subjectId":"eng2"}' >/dev/null
curl -s -XPOST $B/relation-tuples -H "$J" -d '{"objectKind":"mdoc","objectId":"MD2","relation":"viewer","subjectKind":"user","subjectId":"alice"}' >/dev/null
MRP=$(curl -s -XPOST $B/policies -H "$J" -d '{"name":"smoke-rebac2","resourceKind":"mdoc-smoke","action":"read","effect":"permit","constraintTpl":{"kind":"relation","field":"mdoc_id","rel":"viewer","subject":"$user"}}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["id"])')
curl -s -XPOST $B/grants -H "$J" -d "{\"policyId\":$MRP,\"subjectType\":\"USER\",\"subjectId\":\"alice\"}" >/dev/null
MRC=$(curl -s -XPOST $B/compile -H "$J" -d '{"subject":{"userId":"alice"},"resource":{"kind":"mdoc-smoke","action":"read","rowCtx":["mdoc_id"]},"backend":"sql"}')
chk "多跳含直接授权 MD2" '"MD2"' "$MRC"
chk "多跳含嵌套组 MD1（alice∈eng∈eng2）" '"MD1"' "$MRC"

echo "== 7. ENFORCE 内存过滤 + 脱敏（archetype-③，不碰 DB）=="
# 复用第 2 步的 voucher-smoke 策略（u42@org=1001 + public）。补一条 salary 脱敏规则。
curl -s -XPOST $B/mask-rules -H "$J" -d '{"resourceKind":"voucher-smoke","column":"amount","maskType":"FULL"}' >/dev/null
EN=$(curl -s -XPOST $B/enforce -H "$J" -d '{
  "subject":{"userId":"u42","roles":["finance"]},
  "resource":{"kind":"voucher-smoke","action":"read","dimBindings":{"org":"ou_id"},"rowCtx":["ou_id","owner","status","amount"]},
  "rows":[
    {"ou_id":"100101","owner":"u42","status":"draft","amount":100},
    {"ou_id":"1001","owner":"other","status":"public","amount":200},
    {"ou_id":"9999","owner":"u42","status":"draft","amount":300}
  ]
}')
chk "保留 2 行（org 子孙+owner / org+public）" '"kept":2' "$EN"
chk "过滤 1 行（org 不在集）" '"filtered":1' "$EN"
chk "amount 脱敏为 ****" '"amount":"****"' "$EN"

echo "== 7b. 列隐藏 HIDE（P1#8）=="
curl -s -XPOST $B/mask-rules -H "$J" -d '{"resourceKind":"voucher-smoke","column":"secret","maskType":"HIDE"}' >/dev/null
EH=$(curl -s -XPOST $B/enforce -H "$J" -d '{
  "subject":{"userId":"u42","roles":["finance"]},
  "resource":{"kind":"voucher-smoke","action":"read","dimBindings":{"org":"ou_id"},"rowCtx":["ou_id","owner","status","amount"]},
  "rows":[{"ou_id":"100101","owner":"u42","status":"draft","amount":100,"secret":"TOP"}]
}')
chk "保留 1 行" '"kept":1' "$EH"
chkno "HIDE 列值不外泄（无 secret:TOP）" '"secret":"TOP"' "$EH"
chk "数据行无 HIDE 列键" '"rows":[{"ou_id":"100101","owner":"u42","status":"draft","amount":"****"}]' "$EH"
chk "amount 仍脱敏 ****" '"amount":"****"' "$EH"

echo "== 8. D3 决策表作策略源（region=east→org；否则 false）=="
DP=$(curl -s -XPOST $B/policies -H "$J" -d '{"name":"smoke-dt","resourceKind":"dt-smoke","action":"read","effect":"permit","source":"decisionTable","constraintTpl":{"kind":"decisionTable","hitPolicy":"F","inputs":[{"id":"i1","label":"区域","expression":"region"}],"outputs":[{"id":"o1","label":"约束","name":"constraint"}],"rules":[{"id":"r1","inputEntries":["\"east\""],"outputEntries":["\"{\\\"kind\\\":\\\"in\\\",\\\"field\\\":\\\"ou_id\\\",\\\"values\\\":[\\\"$dim:org\\\"]}\""]},{"id":"r2","inputEntries":["-"],"outputEntries":["\"{\\\"kind\\\":\\\"false\\\"}\""]}]}}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["id"])')
curl -s -XPOST $B/grants -H "$J" -d "{\"policyId\":$DP,\"subjectType\":\"USER\",\"subjectId\":\"dte\",\"dimKey\":\"org\",\"dimValues\":[\"1001\"]}" >/dev/null
DEAST=$(curl -s -XPOST $B/compile -H "$J" -d '{"subject":{"userId":"dte","attrs":{"region":"east"}},"resource":{"kind":"dt-smoke","action":"read","dimBindings":{"org":"ou_id"},"rowCtx":["ou_id"]},"backend":"sql"}')
chk "east → 决策表输出 org 展开 SQL" "ou_id IN" "$DEAST"
DWEST=$(curl -s -XPOST $B/decide -H "$J" -d '{"subject":{"userId":"dte","attrs":{"region":"west"}},"resource":{"kind":"dt-smoke","action":"read","dimBindings":{"org":"ou_id"},"rowCtx":["ou_id"]}}')
chk "west → 决策表输出 false → Deny" '"effect":"deny"' "$DWEST"

echo "== 8b. ORG 主体授权（P1#9）=="
PORG=$(curl -s -XPOST $B/policies -H "$J" -d '{"name":"smoke-org","resourceKind":"voucher-org","action":"read","effect":"permit","constraintTpl":{"kind":"in","field":"ou_id","values":["$dim:org"]}}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["id"])')
curl -s -XPOST $B/grants -H "$J" -d "{\"policyId\":$PORG,\"subjectType\":\"ORG\",\"subjectId\":\"1001\",\"dimKey\":\"org\",\"dimValues\":[\"1001\"]}" >/dev/null
CORG=$(curl -s -XPOST $B/compile -H "$J" -d '{"subject":{"userId":"anyone","orgs":["1001"]},"resource":{"kind":"voucher-org","action":"read","dimBindings":{"org":"ou_id"},"rowCtx":["ou_id"]},"backend":"sql"}')
chk "ORG 主体命中 → ou_id IN 子树" "ou_id IN (\$1, \$2, \$3)" "$CORG"
chk "ORG 展开含子孙 100101" '"100101"' "$CORG"

echo "== 8c. 条件 Deny 扣除行集（P1#7）=="
curl -s -XPOST $B/policies -H "$J" -d '{"name":"cd-permit","resourceKind":"voucher-cd","action":"read","effect":"permit","constraintTpl":{"kind":"true"}}' >/dev/null
curl -s -XPOST $B/policies -H "$J" -d '{"name":"cd-deny","resourceKind":"voucher-cd","action":"read","effect":"deny","constraintTpl":{"kind":"cmp","field":"amount","op":"gt","value":1000000}}' >/dev/null
CCD=$(curl -s -XPOST $B/compile -H "$J" -d '{"subject":{"userId":"u1"},"resource":{"kind":"voucher-cd","action":"read","rowCtx":["amount"]},"backend":"sql"}')
chk "条件 Deny → NOT(amount>阈值)" "NOT (amount > \$1)" "$CCD"
chk "Deny 阈值参数 1000000" "1000000" "$CCD"
curl -s -XPOST $B/policies -H "$J" -d '{"name":"blk-permit","resourceKind":"voucher-block","action":"read","effect":"permit","constraintTpl":{"kind":"true"}}' >/dev/null
curl -s -XPOST $B/policies -H "$J" -d '{"name":"blk-denyall","resourceKind":"voucher-block","action":"read","effect":"deny","constraintTpl":{"kind":"true"}}' >/dev/null
CBLK=$(curl -s -XPOST $B/decide -H "$J" -d '{"subject":{"userId":"u1"},"resource":{"kind":"voucher-block","action":"read"}}')
chk "Deny 约束=True → 拒全部 deny" '"effect":"deny"' "$CBLK"

echo "== 9. D6 PEP + P0 认证/管理面 =="
echo "  ⏭  见独立脚本 ./dataauth-auth.sh（须以 DATAAUTH_AUTH_MODE=jwt 起服务；本 off 模式脚本不测认证）"

echo "== 10. L3 物化权限集缓存（空间换时间）=="
# org 字典树：华东1001→{沪100101,杭100102}；华南2001→{广2002}。
for row in '1001|华东|' '100101|上海|1001' '100102|杭州|1001' '2001|华南|' '2002|广州|2001'; do
  IFS='|' read -r v l p <<< "$row"
  curl -s -XPOST $B/dimension-values -H "$J" -d "{\"dimKey\":\"org\",\"dimValue\":\"$v\",\"label\":\"$l\",\"parentValue\":\"$p\"}" >/dev/null
done
curl -s -XPOST $B/grants -H "$J" -d '{"policyId":0,"subjectType":"ROLE","subjectId":"mc-fin","dimKey":"org","dimValues":["1001"]}' >/dev/null
M1=$(curl -s "$B/dict/org/permitted?roles=mc-fin")
chk "首查物化 fromCache=false" '"fromCache":false' "$M1"
chk "华东子树 3 条" '"count":3' "$M1"
M2=$(curl -s "$B/dict/org/permitted?roles=mc-fin")
chk "再查缓存命中 fromCache=true" '"fromCache":true' "$M2"
# 重分配追加华南 → save 自动失效。
GID=$(curl -s "$B/grants" | python3 -c 'import sys,json;print([g["id"] for g in json.load(sys.stdin)["data"]["items"] if g["subjectId"]=="mc-fin"][0])')
curl -s -XPOST $B/grants -H "$J" -d "{\"id\":$GID,\"policyId\":0,\"subjectType\":\"ROLE\",\"subjectId\":\"mc-fin\",\"dimKey\":\"org\",\"dimValues\":[\"1001\",\"2001\"]}" >/dev/null
M3=$(curl -s "$B/dict/org/permitted?roles=mc-fin")
chk "重分配后自动失效重算 fromCache=false" '"fromCache":false' "$M3"
chk "新集含华南 2002" '"2002"' "$M3"
# 显式刷新端点。
MR=$(curl -s -XPOST $B/dict/org/refresh)
chk "显式 refresh 返回失效键数" '"invalidated"' "$MR"

echo "== 11. RLS DDL 生成（防绕过纵深，P1#11）=="
RLS=$(curl -s -XPOST $B/rls/ddl -H "$J" -d '{"table":"voucher","dimColumn":"ou_id"}')
chk "启用 RLS" "ENABLE ROW LEVEL SECURITY" "$RLS"
chk "策略引用会话 GUC" "current_setting('dataauth.voucher_scope', true)" "$RLS"
chk "维度列过滤 (fail-closed)" "ou_id::text = ANY (string_to_array" "$RLS"
chk "set_config 写 scope" "set_config('dataauth.voucher_scope'" "$RLS"
RLSBAD=$(curl -s -XPOST $B/rls/ddl -H "$J" -d '{"table":"v; DROP TABLE x","dimColumn":"ou_id"}')
chk "非法表名被拒（防注入）" "非法标识符" "$RLSBAD"

echo "== 12. 列表分页/检索（P2#14）=="
PG1=$(curl -s "$B/policies?limit=2&offset=0")
chk "分页信封含 total" '"total":' "$PG1"
chk "分页 limit=2 生效" '"limit":2' "$PG1"
N=$(echo "$PG1" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["data"]["items"]))')
chk "本页返回 2 条" "2" "$N"
PGQ=$(curl -s "$B/policies?q=smoke-org")
chk "检索 q=smoke-org 命中" "smoke-org" "$PGQ"
chk "检索 smoke-org total=1" '"total":1' "$PGQ"

echo "== 13. 审计上下文（P2#20）=="
curl -s -XPOST $B/decide -H "$J" -d '{"subject":{"userId":"auditu","roles":["finance"],"orgs":["1001"]},"resource":{"kind":"voucher-org","action":"read","dimBindings":{"org":"ou_id"}}}' >/dev/null
# 取该用户的审计条目（从充足窗口里筛 userId=auditu，避免同秒时间戳排序抖动）。
AL=$(curl -s "$B/audit-logs?limit=200" | python3 -c 'import sys,json
d=json.load(sys.stdin)["data"]
rows=d.get("items") if isinstance(d,dict) else d
for r in rows or []:
  if r.get("userId")=="auditu": print(json.dumps(r,ensure_ascii=False)); break')
chk "审计含 subjectCtx" '"subjectCtx"' "$AL"
chk "审计记录 roles(finance)" "finance" "$AL"
chk "审计记录 orgs(1001)" '"1001"' "$AL"
chk "审计含 obligations 字段" '"obligations"' "$AL"

echo "== 14. 审计保留期清理 TTL（P2#13）=="
PRUNEHI=$(curl -s -XPOST "$B/audit-logs/prune?beforeDays=99999")
chk "高保留期删 0（无超期）" '"deleted":0' "$PRUNEHI"
PRUNE0=$(curl -s -XPOST "$B/audit-logs/prune?beforeDays=0")
chk "beforeDays=0 返回删除条数" '"deleted":' "$PRUNE0"

echo "== 15. L1 缓存：展开记忆 #15 + decide 缓存 #12 =="
sv() { curl -s "$B/stats" | python3 -c "import sys,json;print(json.load(sys.stdin)['data'].get('$1',0))"; }
DREQ='{"subject":{"userId":"u42","roles":["finance"]},"resource":{"kind":"voucher-smoke","action":"read","dimBindings":{"org":"ou_id"},"rowCtx":["owner","status"]}}'
curl -s -XPOST $B/decide -H "$J" -d "$DREQ" >/dev/null   # 触发 org 展开 → 展开记忆填充
D1=$(sv descCacheEntries)
chk "展开记忆已填充(>0)" "1" "$([ "${D1:-0}" -ge 1 ] && echo 1 || echo 0)"
curl -s -XPOST $B/dimension-values -H "$J" -d '{"dimKey":"org","dimValue":"1001","label":"华东"}' >/dev/null  # 配置写 → bump
D2=$(sv descCacheEntries)
chk "配置写后展开缓存清零" "1" "$([ "${D2:-0}" = "0" ] && echo 1 || echo 0)"
curl -s -XPOST $B/decide -H "$J" -d "$DREQ" >/dev/null
DEC=$(sv decideCacheEntries)
if [ "${DEC:-0}" -ge 1 ]; then chk "decide 缓存已填充(>0)" "1" "1"; else echo "  ⏭ decide 缓存未启用（DATAAUTH_DECIDE_CACHE_TTL_SECS=0，默认关闭），跳过"; fi

echo "== 16. 治理：变更审计 #21 + 决策解释 #19 + 策略重叠 #19 =="
CL=$(curl -s "$B/change-logs?limit=200")
chk "变更审计记录 policy 实体" '"entityType":"policy"' "$CL"
chk "变更审计含 op=upsert" '"op":"upsert"' "$CL"
EX=$(curl -s -XPOST $B/explain -H "$J" -d '{"subject":{"userId":"u42","roles":["finance"]},"resource":{"kind":"voucher-smoke","action":"read","dimBindings":{"org":"ou_id"},"rowCtx":["owner","status"]}}')
chk "explain 含解释数组" '"explanation"' "$EX"
chk "explain 命中策略 smoke-voucher" "smoke-voucher" "$EX"
OV=$(curl -s "$B/policies/overlap?resourceKind=voucher-block&action=read")
chk "overlap 检出 Deny=True 拒全部" "拒全部" "$OV"
chk "overlap denies=1" '"denies":1' "$OV"

echo "== 17. 生效期 valid_from/valid_to（P3#21b）=="
# 过期授权：valid_to 在过去 → decide 看不到；未来策略：valid_from 在未来 → decide 看不到。
PAST="2000-01-01T00:00:00Z"; FUTURE="2999-01-01T00:00:00Z"
PVF=$(curl -s -XPOST $B/policies -H "$J" -d '{"name":"vf-policy","resourceKind":"voucher-vf","action":"read","effect":"permit","constraintTpl":{"kind":"in","field":"ou_id","values":["$dim:org"]}}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["id"])')
# 授权已过期（valid_to 过去）
curl -s -XPOST $B/grants -H "$J" -d "{\"policyId\":$PVF,\"subjectType\":\"USER\",\"subjectId\":\"uvf\",\"dimKey\":\"org\",\"dimValues\":[\"1001\"],\"validTo\":\"$PAST\"}" >/dev/null
DVF=$(curl -s -XPOST $B/decide -H "$J" -d '{"subject":{"userId":"uvf"},"resource":{"kind":"voucher-vf","action":"read","dimBindings":{"org":"ou_id"}}}')
chk "过期授权 → decide 拒绝" '"effect":"deny"' "$DVF"
# 但管理面 list 仍能看到该授权（含 validTo）
GVF=$(curl -s "$B/grants?q=uvf")
chk "管理面 list 仍见过期授权" '"validTo"' "$GVF"
# 未生效策略（valid_from 未来）
curl -s -XPOST $B/policies -H "$J" -d "{\"name\":\"future-policy\",\"resourceKind\":\"voucher-fut\",\"action\":\"read\",\"effect\":\"permit\",\"validFrom\":\"$FUTURE\",\"constraintTpl\":{\"kind\":\"true\"}}" >/dev/null
curl -s -XPOST $B/grants -H "$J" -d '{"policyId":0,"subjectType":"USER","subjectId":"ufut","dimKey":"org","dimValues":["1001"]}' >/dev/null
DFUT=$(curl -s -XPOST $B/decide -H "$J" -d '{"subject":{"userId":"ufut"},"resource":{"kind":"voucher-fut","action":"read"}}')
chk "未生效策略 → decide 拒绝" '"effect":"deny"' "$DFUT"

echo "== 18. 工作台 #17 + OpenAPI #18 =="
ROOT="${B%/api/dataauth/v1}"
chk "OpenAPI 3.0 契约有效" '"openapi":"3.0.3"' "$(curl -s $B/openapi.json)"
chk "OpenAPI 覆盖 /decide" '"/decide"' "$(curl -s $B/openapi.json)"
chk "管理工作台 /console 可达" "数据权限工作台" "$(curl -s $ROOT/console)"
chk "Swagger UI /swagger 可达" "swagger-ui" "$(curl -s $ROOT/swagger)"

echo
echo "==== 通过 $pass · 失败 $fail ===="
[[ $fail -eq 0 ]]
