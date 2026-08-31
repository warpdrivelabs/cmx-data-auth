#!/usr/bin/env bash
# cmx-dataauth 冒烟测试：seed 维度树 + 策略 + 授权 + 脱敏 + ReBAC，跑 decide/compile 断言。
#
# 用法（先启动服务）：
#   DATAAUTH_PG_URL=postgres://postgres:postgres@127.0.0.1:5432/fico SERVER__PORT=8096 \
#     cargo run -p cmx-dataauth-server &
#   ./dataauth.sh
set -euo pipefail
B="${DATAAUTH_BASE:-http://127.0.0.1:8096/api/dataauth/v1}"
pass=0; fail=0
chk() { # chk "名称" "期望子串" "实际"
  if [[ "$3" == *"$2"* ]]; then echo "  ✅ $1"; pass=$((pass+1));
  else echo "  ❌ $1"; echo "     期望含: $2"; echo "     实际: $3"; fail=$((fail+1)); fi
}
J='content-type: application/json'

echo "== 0. 清理（幂等：删旧策略/授权/元组，避免跨次累积污染）=="
del_all() { # del_all <list-path> <del-prefix>
  for id in $(curl -s "$B/$1" | python3 -c 'import sys,json
try:
  for x in json.load(sys.stdin).get("data") or []: print(x["id"])
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
GID=$(curl -s "$B/grants" | python3 -c 'import sys,json;print([g["id"] for g in json.load(sys.stdin)["data"] if g["subjectId"]=="mc-fin"][0])')
curl -s -XPOST $B/grants -H "$J" -d "{\"id\":$GID,\"policyId\":0,\"subjectType\":\"ROLE\",\"subjectId\":\"mc-fin\",\"dimKey\":\"org\",\"dimValues\":[\"1001\",\"2001\"]}" >/dev/null
M3=$(curl -s "$B/dict/org/permitted?roles=mc-fin")
chk "重分配后自动失效重算 fromCache=false" '"fromCache":false' "$M3"
chk "新集含华南 2002" '"2002"' "$M3"
# 显式刷新端点。
MR=$(curl -s -XPOST $B/dict/org/refresh)
chk "显式 refresh 返回失效键数" '"invalidated"' "$MR"

echo
echo "==== 通过 $pass · 失败 $fail ===="
[[ $fail -eq 0 ]]
