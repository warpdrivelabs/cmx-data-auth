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

echo
echo "==== 通过 $pass · 失败 $fail ===="
[[ $fail -eq 0 ]]
