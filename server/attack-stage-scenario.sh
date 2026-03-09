#!/usr/bin/env zsh

set -e
set -o pipefail

BASE_URL=${BASE_URL:-"http://localhost:4000"}
CLIENT_ORIGIN=${CLIENT_ORIGIN:-"http://localhost:5173"}
STAGE=${STAGE:-1}
REPORT_MODE=${REPORT_MODE:-"normal"}

UA_A="victim-browser/1.0"
UA_B="attacker-browser/2.0"

JAR_A="/tmp/stage_attack_A.txt"
JAR_B="/tmp/stage_attack_B.txt"
JAR_STEAL="/tmp/stage_attack_stolen.txt"
JAR_TEMP="/tmp/stage_attack_tmp.txt"

print_step() {
  echo
  echo "---- $1 ----"
}

need_jq() {
  if ! command -v jq >/dev/null 2>&1; then
    echo "[ERR] jq가 필요합니다. 설치: brew install jq"
    exit 1
  fi
}

csrf_cookie_value() {
  local jar_file="$1"
  awk '$6=="csrf_token"{print $7; exit}' "$jar_file" | tr -d '\r'
}

cookie_request() {
  local method="$1"
  local url="$2"
  local jar_file="$3"
  local ua="$4"
  shift 4
  local -a extra=( "$@" )

  local csrf=""
  local -a headers=(-H "Origin: ${CLIENT_ORIGIN}")
  headers+=( -H "User-Agent: ${ua}" )
  headers+=( -H "Content-Type: application/json" )
  headers+=( -A "${ua}" )

  if (( STAGE >= 6 )); then
    csrf=$(csrf_cookie_value "$jar_file")
    if [[ -n "$csrf" ]]; then
      headers+=( -H "x-csrf-token: ${csrf}" )
    fi
  fi

  if [[ -f "$jar_file" ]]; then
    local -a use_jar=( -b "$jar_file" )
  else
    local -a use_jar=()
  fi

  curl -s -i -X "$method" "${use_jar[@]}" "${headers[@]}" "${extra[@]}" "$url"
}

status_code() {
  echo "$1" | head -n 1 | awk '{print $2}'
}

expected_status() {
  local stage="$1"
  local step="$2"

  case "$step" in
    BASELINE_REFRESH)
      echo "200"
      ;;
    REPLAY_ATTACK)
      if (( stage >= 7 )); then
        echo "401|403"
      else
        echo "200"
      fi
      ;;
    B_REFRESH)
      echo "200"
      ;;
    A_AFTER_B_REFRESH)
      if (( stage >= 8 )); then
        echo "401|403"
      else
        echo "200"
      fi
      ;;
    UA_MISMATCH)
      if (( stage >= 8 )); then
        echo "401|403"
      else
        echo "200"
      fi
      ;;
    ORIGIN_ATTACK)
      if (( stage >= 6 )); then
        echo "403"
      else
        echo "200"
      fi
      ;;
    *)
      echo "*"
      ;;
  esac
}

status_ok() {
  local got="$1"
  local expected="$2"
  [[ "$expected" == "*" ]] && return 0
  [[ ":${expected//|/:}:" == *":$got:"* ]]
}

check_status() {
  local label="$1"
  local got="$2"
  local expected="$3"

  if status_ok "$got" "$expected"; then
    echo "[OK] $label: status=$got (expected=$expected)"
    ((PASS_COUNT++))
    return 0
  else
    echo "[WARN] $label: status=$got (expected=$expected)"
    ((WARN_COUNT++))
    return 1
  fi
}

report_row() {
  local label="$1"
  local status="$2"
  local expect="$3"
  if status_ok "$status" "$expect"; then
    printf "| %-36s | PASS | %-9s | %-12s |\n" "$label" "$status" "$expect"
  else
    printf "| %-36s | FAIL | %-9s | %-12s |\n" "$label" "$status" "$expect"
  fi
}

print_stage_matrix() {
  local stage
  print_step "고정 시나리오 기대값 매트릭스"
  echo "- 공격 시나리오는 고정, STAGE만 바뀌어 방어가 강화되는 구조"
  printf "| STAGE | BASELINE_REFRESH | REPLAY_ATTACK | B_REFRESH | A_AFTER_B_REFRESH | UA_MISMATCH | ORIGIN_ATTACK |\n"
  printf "|---|---|---|---|---|---|---|\n"
  for stage in {1..8}; do
    printf "| %5s | %-16s | %-13s | %-9s | %-18s | %-11s | %-13s |\n" \
      "$stage" \
      "$(expected_status "$stage" "BASELINE_REFRESH")" \
      "$(expected_status "$stage" "REPLAY_ATTACK")" \
      "$(expected_status "$stage" "B_REFRESH")" \
      "$(expected_status "$stage" "A_AFTER_B_REFRESH")" \
      "$(expected_status "$stage" "UA_MISMATCH")" \
      "$(expected_status "$stage" "ORIGIN_ATTACK")"
  done
}

cleanup() {
  rm -f "$JAR_A" "$JAR_B" "$JAR_STEAL" "$JAR_TEMP"
}

trap cleanup EXIT

need_jq
rm -f "$JAR_A" "$JAR_B" "$JAR_STEAL" "$JAR_TEMP"
PASS_COUNT=0
WARN_COUNT=0

print_step "1) Stage 환경 체크"
echo "TARGET: $BASE_URL"
echo "CLIENT_ORIGIN: $CLIENT_ORIGIN"
echo "STAGE: $STAGE"
print_stage_matrix

print_step "2) A 세션 시작: CSRF 발급(+저장) -> 로그인"
login_headers=(
  -H "Origin: ${CLIENT_ORIGIN}"
  -H "Content-Type: application/json"
  -A "$UA_A"
)
if (( STAGE >= 6 )); then
  curl -s -c "$JAR_A" -b "$JAR_A" -H "Origin: ${CLIENT_ORIGIN}" -A "$UA_A" "$BASE_URL/auth/csrf" > "$JAR_TEMP" 2>/dev/null
  csrfA=$(csrf_cookie_value "$JAR_A")
  if [[ -z "$csrfA" ]]; then
    echo "[ERR] A 세션 CSRF 쿠키 발급 실패"
    exit 1
  fi
  login_headers+=( -H "x-csrf-token: ${csrfA}" )
  echo "A CSRF 쿠키: ${csrfA}"
fi

resp1=$(curl -s -c "$JAR_A" -b "$JAR_A" "${login_headers[@]}" \
  --data '{"username":"demo","password":"demo"}' \
  "$BASE_URL/login")

echo "$resp1"
if ! echo "$resp1" | jq -e '.accessToken or .token or .message' >/dev/null 2>&1; then
  echo "[ERR] A 로그인 응답 형식이 비정상"
  exit 1
fi
if (( STAGE < 6 )); then
  echo "A 응답에 stage 정보 없음(구버전 응답 형식)"
fi

print_step "3) 공격자 관점 토큰 획득(복제)"
cp "$JAR_A" "$JAR_STEAL"

print_step "4) A 정상 refresh (baseline)"
resp2=$(cookie_request POST "$BASE_URL/auth/refresh" "$JAR_A" "$UA_A")
status2=$(status_code "$resp2")
echo "$resp2"
expected2=$(expected_status "$STAGE" "BASELINE_REFRESH")
check_status "A baseline refresh" "$status2" "$expected2"

print_step "5) A 재사용 공격: 갱신 전 쿠키로 즉시 재요청(Reuse Replay)"
cp "$JAR_STEAL" "$JAR_TEMP"
resp3=$(cookie_request POST "$BASE_URL/auth/refresh" "$JAR_TEMP" "$UA_A")
status3=$(status_code "$resp3")
echo "$resp3"
expected3=$(expected_status "$STAGE" "REPLAY_ATTACK")
check_status "A replay attack" "$status3" "$expected3"

print_step "6) B 세션 시작 (동일 계정 재로그인) -> 이전 세션 덮어쓰기 확인"
login_headers_b=(
  -H "Origin: ${CLIENT_ORIGIN}"
  -H "Content-Type: application/json"
  -A "$UA_B"
)
if (( STAGE >= 6 )); then
  curl -s -c "$JAR_B" -b "$JAR_B" -H "Origin: ${CLIENT_ORIGIN}" -A "$UA_B" "$BASE_URL/auth/csrf" > "$JAR_TEMP" 2>/dev/null
  csrfB=$(csrf_cookie_value "$JAR_B")
  if [[ -z "$csrfB" ]]; then
    echo "[ERR] B 세션 CSRF 쿠키 발급 실패"
    exit 1
  fi
  login_headers_b+=( -H "x-csrf-token: ${csrfB}" )
  echo "B CSRF 쿠키: ${csrfB}"
fi

curl -s -c "$JAR_B" -b "$JAR_B" "${login_headers_b[@]}" \
  --data '{"username":"demo","password":"demo"}' \
  "$BASE_URL/login" > "$JAR_TEMP"

resp4=$(cookie_request POST "$BASE_URL/auth/refresh" "$JAR_B" "$UA_B")
status4=$(status_code "$resp4")
echo "$resp4"
expected4=$(expected_status "$STAGE" "B_REFRESH")
check_status "B refresh" "$status4" "$expected4"

print_step "7) B 로그인 후 A 세션 refresh 재시도 (단일세션 방어)"
resp5=$(cookie_request POST "$BASE_URL/auth/refresh" "$JAR_A" "$UA_A")
status5=$(status_code "$resp5")
echo "$resp5"
expected5=$(expected_status "$STAGE" "A_AFTER_B_REFRESH")
check_status "A after B login refresh" "$status5" "$expected5"

print_step "8) UA 바인딩 변조 공격(가능하면) – Stage 8의 바인딩 감지"
resp6=""
status6="*"
if (( STAGE >= 8 )); then
  resp6=$(cookie_request POST "$BASE_URL/auth/refresh" "$JAR_STEAL" "$UA_B")
  status6=$(status_code "$resp6")
  echo "$resp6"
  expected6=$(expected_status "$STAGE" "UA_MISMATCH")
  check_status "UA mismatch" "$status6" "$expected6"
else
  echo "[SKIP] Stage < 8: 바인딩 미적용"
fi

print_step "9) Origin 위조/CSRF 누락 공격(단순 형태)"
resp7=$(curl -i -s -X POST -b "$JAR_B" \
  -H "Origin: http://evil.example" \
  -A "$UA_B" \
  "$BASE_URL/auth/refresh")
status7=$(status_code "$resp7")
echo "$resp7"
expected7=$(expected_status "$STAGE" "ORIGIN_ATTACK")
check_status "Cross-origin + CSRF missing" "$status7" "$expected7"

print_step "요약"
echo "A baseline refresh status: $status2 (expect: $(expected_status "$STAGE" "BASELINE_REFRESH"))"
echo "A replay using old token status: $status3 (expect: $(expected_status "$STAGE" "REPLAY_ATTACK"))"
echo "B refresh status: $status4 (expect: $(expected_status "$STAGE" "B_REFRESH"))"
echo "A after B login status: $status5 (expect: $(expected_status "$STAGE" "A_AFTER_B_REFRESH"))"
if (( STAGE >= 8 )); then
  echo "A token UA mismatch status: $status6 (expect: $(expected_status "$STAGE" "UA_MISMATCH"))"
fi
echo "Cross-origin/CSRF missing status: $status7 (expect: $(expected_status "$STAGE" "ORIGIN_ATTACK"))"

echo "PASS=$PASS_COUNT, WARN=$WARN_COUNT"

if [[ "$REPORT_MODE" == "report" || "$REPORT_MODE" == "markdown" ]]; then
  print_step "보고서 출력(복붙용)"
  run_at=$(date '+%Y-%m-%d %H:%M:%S %Z')
  echo "실행일시: $run_at"
  echo "대상: $BASE_URL"
  echo "클라이언트 오리진: $CLIENT_ORIGIN"
  echo "테스트 Stage: $STAGE"
  echo
  echo "|항목|결과|실측|기대|"
  echo "|---|---|---|---|"
  report_row "1) A baseline refresh" "$status2" "$(expected_status "$STAGE" "BASELINE_REFRESH")"
  report_row "2) A replay attack" "$status3" "$(expected_status "$STAGE" "REPLAY_ATTACK")"
  report_row "3) B refresh" "$status4" "$(expected_status "$STAGE" "B_REFRESH")"
  report_row "4) A after B login refresh" "$status5" "$(expected_status "$STAGE" "A_AFTER_B_REFRESH")"
  if (( STAGE >= 8 )); then
    report_row "5) UA mismatch" "$status6" "$(expected_status "$STAGE" "UA_MISMATCH")"
    echo "|6) Cross-origin + CSRF missing|$(status_ok "$status7" "$(expected_status "$STAGE" "ORIGIN_ATTACK")" && echo PASS || echo FAIL)|$status7|$(expected_status "$STAGE" "ORIGIN_ATTACK")|"
  else
    echo "|5) Cross-origin + CSRF missing|$(status_ok "$status7" "$(expected_status "$STAGE" "ORIGIN_ATTACK")" && echo PASS || echo FAIL)|$status7|$(expected_status "$STAGE" "ORIGIN_ATTACK")|"
  fi

  if (( WARN_COUNT == 0 )); then
    echo
    echo "결론: PASS - 단계별 기대 결과와 일치"
  else
    echo
    echo "결론: WARN - 일부 항목이 기대와 다름. 출력 헤더/바디 로그를 점검할 것"
  fi
  echo "권장 첨부: 스크립트 실행 로그 전체, /tmp 쿠키 파일 스냅샷, 서버 로그(가능하면)"
fi
