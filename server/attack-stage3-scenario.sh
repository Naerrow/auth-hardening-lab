#!/usr/bin/env bash
set -euo pipefail

BASE_URL=${BASE_URL:-"http://localhost:4000"}
SECRET=${JWT_SECRET:-"dev-secret-change-me"}
MAX_TTL_SEC=${MAX_TTL_SEC:-30}
EXPECTED_TTL_SEC=${EXPECTED_TTL_SEC:-10}
HTTP_BODY=""
status=""
ACCESS_TOKEN=""
REFRESH_COOKIE=""
CONCURRENT_REFRESH_COOKIE=""

HEADER_FILE="/tmp/attack_stage3_headers.txt"
BODY_FILE="/tmp/attack_stage3_body.txt"
CODE_FILE="/tmp/attack_stage3_code.txt"

RESULTS=()
VULNERABLE_COUNT=0
SECURE_COUNT=0
NOT_TESTABLE_COUNT=0

log() {
  echo "[`date '+%H:%M:%S'`] $*"
}

http_call() {
  local with_headers="$1"
  shift
  rm -f "$HEADER_FILE" "$BODY_FILE" "$CODE_FILE"
  if [ "$with_headers" = "1" ]; then
    curl -sS -D "$HEADER_FILE" -o "$BODY_FILE" -w "%{http_code}" "$@" > "$CODE_FILE"
  else
    curl -sS -o "$BODY_FILE" -w "%{http_code}" "$@" > "$CODE_FILE"
  fi
}

capture_response() {
  status="$(cat "$CODE_FILE")"
  HTTP_BODY="$(cat "$BODY_FILE")"
}

json_get() {
  local body="$1"
  local key="$2"
  node --input-type=module -e "const raw = process.argv[1] || ''; const key = process.argv[2] || ''; try { const data = JSON.parse(raw); process.stdout.write(data?.[key] ?? ''); } catch { process.stdout.write(''); }" "$body" "$key"
}

jwt_payload_claim() {
  local token="$1"
  local claim="$2"
  node --input-type=module -e "const token = process.argv[1] || ''; const claim = process.argv[2] || ''; try { const parts = token.split('.'); if (parts.length !== 3) process.exit(1); const p = parts[1].replace(/-/g,'+').replace(/_/g,'/'); const pad='='.repeat((4 - p.length % 4) % 4); const payload = JSON.parse(Buffer.from(p + pad, 'base64').toString('utf8')); process.stdout.write(String(payload?.[claim] ?? '')); } catch { process.exit(1); }" "$token" "$claim"
}

now_epoch() {
  node --input-type=module -e "console.log(Math.floor(Date.now() / 1000))"
}

is_int() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

extract_cookie_attr() {
  local header_file="$1"
  local attr="$2"
  node --input-type=module -e "import fs from 'fs'; const raw=fs.readFileSync(process.argv[1],'utf8'); const line=raw.split(/\\r?\\n/).find((l)=>/^set-cookie:\\s*refresh_token=/i.test(l)); if(!line){process.exit(0);} const lower=line.toLowerCase(); console.log((lower.includes(process.argv[2].toLowerCase())?'1':'0'));" "$header_file" "$attr"
}

extract_refresh_cookie() {
  node --input-type=module -e "import fs from 'fs'; const raw=fs.readFileSync(process.argv[1],'utf8'); const line=raw.split(/\\r?\\n/).find((l)=>/^set-cookie:\\s*refresh_token=/i.test(l)); if(!line){process.stdout.write(''); process.exit(0);} const m=line.match(/refresh_token=([^;\\s]+)/i); process.stdout.write(m?m[1]:'');" "$HEADER_FILE"
}

add_result() {
  RESULTS+=("$1")
}

secure() {
  SECURE_COUNT=$((SECURE_COUNT + 1))
  add_result "SECURE|$1|$2"
  echo "[SECURE] $1"
}

vulnerable() {
  VULNERABLE_COUNT=$((VULNERABLE_COUNT + 1))
  add_result "VULNERABLE|$1|$2"
  echo "[VULNERABLE] $1"
}

not_testable() {
  NOT_TESTABLE_COUNT=$((NOT_TESTABLE_COUNT + 1))
  add_result "NOT_TESTABLE|$1|$2"
  echo "[NOT_TESTABLE] $1"
}

log "Stage3 취약점 검증 시나리오 시작 (Base: ${BASE_URL})"

log "1) 로그인 토큰 발급(전제) + refresh 쿠키 수신"
http_call 1 -X POST "${BASE_URL}/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"demo","password":"demo"}'
capture_response
if [ "$status" != "200" ]; then
  not_testable "/login 전제" "HTTP ${status}"
  exit 1
fi

ACCESS_TOKEN=$(json_get "$HTTP_BODY" "accessToken")
if [ -z "$ACCESS_TOKEN" ]; then
  not_testable "accessToken 추출" "응답 본문에서 accessToken 누락"
  exit 1
fi
REFRESH_COOKIE=$(extract_refresh_cookie "$HEADER_FILE")
secure "accessToken 발급" "HTTP 200"

if [ -z "$REFRESH_COOKIE" ]; then
  not_testable "refresh 쿠키 수신" "Set-Cookie에 refresh_token 없음"
else
  secure "refresh 쿠키 발급" "Set-Cookie에 refresh_token 존재"
fi

if [ -n "${REFRESH_COOKIE}" ]; then
  if [ "$(extract_cookie_attr "$HEADER_FILE" "HttpOnly")" = "1" ]; then
    secure "refresh 쿠키 HttpOnly 속성" "Set-Cookie에 HttpOnly 존재"
  else
    vulnerable "refresh 쿠키 HttpOnly 미설정" "Set-Cookie에 HttpOnly 없음"
  fi

  if [ "$(extract_cookie_attr "$HEADER_FILE" "samesite")" = "1" ]; then
    secure "refresh 쿠키 SameSite 속성" "Set-Cookie에 SameSite 존재"
  else
    vulnerable "refresh 쿠키 SameSite 미설정" "Set-Cookie에 SameSite 없음"
  fi

  if [ "$(extract_cookie_attr "$HEADER_FILE" "path=/auth/refresh")" = "1" ]; then
    secure "refresh 쿠키 경로 제한" "Set-Cookie path=/auth/refresh"
  else
    not_testable "refresh 쿠키 경로 제한" "path가 감지되지 않음"
  fi
fi

TOKEN_EXP="$(jwt_payload_claim "$ACCESS_TOKEN" "exp")"
if [ -z "$TOKEN_EXP" ] || ! is_int "$TOKEN_EXP"; then
  vulnerable "액세스 토큰 유효시간 미적용" "accessToken에 exp가 없어 영구 토큰 가능성"
else
  NOW_SEC="$(now_epoch)"
  TTL_SEC=$((TOKEN_EXP - NOW_SEC))
  if [ "$TTL_SEC" -le 0 ]; then
    vulnerable "액세스 토큰 만료값 이상" "TTL=${TTL_SEC}s"
  elif [ "$TTL_SEC" -gt "$MAX_TTL_SEC" ]; then
    vulnerable "액세스 토큰 TTL 과도" "TTL=${TTL_SEC}s (<= ${MAX_TTL_SEC}s) 필요"
  else
    secure "액세스 토큰 유효기간 제한" "TTL=${TTL_SEC}s (<= ${MAX_TTL_SEC}s)"
    if [ "$TTL_SEC" -gt "$EXPECTED_TTL_SEC" ]; then
      secure "기본 만료정책 수치 검증 보조" "TTL=${TTL_SEC}s (권장=${EXPECTED_TTL_SEC}s)"
    else
      secure "기본 만료정책 수치 검증" "TTL=${TTL_SEC}s"
    fi
  fi
fi

log "2) /me 정상 접근 검증(액세스 토큰)"
http_call 0 -H "Authorization: Bearer ${ACCESS_TOKEN}" "${BASE_URL}/me"
capture_response
if [ "$status" = "200" ]; then
  secure "액세스 토큰으로 보호 자원 접근" "HTTP 200"
else
  vulnerable "액세스 토큰으로 보호 자원 접근 실패" "HTTP ${status}"
fi

if [ -n "$TOKEN_EXP" ] && is_int "$TOKEN_EXP"; then
  log "3) 만료된 액세스 토큰 즉시 차단"
  NOW_SEC="$(now_epoch)"
  TTL_SEC=$((TOKEN_EXP - NOW_SEC))
  if [ "$TTL_SEC" -le 0 ]; then
    not_testable "만료 토큰 차단" "토큰 발급 시점에서 이미 만료로 판단"
  else
    sleep $((TTL_SEC + 1))
    http_call 0 -H "Authorization: Bearer ${ACCESS_TOKEN}" "${BASE_URL}/me"
    capture_response
    if [ "$status" = "401" ]; then
      secure "만료 토큰 차단" "만료 후 /me가 401"
    else
      vulnerable "만료 토큰 차단 실패" "만료 후 /me가 HTTP ${status}"
    fi
  fi
else
  not_testable "만료 토큰 차단" "토큰 exp가 없어 검사 생략"
fi

log "4) Stage3: refresh 없이 /auth/refresh 호출 방어"
http_call 0 -X POST "${BASE_URL}/auth/refresh"
capture_response
if [ "$status" = "401" ]; then
  secure "refresh 쿠키 미소지 차단" "/auth/refresh가 쿠키 미존재 시 401"
else
  vulnerable "refresh 쿠키 미소지 허용" "HTTP ${status}"
fi

if [ -z "$REFRESH_COOKIE" ]; then
  not_testable "refresh 재발급 동작" "refresh 쿠키 미수신"
else
  log "5) Stage3: refresh 쿠키 기반 액세스 재발급"
  http_call 0 -X POST "${BASE_URL}/auth/refresh" -H "Cookie: refresh_token=${REFRESH_COOKIE}"
  capture_response
  if [ "$status" != "200" ]; then
    vulnerable "refresh 기반 액세스 재발급 실패" "HTTP ${status}"
  else
    secure "refresh 기반 액세스 재발급" "HTTP 200"
    REFRESHED_TOKEN="$(json_get "$HTTP_BODY" "accessToken")"
    if [ -z "$REFRESHED_TOKEN" ]; then
      vulnerable "재발급 토큰 추출" "응답 accessToken 누락"
    elif [ "$REFRESHED_TOKEN" = "$ACCESS_TOKEN" ]; then
      not_testable "재발급 토큰 신선도" "재발급 토큰이 기존 토큰과 동일"
    else
      secure "재발급 토큰 생성" "새 Access 토큰 발급"
      http_call 0 -H "Authorization: Bearer ${REFRESHED_TOKEN}" "${BASE_URL}/me"
      capture_response
      if [ "$status" = "200" ]; then
        secure "재발급 토큰 즉시 접근" "새 토큰으로 /me 호출 성공"
      else
        vulnerable "재발급 토큰 즉시 접근 실패" "HTTP ${status}"
      fi
    fi
  fi

  log "6) Stage3: 로그아웃에서 refresh 폐기 확인"
  http_call 0 -X POST "${BASE_URL}/logout" -H "Cookie: refresh_token=${REFRESH_COOKIE}"
  capture_response
  if [ "$status" != "200" ]; then
    not_testable "로그아웃 응답" "HTTP ${status}"
  else
    http_call 0 -X POST "${BASE_URL}/auth/refresh" -H "Cookie: refresh_token=${REFRESH_COOKIE}"
    capture_response
    if [ "$status" = "401" ]; then
      secure "로그아웃 refresh 폐기" "로그아웃 후 동일 refresh로 /auth/refresh가 401"
    else
      vulnerable "로그아웃 refresh 폐기 미흡" "로그아웃 후 동일 refresh로 HTTP ${status}"
    fi
  fi

  log "7) Stage3: refresh 토큰 재사용성(회전 부재) 테스트"
  # 재발급 후 같은 refresh 쿠키로 다시 시도 시 토큰이 다시 발급되면 회전 미적용
  http_call 1 -X POST "${BASE_URL}/login" -H 'Content-Type: application/json' -d '{"username":"demo","password":"demo"}'
  capture_response
  NEW_REFRESH=$(extract_refresh_cookie "$HEADER_FILE")
  if [ -z "$NEW_REFRESH" ]; then
    not_testable "refresh 회전 테스트 준비" "새 refresh 쿠키 미수신"
  else
    CONCURRENT_REFRESH_COOKIE="$NEW_REFRESH"
    http_call 0 -X POST "${BASE_URL}/auth/refresh" -H "Cookie: refresh_token=${NEW_REFRESH}"
    capture_response
    FIRST_REFRESH_STATUS="$status"
    http_call 0 -X POST "${BASE_URL}/auth/refresh" -H "Cookie: refresh_token=${NEW_REFRESH}"
    capture_response
    SECOND_REFRESH_STATUS="$status"
    if [ "$FIRST_REFRESH_STATUS" = "200" ] && [ "$SECOND_REFRESH_STATUS" = "200" ]; then
      vulnerable "refresh 회전 미구현" "동일 refresh 쿠키로 연속 refresh 성공(현재 재사용 허용)"
    else
      not_testable "refresh 회전 구현" "재사용 실험 결과: 1회=${FIRST_REFRESH_STATUS}, 2회=${SECOND_REFRESH_STATUS}"
    fi
  fi
fi

log "8) Stage5: 다중 401 레이스 동시성 테스트(동시 refresh 중복 사용)"
if [ -z "$CONCURRENT_REFRESH_COOKIE" ]; then
  CONCURRENT_REFRESH_COOKIE="$REFRESH_COOKIE"
fi

if [ -z "$CONCURRENT_REFRESH_COOKIE" ]; then
  http_call 0 -X POST "${BASE_URL}/login" -H 'Content-Type: application/json' -d '{"username":"demo","password":"demo"}'
  capture_response
  REFRESH_COOKIE=$(extract_refresh_cookie "$HEADER_FILE")
  CONCURRENT_REFRESH_COOKIE="$REFRESH_COOKIE"
fi

if [ -z "$CONCURRENT_REFRESH_COOKIE" ]; then
  not_testable "refresh 동시성 제어" "검증용 refresh 쿠키 미수신"
else
  ST5_CODE1=$(mktemp)
  ST5_CODE2=$(mktemp)
  ST5_BODY1=$(mktemp)
  ST5_BODY2=$(mktemp)

  ( curl -sS -o "${ST5_BODY1}" -w "%{http_code}" -X POST "${BASE_URL}/auth/refresh" -H "Cookie: refresh_token=${CONCURRENT_REFRESH_COOKIE}" > "${ST5_CODE1}" ) &
  ( curl -sS -o "${ST5_BODY2}" -w "%{http_code}" -X POST "${BASE_URL}/auth/refresh" -H "Cookie: refresh_token=${CONCURRENT_REFRESH_COOKIE}" > "${ST5_CODE2}" ) &
  wait

  ST5_STATUS1="$(cat "${ST5_CODE1}")"
  ST5_STATUS2="$(cat "${ST5_CODE2}")"
  rm -f "${ST5_CODE1}" "${ST5_CODE2}" "${ST5_BODY1}" "${ST5_BODY2}"

  ST5_SUCCESS_COUNT=0
  [ "$ST5_STATUS1" = "200" ] && ST5_SUCCESS_COUNT=$((ST5_SUCCESS_COUNT + 1))
  [ "$ST5_STATUS2" = "200" ] && ST5_SUCCESS_COUNT=$((ST5_SUCCESS_COUNT + 1))

  if [ "$ST5_SUCCESS_COUNT" -ge 2 ]; then
    vulnerable "refresh 동시성 제어 미흡" "동일 refresh로 동시 호출이 모두 200 (1회만 갱신해야 함): 결과=${ST5_STATUS1},${ST5_STATUS2}"
  elif [ "$ST5_SUCCESS_COUNT" = 1 ] && { [ "$ST5_STATUS1" = "401" ] || [ "$ST5_STATUS2" = "401" ] || [ "$ST5_STATUS1" = "409" ] || [ "$ST5_STATUS2" = "409" ] || [ "$ST5_STATUS1" = "429" ] || [ "$ST5_STATUS2" = "429" ]; }; then
    secure "refresh 동시성 제어" "동일 refresh 동시 호출 제어됨(200 한 번): 결과=${ST5_STATUS1},${ST5_STATUS2}"
  else
    not_testable "refresh 동시성 제어" "동시 호출 결과 판별 불가: 결과=${ST5_STATUS1},${ST5_STATUS2}"
  fi
fi

log "9) Stage3: 기본 시크릿 기반 토큰 위조 방어"
FORGED_ACCESS=$(node --input-type=module - <<NODE
import jwt from 'jsonwebtoken';
const token = jwt.sign(
  { sub: 'admin', typ: 'access' },
  process.env.JWT_SECRET || '${SECRET}',
  { expiresIn: 60 * 5 }
);
process.stdout.write(token);
NODE
)
http_call 0 -H "Authorization: Bearer ${FORGED_ACCESS}" "${BASE_URL}/me"
capture_response
if [ "$status" = "401" ]; then
  secure "기본 시크릿 위조 토큰 차단" "위조 Access 토큰이 401"
else
  vulnerable "기본 시크릿 위조 토큰 허용" "위조 Access 토큰이 HTTP ${status}"
fi

log "10) Stage3: CSRF 가드(Origin/Referer) 부재"
http_call 1 -X POST "${BASE_URL}/login" -H 'Content-Type: application/json' -d '{"username":"demo","password":"demo"}'
capture_response
CSRF_REFRESH_COOKIE=$(extract_refresh_cookie "$HEADER_FILE")
if [ -z "$CSRF_REFRESH_COOKIE" ]; then
  not_testable "CSRF 가드" "검증용 refresh 쿠키 미수신"
else
  http_call 0 -X POST "${BASE_URL}/auth/refresh" \
    -H "Cookie: refresh_token=${CSRF_REFRESH_COOKIE}" \
    -H "Origin: https://evil.example.test" \
    -H "Referer: https://evil.example.test/page"
  capture_response
  if [ "$status" = "200" ]; then
    vulnerable "CSRF 가드 미구현" "Origin/Referer 오염 요청에서도 /auth/refresh가 200"
  else
    secure "CSRF 가드" "출처 헤더를 섞은 /auth/refresh가 200이 아님"
  fi
fi

log "11) Stage2 기반 레거시 테스트: 로그아웃 후 access 토큰 무효화"
http_call 1 -X POST "${BASE_URL}/login" -H 'Content-Type: application/json' -d '{"username":"demo","password":"demo"}'
capture_response
LEGACY_ACCESS_TOKEN="$(json_get "$HTTP_BODY" "accessToken")"
LEGACY_REFRESH_COOKIE="$(extract_refresh_cookie "$HEADER_FILE")"
if [ -z "$LEGACY_ACCESS_TOKEN" ] || [ -z "$LEGACY_REFRESH_COOKIE" ]; then
  not_testable "로그아웃 후 access 무효화 전제" "로그인 결과 access/refresh 토큰 미수신"
else
  http_call 0 -X POST "${BASE_URL}/logout" -H "Cookie: refresh_token=${LEGACY_REFRESH_COOKIE}"
  capture_response
  if [ "$status" != "200" ]; then
    not_testable "로그아웃 응답" "로그아웃 응답 HTTP ${status}"
  else
    http_call 0 -H "Authorization: Bearer ${LEGACY_ACCESS_TOKEN}" "${BASE_URL}/me"
    capture_response
    if [ "$status" = "401" ]; then
      secure "액세스 토큰 즉시 무효화" "로그아웃 후 동일 Access가 401"
    else
    vulnerable "액세스 토큰 무효화 미흡" "로그아웃 후 동일 Access가 HTTP ${status}"
    fi
  fi
fi

echo
printf '%s\n' '[RESULT MATRIX]'
printf '%s\n' '결과 | 항목 | 근거'
printf '%s\n' '--------------------------------------------------------------'
for line in "${RESULTS[@]}"; do
  IFS='|' read -r result item evidence <<< "$line"
  printf '%-12s | %-52s | %s\n' "$result" "$item" "$evidence"
done

echo
TOTAL=$((VULNERABLE_COUNT + SECURE_COUNT + NOT_TESTABLE_COUNT))
echo "[SUMMARY] VULNERABLE=${VULNERABLE_COUNT}, SECURE=${SECURE_COUNT}, NOT_TESTABLE=${NOT_TESTABLE_COUNT}, TOTAL=${TOTAL}"
if [ "$VULNERABLE_COUNT" -gt 0 ]; then
  echo "[SUMMARY] Stage3에서 재현 가능한 취약점이 확인되었습니다."
  exit 2
fi

echo "[SUMMARY] Stage3 기준 즉시 재현 취약점이 없습니다."
