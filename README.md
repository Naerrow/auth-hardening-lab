# mini-auth-lab

인증(Auth)을 **보안 관점에서 단계별로 보완**해 나가는 과정을, 프론트/백엔드 풀스택으로 직접 구현하고 재현 가능한 형태로 검증하는 실습용 프로젝트입니다.

- Client: React + Vite 기반 SPA
- Server: Node.js + Express 기반 인증 API

---

## 프로젝트 목적 (Why)

이 저장소는 “로그인/인증(Auth)을 보안 관점에서 단계적으로 보완해 나가는 과정”을 **직접 구현하고 테스트**하기 위해 만들었습니다.

- Access Token만 사용하는 가장 단순한 형태(Stage 1)부터 시작해
- Refresh Token, HttpOnly Cookie, CSRF 방어(Double Submit Cookie), 토큰 회전(Rotation) 등
- 실무에서 마주치는 보안 트레이드오프를 단계별로 추가하며 동작을 확인합니다.

핵심 목표는 “프레임워크 기능 구현”이 아니라, **HTTP 레벨(헤더/쿠키/CORS/CSRF)에서 인증이 어떻게 동작하고 어디가 취약해지는지**를 투명하게 이해하는 것입니다.

---

## 기술 스택 (What)

- `client/` – React + Vite SPA (서버 API 호출/테스트 UI)
- `server/` – Express 기반 REST API (JWT 발급/검증)

---

## 프레임워크 선택 이유 (Why this stack)

### Server: Express를 선택한 이유

이 프로젝트의 본질은 인증/보안 메커니즘을 실험하는 것이므로, 서버는 다음 조건을 만족해야 했습니다.

- 요청/응답을 **있는 그대로** 다루며 헤더/쿠키를 명확히 제어할 수 있을 것
- CORS, Cookie, CSRF 등 보안 요소를 **코드 레벨에서 투명하게 관찰/재현**할 수 있을 것
- 자료/예제가 풍부해 막혔을 때 빠르게 검증하고, **재현 가능한 실험**을 만들 수 있을 것
- 최소 구성으로 Stage를 쌓아가며 변경점을 작게 유지할 수 있을 것

Express는 `req.headers`, `Authorization`, `Set-Cookie`, 미들웨어 체인처럼 HTTP 흐름이 코드에 직접 드러나서,
인증 보안 실험(토큰/쿠키/CSRF/CORS)에 적합한 선택이었습니다.

### Client: React + Vite를 선택한 이유

- 인증 실험에서 UI는 최소(로그인 버튼/호출 버튼/로그 출력)면 충분하므로,
  빌드 설정에 시간을 쓰기보다 개발 속도가 빠른 구성이 필요했습니다.
- Vite는 설정이 단순하고 개발 서버가 빠르며, SPA에서 API 호출/헤더/쿠키 테스트를 반복하기에 적합합니다.

---

## 단계별 로드맵 (Stages)

- Stage 1: Access Token only (Bearer Authorization)
- Stage 2: Access 만료/401 처리(Refresh 없음 → 재로그인)
- Stage 3: Refresh Token 도입(HttpOnly Cookie) + `/auth/refresh`
- Stage 4: 세션 복원(초기 로딩 시 refresh)
- Stage 5: 401 동시성 제어(Refresh 1회만)
- Stage 6: CSRF 방어(Origin/Referer + Double Submit Cookie)
- Stage 7: Refresh Token 회전(Rotation) + 재사용 감지 + 절대 만료
- Stage 8: 로그아웃(토큰 폐기/쿠키 삭제 정책)

---

## 시작하기 (Getting Started)

### 1) 의존성 설치

루트에서 각각 설치합니다.

````bash
npm install --prefix client
npm install --prefix server
````
### 2) 실행
서버와 클라이언트를 각각 다른 터미널에서 실행합니다.

```bash
npm run dev --prefix server
npm run dev --prefix client
```

#### STAGE 환경변수
서버는 `STAGE` 환경변수로 현재 구현된 인증 스테이지를 인식합니다. 기본값은 1이며, Stage 1 전용 엔드포인트만 열려 있습니다. 예를 들어 다음처럼 명시적으로 붙이면 해당 실행에서는 `STAGE=1`으로 동작합니다.

```bash
STAGE=1 npm run dev --prefix server
```

다른 Stage(예: 향후 `STAGE=2`)나 환경에서 돌릴 때 실수로 Stage 1 전용 라우트가 열리지 않도록 `STAGE` 값을 의도적으로 설정하세요.
### 3) 접속
Client: http://localhost:5173

Server: http://localhost:4000

테스트 시나리오 (Stage 1)
Stage 1은 “Access Token만으로 인증”을 재현합니다.

로그인 전 Call /me → 401

demo / demo로 로그인 → Call /me → 200

Access 만료 후 Call /me → 401 (Stage 1은 refresh가 없으므로 재로그인 필요)

저장소 구조
client/ – React/Vite 프론트엔드

server/ – Express + jsonwebtoken 백엔드

라이선스
MIT License. 자세한 내용은 LICENSE 파일을 참고하세요.
sql
코드 복사

저장 후 커밋/푸시는 이렇게:

```bash
git add README.md
git commit -m "docs: update readme for stage 1"
git push
````
