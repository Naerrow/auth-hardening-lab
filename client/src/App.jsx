import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  hasToken,
  login,
  logout,
  me,
  refreshAccess,
  subscribeTokenChange,
} from "./api";
import "./App.css";

export default function App() {
  const [username, setUsername] = useState("demo");
  const [password, setPassword] = useState("demo");
  const [logs, setLogs] = useState([]);
  const [tokenState, setTokenState] = useState(hasToken());
  const [refreshCount, setRefreshCount] = useState(0);
  const [lastRefresh, setLastRefresh] = useState(null);
  const [initializing, setInitializing] = useState(true);
  const [sessionStatus, setSessionStatus] = useState("세션 복원 대기");

  const pushLog = useCallback((msg) => {
    const line = `${new Date().toLocaleTimeString()}  ${msg}`;
    setLogs((prev) => [line, ...prev]);
  }, []);

  const [expiresAt, setExpiresAt] = useState(null); // epoch ms
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);
  const remainingSec = useMemo(() => {
    if (!expiresAt) return null;
    return Math.max(0, Math.floor((expiresAt - now) / 1000));
  }, [expiresAt, now]);

  const tokenLabel = useMemo(() => {
    if (!tokenState) return "NO";
    if (!expiresAt) return "YES (in memory)";
    if (remainingSec <= 0) return "YES (expired)";
    return `YES (expires in ${remainingSec}s)`;
  }, [tokenState, expiresAt, remainingSec]);

  const refreshLabel = useMemo(() => {
    if (!refreshCount) return "자동 갱신 없음";
    const formattedTime = lastRefresh
      ? new Date(lastRefresh).toLocaleTimeString()
      : "알 수 없음";
    return `마지막 자동 갱신 시간 : ${formattedTime}`;
  }, [refreshCount, lastRefresh]);

  const sessionLabel = useMemo(() => {
    if (initializing) return "세션 복원 중...";
    return sessionStatus;
  }, [initializing, sessionStatus]);

  const restoringRef = useRef(false);

  useEffect(() => {
    const unsubscribe = subscribeTokenChange((info) => {
      if (!info) return;
      setTokenState(Boolean(info.accessToken));
      if (typeof info.expiresInSec === "number") {
        setExpiresAt(Date.now() + info.expiresInSec * 1000);
      } else {
        setExpiresAt(null);
      }

      if (info.cause === "refresh") {
        if (restoringRef.current) return;
        setRefreshCount((prev) => prev + 1);
        console.log("refresh count", refreshCount);
        setLastRefresh(Date.now());
        pushLog(
          `Access 자동 갱신: ${info.expiresInSec ?? "unknown"}초 · 새 토큰 사용`,
        );
      } else if (info.cause === "login") {
        setRefreshCount(0);
        setLastRefresh(null);
      } else if (info.cause === "clear") {
        setRefreshCount(0);
        setLastRefresh(null);
      }
    });
    return unsubscribe;
  }, [pushLog]);

  useEffect(() => {
    let cancelled = false;
    const restoreSession = async () => {
      setInitializing(true);
      setSessionStatus("세션 복원 시도 중...");
      restoringRef.current = true;
      try {
        await refreshAccess();
        if (cancelled) return;
        setSessionStatus("Refresh 쿠키로 자동 복원됨");
        setRefreshCount((prev) => prev + 1);
        setLastRefresh(Date.now());
        pushLog("세션 복원 성공: Refresh 쿠키로 Access 재발급");
      } catch (error) {
        if (cancelled) return;
        setSessionStatus("세션 복원 실패 · 로그인 필요");
        pushLog(`세션 복원 실패: ${error?.message ?? "Refresh 실패"}`);
      } finally {
        restoringRef.current = false;
        if (!cancelled) setInitializing(false);
      }
    };

    restoreSession();
    return () => {
      cancelled = true;
    };
  }, [pushLog]);

  return (
    <div className="app-shell">
      <main className="app-layout">
        <header className="app-heading">
          <h1>auth-hardening-lab</h1>
          <p className="subtitle">
            서버 http://localhost:4000 · 클라이언트 http://localhost:5173
          </p>
          <div className="status-row">
            <span className="status-label">액세스 토큰 상태(만료)</span>

            <span className="status-pill">{tokenLabel}</span>
          </div>
          <div className="status-row">
            <span className="status-label">자동 갱신 현황</span>
            <span className="status-pill">{refreshLabel}</span>
          </div>
          <div className="status-row">
            <span className="status-label">세션 복원 상태</span>
            <span className="status-pill">{sessionLabel}</span>
          </div>
        </header>

        <section className="app-card">
          <div className="card-header">
            <h2>사용자 정보</h2>
            <p>
              로그인 시 Refresh(HttpOnly Cookie)가 저장됩니다. Access가 만료되면
              /auth/refresh로 재발급 후 /me를 자동 재시도합니다.
            </p>

            <p className="credential-tip">테스트 계정 ID : demo · PWD : demo</p>
          </div>

          <div className="control-row">
            <label className="field">
              <span>Username</span>
              <input
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                placeholder="demo"
              />
            </label>
            <label className="field">
              <span>Password</span>
              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="demo"
              />
            </label>
          </div>

          <div className="actions">
            <button
              className="primary"
              onClick={async () => {
                try {
                  const response = await login(username, password);
                  setTokenState(true);
                  setExpiresAt(
                    response.expiresAt ??
                      Date.now() + response.expiresInSec * 1000,
                  );
                  setSessionStatus("직접 로그인됨");
                  setInitializing(false);
                  pushLog(`로그인 성공 · 만료까지 ${response.expiresInSec}초`);
                } catch (error) {
                  pushLog(`로그인 실패: ${error.message}`);
                }
              }}
            >
              로그인
            </button>

            <button
              onClick={async () => {
                try {
                  const response = await me();
                  pushLog(`/me 조회 성공: ${JSON.stringify(response)}`);
                } catch (error) {
                  pushLog(`/me 조회 실패: ${error.message} (재로그인 필요)`);
                }
              }}
            >
              /me 호출
            </button>

            <button
              onClick={async () => {
                try {
                  await logout();
                  setTokenState(false);
                  setExpiresAt(null);
                  setSessionStatus("세션 없음");
                  setInitializing(false);
                  pushLog("로그아웃 성공 · 클라이언트 토큰 제거 완료");
                } catch (error) {
                  pushLog(`로그아웃 실패: ${error.message}`);
                }
              }}
            >
              로그아웃
            </button>
          </div>

          <div className="quiet">
            <p>테스트 시나리오</p>
            <ol>
              <li>
                브라우저 A(일반), 브라우저 B(시크릿/다른 브라우저)에서 각각
                로그인 페이지를 엽니다.
              </li>
              <li>A에서 demo/demo 로그인 후 `/me` 호출 → 200 확인</li>
              <li>B에서 동일 계정으로 로그인 후 `/me` 호출 → 200 확인</li>
              <li>
                A로 돌아와 바로 `/me` 호출(1~2회) → 액세스가 유효하면 잠깐 200이
                나올 수 있음
              </li>
              <li>A에서 10초 정도 기다린 뒤 `/me` 호출 → 401이 되어야 함</li>
              <li>
                A에서 바로 `/auth/refresh` 호출 → 실패(401)여야 함 (Stage 8에서
                기존 패밀리 폐기됨)
              </li>
              <li>B에서 `/auth/refresh` 호출 → 성공(200)이어야 함</li>
            </ol>
          </div>
        </section>

        <section className="app-card log-card">
          <div className="card-header">
            <h2>활동 로그</h2>
            <p>최근 API 흐름을 타임스탬프와 함께 기록합니다.</p>
          </div>
          <div
            className="log-window"
            role="log"
            aria-live="polite"
            aria-label="Authentication activity log"
          >
            {logs.length === 0 ? (
              <p className="quiet">
                로그가 비어 있습니다. API를 호출해 보세요.
              </p>
            ) : (
              logs.map((line, index) => (
                <p key={index} className="log-line">
                  {line}
                </p>
              ))
            )}
          </div>
        </section>
      </main>
    </div>
  );
}
