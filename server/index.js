import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import crypto from "crypto";

const app = express();
app.use(express.json());
app.use(cookieParser());

const PORT = 4000;
const CLIENT_ORIGIN = "http://localhost:5173";
const STAGE = Number(process.env.STAGE || 3);
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

// Stage별 TTL (원하는 값으로 조절 가능)
const ACCESS_TTL_SEC = 10; // Stage2는 10초 만료 재현, 그 외는 5분
const REFRESH_TTL_SEC = 60 * 60 * 24 * 7; // 7일 (Stage3에서 refresh 도입)

// 쿠키 옵션(로컬 개발 기준)
const isProd = process.env.NODE_ENV === "production";
const REFRESH_COOKIE_NAME = "refresh_token";
const refreshingRefreshJtis = new Set();

const refreshCookieOptions = {
  httpOnly: true,
  secure: isProd, // 로컬(http)에서는 false, 운영(https)에서는 true
  sameSite: "lax",
  // path를 refresh 엔드포인트로 제한하면 표면을 줄일 수 있음
  path: "/auth/refresh",
  maxAge: REFRESH_TTL_SEC * 1000,
};

// Stage3: refresh 토큰을 서버가 "세션처럼" 관리하기 위한 인메모리 저장소
const refreshStore = new Map(); // key: jti, value: { userId, expiresAt, refreshing }

app.use(
  cors({
    origin: CLIENT_ORIGIN,
    credentials: true, // ✅ 쿠키 주고받으려면 true
  }),
);

// Access Token 생성
function signAccessToken(userId) {
  return jwt.sign({ sub: userId, typ: "access" }, JWT_SECRET, {
    expiresIn: ACCESS_TTL_SEC,
  });
}

// Refresh Token 생성(서버 저장소에 jti 기록)
function signRefreshToken(userId) {
  const jti = crypto.randomUUID();
  const token = jwt.sign({ sub: userId, typ: "refresh", jti }, JWT_SECRET, {
    expiresIn: REFRESH_TTL_SEC,
  });

  refreshStore.set(jti, {
    userId,
    expiresAt: Date.now() + REFRESH_TTL_SEC * 1000,
    refreshing: false,
  });

  return { token, jti };
}

// Authorization Bearer Access 검증
function requireAccess(req, res, next) {
  const auth = req.header("Authorization") || "";
  const [type, token] = auth.split(" ");
  if (type !== "Bearer" || !token) {
    return res
      .status(401)
      .json({ message: "Authorization Bearer 토큰이 없습니다." });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.typ !== "access") throw new Error("액세스 토큰이 아닙니다.");
    req.userId = payload.sub;
    next();
  } catch {
    return res
      .status(401)
      .json({ message: "유효하지 않거나 만료된 액세스 토큰입니다." });
  }
}

// Refresh 쿠키를 검증하고 userId 반환
function verifyRefreshFromCookie(req) {
  const token = req.cookies?.[REFRESH_COOKIE_NAME];
  if (!token) throw new Error("Refresh 쿠키가 없습니다.");

  const payload = jwt.verify(token, JWT_SECRET);
  if (payload.typ !== "refresh") throw new Error("리프레시 토큰이 아닙니다.");

  const record = refreshStore.get(payload.jti);
  if (!record) throw new Error("서버에 등록되지 않은 Refresh 토큰입니다.");

  // (인메모리 만료 체크 — jwt 만료 외 추가 방어)
  if (record.expiresAt < Date.now()) {
    refreshStore.delete(payload.jti);
    throw new Error("만료된 Refresh 토큰입니다.");
  }

  return { userId: payload.sub, jti: payload.jti, record };
}

// 로그인: Stage 1~5에서 가능 (Stage3+에서 refresh 쿠키 발급)
app.post("/login", (req, res) => {
  if (![1, 2, 3, 4, 5].includes(STAGE)) {
    return res.status(400).json({
      message:
        "현재 설정에서는 이 엔드포인트를 Stage 1~5에서만 사용할 수 있습니다.",
    });
  }

  const { username, password } = req.body;
  if (username !== "demo" || password !== "demo") {
    return res
      .status(401)
      .json({ message: "아이디 또는 비밀번호가 일치하지 않습니다." });
  }

  const userId = "user-1";
  const accessToken = signAccessToken(userId);

  // ✅ Stage3: refresh 쿠키 발급
  if (STAGE >= 3) {
    const { token: refreshToken } = signRefreshToken(userId);
    res.cookie(REFRESH_COOKIE_NAME, refreshToken, refreshCookieOptions);
  }

  res.json({
    accessToken,
    tokenType: "Bearer",
    expiresInSec: ACCESS_TTL_SEC,
    stage: STAGE,
    message:
      STAGE >= 3
        ? "로그인 성공: Access(JSON) + Refresh(HttpOnly Cookie) 발급"
        : "로그인 성공: Access(JSON)만 발급",
  });
});

// Access 만료 시, refresh 쿠키로 Access 재발급
app.post("/auth/refresh", (req, res) => {
  if (STAGE < 3) {
    return res
      .status(400)
      .json({ message: "Stage 3부터 refresh를 사용할 수 있습니다." });
  }

  const CONCURRENCY_LOCK_TTL_MS = 1500;
  let parsedJti;

  try {
    const { userId, jti: refreshJti, record } = verifyRefreshFromCookie(req);
    parsedJti = refreshJti;

    if (record.refreshing || refreshingRefreshJtis.has(refreshJti)) {
      return res
        .status(409)
        .json({ message: "Refresh 토큰이 이미 처리 중입니다." });
    }

    // Stage5: 같은 refresh 토큰의 동시 401 레이스 제어
    record.refreshing = true;
    refreshingRefreshJtis.add(refreshJti);
    refreshStore.set(refreshJti, record);

    // 동시성 제어 락은 즉시 해제되지 않고 짧은 구간 유지되어
    // “동일 시점 병렬 요청”이 연쇄적으로 성공하는 것을 방지한다.
    setTimeout(() => {
      const current = refreshStore.get(refreshJti);
      if (current) {
        current.refreshing = false;
        refreshStore.set(refreshJti, current);
      }
      refreshingRefreshJtis.delete(refreshJti);
    }, CONCURRENCY_LOCK_TTL_MS).unref();

    const newAccessToken = signAccessToken(userId);
    return res.json({
      accessToken: newAccessToken,
      tokenType: "Bearer",
      expiresInSec: ACCESS_TTL_SEC,
      message: "Refresh로 Access 재발급 완료",
    });
  } catch (e) {
    if (parsedJti) {
      const current = refreshStore.get(parsedJti);
      if (current) {
        current.refreshing = false;
        refreshStore.set(parsedJti, current);
      }
      refreshingRefreshJtis.delete(parsedJti);
    }
    return res
      .status(401)
      .json({ message: e.message || "Refresh 검증 실패" });
  }
});

// 보호 API
app.get("/me", requireAccess, (req, res) => {
  res.json({
    userId: req.userId,
    stage: STAGE,
    message:
      STAGE >= 3
        ? "Access로 인증되었습니다. (Stage 3: Access+Refresh 구조)"
        : "Access로만 인증되었습니다. (Stage 1/2)",
  });
});

// 로그아웃: Refresh 쿠키 삭제 + 서버 저장소에서도 폐기
app.post("/logout", (req, res) => {
  if (STAGE >= 3) {
    try {
      const { jti } = verifyRefreshFromCookie(req);
      refreshStore.delete(jti);
    } catch {
      // 쿠키가 없거나 검증 실패여도, 클라이언트 입장에선 로그아웃 처리 가능
    }

    // cookie 설정 시 path를 /auth/refresh로 줬으니 삭제도 동일 path로
    res.clearCookie(REFRESH_COOKIE_NAME, {
      ...refreshCookieOptions,
      maxAge: 0,
    });
    return res.json({ message: "로그아웃 완료: Refresh 폐기 + 쿠키 삭제" });
  }

  // Stage1~2
  return res.json({
    message: "Stage1/2 로그아웃: 클라이언트는 로컬에서 Access 토큰 삭제",
  });
});

app.listen(PORT, () =>
  console.log(`서버 실행 중: http://localhost:${PORT} (STAGE=${STAGE})`),
);
