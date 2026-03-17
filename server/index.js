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
const STAGE = Number(process.env.STAGE || 9);
const DEFAULT_JWT_SECRET = "dev-secret-change-me";
const JWT_SECRET =
  process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");

if (!process.env.JWT_SECRET) {
  console.warn(
    "JWT_SECRET 환경변수가 없어 현재 프로세스 전용 임시 서명 시크릿을 생성했습니다.",
  );
} else if (process.env.JWT_SECRET === DEFAULT_JWT_SECRET) {
  console.warn(
    "JWT_SECRET가 알려진 기본 개발용 값입니다. 로컬 데모 외 환경에서는 고유한 시크릿으로 변경하세요.",
  );
}

// Stage별 TTL (원하는 값으로 조절 가능)
const ACCESS_TTL_SEC = 10; // Stage2는 10초 만료 재현, 그 외는 5분
const REFRESH_TTL_SEC = 60 * 60 * 24 * 7; // 7일 (Stage3에서 refresh 도입)

// 쿠키 옵션(로컬 개발 기준)
const isProd = process.env.NODE_ENV === "production";
const REFRESH_COOKIE_NAME = "refresh_token";
const CSRF_COOKIE_NAME = "csrf_token";

const refreshCookieOptions = {
  httpOnly: true,
  secure: isProd, // 로컬(http)에서는 false, 운영(https)에서는 true
  sameSite: "lax",
  // path를 refresh 엔드포인트로 제한하면 표면을 줄일 수 있음
  path: "/auth/refresh",
  maxAge: REFRESH_TTL_SEC * 1000,
};

const csrfCookieOptions = {
  httpOnly: false,
  secure: isProd,
  sameSite: "lax",
  path: "/",
  maxAge: REFRESH_TTL_SEC * 1000,
};

// Stage3: refresh 토큰을 서버가 "세션처럼" 관리하기 위한 인메모리 저장소
// Stage7: rotation/재사용 감지 지원
const refreshStore = new Map(); // key: jti, value: { userId, expiresAt, familyId, used, binding }
const SESSION_MAX_TTL_SEC = 30; // 30초: 절대 만료(세션 최대 수명)
const refreshFamilies = new Map(); // key: familyId, value: { jtis: Set<jti>, expiresAt }
const userFamilies = new Map(); // key: userId, value: Set<familyId>

app.use(
  cors({
    origin: CLIENT_ORIGIN,
    credentials: true, // ✅ 쿠키 주고받으려면 true
  }),
);

function issueCsrfToken(res) {
  const token = crypto.randomBytes(32).toString("hex");
  res.cookie(CSRF_COOKIE_NAME, token, csrfCookieOptions);
  return token;
}

function verifyCsrf(req) {
  const origin = req.get("origin") || "";
  const referer = req.get("referer") || "";
  const originOk = origin === CLIENT_ORIGIN;
  const refererOk = referer.startsWith(CLIENT_ORIGIN);

  if (!origin && !referer) {
    throw new Error("Origin/Referer가 없습니다.");
  }
  if (!originOk && !refererOk) {
    throw new Error("Origin/Referer 검증 실패");
  }

  const cookieToken = req.cookies?.[CSRF_COOKIE_NAME];
  const headerToken = req.get("x-csrf-token");
  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    throw new Error("CSRF 토큰 검증 실패");
  }
}

// Stage6: 모든 요청에 CSRF 검증 적용 (토큰 발급 엔드포인트는 예외)
app.use((req, res, next) => {
  if (STAGE < 6) return next();
  if (req.path === "/auth/csrf") return next();
  try {
    verifyCsrf(req);
    next();
  } catch (e) {
    return res.status(403).json({ message: e.message || "CSRF 검증 실패" });
  }
});

// CSRF 토큰 발급 (Double Submit Cookie)
app.get("/auth/csrf", (req, res) => {
  if (STAGE < 6) {
    return res
      .status(400)
      .json({ message: "Stage 6부터 CSRF 토큰을 사용할 수 있습니다." });
  }
  const token = issueCsrfToken(res);
  res.json({ csrfToken: token, message: "CSRF 토큰 발급 완료" });
});

// Access Token 생성
function signAccessToken(userId) {
  return jwt.sign({ sub: userId, typ: "access" }, JWT_SECRET, {
    expiresIn: ACCESS_TTL_SEC,
  });
}

function ensureFamilySet(familyId, expiresAt = null) {
  let record = refreshFamilies.get(familyId);
  if (!record) {
    record = {
      jtis: new Set(),
      expiresAt: expiresAt ?? Date.now() + SESSION_MAX_TTL_SEC * 1000,
    };
    refreshFamilies.set(familyId, record);
  }
  return record;
}

function ensureUserSet(userId) {
  let set = userFamilies.get(userId);
  if (!set) {
    set = new Set();
    userFamilies.set(userId, set);
  }
  return set;
}

function revokeUserFamilies(userId) {
  const families = userFamilies.get(userId);
  if (!families) return;
  for (const familyId of families) {
    revokeFamily(familyId);
  }
}

function revokeFamily(familyId) {
  const record = refreshFamilies.get(familyId);
  if (!record) return;
  for (const jti of record.jtis) {
    refreshStore.delete(jti);
  }
  refreshFamilies.delete(familyId);
}

function revokeRefreshToken(jti) {
  const record = refreshStore.get(jti);
  if (!record) return;
  refreshStore.delete(jti);
  if (record.familyId) {
    const family = refreshFamilies.get(record.familyId);
    if (family) {
      family.jtis.delete(jti);
      if (family.jtis.size === 0) {
        const userId = record.userId;
        const userSet = userFamilies.get(userId);
        if (userSet) {
          userSet.delete(record.familyId);
          if (userSet.size === 0) userFamilies.delete(userId);
        }
        refreshFamilies.delete(record.familyId);
      }
    }
  }
}

// Refresh Token 생성(서버 저장소에 jti 기록)
function getRefreshBinding(req) {
  const ip = req.ip || "";
  const userAgent = req.get("user-agent") || "";
  const fingerprint = crypto
    .createHash("sha256")
    .update(`${ip}|${userAgent}`)
    .digest("hex");
  return { fingerprint };
}

function signRefreshToken(userId, familyId = null, binding = null) {
  const jti = crypto.randomUUID();
  const payload = { sub: userId, typ: "refresh", jti };
  if (familyId) payload.fid = familyId;
  if (binding) payload.bnd = binding.fingerprint;
  const token = jwt.sign(payload, JWT_SECRET, {
    expiresIn: REFRESH_TTL_SEC,
  });

  refreshStore.set(jti, {
    userId,
    expiresAt: Date.now() + REFRESH_TTL_SEC * 1000,
    familyId,
    used: false,
    binding: binding ? binding.fingerprint : null,
  });

  if (familyId) {
    const record = ensureFamilySet(familyId);
    record.jtis.add(jti);
    ensureUserSet(userId).add(familyId);
  }

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
    revokeRefreshToken(payload.jti);
    throw new Error("만료된 Refresh 토큰입니다.");
  }

  if (STAGE >= 7) {
    if (record.familyId) {
      const family = refreshFamilies.get(record.familyId);
      if (!family || family.expiresAt < Date.now()) {
        if (record.familyId) revokeFamily(record.familyId);
        throw new Error("세션이 만료되었습니다. 다시 로그인 해주세요.");
      }
    }
    if (record.used) {
      // 재사용 감지 시 패밀리 전체 폐기
      if (record.familyId) revokeFamily(record.familyId);
      throw new Error("Refresh 토큰 재사용이 감지되었습니다.");
    }
    if (record.familyId && payload.fid !== record.familyId) {
      if (record.familyId) revokeFamily(record.familyId);
      throw new Error("Refresh 토큰 무결성 검증 실패");
    }
  }

  if (STAGE >= 8) {
    const binding = getRefreshBinding(req);
    if (!record.binding || record.binding !== binding.fingerprint) {
      if (record.familyId) revokeFamily(record.familyId);
      throw new Error("Refresh 토큰 바인딩 검증 실패");
    }
  }

  return { userId: payload.sub, jti: payload.jti, familyId: record.familyId };
}

// 로그인: Stage 1~3에서 모두 가능 (Stage3에서 refresh 쿠키 발급)
app.post("/login", (req, res) => {
  if (![1, 2, 3, 4, 5, 6, 7, 8, 9].includes(STAGE)) {
    return res.status(400).json({
      message:
        "현재 설정에서는 이 엔드포인트를 Stage 1~9에서만 사용할 수 있습니다.",
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

  // ✅ Stage3: refresh 쿠키 발급 (Stage7: 패밀리 생성 + 절대 만료)
  if (STAGE >= 3) {
    if (STAGE >= 8) {
      revokeUserFamilies(userId);
    }

    const familyId = STAGE >= 7 ? crypto.randomUUID() : null;
    if (STAGE >= 7 && familyId) {
      ensureFamilySet(familyId, Date.now() + SESSION_MAX_TTL_SEC * 1000);
    }
    const binding = STAGE >= 8 ? getRefreshBinding(req) : null;
    const { token: refreshToken } = signRefreshToken(userId, familyId, binding);
    res.cookie(REFRESH_COOKIE_NAME, refreshToken, refreshCookieOptions);
  }
  // ✅ Stage6: CSRF 쿠키 발급
  if (STAGE >= 6) {
    issueCsrfToken(res);
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

  try {
    const { userId, jti, familyId } = verifyRefreshFromCookie(req);
    const newAccessToken = signAccessToken(userId);
    if (STAGE >= 7) {
      // rotation: 기존 토큰 사용 처리 + 새 토큰 발급
      const record = refreshStore.get(jti);
      if (record) record.used = true;
      const binding = STAGE >= 8 ? getRefreshBinding(req) : null;
      const { token: nextRefreshToken } = signRefreshToken(
        userId,
        familyId,
        binding,
      );
      res.cookie(REFRESH_COOKIE_NAME, nextRefreshToken, refreshCookieOptions);
    }
    if (STAGE >= 6) {
      issueCsrfToken(res);
    }

    res.json({
      accessToken: newAccessToken,
      tokenType: "Bearer",
      expiresInSec: ACCESS_TTL_SEC,
      message: "Refresh로 Access 재발급 완료",
    });
  } catch (e) {
    return res.status(401).json({ message: e.message || "Refresh 검증 실패" });
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
      const { jti, familyId } = verifyRefreshFromCookie(req);
      if (STAGE >= 7 && familyId) {
        revokeFamily(familyId);
      } else {
        revokeRefreshToken(jti);
      }
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
