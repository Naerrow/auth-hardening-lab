import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";

const app = express();
app.use(express.json());

const PORT = 4000;
const CLIENT_ORIGIN = "http://localhost:5173";
const STAGE = Number(process.env.STAGE || 1);
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

app.use(
  cors({
    origin: CLIENT_ORIGIN,
    credentials: false,
  }),
);

// 사용자 ID로 유효 기간이 설정된 액세스 토큰을 생성합니다.
function signAccessToken(userId) {
  return jwt.sign({ sub: userId, typ: "access" }, JWT_SECRET);
}

// 요청에 포함된 Authorization Bearer 토큰을 검증하여 인증된 요청인지 확인합니다.
function requireAccess(req, res, next) {
  const auth = req.header("Authorization") || "";
  const [type, token] = auth.split(" ");
  if (type !== "Bearer" || !token)
    return res
      .status(401)
      .json({ message: "Authorization Bearer 토큰이 없습니다." });

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

// 로그인 요청을 처리하고 조건을 만족하면 액세스 토큰을 발급합니다.
app.post("/login", (req, res) => {
  if (STAGE !== 1)
    return res
      .status(400)
      .json({ message: "현재 설정에서는 이 엔드포인트는 Stage1 전용입니다." });

  const { username, password } = req.body;
  if (username !== "demo" || password !== "demo")
    return res.status(401).json({ message: "잘못된 인증 정보입니다." });

  const accessToken = signAccessToken("user-1");
  res.json({ accessToken, tokenType: "Bearer" });
});

// 토큰 인증된 사용자 정보를 돌려줍니다.
app.get("/me", requireAccess, (req, res) => {
  res.json({
    userId: req.userId,
    message: "액세스 토큰으로만 인증되었습니다 (Stage 1).",
  });
});

// 로그아웃 시뮬레이션: 클라이언트가 토큰을 삭제하도록 알립니다.
app.post("/logout", (req, res) => {
  res.json({
    message: "Stage1 로그아웃: 클라이언트는 로컬에서 토큰을 삭제해야 합니다.",
  });
});

app.listen(PORT, () =>
  console.log(`서버 실행 중: http://localhost:${PORT} (STAGE=${STAGE})`),
);
