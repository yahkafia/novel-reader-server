const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const TOKEN_SECRET = process.env.TOKEN_SECRET || "dev_secret_change_me";
const PASSWORD_SALT_ROUNDS = Number(process.env.PASSWORD_SALT_ROUNDS || 10);

const pool = mysql.createPool({
  host: process.env.MYSQL_HOST,
  port: Number(process.env.MYSQL_PORT || 3306),
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  charset: "utf8mb4"
});

function ok(data = {}) {
  return { code: 0, message: "ok", data };
}

function fail(message) {
  return { code: 1, message, data: {} };
}

function normalizeAccount(account) {
  return String(account || "").trim().toLowerCase();
}

function validateAccount(account) {
  return /^[a-zA-Z0-9_]{4,20}$/.test(account);
}

function validatePassword(password) {
  return typeof password === "string" && password.length >= 6 && password.length <= 32;
}

function createUid() {
  return "u_" + crypto.randomBytes(12).toString("hex");
}

function createToken(user) {
  return jwt.sign(
    {
      uid: user.uid,
      account: user.account,
      loginType: "password"
    },
    TOKEN_SECRET,
    {
      expiresIn: "30d"
    }
  );
}

function toAccountUser(row, accessToken = "") {
  return {
    uid: row.uid,
    nickname: row.nickname || "阅读用户",
    phone: row.phone || "",
    avatarUrl: row.avatar_url || "",
    loginType: row.login_type || "password",
    accessToken
  };
}

async function authRequired(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.substring(7) : "";

    if (!token) {
      return res.json(fail("请先登录"));
    }

    const payload = jwt.verify(token, TOKEN_SECRET);
    const [rows] = await pool.execute(
      "SELECT * FROM users WHERE uid = ? AND deleted = 0 LIMIT 1",
      [payload.uid]
    );

    if (!rows.length) {
      return res.json(fail("账号不存在或已注销"));
    }

    req.user = rows[0];
    next();
  } catch (error) {
    return res.json(fail("登录状态已失效，请重新登录"));
  }
}

app.get("/", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json(ok({
      service: "novel-reader-account-server",
      version: "password-mysql-v1",
      mysql: "connected"
    }));
  } catch (error) {
    res.json(fail("MySQL连接失败：" + error.message));
  }
});

app.post("/auth/password/register", async (req, res) => {
  try {
    const account = normalizeAccount(req.body.account);
    const password = String(req.body.password || "");
    const nickname = String(req.body.nickname || "").trim() || "阅读用户";

    if (!validateAccount(account)) {
      return res.json(fail("账号需为4-20位字母、数字或下划线"));
    }

    if (!validatePassword(password)) {
      return res.json(fail("密码长度需为6-32位"));
    }

    const [exists] = await pool.execute(
      "SELECT uid FROM users WHERE account = ? LIMIT 1",
      [account]
    );

    if (exists.length) {
      return res.json(fail("账号已存在"));
    }

    const uid = createUid();
    const passwordHash = await bcrypt.hash(password, PASSWORD_SALT_ROUNDS);

    await pool.execute(
      `INSERT INTO users
       (uid, account, nickname, password_hash, login_type, total_reading_seconds, total_audiobook_chars, deleted)
       VALUES (?, ?, ?, ?, 'password', 0, 0, 0)`,
      [uid, account, nickname, passwordHash]
    );

    const userRow = {
      uid,
      account,
      nickname,
      phone: "",
      avatar_url: "",
      login_type: "password"
    };

    const accessToken = createToken(userRow);
    res.json(ok({ user: toAccountUser(userRow, accessToken) }));
  } catch (error) {
    console.error("register failed:", error);
    res.json(fail(error.message || "注册失败"));
  }
});

app.post("/auth/password/login", async (req, res) => {
  try {
    const account = normalizeAccount(req.body.account);
    const password = String(req.body.password || "");

    if (!validateAccount(account)) {
      return res.json(fail("请输入正确的账号"));
    }

    if (!password) {
      return res.json(fail("请输入密码"));
    }

    const [rows] = await pool.execute(
      "SELECT * FROM users WHERE account = ? AND deleted = 0 LIMIT 1",
      [account]
    );

    if (!rows.length) {
      return res.json(fail("账号不存在"));
    }

    const user = rows[0];
    const matched = await bcrypt.compare(password, user.password_hash);

    if (!matched) {
      return res.json(fail("密码错误"));
    }

    const accessToken = createToken(user);
    res.json(ok({ user: toAccountUser(user, accessToken) }));
  } catch (error) {
    console.error("login failed:", error);
    res.json(fail(error.message || "登录失败"));
  }
});

app.post("/auth/password/change", authRequired, async (req, res) => {
  try {
    const oldPassword = String(req.body.oldPassword || "");
    const newPassword = String(req.body.newPassword || "");

    if (!oldPassword) {
      return res.json(fail("请输入原密码"));
    }

    if (!validatePassword(newPassword)) {
      return res.json(fail("新密码长度需为6-32位"));
    }

    const matched = await bcrypt.compare(oldPassword, req.user.password_hash);
    if (!matched) {
      return res.json(fail("原密码错误"));
    }

    const newHash = await bcrypt.hash(newPassword, PASSWORD_SALT_ROUNDS);

    await pool.execute(
      "UPDATE users SET password_hash = ? WHERE uid = ?",
      [newHash, req.user.uid]
    );

    res.json(ok());
  } catch (error) {
    console.error("change password failed:", error);
    res.json(fail(error.message || "修改密码失败"));
  }
});

app.post("/auth/logout", authRequired, async (req, res) => {
  // 当前使用 JWT，无服务端 token 表；客户端删除本地 token 即可。
  res.json(ok());
});

app.post("/account/delete", authRequired, async (req, res) => {
  try {
    await pool.execute(
      "UPDATE users SET deleted = 1, account = CONCAT(account, '_deleted_', uid) WHERE uid = ?",
      [req.user.uid]
    );

    res.json(ok());
  } catch (error) {
    console.error("delete account failed:", error);
    res.json(fail(error.message || "注销账号失败"));
  }
});

app.post("/user/stats/sync", authRequired, async (req, res) => {
  try {
    const totalReadingSeconds = Number(req.body.totalReadingSeconds || 0);
    const totalAudiobookChars = Number(req.body.totalAudiobookChars || 0);

    if (!Number.isFinite(totalReadingSeconds) || totalReadingSeconds < 0) {
      return res.json(fail("阅读时长数据异常"));
    }

    if (!Number.isFinite(totalAudiobookChars) || totalAudiobookChars < 0) {
      return res.json(fail("听书字数数据异常"));
    }

    await pool.execute(
      `UPDATE users
       SET total_reading_seconds = GREATEST(total_reading_seconds, ?),
           total_audiobook_chars = GREATEST(total_audiobook_chars, ?)
       WHERE uid = ? AND deleted = 0`,
      [Math.floor(totalReadingSeconds), Math.floor(totalAudiobookChars), req.user.uid]
    );

    res.json(ok());
  } catch (error) {
    console.error("sync stats failed:", error);
    res.json(fail(error.message || "同步统计失败"));
  }
});

app.post("/rankings", async (req, res) => {
  try {
    const [readingRows] = await pool.execute(
      `SELECT nickname, total_reading_seconds AS value
       FROM users
       WHERE deleted = 0
       ORDER BY total_reading_seconds DESC
       LIMIT 50`
    );

    const [audioRows] = await pool.execute(
      `SELECT nickname, total_audiobook_chars AS value
       FROM users
       WHERE deleted = 0
       ORDER BY total_audiobook_chars DESC
       LIMIT 50`
    );

    const readingTime = readingRows.map((row, index) => ({
      rank: index + 1,
      nickname: row.nickname || `读者${index + 1}`,
      value: Number(row.value || 0)
    }));

    const audiobookChars = audioRows.map((row, index) => ({
      rank: index + 1,
      nickname: row.nickname || `读者${index + 1}`,
      value: Number(row.value || 0)
    }));

    res.json(ok({
      readingTime,
      audiobookChars
    }));
  } catch (error) {
    console.error("rankings failed:", error);
    res.json(fail(error.message || "排行榜加载失败"));
  }
});

const port = Number(process.env.PORT || 80);
app.listen(port, "0.0.0.0", () => {
  console.log(`server running on port ${port}`);
});