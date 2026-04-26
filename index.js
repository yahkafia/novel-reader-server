const express = require("express");
const cloudbase = require("@cloudbase/node-sdk");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const PORT = Number(process.env.PORT || 80);
const TCB_ENV_ID = process.env.TCB_ENV_ID;
const TOKEN_SECRET = process.env.TOKEN_SECRET || "dev_secret_change_me";
const PASSWORD_SALT_ROUNDS = Number(process.env.PASSWORD_SALT_ROUNDS || 10);
const USERS_COLLECTION = process.env.USERS_COLLECTION || "users";

if (!TCB_ENV_ID) {
  console.warn("TCB_ENV_ID is not configured.");
}

const cloudbaseApp = cloudbase.init({
  env: TCB_ENV_ID
});

const db = cloudbaseApp.database();
const users = db.collection(USERS_COLLECTION);

function ok(data = {}) {
  return { code: 0, message: "ok", data };
}

function fail(message, data = {}) {
  return { code: 1, message, data };
}

function now() {
  return Date.now();
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

function validateNickname(nickname) {
  return typeof nickname === "string" && nickname.trim().length >= 1 && nickname.trim().length <= 20;
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

function safeNumber(value) {
  const n = Number(value || 0);
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.floor(n);
}

function toAccountUser(row, accessToken = "") {
  return {
    uid: row.uid || "",
    account: row.account || "",
    nickname: row.nickname || "阅读用户",
    phone: row.phone || "",
    avatarUrl: row.avatarUrl || "",
    loginType: row.loginType || "password",
    accessToken
  };
}

async function findUserByAccount(account) {
  const result = await users
    .where({
      account,
      deleted: false
    })
    .limit(1)
    .get();

  return result.data && result.data.length > 0 ? result.data[0] : null;
}

async function findUserByUid(uid) {
  const result = await users
    .where({
      uid,
      deleted: false
    })
    .limit(1)
    .get();

  return result.data && result.data.length > 0 ? result.data[0] : null;
}

async function authRequired(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.substring(7) : "";

    if (!token) {
      return res.json(fail("请先登录"));
    }

    const payload = jwt.verify(token, TOKEN_SECRET);
    const user = await findUserByUid(payload.uid);

    if (!user) {
      return res.json(fail("账号不存在或已注销"));
    }

    req.user = user;
    next();
  } catch (error) {
    console.error("auth failed:", error);
    return res.json(fail("登录状态已失效，请重新登录"));
  }
}

function withTimeout(promise, timeoutMs, message) {
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      setTimeout(() => reject(new Error(message)), timeoutMs);
    })
  ]);
}

app.get("/", async (req, res) => {
  const diag = {
    service: "novel-reader-account-server",
    version: "cloudbase-db-v1",
    env: TCB_ENV_ID || "",
    collection: USERS_COLLECTION,
    hasTokenSecret: Boolean(process.env.TOKEN_SECRET)
  };

  try {
    await withTimeout(
      users.limit(1).get(),
      5000,
      "CloudBase 数据库访问超时，请检查 TCB_ENV_ID、数据库是否开通、集合是否存在、云托管是否有访问权限"
    );

    res.json(ok({
      ...diag,
      database: "connected"
    }));
  } catch (error) {
    console.error("database check failed:", error);
    res.json(fail("CloudBase 数据库连接失败：" + error.message, diag));
  }
});

app.get("/health", (req, res) => {
  res.json(ok({
    service: "novel-reader-account-server",
    version: "cloudbase-db-v1",
    status: "running",
    env: TCB_ENV_ID || "",
    collection: USERS_COLLECTION
  }));
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

    if (!validateNickname(nickname)) {
      return res.json(fail("昵称需为1-20个字符"));
    }

    const existed = await users
      .where({
        account
      })
      .limit(1)
      .get();

    if (existed.data && existed.data.length > 0) {
      const old = existed.data[0];
      if (old.deleted === true) {
        return res.json(fail("该账号已注销，不能重复注册"));
      }
      return res.json(fail("账号已存在"));
    }

    const uid = createUid();
    const passwordHash = await bcrypt.hash(password, PASSWORD_SALT_ROUNDS);

    const user = {
      uid,
      account,
      nickname,
      passwordHash,
      phone: "",
      avatarUrl: "",
      loginType: "password",
      totalReadingSeconds: 0,
      totalAudiobookChars: 0,
      deleted: false,
      createdAt: now(),
      updatedAt: now()
    };

    await users.add(user);

    const accessToken = createToken(user);

    res.json(ok({
      user: toAccountUser(user, accessToken)
    }));
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

    const user = await findUserByAccount(account);

    if (!user) {
      return res.json(fail("账号不存在"));
    }

    const matched = await bcrypt.compare(password, user.passwordHash || "");

    if (!matched) {
      return res.json(fail("密码错误"));
    }

    await users.doc(user._id).update({
      lastLoginAt: now(),
      updatedAt: now()
    });

    const accessToken = createToken(user);

    res.json(ok({
      user: toAccountUser(user, accessToken)
    }));
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

    const matched = await bcrypt.compare(oldPassword, req.user.passwordHash || "");
    if (!matched) {
      return res.json(fail("原密码错误"));
    }

    const newHash = await bcrypt.hash(newPassword, PASSWORD_SALT_ROUNDS);

    await users.doc(req.user._id).update({
      passwordHash: newHash,
      updatedAt: now()
    });

    res.json(ok());
  } catch (error) {
    console.error("change password failed:", error);
    res.json(fail(error.message || "修改密码失败"));
  }
});

app.post("/auth/logout", authRequired, async (req, res) => {
  res.json(ok());
});

app.post("/account/delete", authRequired, async (req, res) => {
  try {
    await users.doc(req.user._id).update({
      deleted: true,
      account: `${req.user.account}_deleted_${req.user.uid}`,
      updatedAt: now()
    });

    res.json(ok());
  } catch (error) {
    console.error("delete account failed:", error);
    res.json(fail(error.message || "注销账号失败"));
  }
});

app.post("/user/stats/sync", authRequired, async (req, res) => {
  try {
    const totalReadingSeconds = safeNumber(req.body.totalReadingSeconds);
    const totalAudiobookChars = safeNumber(req.body.totalAudiobookChars);

    const oldReading = safeNumber(req.user.totalReadingSeconds);
    const oldAudio = safeNumber(req.user.totalAudiobookChars);

    await users.doc(req.user._id).update({
      totalReadingSeconds: Math.max(oldReading, totalReadingSeconds),
      totalAudiobookChars: Math.max(oldAudio, totalAudiobookChars),
      updatedAt: now()
    });

    res.json(ok());
  } catch (error) {
    console.error("sync stats failed:", error);
    res.json(fail(error.message || "同步统计失败"));
  }
});

app.post("/rankings", async (req, res) => {
  try {
    const readingResult = await users
      .where({
        deleted: false
      })
      .orderBy("totalReadingSeconds", "desc")
      .limit(50)
      .get();

    const audioResult = await users
      .where({
        deleted: false
      })
      .orderBy("totalAudiobookChars", "desc")
      .limit(50)
      .get();

    const readingTime = (readingResult.data || []).map((row, index) => ({
      rank: index + 1,
      nickname: row.nickname || `读者${index + 1}`,
      value: safeNumber(row.totalReadingSeconds)
    }));

    const audiobookChars = (audioResult.data || []).map((row, index) => ({
      rank: index + 1,
      nickname: row.nickname || `读者${index + 1}`,
      value: safeNumber(row.totalAudiobookChars)
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

app.listen(PORT, "0.0.0.0", () => {
  console.log(`server running on port ${PORT}`);
});