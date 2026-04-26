const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

function ok(data = {}) {
  return { code: 0, message: "ok", data };
}

function fail(message) {
  return { code: 1, message, data: {} };
}

app.get("/", (req, res) => {
  res.json(ok({ service: "novel-reader-account-server" }));
});

app.post("/auth/sms/code", async (req, res) => {
  const { phone } = req.body || {};

  if (!/^1\d{10}$/.test(phone || "")) {
    return res.json(fail("请输入正确的手机号"));
  }

  return res.json(ok({ mockCode: process.env.MOCK_SMS_CODE || "123456" }));
});

app.post("/auth/sms/login", async (req, res) => {
  const { phone, code } = req.body || {};
  const mockCode = process.env.MOCK_SMS_CODE || "123456";

  if (!/^1\d{10}$/.test(phone || "")) {
    return res.json(fail("请输入正确的手机号"));
  }

  if (code !== mockCode) {
    return res.json(fail("验证码错误"));
  }

  const uid = `u_${phone}`;
  const accessToken = crypto
    .createHash("sha256")
    .update(`${phone}_${Date.now()}_${process.env.TOKEN_SECRET || "dev"}`)
    .digest("hex");

  return res.json(ok({
    user: {
      uid,
      nickname: "手机用户",
      phone,
      avatarUrl: "",
      loginType: "sms",
      accessToken
    }
  }));
});

app.post("/user/stats/sync", async (req, res) => {
  return res.json(ok());
});

app.post("/rankings", async (req, res) => {
  return res.json(ok({
    readingTime: [
      { rank: 1, nickname: "测试用户A", value: 7200 },
      { rank: 2, nickname: "测试用户B", value: 3600 }
    ],
    audiobookChars: [
      { rank: 1, nickname: "测试用户A", value: 120000 },
      { rank: 2, nickname: "测试用户B", value: 50000 }
    ]
  }));
});

const port = Number(process.env.PORT || 80);
app.listen(port, "0.0.0.0", () => {
  console.log(`server running on port ${port}`);
});