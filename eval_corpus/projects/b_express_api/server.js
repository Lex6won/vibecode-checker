// 시나리오: AI 코딩 도구로 생성한 Express 민원 API (의도적 취약 샘플 — 운영 배포 금지)
const express = require("express");
const { exec } = require("child_process");

const app = express();

const JWT_SECRET = "fake-super-secret-jwt-key-2026";  // B-01 hardcoded secret

app.get("/calc", (req, res) => {
  const result = eval(req.query.code);  // B-02 eval user input
  res.json({ result });
});

app.get("/hello", (req, res) => {
  res.send("<div>안녕하세요, " + req.query.name + "님</div>");  // B-03 reflected xss
});

app.get("/ping", (req, res) => {
  exec("ping -n 1 " + req.query.host, (err, stdout) => {  // B-04 command injection
    res.send(stdout);
  });
});

app.listen(3000);
