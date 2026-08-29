// 음성 대조군: 안전하게 작성된 Express API — 여기서 발견되는 항목은 오탐(FP)
const express = require("express");
const mysql = require("mysql");

const app = express();
const JWT_SECRET = process.env.JWT_SECRET;
const connection = mysql.createConnection({ host: "localhost", user: "app" });

app.get("/minwon/:id", (req, res) => {
  connection.query("SELECT * FROM minwon WHERE id = ?", [req.params.id], (e, r) => {
    res.json(r);
  });
});

app.get("/hello", (req, res) => {
  res.json({ message: "안녕하세요", name: String(req.query.name || "") });
});

app.listen(3000);

// 경로 경계 — 구분자를 붙이거나 relative 로 검사(GOV-PATH-BOUNDARY-001 음성)
function safeRead(root, name) {
  const base = path.resolve(root);
  const target = path.resolve(base, name);
  const rel = path.relative(base, target);
  if (rel.startsWith("..") || path.isAbsolute(rel)) throw new Error("bad path");
  if (!target.startsWith(base + path.sep)) throw new Error("bad path");
  return target;
}
