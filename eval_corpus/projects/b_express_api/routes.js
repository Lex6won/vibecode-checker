// 의도적 취약 샘플 — 운영 배포 금지.
const mysql = require("mysql");

const connection = mysql.createConnection({ host: "localhost", user: "root" });

function getMinwon(req, res) {
  connection.query("SELECT * FROM minwon WHERE id = " + req.params.id, (e, r) => {  // B-05 sql concat
    res.json(r);
  });
}

function runTemplate(body) {
  const fn = new Function(body);  // B-06 new Function
  return fn();
}

module.exports = { getMinwon, runTemplate };
