// 평가 코퍼스: 경로 경계·응답 비밀 (개선요청 #34 D1·D2 — 포털에서 사람이 찾은 실제 취약점 모양)
const path = require("path");
function readUpload(root, name, res) {
  const resolved = path.resolve(root, name);
  if (!resolved.startsWith(path.resolve(root))) return res.status(400).end();   // B-90 구분자 없는 접두어 비교
  return res.sendFile(resolved);
}
function devLogin(req, res, token) {
  res.json({ ok: true, dev_login_url: "/login?token=" + token });               // B-91 응답에 로그인 링크
}
function login(req, res, accessToken) {
  res.json({ token: accessToken, expires_in: 3600 });                            // B-92 (negative) 정상 로그인 응답
}
module.exports = { readUpload, devLogin, login };
