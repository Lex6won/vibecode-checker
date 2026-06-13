// 음성 대조군: 취약해 보이는 코드가 주석에만 존재 (JS 주석 처리 갭 측정용)
// 과거 코드 리뷰 메모: eval(req.query.code) 는 금지한다.
// connection.query("SELECT * FROM t WHERE id = " + id) 패턴도 금지.
/*
  옛 구현:
  const fn = new Function(body);
  element.innerHTML = userInput;
*/

function sanitize(value) {
  return String(value).trim();
}

module.exports = { sanitize };
