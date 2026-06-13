// 경계 프로브: 난독화 eval — 미탐 예상 (탐지 한계 측정용)
function runPayload(payload) {
  return window["ev" + "al"](payload);  // H-07 obfuscated eval
}

module.exports = { runPayload };
