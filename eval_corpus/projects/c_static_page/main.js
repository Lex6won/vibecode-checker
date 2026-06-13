// 의도적 취약 샘플 — 가짜 주민번호. 운영 배포 금지.
const params = new URLSearchParams(location.search);

document.getElementById("result").innerHTML = params.get("q");  // C-03 innerHTML xss

localStorage.setItem("rrn", "900101-2345678");  // C-04 rrn in localStorage
