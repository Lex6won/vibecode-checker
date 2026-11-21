"""설정·노출 룰 묶음(2026-11-21) — 로그인 없이 원격에서 닿는 문제 중 구조가 뚜렷한 것.

각 룰마다 잡아야 할 형태와 잡으면 안 되는 형태를 함께 고정한다. 문자열 인자가 패턴의 일부인 룰이 Python 에서
'낮음'으로 떨어지지 않는지, 여러 줄에 걸친 설정도 그런지 본다.
"""
from __future__ import annotations

import pytest

from gvskb.scanner import scan_code


def _hits(code: str, filename: str, rule: str):
    return [f for f in scan_code(code, filename=filename).findings if f.rule_id == rule]


CASES = [
    # (룰, 파일 이름, 잡아야 할 코드, 잡으면 안 되는 코드)
    ("GOV-CORS-CREDENTIALS-001", "main.py",
     'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)\n',
     'app.add_middleware(CORSMiddleware, allow_origins=["https://portal.example.go.kr"], allow_credentials=True)\n'),
    ("GOV-CORS-CREDENTIALS-001", "main.py",
     'app.add_middleware(\n    CORSMiddleware,\n    allow_origins=["*"],\n    allow_methods=["*"],\n    allow_credentials=True,\n)\n',
     'app.add_middleware(\n    CORSMiddleware,\n    allow_origins=["*"],\n    allow_methods=["GET"],\n)\n'),
    ("GOV-CORS-CREDENTIALS-001", "settings.py",
     "CORS_ALLOW_ALL_ORIGINS = True\nCORS_ALLOW_CREDENTIALS = True\n",
     'CORS_ALLOWED_ORIGINS = ["https://portal.example.go.kr"]\nCORS_ALLOW_CREDENTIALS = True\n'),
    ("GOV-CORS-CREDENTIALS-001", "app.js",
     "app.use(cors({ origin: true, credentials: true }));\n",
     "app.use(cors({ origin: ['https://portal.example.go.kr'], credentials: true }));\napp.use(cors({ origin: '*' }));\n"),
    ("GOV-CORS-CREDENTIALS-001", "route.ts",
     'res.headers.set("Access-Control-Allow-Origin", request.headers.get("origin") ?? "*");\nres.headers.set("Access-Control-Allow-Credentials", "true");\n',
     'if (ALLOWED.has(origin)) res.headers.set("Access-Control-Allow-Origin", origin);\n'),
    ("GOV-AUTH-DEFAULT-CREDENTIALS-001", "login.py",
     'if request.form["username"] == "admin" and request.form["password"] == "P@ssw0rd":\n    session["is_admin"] = True\n',
     'if user and check_password_hash(user.password_hash, request.form["password"]):\n    login_user(user)\nif request.form.get("password") == "":\n    abort(400)\n'),
    ("GOV-AUTH-DEFAULT-CREDENTIALS-001", "login.js",
     "if (req.body.username === 'admin' && req.body.password === 'P@ssw0rd') { req.session.isAdmin = true; }\n",
     "if (!user || !(await bcrypt.compare(String(req.body.password), user.passwordHash))) return res.status(401).end();\nif (req.body.password === '') return res.status(400).end();\n"),
    ("GOV-SECRET-WEAK-KEY-001", "app.py",
     'app.secret_key = "dev"\n',
     'app.secret_key = os.environ["FLASK_SECRET_KEY"]\nsecret_key_name = "FLASK_SECRET_KEY"\n'),
    ("GOV-SECRET-WEAK-KEY-001", "token.js",
     "const token = jwt.sign({ sub: user.id, role: user.role }, 'secret');\n",
     "const token = jwt.sign({ sub: user.id }, process.env.JWT_KEY, { expiresIn: '1h' });\nconst c = jwt.verify(token, publicKey, { algorithms: ['RS256'] });\n"),
    ("GOV-UPLOAD-FILENAME-001", "upload.py",
     'f = request.files["file"]\nf.save(os.path.join(UPLOAD, f.filename))\n',
     'f.save(os.path.join(UPLOAD, uuid.uuid4().hex + ext))\nf.save(os.path.join(UPLOAD, secure_filename(f.filename)))\n'),
    ("GOV-UPLOAD-FILENAME-001", "upload.js",
     "const storage = multer.diskStorage({ filename: (req, file, cb) => cb(null, file.originalname) });\n",
     "const storage = multer.diskStorage({ filename: (req, file, cb) => cb(null, crypto.randomUUID() + path.extname(path.basename(file.originalname))) });\n"),
    ("GOV-ARCHIVE-EXTRACT-001", "unpack.py",
     'with tarfile.open(uploaded_path) as tar:\n    tar.extractall("/srv/app/models")\n',
     'with tarfile.open(path) as tar:\n    tar.extractall(dest, filter="data")\nwith zipfile.ZipFile(upload) as zf:\n    zf.extractall(dest)\n'),
    ("GOV-AI-PUBLIC-SHARE-001", "demo.py",
     'demo.launch(server_name="0.0.0.0", share=True)\n',
     'demo.launch(server_name="127.0.0.1", auth=(os.environ["UI_USER"], os.environ["UI_PASSWORD"]))\ndemo.launch()\n'),
    ("GOV-AI-PUBLIC-SHARE-001", "demo.py",
     'iface.launch(server_name="0.0.0.0", server_port=7860)\n',
     'iface.launch(server_name="0.0.0.0", auth=check_login)\n'),
    ("GOV-DEBUG-ENV-EXPOSE-001", "debug.js",
     "app.get('/debug/env', (req, res) => res.json(process.env));\n",
     "app.get('/healthz', (req, res) => res.json({ db_configured: Boolean(process.env.DATABASE_URL) }));\n"),
    ("GOV-DEBUG-ENV-EXPOSE-001", "debug.py",
     "return jsonify(dict(os.environ))\n",
     'return jsonify({"mode": os.environ.get("APP_MODE")})\n'),
    ("GOV-DB-RLS-OFF-001", "schema.sql",
     "alter table public.documents disable row level security;\n",
     'alter table public.documents enable row level security;\ncreate policy "public read" on public.notices for select using (true);\n'),
    ("GOV-DB-RLS-OFF-001", "policy.sql",
     'create policy "allow all" on public.profiles for all using (true) with check (true);\n',
     'create policy "own rows" on public.documents for all using (auth.uid() = owner_id) with check (auth.uid() = owner_id);\n'),
    ("GOV-NOSQL-INJECTION-001", "login.js",
     "const user = await User.findOne({ username: req.body.username, password: req.body.password });\n",
     "const user = await User.findOne({ username: String(req.body.username) });\nconst rows = await Order.find({ status: 'open' });\n"),
    ("GOV-NOSQL-INJECTION-001", "find.py",
     'rows = users.find({"$where": "this.name == \'" + name + "\'"})\n',
     'rows = users.find({"name": str(name)})\n'),
]


@pytest.mark.parametrize("rule,filename,bad,good", CASES, ids=[f"{c[0]}:{c[1]}:{i}" for i, c in enumerate(CASES)])
def test_rule_fires_on_the_risky_shape_only(rule: str, filename: str, bad: str, good: str) -> None:
    assert _hits(bad, filename, rule), "잡아야 할 형태를 놓쳤다"
    assert not _hits(good, filename, rule), "안전한 형태를 잡았다"


def test_config_rules_are_not_attenuated_in_python() -> None:
    """문자열 인자를 포함한 설정형 룰 — 한 줄이든 여러 줄이든 '낮음'으로 떨어지지 않는다."""
    one_line = 'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)\n'
    multi = 'app.add_middleware(\n    CORSMiddleware,\n    allow_origins=["*"],\n    allow_credentials=True,\n)\n'
    for code in (one_line, multi):
        hits = _hits(code, "main.py", "GOV-CORS-CREDENTIALS-001")
        assert hits and hits[0].severity.value == "high", code
    hits = _hits('if request.form["password"] == "P@ssw0rd":\n    pass\n', "login.py", "GOV-AUTH-DEFAULT-CREDENTIALS-001")
    assert hits and hits[0].severity.value == "high"
    hits = _hits('demo.launch(server_name="0.0.0.0", share=True)\n', "demo.py", "GOV-AI-PUBLIC-SHARE-001")
    assert hits and hits[0].severity.value == "high"


def test_config_shapes_quoted_inside_strings_are_attenuated() -> None:
    """같은 모양이 문자열 안에 있으면(시험 입력·안내문) 코드가 아니다."""
    code = 'EXAMPLE = "app.add_middleware(CORSMiddleware, allow_origins=[\'*\'], allow_credentials=True)"\n'
    hits = _hits(code, "docs_example.py", "GOV-CORS-CREDENTIALS-001")
    assert not hits or hits[0].severity.value == "low"
    code = 'HELP = "demo.launch(share=True) 는 쓰지 마세요"\n'
    hits = _hits(code, "help.py", "GOV-AI-PUBLIC-SHARE-001")
    assert not hits or hits[0].severity.value == "low"


def test_only_confirmed_shapes_block() -> None:
    """차단은 형태 자체가 확증인 것만 — 나머지는 확인 필요(경고)로 낸다."""
    env = _hits("app.get('/debug/env', (req, res) => res.json(process.env));\n", "d.js", "GOV-DEBUG-ENV-EXPOSE-001")
    assert env and env[0].decision.value == "block" and env[0].confidence == "confirmed"
    cors = _hits("app.use(cors({ origin: true, credentials: true }));\n", "a.js", "GOV-CORS-CREDENTIALS-001")
    assert cors and cors[0].decision.value == "warn"
