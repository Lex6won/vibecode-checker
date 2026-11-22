"""JS·TS 요청 값 추적(js-flow) — 구현 세션의 자기 반박 회차(W1-a). 시험(test_js_web_flows.py)과 다른 모양으로 새로 쓴
안전한 처리 함수 20개와 취약한 처리 함수 20개. 실제 서비스에서 볼 법한 모양(허용 목록, 정규식, `new URL` 뒤 호스트 비교, 스키마
검증, 숫자 변환, 조회 표, 미들웨어 검증, 구조분해 뒤 한쪽만 검사 등)으로 프레임워크를 섞었다.

보고가 남는 안전 사례는 ``KNOWN_REPORTS``, 놓치는 취약 사례는 ``KNOWN_MISSES`` 에 둔다 — 목록이 줄어들면 시험이 알려 준다.
(이 뒤에 구현과 무관한 세션이 따로 적대적 검증을 한다. 이 회차는 그 전에 뻔한 것을 거르는 용도다.)
"""
from __future__ import annotations

import textwrap

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_javascript")
pytest.importorskip("tree_sitter_typescript")

COMMON = (
    "const express = require('express');\n"
    "const axios = require('axios');\n"
    "const got = require('got');\n"
    "const fs = require('fs');\n"
    "const path = require('path');\n"
    "const { exec, execSync, spawn, execFile } = require('child_process');\n"
    "const app = express();\n"
    "const router = express.Router();\n"
)
KOA = "const Koa = require('koa');\nconst Router = require('koa-router');\nconst axios = require('axios');\n" \
      "const app = new Koa();\nconst router = new Router();\napp.use(router.routes());\n"
FASTIFY = "import Fastify from 'fastify';\nimport { readFile } from 'node:fs/promises';\nconst app = Fastify();\n"
HONO = "import { Hono } from 'hono';\nconst app = new Hono();\n"
TS = "import express, { Request, Response } from 'express';\nimport axios from 'axios';\nimport fs from 'fs';\n"


def _flows(code: str, header: str, filename: str) -> set[str]:
    from gvskb.scanners._ts_parse import parse
    from gvskb.scanners.js_web_flows import scan_js_flows

    source = header + textwrap.dedent(code)
    root, src = parse(source, filename)
    assert not root.has_error, "사례 코드가 구문 오류다"
    return {rule for rule, *_ in scan_js_flows(root, src, filename, strict=True)}


SAFE = [
    ("S01 new URL 구조분해 뒤 호스트 집합", COMMON, "a.js", """
        const TRUSTED = new Set(['cdn.example.com', 'img.example.com']);
        router.get('/thumb', async (req, res, next) => {
          try {
            const raw = req.query.src;
            const { hostname, protocol } = new URL(raw);
            if (protocol !== 'https:' || !TRUSTED.has(hostname)) return res.sendStatus(400);
            const { data } = await axios.get(raw, { responseType: 'arraybuffer' });
            res.type('image/png').send(data);
          } catch (e) { next(e); }
        });
    """),
    ("S02 정규식 상수로 검사 후 예외", COMMON, "a.js", """
        const ID_RE = /^[a-f0-9]{24}$/;
        app.get('/reports/:id', (req, res) => {
          const { id } = req.params;
          if (!ID_RE.test(id)) throw new HttpError(400, 'bad id');
          res.type('json').send(fs.readFileSync(`/var/reports/${id}.json`));
        });
    """),
    ("S03 검증 미들웨어(celebrate)", COMMON, "a.js", """
        router.post('/import', celebrate({ body: importSchema }), async (req, res) => {
          const { feedUrl } = req.body;
          const feed = await got(feedUrl).text();
          res.json({ size: feed.length });
        });
    """),
    ("S04 zod 로 파싱한 결과를 쓴다", COMMON, "a.js", """
        router.get('/preview', async (req, res) => {
          const { url } = PreviewQuery.parse(req.query);
          const r = await axios.get(url);
          res.send(r.data);
        });
    """),
    ("S05 parseInt 로 바꾼 쪽", COMMON, "a.js", """
        app.get('/list', async (req, res) => {
          const page = parseInt(req.query.page, 10) || 1;
          const r = await axios.get(`${page}`);
          res.json(r.data);
        });
    """),
    ("S06 Map 조회로 고른 주소", COMMON, "a.js", """
        const upstreams = new Map([['billing', 'http://billing:8080'], ['users', 'http://users:8080']]);
        app.get('/svc/:name/health', async (req, res) => {
          const base = upstreams.get(req.params.name);
          if (!base) return res.sendStatus(404);
          res.json((await axios.get(base + '/health')).data);
        });
    """),
    ("S07 구조분해 뒤 검사한 쪽만 경로에", COMMON, "a.js", """
        const THEMES = ['light', 'dark'];
        app.get('/theme', (req, res) => {
          const { theme, user } = req.query;
          if (!THEMES.includes(theme)) return res.status(400).end();
          res.sendFile(path.join(__dirname, 'themes', theme + '.css'));
        });
    """),
    ("S08 switch 로 고른 기준 주소", COMMON, "a.js", """
        app.get('/status', async (req, res) => {
          let base;
          switch (req.query.env) {
            case 'prod': base = 'https://api.example.com'; break;
            case 'stage': base = 'https://stage.example.com'; break;
            default: base = 'http://localhost:3000';
          }
          res.json((await axios.get(base + '/status')).data);
        });
    """),
    ("S09 resolve 뒤 뿌리 접두 검사", COMMON, "a.js", """
        const ROOT = path.resolve('public');
        app.get('/static/*', (req, res) => {
          const resolved = path.resolve(ROOT, req.params[0]);
          if (!resolved.startsWith(ROOT + path.sep)) return res.sendStatus(403);
          res.sendFile(resolved);
        });
    """),
    ("S10 URL 파싱 뒤 같은 출처만 리다이렉트", COMMON, "a.js", """
        const ORIGIN = 'https://app.example.com';
        app.get('/auth/callback', (req, res) => {
          const dest = new URL(req.query.returnTo || '/', ORIGIN);
          if (dest.origin !== ORIGIN) return res.redirect('/');
          res.redirect(dest.pathname + dest.search);
        });
    """),
    ("S11 고정 경로 뒤 인코딩한 질의", COMMON, "a.js", """
        app.post('/search', express.urlencoded({ extended: false }), (req, res) => {
          const q = req.body.q;
          res.redirect(`/results?q=${encodeURIComponent(q)}`);
        });
    """),
    ("S12 라이브러리 검사 함수", COMMON, "a.js", """
        const validator = require('validator');
        app.get('/blob/:id', (req, res) => {
          const id = req.params.id;
          if (!validator.isUUID(id)) return res.status(400).end();
          fs.createReadStream(`/data/blobs/${id}`).pipe(res);
        });
    """),
    ("S13 요청 값은 비교에만, 명령은 상수", COMMON, "a.js", """
        app.post('/ops', requireAdmin, (req, res) => {
          const action = req.body.action;
          if (action === 'restart') exec('systemctl restart app');
          res.json({ ok: true });
        });
    """),
    ("S14 라우터 파일의 검증 미들웨어 use", COMMON, "routes.js", """
        router.use(validateRequest(apiSpec));
        router.get('/proxy', async (req, res) => {
          const target = req.query.target;
          res.send((await axios.get(target)).data);
        });
        module.exports = router;
    """),
    ("S15 형 표기 컨트롤러의 숫자 변환", TS, "c.ts", """
        export class FileController {
          async get(req: Request, res: Response) {
            const id = Number(req.params.id);
            if (!Number.isInteger(id)) { res.status(400).end(); return; }
            res.send(fs.readFileSync(`/srv/files/${id}.txt`));
          }
        }
    """),
    ("S16 Koa 검사 함수 뒤 throw", KOA, "k.js", """
        router.get('/fetch', async (ctx) => {
          const url = ctx.query.url;
          if (!isAllowedUrl(url)) ctx.throw(400, 'blocked');
          ctx.body = (await axios.get(url)).data;
        });
    """),
    ("S17 Fastify 이름 집합 검사", FASTIFY, "f.mjs", """
        const NAMES = new Set(['terms', 'privacy']);
        app.get('/docs/:name', async (request, reply) => {
          const { name } = request.params;
          if (!NAMES.has(name)) return reply.code(404).send();
          return readFile(`./docs/${name}.md`, 'utf8');
        });
    """),
    ("S18 Hono 상대 경로만 리다이렉트", HONO, "h.ts", """
        app.get('/continue', (c) => {
          const next = c.req.query('next') ?? '/';
          if (!next.startsWith('/') || next.startsWith('//')) return c.redirect('/');
          return c.redirect(next);
        });
    """),
    ("S19 헤더 값을 기대값과 비교", COMMON, "a.js", """
        const EXPECTED_HOST = 'app.example.com';
        app.get('/canonical', (req, res) => {
          const host = req.headers['x-forwarded-host'];
          if (host !== EXPECTED_HOST) return res.redirect('https://' + EXPECTED_HOST + '/');
          res.redirect(`https://${host}/home`);
        });
    """),
    ("S20 길이 제한 뒤 같은 값", COMMON, "a.js", """
        app.get('/echo-file', (req, res) => {
          const name = req.query.name;
          if (name.length > 64 || name.includes('..')) return res.status(400).end();
          res.send(fs.readFileSync(path.join('/srv/echo', name)));
        });
    """),
]

VULNERABLE = [
    ("V01 웹훅 시험 발송", "KISA-JS-INPUT-12", COMMON, "a.js", """
        app.post('/webhooks/test', express.json(), async (req, res) => {
          const { webhookUrl } = req.body;
          const r = await fetch(webhookUrl, { method: 'POST', body: JSON.stringify({ ping: 1 }) });
          res.json({ status: r.status });
        });
    """),
    ("V02 기본값과 섞은 주소", "KISA-JS-INPUT-12", COMMON, "a.js", """
        const DEFAULT_URL = 'https://example.com/feed.xml';
        router.get('/feed', async (req, res) => {
          const target = req.query.u || DEFAULT_URL;
          const body = await got(target).text();
          res.type('xml').send(body);
        });
    """),
    ("V03 업로드 폴더에서 스트림", "KISA-JS-INPUT-03", COMMON, "a.js", """
        const UPLOAD_DIR = path.join(__dirname, 'uploads');
        app.get('/uploads/:filename', (req, res) => {
          const filePath = path.join(UPLOAD_DIR, req.params.filename);
          fs.createReadStream(filePath).pipe(res);
        });
    """),
    ("V04 다운로드 이름까지 요청 값", "KISA-JS-INPUT-03", COMMON, "a.js", """
        app.get('/export', (req, res) => {
          const name = req.query.name;
          res.download(path.resolve('exports', name), name);
        });
    """),
    ("V05 파일 삭제", "KISA-JS-INPUT-03", COMMON, "a.js", """
        app.delete('/files', requireLogin, async (req, res) => {
          const target = path.join('/srv/user-files', req.body.file);
          await fs.promises.unlink(target);
          res.sendStatus(204);
        });
    """),
    ("V06 로그인 뒤 돌아갈 곳", "KISA-JS-INPUT-07", COMMON, "a.js", """
        app.post('/login', express.urlencoded({ extended: true }), async (req, res) => {
          const returnTo = req.query.returnTo;
          req.session.user = await authenticate(req.body.username, req.body.password);
          return res.redirect(returnTo || '/');
        });
    """),
    ("V07 템플릿 앞머리 리다이렉트", "KISA-JS-INPUT-07", COMMON, "a.js", """
        app.get('/sso/done', (req, res) => {
          const base = req.query.base;
          res.redirect(`${base}/welcome`);
        });
    """),
    ("V08 git 명령 도우미", "KISA-JS-INPUT-05", COMMON, "a.js", """
        function checkout(branch) {
          return execSync(`git -C /srv/repo checkout ${branch}`).toString();
        }
        router.post('/deploy', requireAdmin, (req, res) => {
          const branch = req.body.branch;
          res.send(checkout(branch));
        });
    """),
    ("V09 셸을 켠 spawn 의 인자 배열", "KISA-JS-INPUT-05", COMMON, "a.js", """
        app.post('/archive', (req, res) => {
          const dir = req.body.dir;
          const p = spawn('tar', ['-czf', '/tmp/out.tgz', dir], { shell: true });
          p.on('close', () => res.download('/tmp/out.tgz'));
        });
    """),
    ("V10 스킴과 호스트를 받아 조립", "KISA-JS-INPUT-12", COMMON, "a.js", """
        app.post('/integrations/ping', async (req, res) => {
          const { scheme, host } = req.body;
          const r = await axios.post(`${scheme}://${host}/api/ping`, { from: 'us' });
          res.json(r.data);
        });
    """),
    ("V11 업로드 미들웨어 뒤 원격 가져오기", "KISA-JS-INPUT-12", COMMON, "a.js", """
        const multer = require('multer');
        const upload = multer({ dest: 'tmp/' });
        router.post('/import', upload.single('file'), async (req, res) => {
          const source = req.body.source;
          const r = await axios.get(source);
          res.json({ bytes: r.data.length });
        });
    """),
    ("V12 Fastify 상태 코드 먼저인 리다이렉트", "KISA-JS-INPUT-07", FASTIFY, "f.mjs", """
        app.get('/out', async (request, reply) => {
          const url = request.query.url;
          return reply.redirect(302, url);
        });
    """),
    ("V13 Koa 본문 콜백", "KISA-JS-INPUT-12", KOA, "k.js", """
        router.post('/notify', async (ctx) => {
          const cb = ctx.request.body.callback;
          await axios.post(cb, { done: true });
          ctx.status = 202;
        });
    """),
    ("V14 폴더 목록", "KISA-JS-INPUT-03", COMMON, "a.js", """
        app.get('/ls', (req, res) => {
          const dir = path.join('/srv/share', req.query.dir);
          fs.readdir(dir, (err, files) => res.json(files || []));
        });
    """),
    ("V15 헤더로 받은 대상", "KISA-JS-INPUT-12", COMMON, "a.js", """
        app.all('/forward', async (req, res) => {
          const target = req.headers['x-target-url'];
          const r = await axios.request({ url: target, method: req.method });
          res.status(r.status).send(r.data);
        });
    """),
    ("V16 다른 필드와 비교한 삼항", "KISA-JS-INPUT-12", COMMON, "a.js", """
        app.get('/mirror', async (req, res) => {
          const url = req.query.mode === 'default' ? 'https://example.com' : req.query.url;
          res.send((await axios.get(url)).data);
        });
    """),
    ("V17 상수에 담은 화살표 처리 함수", "KISA-JS-INPUT-03", COMMON, "a.js", """
        const showLog = (req, res) => {
          const file = req.query.file;
          res.type('text').send(fs.readFileSync('/var/log/app/' + file, 'utf8'));
        };
        router.get('/logs', requireAdmin, showLog);
    """),
    ("V18 주소를 만드는 async 도우미", "KISA-JS-INPUT-12", COMMON, "a.js", """
        async function buildUrl(host) {
          return `http://${host}/metrics`;
        }
        app.get('/metrics', async (req, res) => {
          const r = await axios.get(await buildUrl(req.query.host));
          res.send(r.data);
        });
    """),
    ("V19 형 표기 컨트롤러 메서드", "KISA-JS-INPUT-12", TS, "c.ts", """
        export class AvatarController {
          async proxy(req: Request, res: Response) {
            const url = req.query.avatar as string;
            const img = await axios.get(url, { responseType: 'arraybuffer' });
            res.type('png').send(img.data);
          }
        }
    """),
    ("V20 exports 에 붙인 처리 함수", "KISA-JS-INPUT-07", COMMON, "a.js", """
        exports.logout = (req, res) => {
          const next = req.query.next;
          req.logout(() => res.redirect(next));
        };
        router.get('/logout', exports.logout);
    """),
]

#: 보고가 남는 안전 사례(라벨 → 까닭). 비어 있어야 한다 — 생기면 원칙(다른 데 쓰였으면 침묵)으로 고친다.
KNOWN_REPORTS: dict[str, str] = {}
#: 놓치는 취약 사례(라벨 → 까닭).
KNOWN_MISSES: dict[str, str] = {
    "V20 exports 에 붙인 처리 함수": "처리 함수를 `exports.x` 속성으로 넘기면 같은 파일 함수로 풀지 않는다(객체 속성은 따라가지 않는다)",
}


@pytest.mark.parametrize("label,header,filename,code", SAFE, ids=[c[0] for c in SAFE])
def test_safe_handler(label: str, header: str, filename: str, code: str) -> None:
    reported = bool(_flows(code, header, filename))
    assert reported == (label in KNOWN_REPORTS), label


@pytest.mark.parametrize("label,rule,header,filename,code", VULNERABLE, ids=[c[0] for c in VULNERABLE])
def test_vulnerable_handler(label: str, rule: str, header: str, filename: str, code: str) -> None:
    detected = rule in _flows(code, header, filename)
    assert detected == (label not in KNOWN_MISSES), label


def test_round_sizes() -> None:
    assert len(SAFE) == 20 and len(VULNERABLE) == 20
    assert set(KNOWN_REPORTS) <= {c[0] for c in SAFE} and set(KNOWN_MISSES) <= {c[0] for c in VULNERABLE}
