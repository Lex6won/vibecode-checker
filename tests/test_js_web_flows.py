"""JS·TS 요청 값 추적(js_web_flows, 엔진 `js-flow`) — 정탐과, 같은 모양의 안전한 코드.

실측(2026-11-21 말뭉치): `axios.get(req.query.url)` 처럼 한 줄에 다 있을 때만 잡았고 변수 하나만 거치면 전부 놓쳤다.
추적을 넓히되 원칙은 Python 판과 같다 — 그 값(과 한 묶음)이 해가 없다고 아는 쓰임 밖에서 한 번이라도 쓰였으면 침묵한다.
분석 결과를 직접 본다(`strict=True` — 실패를 숨기지 않는다). 보고서 경유 시험은 test_js_flow_integration.py 에 있다.
"""
from __future__ import annotations

import textwrap

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_javascript")
pytest.importorskip("tree_sitter_typescript")

SSRF, PATH, REDIRECT, CMD = "KISA-JS-INPUT-12", "KISA-JS-INPUT-03", "KISA-JS-INPUT-07", "KISA-JS-INPUT-05"

EXPRESS = (
    "const express = require('express');\n"
    "const axios = require('axios');\n"
    "const fs = require('fs');\n"
    "const path = require('path');\n"
    "const { exec, execSync, spawn, execFile } = require('child_process');\n"
    "const app = express();\n"
)
ESM = (
    "import express from 'express';\n"
    "import axios from 'axios';\n"
    "import { readFile } from 'fs/promises';\n"
    "import * as cp from 'node:child_process';\n"
    "const app = express();\n"
)
KOA = (
    "const Koa = require('koa');\n"
    "const Router = require('@koa/router');\n"
    "const axios = require('axios');\n"
    "const app = new Koa();\n"
    "const router = new Router();\n"
    "app.use(router.routes()).use(router.allowedMethods());\n"
)
FASTIFY = (
    "const fastify = require('fastify')({ logger: true });\n"
    "const fs = require('fs');\n"
    "const axios = require('axios');\n"
)
HONO = (
    "import { Hono } from 'hono';\n"
    "import { exec } from 'child_process';\n"
    "const app = new Hono();\n"
)
TS_TYPED = (
    "import type { Request, Response } from 'express';\n"
    "import { exec } from 'child_process';\n"
    "import axios from 'axios';\n"
)


def _hits(code: str, header: str = EXPRESS, filename: str = "app.js") -> list[tuple[str, int, str, str]]:
    from gvskb.scanners._ts_parse import parse
    from gvskb.scanners.js_web_flows import scan_js_flows

    source = header + textwrap.dedent(code)
    root, src = parse(source, filename)
    hits = scan_js_flows(root, src, filename, strict=True)
    assert all(confidence == "likely" for *_, confidence in hits)
    return hits


def _flows(code: str, header: str = EXPRESS, filename: str = "app.js") -> set[str]:
    return {rule for rule, *_ in _hits(code, header, filename)}


VULNERABLE = [
    ("변수 경유 서버 대리 요청", SSRF, EXPRESS, "app.js", """
        app.get('/preview', async (req, res) => {
          const target = req.query.url;
          const r = await axios.get(target);
          res.send(r.data);
        });
    """),
    ("전역 fetch 와 템플릿 앞머리", SSRF, EXPRESS, "app.js", """
        app.get('/proxy', async (req, res) => {
          const target = req.query.target;
          const upstream = await fetch(`${target}`);
          res.send(await upstream.text());
        });
    """),
    ("스킴 뒤 호스트 자리", SSRF, EXPRESS, "app.js", """
        app.get('/status', async (req, res) => {
          const host = req.query.host;
          const r = await axios.get('http://' + host + '/health');
          res.json({ ok: r.status === 200 });
        });
    """),
    ("설정 객체의 url", SSRF, EXPRESS, "app.js", """
        app.post('/hook/test', async (req, res) => {
          const { callback } = req.body;
          await axios({ method: 'post', url: callback, data: { ping: true } });
          res.status(204).end();
        });
    """),
    ("구조분해와 이름 바꾸기", SSRF, EXPRESS, "app.js", """
        app.get('/fetch', async (req, res) => {
          const { url: remote = '' } = req.query;
          const r = await axios.post(remote, {});
          res.send(r.data);
        });
    """),
    ("요청 헤더 값", SSRF, EXPRESS, "app.js", """
        app.get('/relay', async (req, res) => {
          const upstream = req.get('x-upstream');
          const r = await axios.get(upstream);
          res.send(r.data);
        });
    """),
    ("한 번만 대입한 그릇 별칭", SSRF, EXPRESS, "app.js", """
        app.get('/a', async (req, res) => {
          const q = req.query;
          const target = q.target;
          res.send((await axios.get(target)).data);
        });
    """),
    ("다시 대입해도 값을 옮기는 trim", SSRF, EXPRESS, "app.js", """
        app.get('/a', async (req, res) => {
          let target = req.query.target;
          target = target.trim();
          res.send((await axios.get(target)).data);
        });
    """),
    ("String 으로 감싼 값", SSRF, EXPRESS, "app.js", """
        app.get('/a', async (req, res) => {
          const target = String(req.query.target);
          res.send((await axios.get(target)).data);
        });
    """),
    ("배열을 돌며 보내는 요청", SSRF, EXPRESS, "app.js", """
        app.post('/batch', async (req, res) => {
          for (const u of req.body.urls) {
            await axios.get(u);
          }
          res.end();
        });
    """),
    ("try 안의 요청", SSRF, EXPRESS, "app.js", """
        app.get('/a', async (req, res) => {
          const target = req.query.target;
          try {
            const r = await axios.get(target);
            res.send(r.data);
          } catch (err) {
            res.status(502).end();
          }
        });
    """),
    ("값이 없으면 끝내는 것은 검사가 아니다", SSRF, EXPRESS, "app.js", """
        app.get('/a', async (req, res) => {
          const url = req.query.url;
          if (!url) return res.status(400).send('url required');
          res.send((await axios.get(url)).data);
        });
    """),
    ("형만 본 것도 검사가 아니다", SSRF, EXPRESS, "app.js", """
        app.get('/a', async (req, res) => {
          const url = req.query.url;
          if (typeof url !== 'string' || url.length === 0) {
            return res.status(400).end();
          }
          res.send((await axios.get(url)).data);
        });
    """),
    ("기록·응답에 싣기는 쓰임이 아니다", SSRF, EXPRESS, "app.js", """
        app.get('/a', async (req, res) => {
          const url = req.query.url;
          console.log('fetching', url);
          const r = await axios.get(url);
          res.json({ requested: url, status: r.status });
        });
    """),
    ("라우터 객체와 경로 체인", SSRF, EXPRESS, "routes.js", """
        const router = express.Router();
        router.route('/a').get(async (req, res) => {
          const target = req.query.target;
          res.send((await axios.get(target)).data);
        });
        module.exports = router;
    """),
    ("인증 미들웨어는 침묵 사유가 아니다", SSRF, EXPRESS, "app.js", """
        app.get('/admin/fetch', requireAuth, express.json(), async (req, res) => {
          const target = req.query.target;
          res.send((await axios.get(target)).data);
        });
    """),
    ("이름으로 넘긴 처리 함수", SSRF, EXPRESS, "app.js", """
        async function preview(req, res) {
          const target = req.query.target;
          res.send((await axios.get(target)).data);
        }
        app.get('/preview', preview);
    """),
    ("같은 파일 함수를 거친 요청", SSRF, EXPRESS, "app.js", """
        function loadRemote(address) {
          return axios.get(address);
        }
        app.get('/a', async (req, res) => {
          const target = req.query.target;
          res.send((await loadRemote(target)).data);
        });
    """),
    ("경로 조립 뒤 읽기", PATH, EXPRESS, "app.js", """
        app.get('/file', (req, res) => {
          const name = req.query.name;
          const full = path.join(__dirname, 'files', name);
          res.send(fs.readFileSync(full, 'utf8'));
        });
    """),
    ("본문 값으로 쓰기", PATH, EXPRESS, "app.js", """
        app.post('/save', (req, res) => {
          const { filename, content } = req.body;
          fs.writeFile('/srv/data/' + filename, content, () => res.end());
        });
    """),
    ("sendFile 뿌리 옵션 없음", PATH, EXPRESS, "app.js", """
        app.get('/dl', (req, res) => {
          const file = req.params.file;
          res.sendFile(path.resolve('uploads', file));
        });
    """),
    ("download", PATH, EXPRESS, "app.js", """
        app.get('/dl', (req, res) => {
          const file = req.query.file;
          res.download(`/srv/files/${file}`);
        });
    """),
    ("fs/promises 를 import 한 것", PATH, ESM, "app.mjs", """
        app.get('/file', async (req, res) => {
          const name = req.query.name;
          res.send(await readFile(`./public/${name}`, 'utf8'));
        });
    """),
    ("변수 경유 리다이렉트", REDIRECT, EXPRESS, "app.js", """
        app.get('/login/done', (req, res) => {
          const next = req.query.next;
          res.redirect(next);
        });
    """),
    ("분기 한쪽만 요청 값", REDIRECT, EXPRESS, "app.js", """
        app.get('/go', (req, res) => {
          let dest = '/';
          if (req.query.next) {
            dest = req.query.next;
          }
          res.redirect(dest);
        });
    """),
    ("상태 코드 뒤 리다이렉트", REDIRECT, EXPRESS, "app.js", """
        app.get('/go', (req, res) => {
          const dest = req.query.to;
          res.status(302).redirect(dest);
        });
    """),
    ("슬래시 뒤의 값은 //evil 이 된다", REDIRECT, EXPRESS, "app.js", """
        app.get('/go', (req, res) => {
          const dest = req.query.to;
          res.redirect(302, '/' + dest);
        });
    """),
    ("응답 객체를 넘겨받은 함수의 리다이렉트", REDIRECT, EXPRESS, "app.js", """
        function finish(response, location) {
          return response.redirect(location);
        }
        app.get('/go', (req, res) => {
          const dest = req.query.to;
          finish(res, dest);
        });
    """),
    ("템플릿으로 만든 명령", CMD, EXPRESS, "app.js", """
        app.get('/ping', (req, res) => {
          const host = req.query.host;
          exec(`ping -c 1 ${host}`, (err, out) => res.send(out));
        });
    """),
    ("execSync", CMD, EXPRESS, "app.js", """
        app.post('/convert', (req, res) => {
          const name = req.body.name;
          const out = execSync('convert ' + name + ' out.png');
          res.send(out);
        });
    """),
    ("셸을 켠 spawn", CMD, EXPRESS, "app.js", """
        app.get('/grep', (req, res) => {
          const term = req.query.term;
          const p = spawn('grep ' + term + ' /var/log/app.log', { shell: true });
          p.stdout.pipe(res);
        });
    """),
    ("이름을 바꿔 가져온 exec", CMD, "const express = require('express');\nconst { exec: run } = require('child_process');\n"
     "const app = express();\n", "app.js", """
        app.get('/x', (req, res) => {
          const v = req.query.v;
          run('echo ' + v);
          res.end();
        });
    """),
    ("ESM 이름공간 child_process", CMD, ESM, "app.mjs", """
        app.get('/x', (req, res) => {
          const v = req.query.v;
          cp.exec('ls ' + v);
          res.end();
        });
    """),
    ("Koa 라우터", SSRF, KOA, "app.js", """
        router.get('/a', async (ctx) => {
          const target = ctx.query.target;
          ctx.body = (await axios.get(target)).data;
        });
    """),
    ("Koa 리다이렉트", REDIRECT, KOA, "app.js", """
        router.get('/go', async (ctx) => {
          const dest = ctx.request.query.next;
          ctx.redirect(dest);
        });
    """),
    ("Fastify 리다이렉트", REDIRECT, FASTIFY, "app.js", """
        fastify.get('/go', async (request, reply) => {
          const dest = request.query.next;
          return reply.redirect(dest);
        });
    """),
    ("Fastify 파일 읽기", PATH, FASTIFY, "app.js", """
        fastify.get('/f', async (request, reply) => {
          const name = request.params.name;
          return fs.promises.readFile('/srv/' + name, 'utf8');
        });
    """),
    ("Hono 질의 값", CMD, HONO, "app.ts", """
        app.get('/x', (c) => {
          const host = c.req.query('host');
          exec('nslookup ' + host);
          return c.text('ok');
        });
    """),
    ("express 형으로 표기한 매개변수", CMD, TS_TYPED, "convert.ts", """
        export function convert(req: Request, res: Response) {
          const file = req.query.file as string;
          exec('convert ' + file + ' out.png');
          res.end();
        }
    """),
    ("TS 캐스트·non-null 을 거친 값", SSRF, TS_TYPED + "import express from 'express';\nconst app = express();\n", "a.ts", """
        app.get('/a', async (req, res) => {
          const target = (req.query.target as string)!;
          const r = await axios.get<string>(target);
          res.send(r.data);
        });
    """),
    ("라우터 없는 Koa 처리 함수", SSRF, KOA, "app.js", """
        app.use(async (ctx) => {
          const { url } = ctx.query;
          ctx.body = (await axios.get(url)).data;
        });
    """),
    ("Fastify route 객체", REDIRECT, FASTIFY, "app.js", """
        fastify.route({
          method: 'GET',
          url: '/go',
          handler: async (request, reply) => {
            const dest = request.query.next;
            return reply.redirect(dest);
          },
        });
    """),
    ("헬퍼의 반환값을 받아 쓴다", SSRF, EXPRESS, "app.js", """
        async function grab(u) {
          const r = await axios.get(u);
          return r.data;
        }
        app.get('/embed', async (req, res) => {
          const html = await grab(req.query.src);
          res.send(html);
        });
    """),
    ("숫자 첨자 경로 매개변수", PATH, EXPRESS, "app.js", """
        app.get('/files/*', (req, res) => {
          const rel = req.params[0];
          fs.stat('/srv/data/' + rel, (err, st) => res.json(st));
        });
    """),
    ("Hono JSON 본문 구조분해", CMD, HONO, "app.ts", """
        app.post('/x', async (c) => {
          const { host } = await c.req.json();
          exec('ping ' + host);
          return c.json({ ok: true });
        });
    """),
    ("셸에 -c 로 넘긴 명령", CMD, EXPRESS, "app.js", """
        app.get('/sh', (req, res) => {
          const dir = req.query.dir;
          spawn('sh', ['-c', 'ls -la ' + dir]).stdout.pipe(res);
        });
    """),
    ("sendFile 콜백만 넘긴 것", PATH, EXPRESS, "app.js", """
        app.get('/dl', (req, res) => {
          const file = req.query.file;
          res.sendFile('/srv/' + file, (err) => err && res.end());
        });
    """),
    ("요청 값을 읽지 않는 기록 미들웨어 뒤", PATH, EXPRESS, "app.js", """
        app.use((req, res, next) => {
          console.log(req.method, req.url);
          res.set('X-Served-By', 'app');
          next();
        });
        app.get('/f', (req, res) => {
          const file = req.query.file;
          res.send(fs.readFileSync('/srv/' + file));
        });
    """),
    ("root 가 빈 문자열인 sendFile", PATH, EXPRESS, "app.js", """
        app.get('/dl', (req, res) => {
          const file = req.query.file;
          res.sendFile(file, { root: '' });
        });
    """),
    ("root 자체가 요청 값", PATH, EXPRESS, "app.js", """
        app.get('/dl', (req, res) => {
          const dir = req.query.dir;
          res.sendFile('index.html', { root: dir });
        });
    """),
    ("앱을 담지 않은 체인", PATH, "const express = require('express');\nconst fs = require('fs');\n", "app.js", """
        express()
          .get('/raw', (req, res) => {
            const p = req.query.p;
            fs.createReadStream(p).pipe(res);
          })
          .listen(3000);
    """),
    ("koa-body 를 거친 본문", PATH, "const Koa = require('koa');\nconst Router = require('@koa/router');\n"
     "const { koaBody } = require('koa-body');\nconst fs = require('fs');\nconst app = new Koa();\nconst router = new Router();\n"
     "app.use(koaBody());\napp.use(router.routes());\n", "app.js", """
        router.post('/save', koaBody(), async (ctx) => {
          const { filename } = ctx.request.body;
          await fs.promises.writeFile(`/srv/notes/${filename}`, 'x');
        });
    """),
    # ── 설계상 침묵(놓치는 것을 알고 둔다) ──
    ("모르는 함수에 넘겼다", SSRF, EXPRESS, "app.js", """
        app.get('/a', async (req, res) => {
          const target = req.query.target;
          audit('fetch', target);
          res.send((await axios.get(target)).data);
        });
    """),
    ("검증 미들웨어가 걸린 라우트", SSRF, EXPRESS, "app.js", """
        app.get('/a', validate(schema), async (req, res) => {
          const target = req.query.target;
          res.send((await axios.get(target)).data);
        });
    """),
    ("콜백 매개변수로 넘어간 값", SSRF, EXPRESS, "app.js", """
        app.get('/a', (req, res) => {
          Promise.resolve(req.query.target).then((u) => axios.get(u)).then((r) => res.send(r.data));
        });
    """),
    ("객체 속성에 담아 둔 값", SSRF, EXPRESS, "app.js", """
        app.get('/a', async (req, res) => {
          const job = {};
          job.url = req.query.target;
          res.send((await axios.get(job.url)).data);
        });
    """),
    ("두 단계 함수 경유(W1-a 는 1단계)", SSRF, EXPRESS, "app.js", """
        function inner(u) { return axios.get(u); }
        function outer(v) { return inner(v); }
        app.get('/a', async (req, res) => {
          res.send((await outer(req.query.target)).data);
        });
    """),
]

SILENT_BY_DESIGN = {
    "모르는 함수에 넘겼다": "그 함수가 검사일 수 있다",
    "검증 미들웨어가 걸린 라우트": "미들웨어가 무엇을 거르는지 모른다(4-7)",
    "콜백 매개변수로 넘어간 값": "콜백 매개변수로 넘어가는 흐름은 따라가지 않는다(4-4)",
    "객체 속성에 담아 둔 값": "객체 속성은 따라가지 않는다(9절)",
    "두 단계 함수 경유(W1-a 는 1단계)": "함수 요약 2단계는 W1-b",
}


SAFE = [
    ("허용 목록 대조", EXPRESS, """
        const ALLOWED = ['https://api.example.com'];
        app.get('/a', async (req, res) => {
          const target = req.query.target;
          if (!ALLOWED.includes(target)) return res.status(403).end();
          res.send((await axios.get(target)).data);
        });
    """),
    ("new URL 뒤 호스트 비교", EXPRESS, """
        app.get('/a', async (req, res) => {
          const target = req.query.target;
          const u = new URL(target);
          if (u.hostname !== 'api.example.com') return res.status(403).end();
          res.send((await axios.get(target)).data);
        });
    """),
    ("정규식 검사", EXPRESS, """
        app.get('/f', (req, res) => {
          const name = req.query.name;
          if (!/^[a-z0-9_-]+\\.txt$/.test(name)) return res.status(400).end();
          res.send(fs.readFileSync(path.join('/srv/files', name)));
        });
    """),
    ("고정 호스트 뒤의 경로", EXPRESS, """
        app.get('/item', async (req, res) => {
          const id = req.query.id;
          res.send((await axios.get('https://api.example.com/items/' + id)).data);
        });
    """),
    ("고정 경로 뒤의 리다이렉트 질의", EXPRESS, """
        app.get('/go', (req, res) => {
          const next = req.query.next;
          res.redirect('/login?next=' + next);
        });
    """),
    ("execFile 에 인자 배열", EXPRESS, """
        app.get('/ping', (req, res) => {
          const host = req.query.host;
          execFile('ping', ['-c', '1', host], (err, out) => res.send(out));
        });
    """),
    ("셸 없는 spawn", EXPRESS, """
        app.get('/ping', (req, res) => {
          const host = req.query.host;
          spawn('ping', ['-c', '1', host]).stdout.pipe(res);
        });
    """),
    ("sendFile 의 root 옵션", EXPRESS, """
        app.get('/dl', (req, res) => {
          const file = req.query.file;
          res.sendFile(file, { root: '/srv/public' });
        });
    """),
    ("basename 으로 자른 값", EXPRESS, """
        app.get('/dl', (req, res) => {
          const file = path.basename(req.query.file);
          res.sendFile(path.join('/srv/public', file));
        });
    """),
    ("숫자로 바꾼 값", EXPRESS, """
        app.get('/page', async (req, res) => {
          const n = Number(req.query.n);
          res.send((await axios.get(`${n}`)).data);
        });
    """),
    ("조회 표의 열쇠", EXPRESS, """
        const SERVICES = { a: 'https://a.example.com', b: 'https://b.example.com' };
        app.get('/svc', async (req, res) => {
          const target = SERVICES[req.query.svc];
          res.send((await axios.get(target)).data);
        });
    """),
    ("이름만 req 인 다른 콜백", EXPRESS, """
        const https = require('https');
        function relay(req) {
          return axios.get(req.query.url);
        }
        https.get('https://example.com', (req) => {
          exec('echo ' + req.headers.host);
        });
    """),
    ("프레임워크 객체가 아닌 app", "const axios = require('axios');\nconst express = require('express');\n"
     "const app = createApp();\n", """
        app.get('/a', async (req, res) => {
          const target = req.query.target;
          res.send((await axios.get(target)).data);
        });
    """),
    ("모르는 app.use 가 있는 파일", EXPRESS, """
        app.use(validateAll);
        app.get('/a', async (req, res) => {
          const target = req.query.target;
          res.send((await axios.get(target)).data);
        });
    """),
    ("요청 값을 읽는 인라인 미들웨어", EXPRESS, """
        app.use((req, res, next) => {
          if (req.query.target && !req.query.target.startsWith('https://')) return res.status(400).end();
          next();
        });
        app.get('/a', async (req, res) => {
          const target = req.query.target;
          res.send((await axios.get(target)).data);
        });
    """),
    ("상수로 다시 대입", EXPRESS, """
        app.get('/a', async (req, res) => {
          let target = req.query.target;
          target = 'https://api.example.com/status';
          res.send((await axios.get(target)).data);
        });
    """),
    ("경로 제약이 걸린 매개변수", EXPRESS, """
        app.get('/files/:id(\\\\d+)', (req, res) => {
          const id = req.params.id;
          res.send(fs.readFileSync('/srv/files/' + id));
        });
    """),
    ("startsWith 로 본 값", EXPRESS, """
        app.get('/go', (req, res) => {
          const next = req.query.next;
          res.redirect(next.startsWith('/') && !next.startsWith('//') ? next : '/');
        });
    """),
    ("콜백 안에서 본 값", EXPRESS, """
        const HOSTS = ['https://a.example.com/', 'https://b.example.com/'];
        app.get('/a', async (req, res) => {
          const target = req.query.target;
          if (!HOSTS.some((h) => target.startsWith(h))) return res.status(403).end();
          res.send((await axios.get(target)).data);
        });
    """),
    ("다른 처리 함수가 같은 필드를 들여다봄", EXPRESS, """
        app.get('/check', (req, res) => {
          res.json({ ok: isSafeUrl(req.query.target) });
        });
        app.get('/a', async (req, res) => {
          const target = req.query.target;
          res.send((await axios.get(target)).data);
        });
    """),
    ("스키마 검증", EXPRESS, """
        app.post('/hook', async (req, res) => {
          const body = schema.parse(req.body);
          await axios.post(body.callback, {});
          res.end();
        });
    """),
    ("값과 비교", EXPRESS, """
        app.get('/go', (req, res) => {
          const next = req.query.next;
          if (next !== '/home' && next !== '/profile') return res.redirect('/');
          res.redirect(next);
        });
    """),
    ("eval 이 있는 파일은 이름을 풀 수 없다", EXPRESS, """
        app.get('/a', async (req, res) => {
          const target = req.query.target;
          eval('1');
          res.send((await axios.get(target)).data);
        });
    """),
    ("arguments 를 쓰는 함수", EXPRESS, """
        function load(address) {
          check(arguments);
          return axios.get(address);
        }
        app.get('/a', async (req, res) => {
          res.send((await load(req.query.target)).data);
        });
    """),
    ("다른 함수에서 다시 대입되는 이름", EXPRESS, """
        app.get('/a', async (req, res) => {
          let target = req.query.target;
          [1].forEach(() => { target = normalize(target); });
          res.send((await axios.get(target)).data);
        });
    """),
    ("Hono 검증 미들웨어", HONO, """
        app.get('/x', validator('query', check), (c) => {
          const host = c.req.query('host');
          exec('nslookup ' + host);
          return c.text('ok');
        });
    """),
    ("Fastify 스키마 옵션", FASTIFY, """
        fastify.get('/go', { schema: { querystring: S } }, async (request, reply) => {
          const dest = request.query.next;
          return reply.redirect(dest);
        });
    """),
    ("router.param 으로 먼저 들여다본 경로 매개변수", EXPRESS, """
        const router = express.Router();
        router.param('file', checkFileParam);
        router.get('/f/:file', (req, res) => {
          const f = req.params.file;
          res.send(fs.readFileSync('/srv/' + f));
        });
    """),
    ("Koa 에서 요청 값을 읽는 use 가 둘", KOA, """
        app.use(async (ctx, next) => {
          if (!isAllowed(ctx.query.target)) ctx.throw(400);
          await next();
        });
        app.use(async (ctx) => {
          const target = ctx.query.target;
          ctx.body = (await axios.get(target)).data;
        });
    """),
    ("Fastify route 객체의 스키마", FASTIFY, """
        fastify.route({
          method: 'GET', url: '/go', schema: { querystring: S },
          handler: async (request, reply) => reply.redirect(request.query.next),
        });
    """),
    ("sendFile 의 모르는 옵션 변수", EXPRESS, """
        app.get('/dl', (req, res) => {
          const file = req.query.file;
          res.sendFile(file, loadOptions());
        });
    """),
    ("sendFile 의 펼친 옵션", EXPRESS, """
        const BASE = { root: '/srv/public' };
        app.get('/dl', (req, res) => {
          const file = req.query.file;
          res.sendFile(file, { ...BASE, maxAge: 60 });
        });
    """),
    ("download 의 셋째 자리 root 옵션", EXPRESS, """
        app.get('/dl', (req, res) => {
          const file = req.query.file;
          res.download(file, 'report.pdf', { root: '/srv/reports' });
        });
    """),
    ("요청 값을 읽는 express 검증 use", EXPRESS, """
        app.use((req, res, next) => {
          if (!isSafe(req.query.file)) return res.status(400).end();
          next();
        });
        app.get('/f', (req, res) => {
          const file = req.query.file;
          res.send(fs.readFileSync('/srv/' + file));
        });
    """),
    ("셸이 아닌 프로그램의 -c 인자", EXPRESS, """
        app.get('/z', (req, res) => {
          const v = req.query.v;
          spawn('python3', ['-c', 'print(1)', v]).stdout.pipe(res);
        });
    """),
    ("표지가 없는 파일", "const axios = require('axios');\n", """
        function handler(req, res) {
          const target = req.query.target;
          return axios.get(target);
        }
    """),
]


@pytest.mark.parametrize("label,rule,header,filename,code", VULNERABLE, ids=[c[0] for c in VULNERABLE])
def test_flow_is_reported(label: str, rule: str, header: str, filename: str, code: str) -> None:
    assert (rule in _flows(code, header, filename)) == (label not in SILENT_BY_DESIGN), label


@pytest.mark.parametrize("label,header,code", SAFE, ids=[c[0] for c in SAFE])
def test_safe_shape_is_not_reported(label: str, header: str, code: str) -> None:
    filename = "app.ts" if header is HONO else "app.js"
    assert _flows(code, header, filename) == set(), label


def test_silent_by_design_labels_exist() -> None:
    labels = {c[0] for c in VULNERABLE}
    assert set(SILENT_BY_DESIGN) <= labels


def test_report_points_at_the_sink_line() -> None:
    hits = _hits("""
        app.get('/a', async (req, res) => {
          const target = req.query.target;
          const r = await axios.get(target);
          res.send(r.data);
        });
    """)
    line = EXPRESS.count("\n") + 4
    assert [(r, ln) for r, ln, *_ in hits] == [(SSRF, line)]
    assert "axios.get(target)" in hits[0][2]


def test_function_summary_reports_inside_the_helper() -> None:
    """함수 경유는 함수 안의 위험한 자리 줄로 보고한다(말뭉치 `*__3func` 와 같다)."""
    hits = _hits("""
        function helper(res, value) {
          return res.redirect(value);
        }
        app.get('/x', (req, res) => {
          const input = req.query.next;
          helper(res, input);
        });
    """)
    assert [(r, ln) for r, ln, *_ in hits] == [(REDIRECT, EXPRESS.count("\n") + 3)]


def test_helper_that_checks_its_parameter_silences_the_caller() -> None:
    """같은 파일 함수가 그 매개변수를 다른 데 쓰면(검사일 수 있다) 호출부의 값도 쓰인 것이다."""
    assert _flows("""
        function safeGet(address) {
          if (!isAllowed(address)) throw new Error('blocked');
          return axios.get(address);
        }
        app.get('/a', async (req, res) => {
          const target = req.query.target;
          res.send((await safeGet(target)).data);
        });
    """) == set()


def test_response_name_alone_is_not_a_response_object() -> None:
    """이름이 res 라는 것만으로는 응답 객체가 아니다 — 요청 객체 바로 다음 매개변수거나 그것을 넘겨받은 매개변수여야 한다."""
    assert _flows("""
        function go(res, location) {
          return res.redirect(location);
        }
        app.get('/x', (req, res) => {
          const dest = req.query.to;
          go(makeResponder(), dest);
        });
    """) == set()


def test_shadowed_request_name_is_not_the_request() -> None:
    """가림 — 안쪽에서 같은 이름을 다시 선언하면 다른 값이다."""
    assert _flows("""
        app.get('/a', async (req, res) => {
          const handle = async (req) => axios.get(req.query.target);
          res.send('ok');
        });
    """) == set()


def test_unknown_module_named_like_a_sink_is_not_a_sink() -> None:
    """import 를 확인하지 못한 exec·request 는 싱크로 치지 않는다."""
    assert _flows("""
        app.get('/a', (req, res) => {
          const v = req.query.v;
          request(v);
          exec2('ls ' + v);
          res.end();
        });
    """, header="const express = require('express');\nconst app = express();\n") == set()


MIDDLEWARE_FIELD_CASES = [
    # (라벨, 미들웨어 본문, 보고하는가) — 처리 함수는 늘 `req.query.file` 을 경로에 쓴다
    ("URL 원문을 파싱해 검사 → 쿼리 전체가 쓰였다",
     "const f = new URL(req.originalUrl, 'http://x').searchParams.get('file');\n"
     "  if (f && !/^[\\w-]+$/.test(f)) return res.sendStatus(400);", False),
    ("req.url 쿼리스트링 검사", "if (!ok(req.url.split('?')[1])) return res.sendStatus(400);", False),
    ("_parsedUrl", "if (bad(req._parsedUrl.query)) return res.sendStatus(400);", False),
    ("쿼리 그릇 통째로", "if (Object.keys(req.query).length > 3) return res.sendStatus(400);", False),
    ("계산식 열쇠", "const k = 'file';\n  if (!ok(req.query[k])) return res.sendStatus(400);", False),
    ("요청 객체를 통째로 넘김", "if (!validate(req)) return res.sendStatus(400);", False),
    ("열쇠를 모르는 헤더 읽기는 헤더만", "if (!ok(req.get(HEADER))) return res.sendStatus(401);", True),
    ("인증 헤더만 읽음 → 다른 열쇠는 그대로", "if (!verify(req.headers.authorization)) return res.sendStatus(401);", True),
    ("API 키 헤더", "if (req.get('x-api-key') !== KEY) return res.sendStatus(401);", True),
    ("세션 쿠키", "if (!req.cookies.sid) return res.sendStatus(401);", True),
    ("경로만 검사 → 쿼리 흐름은 그대로", "if (decodeURIComponent(req.path).includes('..')) return res.sendStatus(400);", True),
    ("기록만", "console.log(req.method, req.originalUrl, req.query);", True),
    ("권한 게이트", "if (req.user.role !== 'admin') return res.sendStatus(403);", True),
]


@pytest.mark.parametrize("label,body,reported", MIDDLEWARE_FIELD_CASES, ids=[c[0] for c in MIDDLEWARE_FIELD_CASES])
def test_middleware_uses_are_counted_per_field(label: str, body: str, reported: bool) -> None:
    """함수 미들웨어의 쓰임은 파일 전체의 필드별 열쇠로 센다 — 같은 열쇠(또는 그 그릇·URL 원문)를 썼으면 침묵, 다른 열쇠면 보고."""
    code = (
        "app.use((req, res, next) => {\n  " + body + "\n  next();\n});\n"
        "app.get('/f', (req, res) => {\n  const file = req.query.file;\n  res.send(fs.readFileSync('/srv/' + file));\n});\n"
    )
    assert (PATH in _flows(code)) == reported, label


def test_path_read_silences_only_path_parameters() -> None:
    mw = "app.use((req, res, next) => {\n  if (req.path.includes('..')) return res.sendStatus(400);\n  next();\n});\n"
    by_param = mw + "app.get('/f/*', (req, res) => {\n  res.send(fs.readFileSync('/srv/' + req.params[0]));\n});\n"
    assert _flows(by_param) == set()


def test_raw_url_read_silences_path_parameters_too() -> None:
    """URL 원문에는 경로도 들어 있다 — 원문으로 경로를 검사한 미들웨어는 경로 매개변수 흐름도 침묵시킨다."""
    mw = ("app.use((req, res, next) => {\n  const p = new URL(req.originalUrl, 'http://x').pathname;\n"
          "  if (p.includes('..')) return res.sendStatus(400);\n  next();\n});\n")
    route = "app.get('/f/:name', (req, res) => {\n  res.send(fs.readFileSync('/srv/' + req.params.name));\n});\n"
    assert _flows(mw + route) == set()
    hono = HONO + "import fs from 'fs';\n"
    hono_mw = "app.use('*', async (c, next) => {\n  if (new URL(c.req.url).pathname.includes('..')) return c.text('bad', 400);\n  await next();\n});\n"
    hono_route = "app.get('/f/:name', (c) => c.text(fs.readFileSync('/srv/' + c.req.param('name'), 'utf8')));\n"
    assert _flows(hono_mw + hono_route, header=hono, filename="a.ts") == set()


def test_query_only_read_keeps_path_parameter_flows() -> None:
    """쿼리 부분만 읽는 미들웨어(`ctx.querystring`)는 경로 매개변수 흐름을 침묵시키지 않는다."""
    koa_fs = KOA + "const fs = require('fs');\n"
    qs = "app.use(async (ctx, next) => {\n  if (!ok(ctx.querystring)) ctx.throw(400);\n  await next();\n});\n"
    by_param = "router.get('/f/:name', async (ctx) => {\n  ctx.body = fs.readFileSync('/srv/' + ctx.params.name);\n});\n"
    assert _flows(qs + by_param, header=koa_fs) == {PATH}
    by_query = "router.get('/f', async (ctx) => {\n  ctx.body = fs.readFileSync('/srv/' + ctx.query.name);\n});\n"
    assert _flows(qs + by_query, header=koa_fs) == set()


def test_koa_raw_querystring_and_path_reads() -> None:
    koa_fs = KOA + "const fs = require('fs');\n"
    qs = "app.use(async (ctx, next) => {\n  if (!ok(new URLSearchParams(ctx.querystring).get('f'))) ctx.throw(400);\n  await next();\n});\n"
    route = "router.get('/x', async (ctx) => {\n  ctx.body = fs.readFileSync('/srv/' + ctx.query.f);\n});\n"
    assert _flows(qs + route, header=koa_fs) == set()
    raw = "app.use(async (ctx, next) => {\n  if (!ok(ctx.req.url)) ctx.throw(400);\n  await next();\n});\n"
    assert _flows(raw + route, header=koa_fs) == set()
    timing = "app.use(async (ctx, next) => {\n  const t = Date.now();\n  await next();\n  ctx.set('X-Time', String(Date.now() - t));\n});\n"
    assert _flows(timing + route, header=koa_fs) == {PATH}


def test_fastify_hook_and_route_prehandler_are_counted_per_field() -> None:
    route = "fastify.get('/f', async (request, reply) => fs.readFileSync('/srv/' + request.query.f));\n"
    hook = "fastify.addHook('onRequest', async (request, reply) => {\n  if (!ok(request.url)) return reply.code(400).send();\n});\n"
    assert _flows(hook + route, header=FASTIFY) == set()
    log_hook = "fastify.addHook('onRequest', async (request) => {\n  request.log.info({ url: request.url }, 'in');\n});\n"
    assert _flows(log_hook + route, header=FASTIFY) == {PATH}
    pre = ("fastify.get('/g', { preHandler: async (request) => { if (!request.headers.authorization) throw new Error('x'); } },\n"
           "  async (request, reply) => fs.readFileSync('/srv/' + request.query.f));\n")
    assert _flows(pre, header=FASTIFY) == {PATH}


def test_hono_middleware_uses_are_counted_per_field() -> None:
    hono_fs = HONO + "import fs from 'fs';\n"
    route = "app.get('/x', (c) => c.text(fs.readFileSync('/srv/' + c.req.query('f'), 'utf8')));\n"
    url_mw = "app.use('*', async (c, next) => {\n  if (!ok(new URL(c.req.url).searchParams.get('f'))) return c.text('bad', 400);\n  await next();\n});\n"
    assert _flows(url_mw + route, header=hono_fs, filename="a.ts") == set()
    auth_mw = "app.use('*', async (c, next) => {\n  if (!c.req.header('authorization')) return c.text('no', 401);\n  await next();\n});\n"
    assert _flows(auth_mw + route, header=hono_fs, filename="a.ts") == {PATH}


def test_root_assigned_later_from_the_request_is_reported() -> None:
    code = """
        app.get('/doc', (req, res) => {
          const opts = { root: '/srv/docs' };
          if (req.query.d) opts.root = req.query.d;
          res.sendFile(req.query.f, opts);
        });
    """
    assert _flows(code) == {PATH}
    constant = code.replace("opts.root = req.query.d", "opts.root = '/srv/other'")
    assert _flows(constant) == set()


def test_harmless_response_methods_and_async_wrapper() -> None:
    attach = """
        app.get('/dl', (req, res) => {
          const file = req.query.file;
          res.attachment(file);
          res.set('X-File', file);
          res.send(fs.readFileSync('/srv/' + file));
        });
    """
    assert _flows(attach) == {PATH}
    wrapped = "const asyncHandler = require('express-async-handler');\n" + textwrap.dedent("""
        app.get('/r', asyncHandler(async (req, res) => {
          res.send(fs.readFileSync('/srv/' + req.query.name));
        }));
    """)
    assert _flows(wrapped) == {PATH}
    unknown = wrapped.replace("require('express-async-handler')", "require('./my-wrapper')")
    assert _flows(unknown) == set()                       # 모르는 래퍼 — 침묵


def test_locally_declared_fetch_is_not_global_fetch() -> None:
    assert _flows("""
        function fetch(x) { return x; }
        app.get('/a', (req, res) => {
          const v = req.query.v;
          res.send(fetch(v));
        });
    """) == set()
