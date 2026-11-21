const express = require('express');
const app = express();
app.use(express.json());

app.get('/healthz', (req, res) => res.json({ ok: true, db_configured: Boolean(process.env.DATABASE_URL) }));

app.listen(3000, '127.0.0.1');
