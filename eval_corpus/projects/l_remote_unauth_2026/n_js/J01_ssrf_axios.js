const express = require('express');
const app = express();
app.use(express.json());

const axios = require('axios');
const ALLOWED = new Set(['api.example.go.kr']);

app.get('/preview', async (req, res) => {
  const target = new URL(String(req.query.url));
  if (!ALLOWED.has(target.hostname)) return res.status(403).end();
  const response = await axios.get('https://api.example.go.kr/status');
  res.send(response.data);
});
