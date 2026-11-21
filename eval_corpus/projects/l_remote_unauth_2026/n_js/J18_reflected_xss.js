const express = require('express');
const app = express();
app.use(express.json());

const escapeHtml = require('escape-html');

app.get('/hello', (req, res) => {
  res.send(`<h1>Hello ${escapeHtml(String(req.query.name))}</h1>`);
});
