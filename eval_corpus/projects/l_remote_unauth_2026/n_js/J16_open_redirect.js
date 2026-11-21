const express = require('express');
const app = express();
app.use(express.json());

app.get('/login/done', (req, res) => {
  const next = String(req.query.next || '/');
  res.redirect(next.startsWith('/') && !next.startsWith('//') ? next : '/');
});
