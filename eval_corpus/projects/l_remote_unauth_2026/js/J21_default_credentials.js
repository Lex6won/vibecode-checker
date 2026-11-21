const express = require('express');
const app = express();
app.use(express.json());

app.post('/login', (req, res) => {
  if (req.body.username === 'admin' && req.body.password === 'P@ssw0rd') {
    req.session.isAdmin = true;
    return res.redirect('/admin');
  }
  res.status(401).end();
});
