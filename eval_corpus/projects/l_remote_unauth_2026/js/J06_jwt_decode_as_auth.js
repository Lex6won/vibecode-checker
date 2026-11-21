const express = require('express');
const app = express();
app.use(express.json());

const jwt = require('jsonwebtoken');

app.get('/admin/users', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const claims = jwt.decode(token);
  if (claims && claims.role === 'admin') return res.json(listUsers());
  res.status(403).end();
});
