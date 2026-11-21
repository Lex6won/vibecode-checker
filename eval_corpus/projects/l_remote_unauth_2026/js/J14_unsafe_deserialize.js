const express = require('express');
const app = express();
app.use(express.json());

const serialize = require('node-serialize');

app.get('/profile', (req, res) => {
  const profile = serialize.unserialize(Buffer.from(req.cookies.profile, 'base64').toString());
  res.json(profile);
});
