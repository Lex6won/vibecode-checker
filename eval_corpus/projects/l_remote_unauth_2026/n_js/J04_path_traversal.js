const express = require('express');
const app = express();
app.use(express.json());

const path = require('path');
const ROOT = path.resolve(__dirname, 'files');

app.get('/download', (req, res) => {
  const target = path.resolve(ROOT, path.basename(String(req.query.name)));
  if (!target.startsWith(ROOT + path.sep)) return res.status(400).end();
  res.sendFile(target);
});
