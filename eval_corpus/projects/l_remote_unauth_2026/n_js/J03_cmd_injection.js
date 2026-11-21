const express = require('express');
const app = express();
app.use(express.json());

const { execFile } = require('child_process');
const net = require('net');

app.get('/ping', (req, res) => {
  const host = String(req.query.host);
  if (!net.isIP(host)) return res.status(400).end();
  execFile('ping', ['-c', '1', host], (err, stdout) => res.send(stdout));
});
