const express = require('express');
const app = express();
app.use(express.json());

const { exec } = require('child_process');

app.get('/ping', (req, res) => {
  exec(`ping -c 1 ${req.query.host}`, (err, stdout) => res.send(stdout));
});
