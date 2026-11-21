const express = require('express');
const app = express();
app.use(express.json());

const path = require('path');
const fs = require('fs');

app.get('/download', (req, res) => {
  res.sendFile(path.join(__dirname, 'files', req.query.name));
});

app.get('/read', (req, res) => {
  fs.readFile('/srv/app/files/' + req.query.p, 'utf8', (err, data) => res.send(data));
});
