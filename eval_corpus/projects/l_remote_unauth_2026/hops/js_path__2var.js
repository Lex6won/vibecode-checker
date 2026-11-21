const express = require('express');
const { exec } = require('child_process');
const axios = require('axios');
const fs = require('fs');
const app = express();

app.get('/x', (req, res) => {
  const value = req.query.name;
  fs.readFileSync('/srv/files/' + value);
});
