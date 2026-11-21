const express = require('express');
const { exec } = require('child_process');
const axios = require('axios');
const fs = require('fs');
const app = express();

function helper(res, value) {
  return fs.readFileSync('/srv/files/' + value);
}

app.get('/x', (req, res) => {
  const input = req.query.name as string;
  helper(res, input);
});
