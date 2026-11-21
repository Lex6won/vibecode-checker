const express = require('express');
const { exec } = require('child_process');
const axios = require('axios');
const fs = require('fs');
const app = express();

function helper(res, value) {
  return db.query("SELECT * FROM t WHERE n='" + value + "'");
}

app.get('/x', (req, res) => {
  const input = req.query.n;
  helper(res, input);
});
