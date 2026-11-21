const express = require('express');
const { exec } = require('child_process');
const axios = require('axios');
const fs = require('fs');
const app = express();

function helper(res, value) {
  return res.send('<h1>' + value + '</h1>');
}

app.get('/x', (req, res) => {
  const input = req.query.name as string;
  helper(res, input);
});
