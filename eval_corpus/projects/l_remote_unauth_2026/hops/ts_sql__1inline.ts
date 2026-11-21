const express = require('express');
const { exec } = require('child_process');
const axios = require('axios');
const fs = require('fs');
const app = express();

app.get('/x', (req, res) => {
  db.query("SELECT * FROM t WHERE n='" + req.query.n + "'");
});
