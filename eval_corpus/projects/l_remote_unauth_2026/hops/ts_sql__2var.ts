const express = require('express');
const { exec } = require('child_process');
const axios = require('axios');
const fs = require('fs');
const app = express();

app.get('/x', (req, res) => {
  const value = req.query.n as string;
  db.query("SELECT * FROM t WHERE n='" + value + "'");
});
