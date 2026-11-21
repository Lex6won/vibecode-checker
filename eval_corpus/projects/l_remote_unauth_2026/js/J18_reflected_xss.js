const express = require('express');
const app = express();
app.use(express.json());

app.get('/hello', (req, res) => {
  res.send(`<h1>Hello ${req.query.name}</h1>`);
});
