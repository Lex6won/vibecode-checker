const express = require('express');
const app = express();
app.use(express.json());

const ejs = require('ejs');

app.post('/render', (req, res) => {
  res.send(ejs.render(req.body.template, { user: req.body.user }));
});
