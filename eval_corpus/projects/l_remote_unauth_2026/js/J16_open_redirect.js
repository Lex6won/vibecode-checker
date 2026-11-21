const express = require('express');
const app = express();
app.use(express.json());

app.get('/login/done', (req, res) => {
  res.redirect(req.query.next);
});
