const express = require('express');
const app = express();
app.use(express.json());

app.post('/login', async (req, res) => {
  const user = await User.findOne({ username: req.body.username, password: req.body.password });
  if (!user) return res.status(401).end();
  req.session.userId = user.id;
  res.json({ ok: true });
});
