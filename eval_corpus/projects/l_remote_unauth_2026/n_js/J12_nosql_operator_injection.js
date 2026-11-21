const express = require('express');
const app = express();
app.use(express.json());

app.post('/login', async (req, res) => {
  const user = await User.findOne({ username: String(req.body.username) });
  if (!user || !(await verifyPassword(String(req.body.password), user.passwordHash))) return res.status(401).end();
  req.session.userId = user.id;
  res.json({ ok: true });
});
