const express = require('express');
const app = express();
app.use(express.json());

const bcrypt = require('bcrypt');

app.post('/login', async (req, res) => {
  const user = await User.findOne({ where: { username: String(req.body.username) } });
  if (!user || !(await bcrypt.compare(String(req.body.password), user.passwordHash))) return res.status(401).end();
  req.session.userId = user.id;
  res.redirect('/');
});
