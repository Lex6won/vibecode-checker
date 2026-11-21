const express = require('express');
const app = express();
app.use(express.json());

const { requireAdmin } = require('./auth');

app.delete('/admin/users/:id', requireAdmin, async (req, res) => {
  await db.users.destroy({ where: { id: req.params.id } });
  res.status(204).end();
});
