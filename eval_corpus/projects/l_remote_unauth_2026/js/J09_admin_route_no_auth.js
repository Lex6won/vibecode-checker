const express = require('express');
const app = express();
app.use(express.json());

app.delete('/admin/users/:id', async (req, res) => {
  await db.users.destroy({ where: { id: req.params.id } });
  res.status(204).end();
});

app.get('/admin/export', async (req, res) => {
  res.json(await db.users.findAll());
});
