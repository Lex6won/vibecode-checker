const express = require('express');
const app = express();
app.use(express.json());

app.get('/users/:id', async (req, res) => {
  const rows = await db.query(`SELECT id, name FROM users WHERE id = ${req.params.id}`);
  res.json(rows);
});
