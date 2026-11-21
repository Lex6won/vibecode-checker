const express = require('express');
const app = express();
app.use(express.json());

app.get('/api/orders/:id', async (req, res) => {
  const order = await Order.findByPk(req.params.id);
  res.json(order);
});
