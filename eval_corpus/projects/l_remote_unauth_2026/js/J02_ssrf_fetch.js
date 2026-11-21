const express = require('express');
const app = express();
app.use(express.json());

app.post('/webhook-test', async (req, res) => {
  const r = await fetch(req.body.callbackUrl, { method: 'POST', body: '{}' });
  res.json({ status: r.status });
});
