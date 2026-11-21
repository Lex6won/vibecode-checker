const express = require('express');
const app = express();
app.use(express.json());

const axios = require('axios');

app.get('/preview', async (req, res) => {
  const response = await axios.get(req.query.url);
  res.send(response.data);
});
