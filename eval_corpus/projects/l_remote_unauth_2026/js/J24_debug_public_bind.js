const express = require('express');
const app = express();
app.use(express.json());

app.get('/debug/env', (req, res) => res.json(process.env));

app.listen(3000, '0.0.0.0');
