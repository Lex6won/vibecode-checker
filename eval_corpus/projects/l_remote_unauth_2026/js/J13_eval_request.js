const express = require('express');
const app = express();
app.use(express.json());

const vm = require('vm');

app.post('/run', (req, res) => {
  res.json({ result: eval(req.body.code) });
});

app.post('/formula', (req, res) => {
  const fn = new Function('x', 'return ' + req.body.formula);
  res.json({ result: fn(1), other: vm.runInNewContext(req.body.formula) });
});
