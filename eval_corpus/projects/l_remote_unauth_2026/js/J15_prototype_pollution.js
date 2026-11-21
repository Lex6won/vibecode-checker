const express = require('express');
const app = express();
app.use(express.json());

const _ = require('lodash');

const settings = {};
app.post('/settings', (req, res) => {
  _.merge(settings, req.body);
  res.json(settings);
});

function deepAssign(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object') {
      target[key] = target[key] || {};
      deepAssign(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
}
app.post('/prefs', (req, res) => { deepAssign(settings, req.body); res.end(); });
