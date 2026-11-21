const express = require('express');
const app = express();
app.use(express.json());

const libxmljs = require('libxmljs');

app.post('/import', express.text({ type: 'application/xml' }), (req, res) => {
  const doc = libxmljs.parseXml(req.body, { noent: true, dtdload: true });
  res.send(doc.get('//name').text());
});
