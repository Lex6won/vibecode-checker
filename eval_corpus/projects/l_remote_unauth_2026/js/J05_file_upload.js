const express = require('express');
const app = express();
app.use(express.json());

const multer = require('multer');
const path = require('path');

const storage = multer.diskStorage({
  destination: 'public/uploads',
  filename: (req, file, cb) => cb(null, file.originalname),
});
const upload = multer({ storage });

app.post('/upload', upload.single('file'), (req, res) => res.json({ path: req.file.path }));
