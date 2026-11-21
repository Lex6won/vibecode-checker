const express = require('express');
const app = express();
app.use(express.json());

const crypto = require('crypto');
const multer = require('multer');
const path = require('path');

const ALLOWED = new Set(['.png', '.jpg', '.pdf']);
const storage = multer.diskStorage({
  destination: 'private/uploads',
  filename: (req, file, cb) => cb(null, crypto.randomUUID() + path.extname(path.basename(file.originalname)).toLowerCase()),
});
const upload = multer({ storage, fileFilter: (req, file, cb) => cb(null, ALLOWED.has(path.extname(path.basename(file.originalname)).toLowerCase())) });

app.post('/upload', requireLogin, upload.single('file'), (req, res) => res.json({ ok: true }));
