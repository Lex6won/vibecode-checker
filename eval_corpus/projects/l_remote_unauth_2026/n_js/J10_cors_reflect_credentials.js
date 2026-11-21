const express = require('express');
const app = express();
app.use(express.json());

const cors = require('cors');

app.use(cors({ origin: ['https://portal.example.go.kr'], credentials: true }));
