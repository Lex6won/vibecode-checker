const express = require('express');
const app = express();
app.use(express.json());

const session = require('express-session');

app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false, cookie: { secure: true, httpOnly: true, sameSite: 'lax' } }));
