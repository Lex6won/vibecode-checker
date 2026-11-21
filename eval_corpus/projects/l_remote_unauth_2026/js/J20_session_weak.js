const express = require('express');
const app = express();
app.use(express.json());

const session = require('express-session');

app.use(session({ secret: 'keyboard cat', resave: false, saveUninitialized: true, cookie: { secure: false, httpOnly: false } }));
