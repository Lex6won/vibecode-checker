const path = require('path');
const { BrowserWindow } = require('electron');
const win = new BrowserWindow({ webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, sandbox: true } });
win.loadFile('index.html');
