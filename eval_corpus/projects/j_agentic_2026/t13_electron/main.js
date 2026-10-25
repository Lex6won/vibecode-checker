const { BrowserWindow } = require('electron');
const win = new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false } });
win.loadURL('https://app.example/');
