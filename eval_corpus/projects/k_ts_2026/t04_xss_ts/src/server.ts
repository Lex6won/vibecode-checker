import express, { Request, Response } from "express";
const app = express();

app.get("/hello", (req: Request, res: Response) => {
  res.send(`<div>${req.query.name}</div>`);
});
