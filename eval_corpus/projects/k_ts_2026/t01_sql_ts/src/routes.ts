import { Router, Request, Response } from "express";
import { Pool } from "pg";
const db = new Pool();
export const router = Router();

router.get("/items/:id", async (req: Request, res: Response) => {
  const rows = await db.query("SELECT * FROM items WHERE id = " + req.params.id);
  res.json(rows);
});

router.get("/search", async (req: Request, res: Response) => {
  const q = `SELECT * FROM items WHERE name = '${req.query.name}'`;
  const rows = await db.query(q as string);
  res.json(rows);
});
