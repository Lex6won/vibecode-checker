import { Router, Request, Response } from "express";
import { Pool } from "pg";
const db = new Pool();
export const router = Router();

router.get("/items/:id", async (req: Request, res: Response) => {
  const rows = await db.query("SELECT * FROM items WHERE id = $1", [req.params.id]);
  res.json(rows);
});

router.post("/items", async (req: Request, res: Response) => {
  const parsed = JSON.parse(req.body.payload as string);
  const evalResult = compute(parsed);
  res.json({ evalResult });
});

function compute(x: unknown): number { return 0; }
